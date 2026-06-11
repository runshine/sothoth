"""Unified child-task access layer for binary-security orchestration.

All downstream child-task operations must go through this module. Business
orchestration code must not call downstream service clients directly.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import re
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.exception import ConflictError, NotFoundError, UpstreamError, ValidationError
from app.model import BinarySecurityStageItem, BinarySecurityTask, normalize_stage_name
from app.time_utils import now_local


DOWNSTREAM_REF_ACTIVE_STATUSES = {"queued", "running", "dispatching", "pending", "cancelling", "cancel_requested"}
DOWNSTREAM_REF_DELETED_STATUSES = {"deleted", "missing", "downstream_missing", "not_found"}
LEGACY_UNSUPPORTED_DOWNSTREAM_SERVICES = {"dataflow_analyse", "dataflow_vuln_scanner"}


def get_binary_to_source_client():
    from app.service import task_manager as task_manager_module

    return task_manager_module.get_binary_to_source_client()


def get_dataflow_vuln_scan_client():
    from app.service import task_manager as task_manager_module

    return task_manager_module.get_dataflow_vuln_scan_client()


def get_entry_analyse_client():
    from app.service import task_manager as task_manager_module

    return task_manager_module.get_entry_analyse_client()


def get_firmware_unpacker_client():
    from app.service import task_manager as task_manager_module

    return task_manager_module.get_firmware_unpacker_client()


def get_system_analyse_client():
    from app.service import task_manager as task_manager_module

    return task_manager_module.get_system_analyse_client()


class DownstreamTaskGateway:
    @staticmethod
    async def _call_with_optional_token(method: Any, task_id: str, token: str | None) -> dict[str, Any]:
        try:
            signature = inspect.signature(method)
        except (TypeError, ValueError):
            signature = None
        if signature is not None and "token" not in signature.parameters:
            return await method(task_id)
        return await method(task_id, token or "")

    def _binary_to_source_client(self):
        return get_binary_to_source_client()

    def _dataflow_vuln_scan_client(self):
        return get_dataflow_vuln_scan_client()

    def _entry_analyse_client(self):
        return get_entry_analyse_client()

    def _firmware_unpacker_client(self):
        return get_firmware_unpacker_client()

    def _system_analyse_client(self):
        return get_system_analyse_client()

    def _normalize_service(self, service: str) -> str:
        value = str(service or "").strip()
        if not value:
            raise ValidationError("缺少下游服务标识")
        return value

    def _reject_legacy_service(self, service: str) -> None:
        raise ValidationError(f"历史下游服务 {service} 已移除，请使用 dataflow_vuln_scan")

    async def get_task(self, service: str, *, project_id: str | None, task_id: str, token: str | None) -> dict[str, Any]:
        normalized = self._normalize_service(service)
        if normalized == "firmware_unpacker":
            return await self._firmware_unpacker_client().get_task(project_id or "", task_id, token or "")
        if normalized == "system_analyse":
            return await self._system_analyse_client().get_task(task_id)
        if normalized == "binary_to_source":
            return await self._binary_to_source_client().get_task(project_id or "", task_id, token or "")
        if normalized == "entry_analyse":
            return await self._entry_analyse_client().get_task(task_id, token or "")
        if normalized in LEGACY_UNSUPPORTED_DOWNSTREAM_SERVICES:
            self._reject_legacy_service(normalized)
        if normalized == "dataflow_vuln_scan":
            return await self._call_with_optional_token(self._dataflow_vuln_scan_client().get_task, task_id, token)
        raise ValidationError(f"未知下游服务: {normalized}")

    async def list_tasks(self, service: str, *, project_id: str, token: str | None, **kwargs: Any) -> dict[str, Any]:
        normalized = self._normalize_service(service)
        if normalized == "firmware_unpacker":
            return await self._firmware_unpacker_client().list_tasks(
                project_id,
                token or "",
                origin_mode=kwargs.get("origin_mode", "linked"),
                limit=int(kwargs.get("limit", 100) or 100),
                offset=int(kwargs.get("offset", 0) or 0),
            )
        if normalized == "system_analyse":
            return await self._system_analyse_client().list_tasks(
                project_id,
                parent_task_id=kwargs.get("parent_task_id"),
                page=int(kwargs.get("page", 1) or 1),
                per_page=int(kwargs.get("per_page", 100) or 100),
                sort_by=str(kwargs.get("sort_by") or "updated_at"),
                sort_order=str(kwargs.get("sort_order") or "desc"),
            )
        if normalized == "binary_to_source":
            return await self._binary_to_source_client().list_tasks(
                project_id,
                token or "",
                parent_task_id=kwargs.get("parent_task_id"),
                parent_stage_item_id=kwargs.get("parent_stage_item_id"),
                limit=int(kwargs.get("limit", 100) or 100),
                offset=int(kwargs.get("offset", 0) or 0),
                status=kwargs.get("status"),
            )
        if normalized == "entry_analyse":
            return await self._entry_analyse_client().list_tasks(
                project_id,
                parent_task_id=kwargs.get("parent_task_id"),
                parent_stage_name=kwargs.get("parent_stage_name"),
                parent_stage_item_id=kwargs.get("parent_stage_item_id"),
                parent_stage_item_key=kwargs.get("parent_stage_item_key"),
                page=int(kwargs.get("page", 1) or 1),
                per_page=int(kwargs.get("per_page", 100) or 100),
                sort_by=str(kwargs.get("sort_by") or "updated_at"),
                sort_order=str(kwargs.get("sort_order") or "desc"),
                token=token,
            )
        if normalized in LEGACY_UNSUPPORTED_DOWNSTREAM_SERVICES:
            self._reject_legacy_service(normalized)
        if normalized == "dataflow_vuln_scan":
            rows = await self._dataflow_vuln_scan_client().list_tasks(
                project_id,
                token or "",
                limit=int(kwargs.get("limit", 100) or 100),
                offset=int(kwargs.get("offset", 0) or 0),
                status=kwargs.get("status"),
                parent_task_id=kwargs.get("parent_task_id"),
                parent_stage_item_id=kwargs.get("parent_stage_item_id"),
            )
            if isinstance(rows, dict):
                return rows
            return {"items": list(rows or [])}
        raise ValidationError(f"未知下游服务: {normalized}")

    async def create_task(self, service: str, *, project_id: str, token: str | None, **kwargs: Any) -> dict[str, Any]:
        normalized = self._normalize_service(service)
        agent_task_key = {
            key: kwargs.get(key)
            for key in (
                "agent_task_key_id",
                "agent_task_key_name",
                "agent_task_key_prefix",
                "agent_task_key_secret",
                "agent_task_key_source",
            )
            if kwargs.get(key) is not None
        }
        if normalized == "firmware_unpacker":
            return await self._firmware_unpacker_client().create_task(
                project_id,
                str(kwargs["firmware_path"]),
                token or "",
                kwargs.get("origin"),
                agent_task_key=agent_task_key or None,
            )
        if normalized == "system_analyse":
            return await self._system_analyse_client().create_task(
                project_id,
                str(kwargs["task_name"]),
                str(kwargs["input_path"]),
                token or "",
                kwargs.get("origin"),
                analysis_mode=str(kwargs.get("analysis_mode") or "binary"),
                agent_task_key=agent_task_key or None,
            )
        if normalized == "binary_to_source":
            return await self._binary_to_source_client().create_task(
                project_id,
                str(kwargs["name"]),
                list(kwargs["elf_tasks"]),
                token or "",
                kwargs.get("origin"),
                agent_task_key=agent_task_key or None,
                mode=kwargs.get("mode"),
                engine=kwargs.get("engine"),
                reuse_cache=kwargs.get("reuse_cache"),
            )
        if normalized == "entry_analyse":
            return await self._entry_analyse_client().create_task(
                project_id,
                str(kwargs["task_name"]),
                str(kwargs["input_path"]),
                str(kwargs["module_name"]),
                token or "",
                kwargs.get("source_path"),
                kwargs.get("origin"),
                agent_task_key=agent_task_key or None,
            )
        if normalized in LEGACY_UNSUPPORTED_DOWNSTREAM_SERVICES:
            self._reject_legacy_service(normalized)
        if normalized == "dataflow_vuln_scan" and "module_input_path" in kwargs:
            return await self._dataflow_vuln_scan_client().create_task(
                project_id,
                str(kwargs["task_name"]),
                str(kwargs["module_input_path"]),
                str(kwargs["source_root_path"]),
                str(kwargs["prompt_content"]),
                kwargs.get("origin"),
                token=token or "",
                agent_task_key=agent_task_key or None,
                source_file=kwargs.get("source_file"),
                function_name=kwargs.get("function_name"),
                line_hint=kwargs.get("line_hint"),
                definition_kind=kwargs.get("definition_kind"),
                taint_params=kwargs.get("taint_params"),
                function_description=kwargs.get("function_description"),
                entry_reason=kwargs.get("entry_reason"),
                taint_details=kwargs.get("taint_details"),
                function_description_source=kwargs.get("function_description_source"),
                entry_reason_source=kwargs.get("entry_reason_source"),
            )
        if normalized == "dataflow_vuln_scan":
            return await self._dataflow_vuln_scan_client().create_task(
                project_id,
                str(kwargs["title"]),
                str(kwargs["data_flow_path"]),
                str(kwargs["source_dir"]),
                str(kwargs.get("prompt_content") or ""),
                kwargs.get("origin"),
                token=token or "",
                agent_task_key=agent_task_key or None,
            )
        raise ValidationError(f"未知下游服务: {normalized}")

    async def retry_or_restart_task(
        self,
        service: str,
        *,
        stage_name: str,
        project_id: str,
        task_id: str,
        token: str | None,
    ) -> dict[str, Any]:
        normalized = self._normalize_service(service)
        if stage_name == "firmware_unpack" and normalized == "firmware_unpacker":
            return await self._firmware_unpacker_client().retry_task(task_id, token or "")
        if stage_name == "system_analysis" and normalized == "system_analyse":
            return await self._system_analyse_client().restart_task(task_id, token or "")
        if stage_name == "binary_to_source" and normalized == "binary_to_source":
            return await self._binary_to_source_client().rerun_task(
                project_id,
                task_id,
                token or "",
                clean_output=True,
                cancel_running=True,
            )
        if stage_name == "entry_analysis" and normalized == "entry_analyse":
            return await self._entry_analyse_client().restart_task(task_id, token or "")
        normalized_stage = normalize_stage_name(stage_name)
        if normalized == "dataflow_vuln_scan" and normalized_stage == "dataflow_vuln_scan":
            return await self._dataflow_vuln_scan_client().retry_task(task_id, token or "")
        raise ValidationError(f"阶段 {stage_name} 未配置安全重试接口")

    async def cancel_task(self, service: str, *, project_id: str | None, task_id: str, token: str | None) -> dict[str, Any]:
        normalized = self._normalize_service(service)
        if normalized == "firmware_unpacker":
            return await self._firmware_unpacker_client().cancel_task(task_id, token or "")
        if normalized == "system_analyse":
            return await self._system_analyse_client().cancel_task(task_id, token or "")
        if normalized == "binary_to_source":
            return await self._binary_to_source_client().cancel_task(project_id or "", task_id, token or "")
        if normalized == "entry_analyse":
            return await self._entry_analyse_client().cancel_task(task_id, token or "")
        if normalized in LEGACY_UNSUPPORTED_DOWNSTREAM_SERVICES:
            self._reject_legacy_service(normalized)
        if normalized == "dataflow_vuln_scan":
            return await self._dataflow_vuln_scan_client().cancel_task(task_id, token or "")
        raise ValidationError(f"未知下游服务: {normalized}")

    async def delete_task(self, service: str, *, project_id: str | None, task_id: str, token: str | None) -> dict[str, Any]:
        normalized = self._normalize_service(service)
        if normalized == "firmware_unpacker":
            return await self._firmware_unpacker_client().delete_task(task_id, token or "")
        if normalized == "system_analyse":
            return await self._system_analyse_client().delete_task(task_id, token or "")
        if normalized == "binary_to_source":
            return await self._binary_to_source_client().delete_task(project_id or "", task_id, token or "")
        if normalized == "entry_analyse":
            return await self._entry_analyse_client().delete_task(task_id, token or "")
        if normalized in LEGACY_UNSUPPORTED_DOWNSTREAM_SERVICES:
            self._reject_legacy_service(normalized)
        if normalized == "dataflow_vuln_scan":
            return await self._dataflow_vuln_scan_client().delete_task(task_id, token or "")
        raise ValidationError(f"未知下游服务: {normalized}")

    async def get_task_result(self, service: str, *, task_id: str) -> dict[str, Any]:
        normalized = self._normalize_service(service)
        if normalized == "system_analyse":
            return await self._system_analyse_client().get_task_result(task_id)
        raise ValidationError(f"下游服务 {normalized} 不支持结果读取")

    async def get_artifacts(self, service: str, *, task_id: str, token: str | None) -> dict[str, Any]:
        normalized = self._normalize_service(service)
        if normalized == "dataflow_vuln_scan":
            return await self._dataflow_vuln_scan_client().get_artifacts(task_id, token or "")
        raise ValidationError(f"下游服务 {normalized} 不支持产物读取")


class DownstreamTaskController:
    def __init__(self, manager: Any) -> None:
        self.manager = manager
        self.gateway = DownstreamTaskGateway()

    def _record_event(
        self,
        db: Session,
        task: BinarySecurityTask,
        event_type: str,
        message: str,
        *,
        level: str = "info",
        stage_name: str | None = None,
        item: BinarySecurityStageItem | dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        self.manager._record_event(
            db,
            task,
            event_type,
            message,
            level=level,
            stage_name=stage_name,
            item=item,
            payload=payload,
        )

    def _record_downstream_item_disposition(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem | dict[str, Any],
        *,
        event_type: str,
        message: str,
        level: str = "info",
        payload: dict[str, Any] | None = None,
    ) -> None:
        self.manager._record_downstream_item_disposition(
            db,
            task,
            item,
            event_type=event_type,
            message=message,
            level=level,
            payload=payload,
        )

    def _record_control_outcome(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        stage_name: str,
        control: dict[str, Any],
    ) -> None:
        outcome = str(control.get("outcome") or "").strip()
        payload = {
            "stage_name": stage_name,
            "operation": "retry_or_restart",
            "control_outcome": outcome,
            "http_status": control.get("http_status"),
            "error": control.get("error_message"),
            "payload": control.get("payload"),
        }
        if outcome == "accepted":
            self._record_downstream_item_disposition(
                db,
                task,
                item,
                event_type="child_task_retry_accepted",
                message=f"下游子任务已接受重试/重启: {item.downstream_service}:{item.downstream_task_id or '-'}",
                payload=payload,
            )
            return
        if outcome == "already_running":
            self._record_downstream_item_disposition(
                db,
                task,
                item,
                event_type="child_task_dispatch_attached",
                message=f"复用已在运行的下游子任务: {item.downstream_service}:{item.downstream_task_id or '-'}",
                payload=payload,
            )
            return
        if outcome == "already_terminal":
            self._record_downstream_item_disposition(
                db,
                task,
                item,
                event_type="child_task_retry_rejected",
                message=f"下游子任务已是终态，未执行重试/重启: {item.downstream_service}:{item.downstream_task_id or '-'}",
                level="warning",
                payload=payload,
            )
            return
        if outcome == "transport_error":
            self._record_downstream_item_disposition(
                db,
                task,
                item,
                event_type="child_task_dispatch_deferred",
                message=f"下游控制通信异常，保留当前子任务等待后续自动对账: {item.downstream_service}:{item.downstream_task_id or '-'}",
                level="warning",
                payload=payload,
            )
            return
        event_type = "child_task_retry_rejected" if outcome in {"invalid_transition", "not_found"} else "child_task_status_sync_failed"
        self._record_downstream_item_disposition(
            db,
            task,
            item,
            event_type=event_type,
            message=f"下游子任务控制未被接受: {item.downstream_service}:{item.downstream_task_id or '-'}",
            level="warning",
            payload=payload,
        )

    @staticmethod
    def _task_id_from_payload(payload: dict[str, Any]) -> str | None:
        return str(payload.get("task_id") or payload.get("id") or "").strip() or None

    async def get_child_task(self, *, service: str, project_id: str | None, task_id: str, token: str | None) -> dict[str, Any]:
        return await self.gateway.get_task(service, project_id=project_id, task_id=task_id, token=token)

    async def fetch_child_payload(self, task: BinarySecurityTask, item: BinarySecurityStageItem, token: str | None) -> dict[str, Any]:
        task_id = str(item.downstream_task_id or "").strip()
        if not task_id:
            raise ValidationError("缺少下游任务ID")
        project_id = None
        if item.downstream_service in {"firmware_unpacker", "binary_to_source"}:
            project_id = (item.result or {}).get("project_id") or task.project_id
        return await self.gateway.get_task(
            str(item.downstream_service or ""),
            project_id=project_id,
            task_id=task_id,
            token=token,
        )

    async def fetch_child_ref_payload(self, ref: dict[str, str], token: str | None) -> dict[str, Any]:
        return await self.gateway.get_task(
            str(ref.get("service") or ""),
            project_id=str(ref.get("project_id") or "") or None,
            task_id=str(ref.get("task_id") or ""),
            token=token,
        )

    async def fetch_child_result(self, item: BinarySecurityStageItem) -> dict[str, Any]:
        return await self.gateway.get_task_result(str(item.downstream_service or ""), task_id=str(item.downstream_task_id or ""))

    async def fetch_child_artifacts(self, item: BinarySecurityStageItem, token: str | None) -> dict[str, Any]:
        return await self.gateway.get_artifacts(
            str(item.downstream_service or ""),
            task_id=str(item.downstream_task_id or ""),
            token=token,
        )

    async def list_child_tasks(self, *, service: str, project_id: str, token: str | None, **kwargs: Any) -> dict[str, Any]:
        return await self.gateway.list_tasks(service, project_id=project_id, token=token, **kwargs)

    async def create_child_task(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        service: str,
        token: str | None,
        payload: dict[str, Any],
        event_payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._record_downstream_item_disposition(
            db,
            task,
            item,
            event_type="child_task_create_requested",
            message=f"请求创建下游子任务: {service}:{item.item_key or item.id or '-'}",
            payload={"operation": "create", **(event_payload or {})},
        )
        try:
            created = await self.gateway.create_task(service, project_id=task.project_id, token=token, **payload)
        except Exception as exc:
            self._record_downstream_item_disposition(
                db,
                task,
                item,
                event_type="child_task_create_failed",
                message=f"创建下游子任务失败: {service}:{item.item_key or item.id or '-'}",
                level="warning",
                payload={
                    "operation": "create",
                    "error": self.manager._extract_downstream_error_text(exc) or str(exc),
                    "http_status": self.manager._extract_http_status_from_exception(exc),
                    **(event_payload or {}),
                },
            )
            raise
        task_id = self._task_id_from_payload(created)
        self._record_downstream_item_disposition(
            db,
            task,
            item,
            event_type="child_task_create_succeeded",
            message=f"下游子任务创建成功: {service}:{task_id or '-'}",
            payload={
                "operation": "create",
                "downstream_task_id": task_id,
                "payload": self.manager._lightweight_downstream_payload(created),
                **(event_payload or {}),
            },
        )
        return created

    async def invoke_retry_or_restart(self, *, stage_name: str, task: BinarySecurityTask, item: BinarySecurityStageItem, token: str | None) -> dict[str, Any]:
        downstream_task_id = str(item.downstream_task_id or "").strip()
        if not downstream_task_id:
            raise ValidationError("缺少下游任务ID，无法安全重试")
        expected_service = self.manager._stage_expected_service(stage_name)
        if expected_service and item.downstream_service != expected_service:
            raise ValidationError(
                f"下游服务不匹配，无法安全重试: 期望 {expected_service}，实际 {item.downstream_service or '-'}"
            )
        return await self.gateway.retry_or_restart_task(
            str(item.downstream_service or ""),
            stage_name=stage_name,
            project_id=task.project_id,
            task_id=downstream_task_id,
            token=token,
        )

    @staticmethod
    def extract_downstream_error_text(exc: Exception) -> str:
        raw_message = str(getattr(exc, "message", exc) or "").strip()
        if not raw_message:
            return ""
        try:
            payload = json.loads(raw_message)
        except Exception:
            return raw_message
        queue: list[Any] = [payload]
        while queue:
            current = queue.pop(0)
            if isinstance(current, dict):
                for key in ("detail", "error", "message", "msg"):
                    value = current.get(key)
                    if isinstance(value, str) and value.strip():
                        return value.strip()
                queue.extend(value for value in current.values() if isinstance(value, (dict, list)))
            elif isinstance(current, list):
                for value in current:
                    if isinstance(value, str) and value.strip():
                        return value.strip()
                    if isinstance(value, (dict, list)):
                        queue.append(value)
        return raw_message

    @staticmethod
    def is_already_running_control_conflict(message: str) -> bool:
        normalized = re.sub(r"\s+", "", str(message or "").lower())
        if not normalized:
            return False
        running_tokens = ("仍在运行", "运行中", "已经在运行", "active", "alreadyrunning", "currentlyrunning", "stillrunning")
        control_tokens = ("重启", "重试", "restart", "retry", "rerun", "cancel", "取消后再", "先取消")
        return any(token in normalized for token in running_tokens) and any(token in normalized for token in control_tokens)

    async def control_existing_child(
        self,
        db: Session | None,
        *,
        stage_name: str,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        token: str | None,
    ) -> dict[str, Any]:
        if db is not None:
            self._record_downstream_item_disposition(
                db,
                task,
                item,
                event_type="child_task_retry_requested",
                message=f"请求控制下游子任务: {item.downstream_service}:{item.downstream_task_id or '-'}",
                payload={"operation": "retry_or_restart", "stage_name": stage_name},
            )
        if normalize_stage_name(stage_name) == "dataflow_vuln_scan" and self.manager._has_retryable_downstream_task(item):
            try:
                payload = await self.fetch_child_payload(task, item, token or "")
            except NotFoundError:
                payload = None
            except Exception as exc:
                if self.manager._is_retryable_downstream_transport_error(exc):
                    control = {
                        "outcome": "transport_error",
                        "payload": None,
                        "error_message": self.extract_downstream_error_text(exc) or str(exc),
                        "http_status": self.manager._extract_http_status_from_exception(exc),
                    }
                    if db is not None:
                        self._record_control_outcome(db, task, item, stage_name=stage_name, control=control)
                    return control
                payload = None
            if isinstance(payload, dict):
                mapped_status = self.manager._map_downstream_status(str(payload.get("status") or ""))
                if mapped_status in {"pending", "queued", "dispatching", "running"}:
                    control = {
                        "outcome": "already_running",
                        "payload": payload,
                        "error_message": None,
                        "http_status": 200,
                    }
                    if db is not None:
                        self._record_control_outcome(db, task, item, stage_name=stage_name, control=control)
                    return control
        try:
            payload = await self.invoke_retry_or_restart(stage_name=stage_name, task=task, item=item, token=token)
            control = {"outcome": "accepted", "payload": payload, "error_message": None, "http_status": 200}
            if db is not None:
                self._record_control_outcome(db, task, item, stage_name=stage_name, control=control)
            return control
        except NotFoundError as exc:
            control = {
                "outcome": "not_found",
                "payload": None,
                "error_message": self.extract_downstream_error_text(exc) or "下游子任务不存在",
                "http_status": getattr(exc, "status_code", 404),
            }
            if db is not None:
                self._record_control_outcome(db, task, item, stage_name=stage_name, control=control)
            return control
        except (ValidationError, ConflictError) as exc:
            error_message = self.extract_downstream_error_text(exc) or str(exc)
            result = {
                "outcome": "already_running" if self.is_already_running_control_conflict(error_message) else "invalid_transition",
                "payload": None,
                "error_message": error_message,
                "http_status": getattr(exc, "status_code", None),
            }
        except UpstreamError as exc:
            control = {
                "outcome": "transport_error",
                "payload": None,
                "error_message": self.extract_downstream_error_text(exc) or str(exc),
                "http_status": getattr(exc, "status_code", 502),
            }
            if db is not None:
                self._record_control_outcome(db, task, item, stage_name=stage_name, control=control)
            return control
        except Exception as exc:
            if self.manager._is_retryable_downstream_transport_error(exc):
                control = {
                    "outcome": "transport_error",
                    "payload": None,
                    "error_message": self.extract_downstream_error_text(exc) or str(exc),
                    "http_status": self.manager._extract_http_status_from_exception(exc),
                }
                if db is not None:
                    self._record_control_outcome(db, task, item, stage_name=stage_name, control=control)
                return control
            control = {
                "outcome": "fatal_error",
                "payload": None,
                "error_message": str(exc),
                "http_status": None,
            }
            if db is not None:
                self._record_control_outcome(db, task, item, stage_name=stage_name, control=control)
            return control

        if not self.manager._has_retryable_downstream_task(item):
            if db is not None:
                self._record_control_outcome(db, task, item, stage_name=stage_name, control=result)
            return result
        try:
            payload = await self.fetch_child_payload(task, item, token or "")
        except NotFoundError as exc:
            control = {
                "outcome": "not_found",
                "payload": None,
                "error_message": self.extract_downstream_error_text(exc) or result["error_message"] or "下游子任务不存在",
                "http_status": getattr(exc, "status_code", 404),
            }
            if db is not None:
                self._record_control_outcome(db, task, item, stage_name=stage_name, control=control)
            return control
        except Exception:
            if db is not None:
                self._record_control_outcome(db, task, item, stage_name=stage_name, control=result)
            return result

        mapped_status = self.manager._map_downstream_status(str(payload.get("status") or ""))
        if mapped_status in {"queued", "running"}:
            control = {**result, "outcome": "already_running", "payload": payload, "retry_outcome": result.get("outcome")}
            if db is not None:
                self._record_control_outcome(db, task, item, stage_name=stage_name, control=control)
            return control
        if mapped_status in {"success", "partial_success", "failed", "cancelled", "downstream_missing"}:
            control = {**result, "outcome": "already_terminal", "payload": payload, "retry_outcome": result.get("outcome")}
            if db is not None:
                self._record_control_outcome(db, task, item, stage_name=stage_name, control=control)
            return control
        control = {**result, "payload": payload}
        if db is not None:
            self._record_control_outcome(db, task, item, stage_name=stage_name, control=control)
        return control

    async def cancel_child_task(self, item: BinarySecurityStageItem, token: str | None) -> None:
        await self.gateway.cancel_task(
            str(item.downstream_service or ""),
            project_id=((item.result or {}).get("project_id") or item.project_id) if item.downstream_service == "binary_to_source" else item.project_id,
            task_id=str(item.downstream_task_id or ""),
            token=token,
        )

    async def cancel_child_refs(self, db: Session, task: BinarySecurityTask, refs: list[dict[str, str]], token: str | None) -> int:
        for ref in refs:
            event_item = self.manager._event_item_for_downstream_ref(db, task, ref)
            self._record_event(
                db,
                task,
                "child_task_cancel_requested",
                f"请求取消下游任务: {ref['service']}:{ref['task_id']}",
                stage_name=ref.get("stage_name"),
                item=event_item,
                payload={**ref, "operation": "cancel"},
            )

        async def do_cancel(ref: dict[str, str]) -> bool:
            await self.gateway.cancel_task(
                str(ref["service"]),
                project_id=str(ref.get("project_id") or "") or None,
                task_id=str(ref["task_id"]),
                token=token,
            )
            return True

        db.commit()
        results = await self.manager._run_with_limits(
            refs,
            do_cancel,
            concurrency=self.manager.cfg.scheduler.downstream_action_concurrency,
            timeout_seconds=self.manager.cfg.scheduler.downstream_request_timeout_seconds,
        )
        success_count = 0
        for ref, ok, exc in results:
            event_item = self.manager._event_item_for_downstream_ref(db, task, ref)
            if exc is None and ok:
                success_count += 1
                self._record_downstream_item_disposition(
                    db,
                    task,
                    event_item,
                    event_type="child_task_cancel_succeeded",
                    message=f"下游子任务已取消: {ref['service']}:{ref['task_id']}",
                    payload={**ref, "operation": "cancel"},
                )
                continue
            self._record_event(
                db,
                task,
                "child_task_cancel_failed",
                f"下游取消失败: {ref['service']}:{ref['task_id']} - {exc}",
                stage_name=ref.get("stage_name"),
                item=event_item,
                level="warning",
                payload={**ref, "operation": "cancel", "error": str(exc)},
            )
        db.commit()
        return success_count

    async def wait_child_refs_inactive(self, refs: list[dict[str, str]], token: str | None) -> None:
        timeout_seconds = max(
            int(self.manager.cfg.scheduler.downstream_request_timeout_seconds or 120),
            int(self.manager.cfg.scheduler.stage_poll_interval_seconds or 5) * 2,
        )
        deadline = now_local() + timedelta(seconds=timeout_seconds)
        while refs and now_local() <= deadline:
            active_refs: list[dict[str, str]] = []
            for ref in refs:
                try:
                    payload = await self.fetch_child_ref_payload(ref, token)
                except NotFoundError:
                    continue
                mapped_status = self.manager._map_downstream_status(str(payload.get("status") or "")) or str(payload.get("status") or "").lower()
                if mapped_status in {"queued", "running", "dispatching", "pending"}:
                    active_refs.append(ref)
            if not active_refs:
                return
            refs = active_refs
            await asyncio.sleep(max(1, int(self.manager.cfg.scheduler.stage_poll_interval_seconds or 5)))
        if refs:
            ref = refs[0]
            raise ValidationError(f"旧下游任务仍在运行，不能安全继续: {ref.get('service')}:{ref.get('task_id')}")

    async def ensure_child_refs_inactive(self, refs: list[dict[str, str]], token: str | None) -> None:
        await self.wait_child_refs_inactive(list(refs), token)

    async def delete_child_task(self, *, service: str, project_id: str | None, task_id: str, token: str | None) -> dict[str, Any]:
        return await self.gateway.delete_task(service, project_id=project_id, task_id=task_id, token=token)

    async def delete_child_refs(
        self,
        db: Session,
        task: BinarySecurityTask,
        refs: list[dict[str, str]],
        token: str | None,
        *,
        force_delete: bool = False,
        best_effort: bool = False,
        cleanup_scope: str = "retry_prepare",
    ) -> int:
        cleanup_results: list[dict[str, Any]] = []
        setattr(self.manager, "_last_downstream_cleanup_results", cleanup_results)
        for ref in refs:
            event_item = self.manager._event_item_for_downstream_ref(db, task, ref)
            self._record_event(
                db,
                task,
                "child_task_delete_requested",
                f"请求删除下游任务: {ref['service']}:{ref['task_id']}",
                stage_name=ref.get("stage_name"),
                item=event_item,
                payload={**ref, "operation": "delete"},
            )

        async def verify_deleted(ref: dict[str, str]) -> tuple[bool, dict[str, object]]:
            verification: dict[str, object] = {
                "verified_absent": False,
                "verified_deleted": False,
                "observed_status": None,
                "observed_active": False,
                "verification_error": None,
            }
            service = str(ref.get("service") or "").strip()
            task_id = str(ref.get("task_id") or "").strip()
            if not task_id:
                return False, verification
            try:
                project_id = str(ref.get("project_id") or "") or None
                payload = await self.get_child_task(service=service, project_id=project_id, task_id=task_id, token=token)
            except NotFoundError:
                verification["verified_absent"] = True
                return True, verification
            except Exception as verify_exc:
                verification["verification_error"] = str(verify_exc)
                return False, verification
            payload_status = str((payload or {}).get("status") or "").strip().lower()
            mapped_status = self.manager._map_downstream_status(payload_status) or payload_status
            verification["observed_status"] = mapped_status
            verification["observed_active"] = mapped_status in DOWNSTREAM_REF_ACTIVE_STATUSES
            if bool((payload or {}).get("is_deleted")) or mapped_status in DOWNSTREAM_REF_DELETED_STATUSES:
                verification["verified_deleted"] = True
                return True, verification
            return False, verification

        async def do_delete(ref: dict[str, str]) -> dict[str, Any]:
            result: dict[str, Any] = {
                **ref,
                "operation": "delete",
                "cleanup_mode": "best_effort" if best_effort else "blocking",
                "cleanup_scope": cleanup_scope,
                "delete_status": "not_sent",
                "verify_status": "not_checked",
                "verified_absent": False,
                "verified_deleted": False,
                "blocking": False,
                "deferred": False,
                "deferred_reason": None,
                "next_retry_at": None,
                "error": None,
            }
            try:
                payload = await self.delete_child_task(
                    service=str(ref["service"]),
                    project_id=str(ref.get("project_id") or "") or None,
                    task_id=str(ref["task_id"]),
                    token=token,
                )
                result["delete_status"] = "succeeded"
                result["delete_payload"] = payload
                return result
            except ConflictError as exc:
                result["delete_status"] = "conflict"
                result["error"] = str(exc)
            except Exception as exc:
                result["delete_status"] = "failed"
                result["error"] = str(exc)
            verified_ok, verification = await verify_deleted(ref)
            result.update(verification)
            result["verify_status"] = "succeeded" if verified_ok else "failed"
            if verified_ok:
                result["delete_status"] = "succeeded_after_verify"
                result["blocking"] = False
                return result
            result["blocking"] = bool(verification.get("observed_active") or result.get("delete_status") == "conflict")
            return result

        db.commit()
        results = await self.manager._run_with_limits(
            refs,
            do_delete,
            concurrency=self.manager.cfg.scheduler.downstream_action_concurrency,
            timeout_seconds=self.manager.cfg.scheduler.downstream_request_timeout_seconds,
        )
        success_count = 0
        for ref, result, exc in results:
            event_item = self.manager._event_item_for_downstream_ref(db, task, ref)
            cleanup_result = dict(result or {})
            cleanup_result["force_delete"] = force_delete
            if exc is not None:
                cleanup_result = {
                    **ref,
                    "operation": "delete",
                    "cleanup_mode": "best_effort" if best_effort else "blocking",
                    "cleanup_scope": cleanup_scope,
                    "delete_status": "failed",
                    "verify_status": "not_checked",
                    "blocking": True,
                    "deferred": False,
                    "deferred_reason": None,
                    "next_retry_at": None,
                    "error": str(exc),
                    "force_delete": force_delete,
                }
            cleanup_results.append(cleanup_result)
            delete_status = str(cleanup_result.get("delete_status") or "").strip()
            verify_status = str(cleanup_result.get("verify_status") or "").strip()
            if exc is None and delete_status == "succeeded":
                success_count += 1
                self._record_downstream_item_disposition(
                    db,
                    task,
                    event_item,
                    event_type="child_task_delete_succeeded",
                    message=f"下游子任务已删除: {ref['service']}:{ref['task_id']}",
                    payload=cleanup_result,
                )
                continue
            if exc is None and verify_status == "succeeded":
                success_count += 1
                self._record_downstream_item_disposition(
                    db,
                    task,
                    event_item,
                    event_type="child_task_delete_verified_absent",
                    message=f"下游删除报错但已确认不存在: {ref['service']}:{ref['task_id']}",
                    level="warning",
                    payload=cleanup_result,
                )
                self._record_downstream_item_disposition(
                    db,
                    task,
                    event_item,
                    event_type="child_task_delete_failed_but_ignored",
                    message=f"下游删除报错但已降级忽略: {ref['service']}:{ref['task_id']}",
                    level="warning",
                    payload=cleanup_result,
                )
                continue
            if force_delete:
                success_count += 1
                cleanup_result["ignored_reason"] = "force_delete"
                self._record_downstream_item_disposition(
                    db,
                    task,
                    event_item,
                    event_type="child_task_delete_failed_but_ignored",
                    message=f"下游删除失败但已按强制删除忽略: {ref['service']}:{ref['task_id']}",
                    level="warning",
                    payload=cleanup_result,
                )
                continue
            if best_effort:
                success_count += 1
                cleanup_result["blocking"] = False
                cleanup_result["deferred"] = True
                cleanup_result["deferred_reason"] = (
                    "conflict"
                    if delete_status == "conflict"
                    else "verify_failed"
                    if verify_status == "failed"
                    else "transport_error"
                )
                cleanup_result["next_retry_at"] = (
                    now_local() + timedelta(seconds=max(60, int(self.manager.cfg.scheduler.downstream_reconcile_interval_seconds or 30) * 2))
                ).isoformat()
                self._record_downstream_item_disposition(
                    db,
                    task,
                    event_item,
                    event_type="child_task_delete_failed_but_ignored",
                    message=f"下游删除失败，已转为后台补偿: {ref['service']}:{ref['task_id']}",
                    level="warning",
                    payload=cleanup_result,
                )
                continue
            blocking_message = (
                f"旧下游任务仍在运行，不能安全删除: {ref['service']}:{ref['task_id']}"
                if cleanup_result.get("blocking")
                else str(cleanup_result.get("error") or exc or "下游删除失败且无法确认资源已删除")
            )
            self._record_event(
                db,
                task,
                "child_task_delete_failed_blocking",
                f"下游删除失败: {ref['service']}:{ref['task_id']} - {blocking_message}",
                stage_name=ref.get("stage_name"),
                item=event_item,
                level="warning",
                payload=cleanup_result,
            )
            raise ValidationError(blocking_message)
        db.commit()
        return success_count

    async def cleanup_child_refs(self, db: Session, task: BinarySecurityTask, refs: list[dict[str, str]], token: str | None) -> int:
        await self.cancel_child_refs(db, task, refs, token)
        await self.ensure_child_refs_inactive(refs, token)
        return await self.delete_child_refs(db, task, refs, token)


def get_downstream_task_controller(manager: Any) -> DownstreamTaskController:
    controller = getattr(manager, "_downstream_task_controller", None)
    if controller is None:
        controller = DownstreamTaskController(manager)
        setattr(manager, "_downstream_task_controller", controller)
    return controller
