"""User task center service for chirmera-platform-schedule."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import ConflictError, NotFoundError, UpstreamError, ValidationError
from app.model import (
    ScheduleUserTask,
    ScheduleUserTaskDispatch,
    ScheduleUserTaskInputBinding,
)
from app.service.http_client import get_shared_async_client
from app.service.runtime_config import get_runtime_config_service


TASK_TYPE_INPUT_TYPE: dict[str, str] = {
    "binary_firmware_e2e": "software",
    "source_scan_e2e": "code",
    "binary_module_e2e": "software",
}

TASK_TYPE_BINARY_SECURITY: dict[str, str] = {
    "binary_firmware_e2e": "binary",
    "source_scan_e2e": "source",
    "binary_module_e2e": "binary_module",
}

TASK_TYPE_DETAIL_VIEW: dict[str, str] = {
    "binary_firmware_e2e": "binary-security-detail",
    "source_scan_e2e": "source-security-detail",
    "binary_module_e2e": "binary-module-security-detail",
    "ai4red": "ai4red-detail",
}

CREATE_TIME_PARENT_TASK_KEY_PLACEHOLDER = "__dispatch_managed__"
AI4RED_STATUS_MAP: dict[str, tuple[str, str, bool]] = {
    "PARSE_PENDING": ("dispatching", "dispatching", False),
    "PARSING": ("running", "running", False),
    "PARSED": ("running", "running", False),
    "EXECUTING": ("running", "running", False),
    "COMPLETED": ("succeeded", "success", True),
    "FAILED": ("failed", "failed", False),
    "PAUSED": ("paused", "paused", False),
    "DELETING": ("cancelling", "cancelling", False),
}
AI4APK_STATUS_MAP: dict[str, tuple[str, str, bool]] = {
    "pending": ("dispatching", "dispatching", False),
    "decompiling": ("running", "running", False),
    "running": ("running", "running", False),
    "paused": ("paused", "paused", False),
    "completed": ("succeeded", "success", True),
    "failed": ("failed", "failed", False),
}

USER_TASK_SORT_FIELDS: dict[str, Any] = {
    "created_at": ScheduleUserTask.created_at,
    "updated_at": ScheduleUserTask.updated_at,
    "name": ScheduleUserTask.name,
    "task_type": ScheduleUserTask.task_type,
    "create_status": ScheduleUserTask.create_status,
    "dispatch_status": ScheduleUserTask.dispatch_status,
    "business_status": ScheduleUserTask.business_status,
    "downstream_status_mapped": ScheduleUserTask.downstream_status_mapped,
    "created_by": ScheduleUserTask.created_by,
    "downstream_task_id": ScheduleUserTask.downstream_task_id,
}


@dataclass
class ResolvedInputRecord:
    upload_id: str
    project_id: str
    input_type: str
    status: str
    keep_original: bool
    target_path: str
    latest_batch_id: Optional[str]
    display_name: str


class TaskKeySecretCipher:
    VERSION = "aesgcm-v1"

    def __init__(self) -> None:
        master_key = get_config().security.task_key_secret_master_key
        self._key = hashlib.sha256(master_key.encode("utf-8")).digest()

    def encrypt(self, secret: str) -> tuple[str, str, str]:
        secret_bytes = str(secret or "").encode("utf-8")
        nonce = hashlib.sha256((str(secret) + self.VERSION).encode("utf-8")).digest()[:12]
        ciphertext = AESGCM(self._key).encrypt(nonce, secret_bytes, None)
        return (
            base64.b64encode(ciphertext).decode("utf-8"),
            base64.b64encode(nonce).decode("utf-8"),
            self.VERSION,
        )

    def decrypt(self, *, cipher_text: str, nonce: str, version: str) -> str:
        if version != self.VERSION:
            raise ValidationError(f"不支持的 task key secret 版本: {version}")
        nonce_bytes = base64.b64decode(nonce.encode("utf-8"))
        cipher_bytes = base64.b64decode(cipher_text.encode("utf-8"))
        plain = AESGCM(self._key).decrypt(nonce_bytes, cipher_bytes, None)
        return plain.decode("utf-8")


class ProjectInputResolver:
    def __init__(self) -> None:
        self.cfg = get_config().fileserver_service

    async def list_uploads(self, project_id: str, bearer_token: str) -> dict[str, Any]:
        query = httpx.QueryParams({"project_id": project_id, "page_size": 200})
        client = await get_shared_async_client("schedule-fileserver", timeout=self.cfg.timeout)
        try:
            response = await client.get(
                f"{self.cfg.base_url.rstrip('/')}{self.cfg.project_input_uploads_path}",
                params=query,
                headers={"Authorization": f"Bearer {bearer_token}"},
            )
        except httpx.TimeoutException as exc:
            raise UpstreamError("读取任务输入列表超时") from exc
        except httpx.RequestError as exc:
            raise UpstreamError(f"读取任务输入列表失败: {exc}") from exc
        if response.status_code != 200:
            raise UpstreamError(f"任务输入服务返回异常状态码: {response.status_code}")
        return response.json()

    async def resolve_single(self, project_id: str, upload_id: str, bearer_token: str) -> ResolvedInputRecord:
        payload = await self.list_uploads(project_id, bearer_token)
        for item in payload.get("items") or []:
            if str(item.get("upload_id")) == upload_id:
                latest_batch = item.get("latest_batch") or {}
                return ResolvedInputRecord(
                    upload_id=str(item.get("upload_id")),
                    project_id=str(item.get("project_id")),
                    input_type=str(item.get("input_type") or ""),
                    status=str(item.get("status") or ""),
                    keep_original=bool(item.get("keep_original")),
                    target_path=str(item.get("target_path") or ""),
                    latest_batch_id=str(latest_batch.get("batch_id")) if latest_batch.get("batch_id") else None,
                    display_name=str(item.get("display_name") or item.get("target_path") or item.get("upload_id") or ""),
                )
        raise ValidationError(f"未找到任务输入记录: {upload_id}")

    async def resolve_path(self, project_id: str, upload_id: str, relative_path: str, bearer_token: str) -> dict[str, Any]:
        client = await get_shared_async_client("schedule-fileserver", timeout=self.cfg.timeout)
        params = httpx.QueryParams({"project_id": project_id, "relative_path": relative_path})
        try:
            response = await client.get(
                f"{self.cfg.base_url.rstrip('/')}/api/fileserver/project-input/uploads/{upload_id}/resolve",
                params=params,
                headers={"Authorization": f"Bearer {bearer_token}"},
            )
        except httpx.TimeoutException as exc:
            raise UpstreamError("解析任务输入路径超时") from exc
        except httpx.RequestError as exc:
            raise UpstreamError(f"解析任务输入路径失败: {exc}") from exc
        if response.status_code != 200:
            raise UpstreamError(f"任务输入服务返回异常状态码: {response.status_code}")
        return response.json()


class AiGatewayTaskKeyClient:
    def __init__(self) -> None:
        self.cfg = get_config().aigw_service

    async def create_task_key(
        self,
        *,
        management_token: str,
        task_id: str,
        dispatch_id: str,
        capacity_pool_ids: list[int],
        max_concurrency: int = 0,
        expires_at: Optional[str] = None,
    ) -> dict[str, Any]:
        if not capacity_pool_ids:
            raise ValidationError("root task key 缺少 capacity_pool_ids，无法创建")
        if not str(management_token or "").strip():
            raise ValidationError("缺少 AI Gateway 管理凭证，无法创建 root task key")
        client = await get_shared_async_client("schedule-aigw", timeout=self.cfg.timeout)
        payload = {
            "key_name": f"dispatch-{task_id}-{dispatch_id}",
            "key_type": "task",
            "task_id": task_id,
            "max_concurrency": max_concurrency,
            "enabled": True,
            "capacity_pool_ids": capacity_pool_ids,
            "description": f"root task key for {task_id}/{dispatch_id}",
        }
        if expires_at:
            payload["expires_at"] = expires_at
        try:
            response = await client.post(
                f"{self.cfg.base_url.rstrip('/')}{self.cfg.llm_keys_path}",
                json=payload,
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {management_token}"},
            )
        except httpx.TimeoutException as exc:
            raise UpstreamError("创建 root task key 超时") from exc
        except httpx.RequestError as exc:
            raise UpstreamError(f"创建 root task key 失败: {exc}") from exc
        if response.status_code not in (200, 201):
            raise UpstreamError(f"创建 root task key 失败: {response.status_code}")
        return response.json()



class BinarySecurityDispatchClient:
    def __init__(self) -> None:
        self.cfg = get_config().binary_security_service

    async def create_task(self, *, project_id: str, task_id: str, payload: dict[str, Any], bearer_token: str) -> dict[str, Any]:
        client = await get_shared_async_client("schedule-binary-security", timeout=self.cfg.timeout)
        try:
            response = await client.post(
                f"{self.cfg.base_url.rstrip('/')}/api/app/binary-security/projects/{project_id}/tasks",
                json={**payload, "task_id": task_id},
                headers={"Authorization": f"Bearer {bearer_token}", "Content-Type": "application/json"},
            )
        except httpx.TimeoutException as exc:
            raise UpstreamError("创建 binary-security 任务超时") from exc
        except httpx.RequestError as exc:
            raise UpstreamError(f"创建 binary-security 任务失败: {exc}") from exc
        if response.status_code != 200:
            raise UpstreamError(f"创建 binary-security 任务失败: {response.status_code}")
        return response.json()

    async def complete_uploads(self, *, project_id: str, task_id: str, files: list[dict[str, Any]], bearer_token: str) -> dict[str, Any]:
        client = await get_shared_async_client("schedule-binary-security", timeout=self.cfg.timeout)
        response = await client.post(
            f"{self.cfg.base_url.rstrip('/')}/api/app/binary-security/projects/{project_id}/tasks/{task_id}/uploads/complete",
            json={"files": files},
            headers={"Authorization": f"Bearer {bearer_token}", "Content-Type": "application/json"},
        )
        if response.status_code != 200:
            raise UpstreamError(f"确认 binary-security 输入失败: {response.status_code}")
        return response.json()

    async def start_task(self, *, project_id: str, task_id: str, bearer_token: str) -> dict[str, Any]:
        client = await get_shared_async_client("schedule-binary-security", timeout=self.cfg.timeout)
        response = await client.post(
            f"{self.cfg.base_url.rstrip('/')}/api/app/binary-security/projects/{project_id}/tasks/{task_id}/start",
            headers={"Authorization": f"Bearer {bearer_token}"},
        )
        if response.status_code != 200:
            raise UpstreamError(f"启动 binary-security 任务失败: {response.status_code}")
        return response.json()

    async def delete_task(self, *, project_id: str, task_id: str, bearer_token: str) -> None:
        client = await get_shared_async_client("schedule-binary-security", timeout=self.cfg.timeout)
        try:
            response = await client.delete(
                f"{self.cfg.base_url.rstrip('/')}/api/app/binary-security/projects/{project_id}/tasks/{task_id}",
                headers={"Authorization": f"Bearer {bearer_token}"},
            )
        except httpx.TimeoutException as exc:
            raise UpstreamError("删除 binary-security 任务超时") from exc
        except httpx.RequestError as exc:
            raise UpstreamError(f"删除 binary-security 任务失败: {exc}") from exc
        if response.status_code in (200, 202, 204, 404):
            return
        raise UpstreamError(f"删除 binary-security 任务失败: {response.status_code}")


class Ai4RedDispatchClient:
    def __init__(self) -> None:
        self.cfg = get_config().ai4red_service

    async def create_task(
        self,
        *,
        project_id: str,
        task_id: str,
        deliver_dir: str,
        bearer_token: str,
        llm_key: Optional[str] = None,
    ) -> dict[str, Any]:
        client = await get_shared_async_client("schedule-ai4red", timeout=self.cfg.timeout)
        payload: dict[str, Any] = {
            "projectId": project_id,
            "taskId": task_id,
            "deliverDir": deliver_dir,
        }
        if str(llm_key or "").strip():
            payload["llmKey"] = str(llm_key).strip()
        try:
            response = await client.post(
                f"{self.cfg.base_url.rstrip('/')}/api/app/ai4red/chimera/tasks",
                json=payload,
                headers={"Authorization": f"Bearer {bearer_token}", "Content-Type": "application/json"},
            )
        except httpx.TimeoutException as exc:
            raise UpstreamError("创建 ai4red 任务超时") from exc
        except httpx.RequestError as exc:
            raise UpstreamError(f"创建 ai4red 任务失败: {exc}") from exc
        if response.status_code != 200:
            raise UpstreamError(f"创建 ai4red 任务失败: {response.status_code}")
        return response.json()

    async def get_task(self, *, downstream_task_id: str, bearer_token: str) -> dict[str, Any]:
        client = await get_shared_async_client("schedule-ai4red", timeout=self.cfg.timeout)
        try:
            response = await client.get(
                f"{self.cfg.base_url.rstrip('/')}/api/app/ai4red/chimera/tasks/{downstream_task_id}",
                headers={"Authorization": f"Bearer {bearer_token}"},
            )
        except httpx.TimeoutException as exc:
            raise UpstreamError("查询 ai4red 任务超时") from exc
        except httpx.RequestError as exc:
            raise UpstreamError(f"查询 ai4red 任务失败: {exc}") from exc
        if response.status_code != 200:
            raise UpstreamError(f"查询 ai4red 任务失败: {response.status_code}")
        return response.json()

    async def delete_task(self, *, downstream_task_id: str, bearer_token: str) -> None:
        raise ValidationError("该任务类型暂不支持同步删除下游任务")


class TuringAppSecurityClient:
    def __init__(self) -> None:
        self.cfg = get_config().turing_app_security_service

    async def create_task(
        self,
        *,
        project_id: str,
        task_id: str,
        file_path: str,
        task_type: str = "APK",
    ) -> dict[str, Any]:
        client = await get_shared_async_client("schedule-ai4apk", timeout=self.cfg.timeout)
        payload = {
            "project_id": project_id,
            "task_id": task_id,
            "file_path": file_path,
            "task_type": task_type,
        }
        try:
            response = await client.post(
                f"{self.cfg.base_url.rstrip('/')}/api/v1/tasks",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
        except httpx.TimeoutException as exc:
            raise UpstreamError("创建 ai4apk 任务超时") from exc
        except httpx.RequestError as exc:
            raise UpstreamError(f"创建 ai4apk 任务失败: {exc}") from exc
        if response.status_code not in (200, 201):
            message = ""
            try:
                message = str((response.json() or {}).get("message") or (response.json() or {}).get("detail") or "").strip()
            except Exception:
                message = str(response.text or "").strip()
            suffix = f": {message}" if message else ""
            raise UpstreamError(f"创建 ai4apk 任务失败: {response.status_code}{suffix}")
        return response.json()

    async def get_task(self, *, downstream_task_id: str) -> dict[str, Any]:
        client = await get_shared_async_client("schedule-ai4apk", timeout=self.cfg.timeout)
        try:
            response = await client.get(
                f"{self.cfg.base_url.rstrip('/')}/api/v1/tasks/{downstream_task_id}",
            )
        except httpx.TimeoutException as exc:
            raise UpstreamError("查询 ai4apk 任务超时") from exc
        except httpx.RequestError as exc:
            raise UpstreamError(f"查询 ai4apk 任务失败: {exc}") from exc
        if response.status_code != 200:
            message = ""
            try:
                message = str((response.json() or {}).get("message") or (response.json() or {}).get("detail") or "").strip()
            except Exception:
                message = str(response.text or "").strip()
            suffix = f": {message}" if message else ""
            raise UpstreamError(f"查询 ai4apk 任务失败: {response.status_code}{suffix}")
        return response.json()

    async def delete_task(self, *, downstream_task_id: str) -> None:
        client = await get_shared_async_client("schedule-ai4apk", timeout=self.cfg.timeout)
        try:
            response = await client.delete(
                f"{self.cfg.base_url.rstrip('/')}/api/v1/tasks/{downstream_task_id}",
            )
        except httpx.TimeoutException as exc:
            raise UpstreamError("删除 ai4apk 任务超时") from exc
        except httpx.RequestError as exc:
            raise UpstreamError(f"删除 ai4apk 任务失败: {exc}") from exc
        if response.status_code in (200, 202, 204, 404):
            return
        message = ""
        try:
            message = str((response.json() or {}).get("message") or (response.json() or {}).get("detail") or "").strip()
        except Exception:
            message = str(response.text or "").strip()
        suffix = f": {message}" if message else ""
        raise UpstreamError(f"删除 ai4apk 任务失败: {response.status_code}{suffix}")


class UserTaskManager:
    def __init__(self) -> None:
        self.input_resolver = ProjectInputResolver()
        self.task_key_cipher = TaskKeySecretCipher()
        self.aigw = AiGatewayTaskKeyClient()
        self.binary_security = BinarySecurityDispatchClient()
        self.ai4red = Ai4RedDispatchClient()
        self.ai4apk = TuringAppSecurityClient()

    @staticmethod
    def _task_type_supports_downstream_delete(task_type: str) -> bool:
        return task_type in {"binary_firmware_e2e", "binary_module_e2e", "source_scan_e2e", "ai4apk"}

    def _filter_tasks_for_bulk_delete(
        self,
        rows: list[ScheduleUserTask],
        *,
        filters: Optional[dict[str, Any]],
    ) -> list[ScheduleUserTask]:
        if not filters:
            return rows
        status = str(filters.get("status") or "").strip()
        task_type = str(filters.get("task_type") or "").strip()
        search = str(filters.get("search") or "").strip().lower()
        has_error = bool(filters.get("has_error"))
        is_retrying = bool(filters.get("is_retrying"))
        filtered: list[ScheduleUserTask] = []
        for task in rows:
            if status and status not in {task.create_status, task.dispatch_status, task.business_status, str(task.downstream_status_mapped or "")}:
                continue
            if task_type and str(task.task_type or "") != task_type:
                continue
            if has_error and not str(task.last_error or "").strip():
                continue
            if is_retrying:
                continue
            if search:
                haystack = " ".join([
                    str(task.id or ""),
                    str(task.name or ""),
                    str(task.description or ""),
                    str(task.downstream_task_id or ""),
                    str(task.last_error or ""),
                ]).lower()
                if search not in haystack:
                    continue
            filtered.append(task)
        return filtered

    async def _delete_downstream_task(self, task: ScheduleUserTask, bearer_token: str) -> None:
        downstream_task_id = str(task.downstream_task_id or "").strip()
        if not downstream_task_id:
            return
        if not self._task_type_supports_downstream_delete(task.task_type):
            raise ValidationError("该任务类型暂不支持同步删除下游任务")
        if task.task_type in {"binary_firmware_e2e", "binary_module_e2e", "source_scan_e2e"}:
            await self.binary_security.delete_task(project_id=task.project_id, task_id=downstream_task_id, bearer_token=bearer_token)
            return
        if task.task_type == "ai4apk":
            await self.ai4apk.delete_task(downstream_task_id=downstream_task_id)
            return
        raise ValidationError("该任务类型暂不支持同步删除下游任务")

    def _delete_parent_task_rows(self, db: Session, task_id: str) -> None:
        db.query(ScheduleUserTaskDispatch).filter(ScheduleUserTaskDispatch.user_task_id == task_id).delete(synchronize_session=False)
        db.query(ScheduleUserTaskInputBinding).filter(ScheduleUserTaskInputBinding.user_task_id == task_id).delete(synchronize_session=False)
        db.query(ScheduleUserTask).filter(ScheduleUserTask.id == task_id).delete(synchronize_session=False)

    async def _delete_single_task(
        self,
        db: Session,
        *,
        project_id: str,
        task: ScheduleUserTask,
        bearer_token: str,
    ) -> dict[str, Any]:
        downstream_task_id = str(task.downstream_task_id or "").strip() or None
        task_id = str(task.id)
        task_type = str(task.task_type or "")
        try:
            if downstream_task_id:
                await self._delete_downstream_task(task, bearer_token)
            self._delete_parent_task_rows(db, task.id)
            db.commit()
            return {
                "task_id": task_id,
                "task_type": task_type,
                "downstream_task_id": downstream_task_id,
                "status": "deleted",
                "message": "任务及下游任务已删除" if downstream_task_id else "任务已删除",
            }
        except Exception as exc:
            db.rollback()
            return {
                "task_id": task_id,
                "task_type": task_type,
                "downstream_task_id": downstream_task_id,
                "status": "unsupported" if isinstance(exc, ValidationError) else "failed",
                "message": str(exc),
            }

    def _dispatch_policy_for_task_type(self, task_type: str):
        runtime_db = None
        try:
            from app.model import get_db_session
            runtime_db = get_db_session()
            runtime_service = get_runtime_config_service()
            if runtime_service.has_database_config(runtime_db):
                snapshot = runtime_service.get_snapshot(runtime_db)
                policy = next((item for item in snapshot.tool_defaults if str(item.task_type) == str(task_type)), None)
            else:
                policy = None
        finally:
            if runtime_db is not None:
                runtime_db.close()
        if policy is None:
            policies = get_config().user_task_dispatch_policy
            policy = getattr(policies, task_type, None)
        if policy is None:
            raise ValidationError(f"任务类型缺少分发策略配置: {task_type}")
        if task_type not in {"ai4red", "ai4apk"} and not list(policy.capacity_pool_ids or []):
            raise ValidationError(f"任务类型缺少 capacity_pool_ids 配置: {task_type}")
        return policy

    def auto_dispatch_token(self) -> str:
        token = str(get_config().auth_service.service_machine_token or "").strip()
        if not token:
            raise ValidationError("缺少调度中心服务凭证，无法自动分发任务")
        return token

    def _aigw_management_token(self) -> str:
        config = get_config()
        token = str(
            config.aigw_service.management_bearer_token
            or config.auth_service.service_machine_token
            or ""
        ).strip()
        if not token:
            raise ValidationError("缺少 AI Gateway 管理凭证配置，无法创建 root task key")
        return token


    @staticmethod
    def _compat_parent_task_key_value(value: Optional[str]) -> Optional[str]:
        raw = str(value or "").strip()
        if not raw or raw == CREATE_TIME_PARENT_TASK_KEY_PLACEHOLDER:
            return None
        return raw

    def get_task_or_404(self, db: Session, project_id: str, task_id: str) -> ScheduleUserTask:
        task = db.query(ScheduleUserTask).filter(
            ScheduleUserTask.project_id == project_id,
            ScheduleUserTask.id == task_id,
        ).first()
        if task is None:
            raise NotFoundError("UserTask", task_id)
        return task

    def _bindings_for_task(self, db: Session, task_id: str) -> list[ScheduleUserTaskInputBinding]:
        return db.query(ScheduleUserTaskInputBinding).filter(
            ScheduleUserTaskInputBinding.user_task_id == task_id
        ).order_by(ScheduleUserTaskInputBinding.created_at.asc()).all()

    def _dispatches_for_task(self, db: Session, task_id: str) -> list[ScheduleUserTaskDispatch]:
        return db.query(ScheduleUserTaskDispatch).filter(
            ScheduleUserTaskDispatch.user_task_id == task_id
        ).order_by(ScheduleUserTaskDispatch.created_at.desc()).all()

    def claim_ready_task(self, db: Session, *, actor: str) -> Optional[ScheduleUserTask]:
        task = db.query(ScheduleUserTask).filter(
            ScheduleUserTask.dispatch_status == "ready_for_dispatch",
            ScheduleUserTask.create_status == "created",
        ).order_by(ScheduleUserTask.created_at.asc()).first()
        if task is None:
            return None
        updated = db.query(ScheduleUserTask).filter(
            ScheduleUserTask.id == task.id,
            ScheduleUserTask.dispatch_status == "ready_for_dispatch",
        ).update(
            {
                ScheduleUserTask.dispatch_status: "dispatch_queued",
                ScheduleUserTask.updated_by: actor,
            },
            synchronize_session=False,
        )
        if updated != 1:
            db.rollback()
            return None
        db.commit()
        return self.get_task_or_404(db, task.project_id, task.id)

    async def auto_dispatch_ready_tasks(self, *, batch_size: int, actor: str) -> int:
        dispatched = 0
        for _ in range(max(1, int(batch_size))):
            db = None
            try:
                from app.model import get_db_session

                db = get_db_session()
                task = self.claim_ready_task(db, actor=actor)
                if task is None:
                    return dispatched
                await self.dispatch_task(
                    db,
                    project_id=task.project_id,
                    task_id=task.id,
                    actor=actor,
                    bearer_token=self.auto_dispatch_token(),
                )
                dispatched += 1
            except Exception as exc:
                if dispatched == 0:
                    raise exc
                continue
            finally:
                if db is not None:
                    db.close()
        return dispatched

    def _serialize_task(
        self,
        task: ScheduleUserTask,
        bindings: list[ScheduleUserTaskInputBinding],
        latest_dispatch: Optional[ScheduleUserTaskDispatch] = None,
    ) -> dict[str, Any]:
        return {
            "id": task.id,
            "project_id": task.project_id,
            "task_type": task.task_type,
            "name": task.name,
            "description": task.description,
            "create_status": task.create_status,
            "dispatch_status": task.dispatch_status,
            "business_status": task.business_status,
            "input_upload_count": len(bindings),
            "inputs": [
                {
                    "input_upload_id": item.input_upload_id,
                    "input_type": item.input_type,
                    "input_label": item.input_label,
                    "target_path": item.target_path,
                    "latest_batch_id": item.latest_batch_id,
                    "keep_original": item.keep_original,
                    "selection_type": item.selection_type,
                    "relative_path": item.relative_path,
                    "relative_paths": list(item.relative_paths or []),
                    "resolved_path": item.resolved_path,
                    "display_name": item.display_name,
                }
                for item in bindings
            ],
            "parent_task_key_id": self._compat_parent_task_key_value(task.parent_task_key_id),
            "parent_task_key_name": self._compat_parent_task_key_value(task.parent_task_key_name),
            "parent_task_key_prefix": self._compat_parent_task_key_value(task.parent_task_key_prefix),
            "parent_task_capacity_pool_ids": list(task.parent_task_capacity_pool_ids or []),
            "root_task_key_id": getattr(latest_dispatch, "dispatched_task_key_id", None),
            "root_task_key_name": getattr(latest_dispatch, "dispatched_task_key_name", None),
            "root_task_key_prefix": getattr(latest_dispatch, "dispatched_task_key_prefix", None),
            "root_task_capacity_pool_ids": list(getattr(latest_dispatch, "dispatched_task_capacity_pool_ids", []) or []),
            "dispatched_task_key_id": getattr(latest_dispatch, "dispatched_task_key_id", None),
            "dispatched_task_key_name": getattr(latest_dispatch, "dispatched_task_key_name", None),
            "dispatched_task_key_prefix": getattr(latest_dispatch, "dispatched_task_key_prefix", None),
            "module_name": task.module_name,
            "downstream_task_id": task.downstream_task_id,
            "downstream_detail_view": task.downstream_detail_view,
            "downstream_status_raw": task.downstream_status_raw,
            "downstream_status_mapped": task.downstream_status_mapped,
            "downstream_report_ready": bool(task.downstream_report_ready),
            "last_error": task.last_error,
            "created_by": task.created_by,
            "updated_at": task.updated_at,
            "created_at": task.created_at,
        }

    def _task_selection_type(self, task_type: str) -> str:
        if task_type == "binary_firmware_e2e":
            return "file"
        if task_type == "binary_module_e2e":
            return "file_list"
        if task_type == "source_scan_e2e":
            return "directory"
        if task_type == "ai4red":
            return "directory"
        if task_type == "ai4apk":
            return "file"
        raise ValidationError(f"不支持的任务类型: {task_type}")

    def _resolve_ai4red_directory(self, input_binding: ScheduleUserTaskInputBinding) -> str:
        source_path = Path(str(input_binding.resolved_path or input_binding.target_path or "").strip())
        if input_binding.selection_type != "directory":
            raise ValidationError("AI4Red 仅支持 directory 输入模式")
        if not source_path.is_dir():
            raise ValidationError(f"AI4Red 输入目录不存在: {source_path}")
        return str(source_path)

    @staticmethod
    def _extract_ai4red_data(payload: dict[str, Any]) -> dict[str, Any]:
        data = payload.get("data")
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _extract_ai4apk_data(payload: dict[str, Any]) -> dict[str, Any]:
        return payload if isinstance(payload, dict) else {}

    def _apply_ai4red_status(self, task: ScheduleUserTask, dispatch: Optional[ScheduleUserTaskDispatch], downstream_payload: dict[str, Any]) -> None:
        status_raw = str(downstream_payload.get("status") or "").strip()
        mapped_dispatch_status, mapped_business_status, report_ready = AI4RED_STATUS_MAP.get(
            status_raw,
            (task.dispatch_status or "running", task.business_status or "running", bool(task.downstream_report_ready)),
        )
        error_message = str(downstream_payload.get("errorMessage") or "").strip() or task.last_error
        task.dispatch_status = mapped_dispatch_status
        task.business_status = mapped_business_status
        task.downstream_status_raw = status_raw or None
        task.downstream_status_mapped = mapped_business_status
        task.downstream_report_ready = report_ready
        task.last_error = error_message or None
        if dispatch is not None:
            dispatch.dispatch_status = mapped_dispatch_status
            dispatch.downstream_status_raw = status_raw or None
            dispatch.downstream_status_mapped = mapped_business_status
            dispatch.downstream_report_ready = report_ready
            dispatch.last_error = error_message or None

    async def _refresh_ai4red_state(self, db: Session, task: ScheduleUserTask, dispatch: Optional[ScheduleUserTaskDispatch], bearer_token: str) -> None:
        if task.task_type != "ai4red" or not str(task.downstream_task_id or "").strip():
            return
        payload = await self.ai4red.get_task(downstream_task_id=task.downstream_task_id, bearer_token=bearer_token)
        self._apply_ai4red_status(task, dispatch, self._extract_ai4red_data(payload))
        db.commit()

    def _apply_ai4apk_status(self, task: ScheduleUserTask, dispatch: Optional[ScheduleUserTaskDispatch], downstream_payload: dict[str, Any]) -> None:
        status_raw = str(downstream_payload.get("status") or "").strip()
        mapped_dispatch_status, mapped_business_status, report_ready = AI4APK_STATUS_MAP.get(
            status_raw,
            (task.dispatch_status or "running", task.business_status or "running", bool(task.downstream_report_ready)),
        )
        error_message = str(downstream_payload.get("error") or "").strip() or task.last_error
        task.dispatch_status = mapped_dispatch_status
        task.business_status = mapped_business_status
        task.downstream_status_raw = status_raw or None
        task.downstream_status_mapped = mapped_business_status
        task.downstream_report_ready = report_ready
        task.last_error = error_message or None
        if dispatch is not None:
            dispatch.dispatch_status = mapped_dispatch_status
            dispatch.downstream_status_raw = status_raw or None
            dispatch.downstream_status_mapped = mapped_business_status
            dispatch.downstream_report_ready = report_ready
            dispatch.last_error = error_message or None

    async def _refresh_ai4apk_state(self, db: Session, task: ScheduleUserTask, dispatch: Optional[ScheduleUserTaskDispatch]) -> None:
        if task.task_type != "ai4apk" or not str(task.downstream_task_id or "").strip():
            return
        payload = await self.ai4apk.get_task(downstream_task_id=task.downstream_task_id)
        self._apply_ai4apk_status(task, dispatch, self._extract_ai4apk_data(payload))
        db.commit()

    async def list_tasks(
        self,
        db: Session,
        project_id: str,
        bearer_token: str,
        *,
        search: str | None = None,
        status: str | None = None,
        task_type: str | None = None,
        has_error: bool = False,
        is_retrying: bool = False,
        page: int = 1,
        page_size: int = 20,
        sort_by: str = "updated_at",
        sort_direction: str = "desc",
    ) -> tuple[int, list[dict[str, Any]], dict[str, int]]:
        normalized_page = max(1, int(page or 1))
        normalized_page_size = max(1, min(200, int(page_size or 20)))
        normalized_status = str(status or "").strip()
        normalized_task_type = str(task_type or "").strip()
        normalized_search = str(search or "").strip()
        normalized_sort_by = str(sort_by or "updated_at").strip()
        normalized_sort_direction = "asc" if str(sort_direction or "").strip().lower() == "asc" else "desc"

        query = db.query(ScheduleUserTask).filter(ScheduleUserTask.project_id == project_id)
        if normalized_status:
            query = query.filter(
                or_(
                    ScheduleUserTask.create_status == normalized_status,
                    ScheduleUserTask.dispatch_status == normalized_status,
                    ScheduleUserTask.business_status == normalized_status,
                    ScheduleUserTask.downstream_status_mapped == normalized_status,
                )
            )
        if normalized_task_type:
            query = query.filter(ScheduleUserTask.task_type == normalized_task_type)
        if has_error:
            query = query.filter(and_(ScheduleUserTask.last_error.isnot(None), ScheduleUserTask.last_error != ""))
        if is_retrying:
            query = query.filter(
                or_(
                    ScheduleUserTask.dispatch_status == "retry_wait",
                    ScheduleUserTask.business_status == "retry_wait",
                    ScheduleUserTask.downstream_status_mapped == "retry_wait",
                )
            )
        if normalized_search:
            search_value = f"%{normalized_search.lower()}%"
            query = query.filter(
                or_(
                    func.lower(ScheduleUserTask.id).like(search_value),
                    func.lower(ScheduleUserTask.name).like(search_value),
                    func.lower(ScheduleUserTask.created_by).like(search_value),
                    func.lower(func.coalesce(ScheduleUserTask.downstream_task_id, "")).like(search_value),
                    func.lower(func.coalesce(ScheduleUserTask.last_error, "")).like(search_value),
                    func.lower(func.coalesce(ScheduleUserTask.module_name, "")).like(search_value),
                )
            )

        stats_rows = query.all()
        total = len(stats_rows)
        sort_column = USER_TASK_SORT_FIELDS.get(normalized_sort_by, ScheduleUserTask.updated_at)
        order_clause = sort_column.asc() if normalized_sort_direction == "asc" else sort_column.desc()
        rows = (
            query.order_by(order_clause, ScheduleUserTask.created_at.desc(), ScheduleUserTask.id.desc())
            .offset((normalized_page - 1) * normalized_page_size)
            .limit(normalized_page_size)
            .all()
        )
        stats = {
            "total": total,
            "created": 0,
            "ready_for_dispatch": 0,
            "dispatching": 0,
            "running": 0,
            "success": 0,
            "failed": 0,
        }
        for task in stats_rows:
            stats[task.dispatch_status] = int(stats.get(task.dispatch_status, 0)) + 1
        items: list[dict[str, Any]] = []
        for task in rows:
            bindings = self._bindings_for_task(db, task.id)
            dispatches = self._dispatches_for_task(db, task.id)
            latest_dispatch = dispatches[0] if dispatches else None
            if task.task_type == "ai4red" and task.downstream_task_id:
                try:
                    await self._refresh_ai4red_state(db, task, latest_dispatch, bearer_token)
                except Exception:
                    db.rollback()
                    task = self.get_task_or_404(db, project_id, task.id)
                    latest_dispatch = self._dispatches_for_task(db, task.id)[0] if self._dispatches_for_task(db, task.id) else None
            if task.task_type == "ai4apk" and task.downstream_task_id:
                try:
                    await self._refresh_ai4apk_state(db, task, latest_dispatch)
                except Exception:
                    db.rollback()
                    task = self.get_task_or_404(db, project_id, task.id)
                    latest_dispatch = self._dispatches_for_task(db, task.id)[0] if self._dispatches_for_task(db, task.id) else None
            items.append(self._serialize_task(task, bindings, latest_dispatch))
        return total, items, stats

    async def create_task(self, db: Session, *, project_id: str, payload, actor: str, bearer_token: str) -> dict[str, Any]:
        if not payload.input_upload_ids:
            raise ValidationError("必须选择任务输入记录")
        if len(payload.input_upload_ids) != 1:
            raise ValidationError("当前版本仅支持单选一个任务输入记录")
        resolved = await self.input_resolver.resolve_single(project_id, payload.input_upload_ids[0], bearer_token)
        if resolved.project_id != project_id:
            raise ValidationError("任务输入记录不属于当前项目")
        if resolved.status not in {"succeeded", "partial_failed"}:
            raise ValidationError("所选任务输入尚未准备完成")
        if payload.task_type == "binary_module_e2e" and not str(payload.module_name or "").strip():
            raise ValidationError("二进制模块任务必须填写模块名")

        selection_type = self._task_selection_type(payload.task_type)
        input_binding_payload = payload.input_binding
        if input_binding_payload is None:
            raise ValidationError("必须提供结构化 input_binding")
        binding_upload_id = str(input_binding_payload.upload_id or payload.input_upload_ids[0]).strip()
        if binding_upload_id != resolved.upload_id:
            raise ValidationError("input_binding.upload_id 与 input_upload_ids 不一致")
        requested_selection_type = str(input_binding_payload.selection_type or selection_type).strip()
        if requested_selection_type != selection_type:
            raise ValidationError("所选输入模式与任务类型不匹配")

        relative_path = str(input_binding_payload.relative_path or "").strip()
        relative_paths = [str(item or "").strip() for item in (input_binding_payload.relative_paths or []) if str(item or "").strip()]
        resolved_relative_path: Optional[str] = None
        resolved_relative_paths: list[str] = []
        resolved_path: Optional[str] = None
        display_name = resolved.display_name
        if selection_type == "file":
            if not relative_path:
                raise ValidationError("当前任务类型必须选择一个文件")
            node = await self.input_resolver.resolve_path(project_id, resolved.upload_id, relative_path, bearer_token)
            if node.get("node_type") != "file":
                raise ValidationError("当前任务类型只允许选择文件")
            resolved_relative_path = str(node.get("relative_path") or "").strip()
            resolved_relative_paths = [resolved_relative_path]
            resolved_path = str(node.get("absolute_path") or "").strip()
            display_name = str(node.get("name") or resolved_relative_path or display_name)
            if payload.task_type == "ai4apk":
                if not resolved_path:
                    raise ValidationError("AI4APK 输入文件解析失败")
                file_path = Path(resolved_path)
                if not file_path.is_file():
                    raise ValidationError(f"AI4APK 输入文件不存在: {file_path}")
        elif selection_type == "file_list":
            if not relative_paths:
                raise ValidationError("盖亚-二进制模块必须至少选择一个文件")
            for item in relative_paths:
                node = await self.input_resolver.resolve_path(project_id, resolved.upload_id, item, bearer_token)
                if node.get("node_type") != "file":
                    raise ValidationError("盖亚-二进制模块只允许选择文件列表")
                resolved_relative_paths.append(str(node.get("relative_path") or "").strip())
            resolved_path = resolved.target_path
            display_name = f"{len(resolved_relative_paths)} files"
        else:
            if not relative_path:
                raise ValidationError("当前任务类型必须显式选择一个文件夹")
            node = await self.input_resolver.resolve_path(project_id, resolved.upload_id, relative_path, bearer_token)
            if node.get("node_type") != "directory":
                raise ValidationError("当前任务类型只允许选择文件夹")
            resolved_relative_path = str(node.get("relative_path") or "").strip()
            resolved_relative_paths = [resolved_relative_path] if resolved_relative_path else []
            resolved_path = str(node.get("absolute_path") or "").strip()
            display_name = str(node.get("name") or resolved_relative_path or display_name)
            if payload.task_type == "ai4red":
                if not resolved_path:
                    raise ValidationError("AI4Red 输入目录解析失败")
                directory_path = Path(resolved_path)
                if not directory_path.is_dir():
                    raise ValidationError(f"AI4Red 输入目录不存在: {directory_path}")

        compatibility_parent_secret = f"{CREATE_TIME_PARENT_TASK_KEY_PLACEHOLDER}:{payload.task_type}"
        parent_task_key_secret_cipher, parent_task_key_secret_nonce, parent_task_key_secret_version = self.task_key_cipher.encrypt(
            compatibility_parent_secret
        )

        task = ScheduleUserTask(
            project_id=project_id,
            task_type=payload.task_type,
            name=payload.name,
            description=payload.description,
            module_name=str(payload.module_name or "").strip() or None,
            create_status="created",
            dispatch_status="ready_for_dispatch",
            business_status="created",
            parent_task_key_id=CREATE_TIME_PARENT_TASK_KEY_PLACEHOLDER,
            parent_task_key_name=CREATE_TIME_PARENT_TASK_KEY_PLACEHOLDER,
            parent_task_key_prefix=CREATE_TIME_PARENT_TASK_KEY_PLACEHOLDER,
            parent_task_capacity_pool_ids=[],
            parent_task_key_secret_cipher=parent_task_key_secret_cipher,
            parent_task_key_secret_nonce=parent_task_key_secret_nonce,
            parent_task_key_secret_version=parent_task_key_secret_version,
            downstream_detail_view=TASK_TYPE_DETAIL_VIEW.get(payload.task_type),
            created_by=actor,
            updated_by=actor,
        )
        db.add(task)
        db.flush()
        binding = ScheduleUserTaskInputBinding(
            user_task_id=task.id,
            project_id=project_id,
            input_upload_id=resolved.upload_id,
            input_type=resolved.input_type,
            input_label=display_name,
            target_path=resolved.target_path,
            latest_batch_id=resolved.latest_batch_id,
            keep_original=resolved.keep_original,
            selection_type=selection_type,
            relative_path=resolved_relative_path,
            relative_paths=resolved_relative_paths,
            resolved_path=resolved_path,
            display_name=display_name,
        )
        db.add(binding)
        db.commit()
        db.refresh(task)
        return self._serialize_task(task, [binding])

    async def dispatch_task(self, db: Session, *, project_id: str, task_id: str, actor: str, bearer_token: str) -> dict[str, Any]:
        task = self.get_task_or_404(db, project_id, task_id)
        bindings = self._bindings_for_task(db, task.id)
        if not bindings:
            raise ValidationError("任务缺少输入绑定，无法分发")
        if task.dispatch_status not in {"ready_for_dispatch", "dispatch_queued", "dispatch_failed"}:
            raise ConflictError(f"任务当前状态不允许分发: {task.dispatch_status}")
        task.dispatch_status = "dispatching"
        task.business_status = "dispatching"
        task.updated_by = actor
        dispatch = ScheduleUserTaskDispatch(
            user_task_id=task.id,
            project_id=project_id,
            dispatch_status="dispatching",
            created_by=actor,
        )
        db.add(dispatch)
        db.commit()
        db.refresh(dispatch)

        try:
            input_binding = bindings[0]
            if task.task_type == "ai4red":
                deliver_dir = self._resolve_ai4red_directory(input_binding)
                create_result = await self.ai4red.create_task(
                    project_id=project_id,
                    task_id=task.id,
                    deliver_dir=deliver_dir,
                    bearer_token=bearer_token,
                )
                downstream_task_id = str(self._extract_ai4red_data(create_result).get("taskId") or "").strip() or task.id
                dispatch.dispatch_status = "running"
                dispatch.downstream_task_id = downstream_task_id
                dispatch.downstream_detail_view = TASK_TYPE_DETAIL_VIEW.get(task.task_type)
                dispatch.downstream_status_raw = "PARSE_PENDING"
                dispatch.downstream_status_mapped = "dispatching"
                dispatch.downstream_report_ready = False
                task.dispatch_status = "running"
                task.business_status = "running"
                task.downstream_task_id = downstream_task_id
                task.downstream_detail_view = dispatch.downstream_detail_view
                task.downstream_status_raw = "PARSE_PENDING"
                task.downstream_status_mapped = "dispatching"
                task.downstream_report_ready = False
                task.last_error = None
                db.commit()
                await self._refresh_ai4red_state(db, task, dispatch, bearer_token)
                return self._serialize_task(task, bindings, dispatch)
            if task.task_type == "ai4apk":
                file_path = Path(str(input_binding.resolved_path or input_binding.target_path or "").strip())
                if input_binding.selection_type != "file":
                    raise ValidationError("AI4APK 仅支持 file 输入模式")
                if not file_path.is_file():
                    raise ValidationError(f"AI4APK 输入文件不存在: {file_path}")
                create_result = await self.ai4apk.create_task(
                    project_id=project_id,
                    task_id=task.id,
                    file_path=str(file_path),
                    task_type="APK",
                )
                downstream_task_id = str(self._extract_ai4apk_data(create_result).get("tool_task_id") or "").strip()
                if not downstream_task_id:
                    raise UpstreamError("创建 ai4apk 任务失败: 下游未返回 tool_task_id")
                dispatch.dispatch_status = "running"
                dispatch.downstream_task_id = downstream_task_id
                dispatch.downstream_detail_view = None
                dispatch.downstream_status_raw = "pending"
                dispatch.downstream_status_mapped = "dispatching"
                dispatch.downstream_report_ready = False
                task.dispatch_status = "running"
                task.business_status = "running"
                task.downstream_task_id = downstream_task_id
                task.downstream_detail_view = None
                task.downstream_status_raw = "pending"
                task.downstream_status_mapped = "dispatching"
                task.downstream_report_ready = False
                task.last_error = None
                db.commit()
                await self._refresh_ai4apk_state(db, task, dispatch)
                return self._serialize_task(task, bindings, dispatch)

            dispatch_policy = self._dispatch_policy_for_task_type(task.task_type)
            dispatch_auth_token = self.auto_dispatch_token()
            dispatch_task_key_result = await self.aigw.create_task_key(
                management_token=self._aigw_management_token(),
                task_id=task.id,
                dispatch_id=dispatch.id,
                capacity_pool_ids=list(dispatch_policy.capacity_pool_ids or []),
                max_concurrency=int(dispatch_policy.root_task_key_max_concurrency or 0),
                expires_at=dispatch_policy.root_task_key_expires_at,
            )
            key_payload = dispatch_task_key_result.get("key") or {}
            dispatch_secret = str(dispatch_task_key_result.get("secret") or "").strip()
            if not dispatch_secret:
                raise UpstreamError("AI Gateway 未返回 root task key secret")
            (
                dispatch.dispatched_task_key_secret_cipher,
                dispatch.dispatched_task_key_secret_nonce,
                dispatch.dispatched_task_key_secret_version,
            ) = self.task_key_cipher.encrypt(dispatch_secret)
            dispatch.dispatched_task_key_id = str(key_payload.get("id") or "")
            dispatch.dispatched_task_key_name = str(key_payload.get("key_name") or "")
            dispatch.dispatched_task_key_prefix = str(key_payload.get("key_prefix") or "")
            dispatch.dispatched_task_capacity_pool_ids = list(key_payload.get("capacity_pool_ids") or dispatch_policy.capacity_pool_ids or [])

            source_path = Path(input_binding.resolved_path or input_binding.target_path)
            if not source_path.exists():
                raise ValidationError(f"任务输入路径不存在: {source_path}")
            target_root = Path(f"/data/files/{project_id}/app/secflow-app-binary-security/{task.id}/input")
            await asyncio.to_thread(target_root.mkdir, parents=True, exist_ok=True)
            copied_files: list[dict[str, Any]] = []
            selected_paths = list(input_binding.relative_paths or [])
            if input_binding.selection_type == "file_list" and selected_paths:
                for item in selected_paths:
                    child = Path(input_binding.target_path) / item
                    if not child.is_file():
                        raise ValidationError(f"选中的任务输入文件不存在: {item}")
                    destination = target_root / item
                    await asyncio.to_thread(destination.parent.mkdir, parents=True, exist_ok=True)
                    await asyncio.to_thread(shutil.copy2, child, destination)
                    copied_files.append({
                        "filename": child.name,
                        "relative_path": item,
                        "size": child.stat().st_size,
                        "metadata": {"input_upload_id": input_binding.input_upload_id},
                    })
            elif source_path.is_dir():
                for child in sorted(source_path.rglob("*")):
                    if not child.is_file():
                        continue
                    relative = child.relative_to(source_path).as_posix()
                    destination = target_root / relative
                    await asyncio.to_thread(destination.parent.mkdir, parents=True, exist_ok=True)
                    await asyncio.to_thread(shutil.copy2, child, destination)
                    copied_files.append({
                        "filename": child.name,
                        "relative_path": relative,
                        "size": child.stat().st_size,
                        "metadata": {"input_upload_id": input_binding.input_upload_id},
                    })
            else:
                destination = target_root / source_path.name
                await asyncio.to_thread(shutil.copy2, source_path, destination)
                copied_files.append({
                    "filename": source_path.name,
                    "relative_path": source_path.name,
                    "size": source_path.stat().st_size,
                    "metadata": {"input_upload_id": input_binding.input_upload_id},
                })
            if not copied_files:
                raise ValidationError("任务输入目录中没有可分发文件")

            create_payload: dict[str, Any] = {
                "task_type": TASK_TYPE_BINARY_SECURITY[task.task_type],
                "name": task.name,
                "description": task.description,
                "input_files": copied_files,
                "policy_overrides": {},
                "root_task_key_id": dispatch.dispatched_task_key_id,
                "root_task_key_name": dispatch.dispatched_task_key_name,
                "root_task_key_prefix": dispatch.dispatched_task_key_prefix,
                "root_task_key_secret": dispatch_secret,
                "task_key_source": "schedule_dispatch",
            }
            if task.task_type == "binary_module_e2e":
                create_payload["module_name"] = str(task.module_name or "").strip() or task.name or "module"
            await self.binary_security.create_task(
                project_id=project_id,
                task_id=task.id,
                payload=create_payload,
                bearer_token=dispatch_auth_token,
            )
            await self.binary_security.complete_uploads(
                project_id=project_id,
                task_id=task.id,
                files=copied_files,
                bearer_token=dispatch_auth_token,
            )

            dispatch.dispatch_status = "succeeded"
            dispatch.downstream_task_id = task.id
            dispatch.downstream_detail_view = TASK_TYPE_DETAIL_VIEW.get(task.task_type)
            task.dispatch_status = "running"
            task.business_status = "running"
            task.downstream_task_id = task.id
            task.downstream_detail_view = dispatch.downstream_detail_view
            task.last_error = None
            db.commit()
        except Exception as exc:
            db.rollback()
            task = self.get_task_or_404(db, project_id, task_id)
            dispatch = db.query(ScheduleUserTaskDispatch).filter(
                ScheduleUserTaskDispatch.id == dispatch.id
            ).first()
            message = str(exc)
            task.dispatch_status = "dispatch_failed"
            task.business_status = "failed"
            task.last_error = message
            task.updated_by = actor
            if dispatch is not None:
                dispatch.dispatch_status = "failed"
                dispatch.last_error = message
            db.commit()
            raise
        latest_dispatch = dispatch
        return self._serialize_task(task, bindings, latest_dispatch)

    async def get_task_detail(self, db: Session, project_id: str, task_id: str, bearer_token: str) -> dict[str, Any]:
        task = self.get_task_or_404(db, project_id, task_id)
        dispatches = self._dispatches_for_task(db, task.id)
        latest_dispatch = dispatches[0] if dispatches else None
        if task.task_type == "ai4red" and task.downstream_task_id:
            try:
                await self._refresh_ai4red_state(db, task, latest_dispatch, bearer_token)
            except Exception:
                db.rollback()
                task = self.get_task_or_404(db, project_id, task_id)
                dispatches = self._dispatches_for_task(db, task.id)
                latest_dispatch = dispatches[0] if dispatches else None
        if task.task_type == "ai4apk" and task.downstream_task_id:
            try:
                await self._refresh_ai4apk_state(db, task, latest_dispatch)
            except Exception:
                db.rollback()
                task = self.get_task_or_404(db, project_id, task_id)
                dispatches = self._dispatches_for_task(db, task.id)
                latest_dispatch = dispatches[0] if dispatches else None
        return self._serialize_task(task, self._bindings_for_task(db, task.id), latest_dispatch)

    async def delete_tasks(
        self,
        db: Session,
        *,
        project_id: str,
        bearer_token: str,
        task_ids: list[str],
        select_all_matching: bool,
        filters: Optional[dict[str, Any]],
    ) -> dict[str, Any]:
        base_query = db.query(ScheduleUserTask).filter(ScheduleUserTask.project_id == project_id)
        results: list[dict[str, Any]] = []

        if select_all_matching:
            tasks = self._filter_tasks_for_bulk_delete(
                base_query.order_by(ScheduleUserTask.created_at.desc()).all(),
                filters=filters,
            )
            for task in tasks:
                results.append(await self._delete_single_task(db, project_id=project_id, task=task, bearer_token=bearer_token))
            deleted_count = sum(1 for item in results if item["status"] == "deleted")
            return {
                "total_requested": len(tasks),
                "deleted_count": deleted_count,
                "failed_count": len(results) - deleted_count,
                "results": results,
            }

        normalized_ids = [str(task_id or "").strip() for task_id in task_ids if str(task_id or "").strip()]
        if not normalized_ids:
            return {
                "total_requested": 0,
                "deleted_count": 0,
                "failed_count": 0,
                "results": [],
            }
        rows = base_query.filter(ScheduleUserTask.id.in_(normalized_ids)).all()
        row_map = {row.id: row for row in rows}
        for task_id in normalized_ids:
            task = row_map.get(task_id)
            if task is None:
                results.append({
                    "task_id": task_id,
                    "task_type": None,
                    "downstream_task_id": None,
                    "status": "deleted",
                    "message": "任务已不存在",
                })
                continue
            results.append(await self._delete_single_task(db, project_id=project_id, task=task, bearer_token=bearer_token))
        deleted_count = sum(1 for item in results if item["status"] == "deleted")
        return {
            "total_requested": len(normalized_ids),
            "deleted_count": deleted_count,
            "failed_count": len(results) - deleted_count,
            "results": results,
        }

    def list_dispatches(self, db: Session, project_id: str, task_id: str) -> tuple[int, list[dict[str, Any]]]:
        self.get_task_or_404(db, project_id, task_id)
        rows = self._dispatches_for_task(db, task_id)
        return len(rows), [
            {
                "id": row.id,
                "user_task_id": row.user_task_id,
                "project_id": row.project_id,
                "dispatch_status": row.dispatch_status,
                "root_task_key_id": row.dispatched_task_key_id,
                "root_task_key_name": row.dispatched_task_key_name,
                "root_task_key_prefix": row.dispatched_task_key_prefix,
                "root_task_capacity_pool_ids": list(row.dispatched_task_capacity_pool_ids or []),
                "dispatched_task_key_id": row.dispatched_task_key_id,
                "dispatched_task_key_name": row.dispatched_task_key_name,
                "dispatched_task_key_prefix": row.dispatched_task_key_prefix,
                "downstream_task_id": row.downstream_task_id,
                "downstream_detail_view": row.downstream_detail_view,
                "downstream_status_raw": row.downstream_status_raw,
                "downstream_status_mapped": row.downstream_status_mapped,
                "downstream_report_ready": bool(row.downstream_report_ready),
                "last_error": row.last_error,
                "created_by": row.created_by,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }
            for row in rows
        ]


_user_task_manager: Optional[UserTaskManager] = None


def get_user_task_manager() -> UserTaskManager:
    global _user_task_manager
    if _user_task_manager is None:
        _user_task_manager = UserTaskManager()
    return _user_task_manager
