from __future__ import annotations

import asyncio
import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.exception import NotFoundError, UpstreamError, ValidationError
from app.model import BinarySecurityArchiveJob, BinarySecurityStageItem, BinarySecurityStageRun, BinarySecurityTask, build_stage_item_identity_key, normalize_stage_name

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class _TaskManagerModuleProxy:
    def __getattr__(self, name: str):
        from app.service import task_manager as task_manager_module

        return getattr(task_manager_module, name)


task_manager_module = _TaskManagerModuleProxy()


class TaskDownstreamServiceMixin:
    CHILD_TRANSITION_IN_PLACE_RESTART = "in_place_restart"
    CHILD_TRANSITION_DESTRUCTIVE_REBUILD = "destructive_rebuild"

    # Downstream orchestration relies on shared task-manager constants/helpers.
    @staticmethod
    def _entry_contract_fields(entry: dict[str, Any] | None) -> dict[str, Any]:
        if not isinstance(entry, dict):
            return {}
        contract_fields = (
            "module_dir",
            "descriptor_root",
            "source_dir",
            "source_root",
            "source_root_path",
            "module_input_path",
            "files_list_path",
            "files_list",
            "entry_descriptor_root",
            "entry_files_list",
            "entry_descriptor_ready",
            "artifact_root",
            "archive_root",
            "task_type",
            "module_key",
            "module_name",
            "firmware_key",
            "firmware_name",
        )
        return {field: entry.get(field) for field in contract_fields if entry.get(field) is not None}

    def _match_entry_identity(self, candidate: dict[str, Any], target: dict[str, Any]) -> bool:
        if not isinstance(candidate, dict) or not isinstance(target, dict):
            return False
        candidate_key = str(candidate.get("entry_key") or "").strip()
        target_key = str(target.get("entry_key") or "").strip()
        if candidate_key and target_key:
            return candidate_key == target_key
        return (
            str(candidate.get("module_key") or "").strip() == str(target.get("module_key") or "").strip()
            and str(candidate.get("function_name") or "").strip() == str(target.get("function_name") or "").strip()
            and str(candidate.get("definition_file") or candidate.get("file_name") or "").strip()
            == str(target.get("definition_file") or target.get("file_name") or "").strip()
            and str(candidate.get("definition_line") or candidate.get("line_no") or "").strip()
            == str(target.get("definition_line") or target.get("line_no") or "").strip()
        )

    @staticmethod
    def _normalize_dataflow_execution_string(value: Any) -> str:
        return str(value or "").strip()

    @classmethod
    def _normalize_dataflow_execution_list(cls, values: Any) -> list[str]:
        if not isinstance(values, list):
            return []
        normalized = {
            cls._normalize_dataflow_execution_string(value)
            for value in values
            if cls._normalize_dataflow_execution_string(value)
        }
        return sorted(normalized)

    def _dataflow_entry_execution_fingerprint_payload(self, entry: dict[str, Any] | None) -> dict[str, Any]:
        candidate = dict(entry or {})
        return {
            "source_file": self._normalize_dataflow_execution_string(
                candidate.get("source_file")
                or candidate.get("definition_file")
                or candidate.get("file_name")
            ),
            "function_name": self._normalize_dataflow_execution_string(candidate.get("function_name")),
            "taint_params": self._normalize_dataflow_execution_list(candidate.get("taint_params")),
            "signature_params": self._normalize_dataflow_execution_list(candidate.get("signature_params")),
        }

    def _dataflow_entry_execution_fingerprint(self, entry: dict[str, Any] | None) -> str:
        payload = self._dataflow_entry_execution_fingerprint_payload(entry)
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def _dataflow_entry_execution_changed_fields(
        self,
        previous_entry: dict[str, Any] | None,
        current_entry: dict[str, Any] | None,
    ) -> list[str]:
        previous_payload = self._dataflow_entry_execution_fingerprint_payload(previous_entry)
        current_payload = self._dataflow_entry_execution_fingerprint_payload(current_entry)
        return [
            field
            for field in ("source_file", "function_name", "taint_params", "signature_params")
            if previous_payload.get(field) != current_payload.get(field)
        ]

    def _entry_analysis_execution_fingerprint_payload(self, module: dict[str, Any] | None) -> dict[str, Any]:
        candidate = dict(module or {})
        return {
            "module_dir": self._normalize_dataflow_execution_string(
                candidate.get("module_dir") or candidate.get("module_input_path") or candidate.get("source_dir")
            ),
            "source_root": self._normalize_dataflow_execution_string(
                candidate.get("source_root_path") or candidate.get("source_root") or candidate.get("source_dir")
            ),
            "entry_files_list": self._normalize_dataflow_execution_string(
                candidate.get("entry_files_list") or candidate.get("files_list_path") or candidate.get("files_list")
            ),
        }

    def _entry_analysis_execution_fingerprint(self, module: dict[str, Any] | None) -> str:
        payload = self._entry_analysis_execution_fingerprint_payload(module)
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def _legacy_vuln_execution_fingerprint_payload(self, result: dict[str, Any] | None) -> dict[str, Any]:
        candidate = dict(result or {})
        return {
            "data_flow_path": self._normalize_dataflow_execution_string(
                candidate.get("module_input_path")
                or candidate.get("data_flow_root")
                or candidate.get("dataflow_dir")
                or candidate.get("data_flow_file")
            ),
            "source_dir": self._normalize_dataflow_execution_string(
                candidate.get("source_root_path") or candidate.get("source_dir")
            ),
            "function_name": self._normalize_dataflow_execution_string(candidate.get("function_name")),
            "entry_key": self._normalize_dataflow_execution_string(candidate.get("entry_key")),
        }

    def _legacy_vuln_execution_fingerprint(self, result: dict[str, Any] | None) -> str:
        payload = self._legacy_vuln_execution_fingerprint_payload(result)
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def _payload_changed_fields(
        self,
        previous_payload: dict[str, Any],
        current_payload: dict[str, Any],
    ) -> list[str]:
        return [field for field in previous_payload.keys() if previous_payload.get(field) != current_payload.get(field)]

    def _dataflow_item_execution_fingerprint(self, item: BinarySecurityStageItem | None) -> str | None:
        if item is None:
            return None
        input_ref = dict(getattr(item, "input_ref", None) or {})
        stored = str(input_ref.get("execution_fingerprint") or "").strip()
        if stored:
            return stored
        result = self._load_stage_item_result_payload(item)
        stored = str(result.get("execution_fingerprint") or "").strip()
        if stored:
            return stored
        if not input_ref:
            return None
        return self._dataflow_entry_execution_fingerprint(input_ref)

    def _decorate_dataflow_entry_with_execution_fingerprint(self, entry: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(entry or {})
        fingerprint = self._dataflow_entry_execution_fingerprint(normalized)
        normalized["execution_fingerprint"] = fingerprint
        return normalized

    def _update_stage_item_metadata_only(
        self,
        item: BinarySecurityStageItem,
        *,
        item_name: str | None,
        input_ref: dict[str, Any],
        output_ref: dict[str, Any] | None = None,
    ) -> BinarySecurityStageItem:
        item.item_name = item_name
        item.input_ref = dict(input_ref or {})
        if output_ref is not None:
            item.output_ref = dict(output_ref or {})
        result = self._load_stage_item_result_payload(item)
        result["execution_fingerprint"] = str(input_ref.get("execution_fingerprint") or "").strip() or None
        item.result = result
        return item

    def _prepare_dataflow_stage_item_for_signature_change(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
    ) -> None:
        old_task_id = str(item.downstream_task_id or "").strip() or None
        if old_task_id:
            self._supersede_archive_jobs_for_downstream_task(
                db,
                task,
                item,
                old_downstream_task_id=old_task_id,
                reason="streaming_entry_execution_signature_changed",
            )
            self._mark_superseded_downstream_state(
                item,
                old_downstream_task_id=old_task_id,
                message="执行契约已变化，旧 child 结果已失效，等待新 child 重建",
            )
        if old_task_id:
            self._record_event(
                db,
                task,
                "stale_dataflow_item_requeued_after_signature_change",
                "DFVS 执行契约已变化，旧下游绑定已废弃，等待定点重建",
                stage_name=item.stage_name,
                item=item,
                level="warning",
                payload={
                    "item_id": item.id,
                    "item_key": item.item_key,
                    "old_downstream_task_id": old_task_id,
                    "reason": "streaming_entry_execution_signature_changed",
                },
            )
        self._clear_item_downstream_runtime_state(item)
        self._mark_replacement_in_progress(
            item,
            old_downstream_task_id=old_task_id,
            binding_cleared=True,
            verification_status="pending",
            transition_type=self.CHILD_TRANSITION_DESTRUCTIVE_REBUILD,
        )
        self._set_downstream_binding_snapshot(
            item,
            state="not_started",
            attempts=0,
            first_attempt_at=None,
            last_attempt_at=None,
            next_retry_at=None,
            last_error=None,
            last_error_type=None,
            recoverable=None,
            message="执行契约变化后等待重建新的下游任务",
        )
        item.status = "pending"
        item.finished_at = None
        item.started_at = None
        item.error_message = None
        self._clear_stage_item_claim(item)

    def _prepare_entry_analysis_stage_item_for_signature_change(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
    ) -> None:
        old_task_id = str(item.downstream_task_id or "").strip() or None
        if old_task_id:
            self._supersede_archive_jobs_for_downstream_task(
                db,
                task,
                item,
                old_downstream_task_id=old_task_id,
                reason="streaming_entry_execution_signature_changed",
            )
            self._mark_superseded_downstream_state(
                item,
                old_downstream_task_id=old_task_id,
                message="入口分析执行契约已变化，旧 child 结果已失效，等待新 child 重建",
            )
        self._clear_item_downstream_runtime_state(item)
        self._set_downstream_binding_snapshot(
            item,
            state="not_started",
            attempts=0,
            first_attempt_at=None,
            last_attempt_at=None,
            next_retry_at=None,
            last_error=None,
            last_error_type=None,
            recoverable=None,
            message="执行契约变化后等待重建新的下游任务",
        )
        item.status = "pending"
        item.finished_at = None
        item.started_at = None
        item.error_message = None
        self._clear_stage_item_claim(item)

    def _dataflow_item_archive_success(self, db: Session, item: BinarySecurityStageItem) -> bool:
        jobs = self._archive_jobs_for_stage_items(db, item.task_id, item.stage_name, [item.id])
        return any(str(getattr(job, "archive_status", "") or "").strip().lower() == "success" for job in jobs)

    def _maybe_reconcile_stale_dataflow_stage_item(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
    ) -> bool:
        if normalize_stage_name(item.stage_name) != "dataflow_vuln_scan":
            return False
        normalized_status = self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower()
        if normalized_status not in {"pending", "queued", "dispatching", "running"}:
            return False
        downstream_status = self._latest_observed_downstream_status(item)
        mapped_downstream_status = self._normalize_downstream_status(downstream_status) or str(downstream_status or "").strip().lower()
        if mapped_downstream_status not in {"success", "partial_success"}:
            return False
        if not self._dataflow_item_archive_success(db, item):
            return False
        fingerprint = self._dataflow_item_execution_fingerprint(item)
        if fingerprint:
            input_ref = dict(item.input_ref or {})
            input_ref["execution_fingerprint"] = fingerprint
            item.input_ref = input_ref
            result = self._load_stage_item_result_payload(item)
            result["execution_fingerprint"] = fingerprint
            item.result = result
        self._apply_child_task_status_change(
            db,
            task=task,
            item=item,
            change_source="stale_dataflow_item_reconcile",
            after_status=mapped_downstream_status,
            downstream_payload=dict(self._load_stage_item_result_payload(item).get("downstream") or {}),
            sync_status="synced",
            downstream_status_raw=downstream_status,
            downstream_status_mapped=mapped_downstream_status,
            downstream_status=downstream_status or mapped_downstream_status,
            state_applied=True,
            event_type="stale_dataflow_item_reconciled_to_success",
            extra_payload={
                "archive_reconciled": True,
                "execution_fingerprint": fingerprint,
            },
        )
        return True

    def _ensure_streaming_stage_run_for_materialization(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        reason: str,
        reopen_terminal: bool = True,
    ) -> BinarySecurityStageRun:
        normalized_stage = normalize_stage_name(stage_name)
        if not normalized_stage:
            raise ValidationError("流式阶段物化失败: stage_name 为空")
        if not self._streaming_mode_enabled(task):
            raise ValidationError(f"流式阶段物化失败: 任务 {task.id} 当前未启用 streaming 模式")
        if normalized_stage not in self._streaming_tail_stage_names(task):
            raise ValidationError(f"流式阶段物化失败: 阶段 {normalized_stage} 不是该任务的 streaming tail stage")
        if not self._task_runtime_owner_matches_current_instance(db, task) and not self._task_runtime_transition_guard_owned_by_current_instance(task):
            self._record_main_state_write_blocked(
                db,
                task,
                source="runtime_worker",
                attempted_stage_name=normalized_stage,
                attempted_status="pending",
                reason=f"{reason}_requires_current_owner",
            )
            raise ValidationError(f"流式阶段物化失败: 当前实例不是任务 {task.id} 的活跃 owner")
        stage_run = self._ensure_stage_run(db, task, normalized_stage)
        normalized_status = str(getattr(stage_run, "status", "") or "").strip().lower()
        if reopen_terminal and normalized_status in {"failed", "cancelled", "downstream_missing", "success", "partial_success"}:
            stage_run.status = "pending"
            stage_run.finished_at = None
            stage_run.last_error = None
            stage_run.updated_at = task_manager_module._now()
        return stage_run

    def _streaming_stage_run_for_seed(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        reason: str,
        reopen_terminal: bool = True,
    ) -> BinarySecurityStageRun:
        normalized_stage = normalize_stage_name(stage_name)
        stage_run = self._latest_stage_run(db, task.id, normalized_stage)
        if stage_run is not None:
            normalized_status = str(getattr(stage_run, "status", "") or "").strip().lower()
            if reopen_terminal and normalized_status in {"failed", "cancelled", "downstream_missing", "success", "partial_success"}:
                stage_run.status = "pending"
                stage_run.finished_at = None
                stage_run.last_error = None
                stage_run.updated_at = task_manager_module._now()
            return stage_run
        return self._ensure_streaming_stage_run_for_materialization(
            db,
            task,
            normalized_stage,
            reason=reason,
            reopen_terminal=reopen_terminal,
        )

    def _recover_entry_output_contract(
        self,
        db: Session,
        task: BinarySecurityTask,
        entry: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(entry, dict):
            return {}
        module_key = str(entry.get("module_key") or "").strip()
        entry_items = [
            item
            for item in self._stage_items(db, task.id, "entry_analysis")
            if item.status == "success" and (not module_key or str(item.item_key or "").strip() == module_key)
        ]
        for item in entry_items:
            input_ref = dict(item.input_ref or {})
            result = self._load_stage_item_result_payload(item)
            output_ref = dict(item.output_ref or {})
            module = {
                **input_ref,
                **result,
                **self._entry_contract_fields(input_ref),
                **self._entry_contract_fields(result),
                **self._entry_contract_fields(output_ref),
                "module_key": str(result.get("module_key") or input_ref.get("module_key") or item.item_key or ""),
                "module_name": str(result.get("module_name") or input_ref.get("module_name") or item.item_name or ""),
                "artifact_root": self._stage_item_artifact_root(item),
                "source_dir": self._resolve_entry_source_dir({**input_ref, **result, **output_ref}) or str(task.firmware_path or ""),
            }
            entries = [dict(row) for row in result.get("entries") or [] if isinstance(row, dict)]
            artifact_root_value = module.get("artifact_root")
            if artifact_root_value:
                parsed_entries = self._parse_entries(Path(str(artifact_root_value)), module)
                if parsed_entries:
                    entries = parsed_entries
            if not entries:
                entries = [dict(row) for row in result.get("entries_preview") or [] if isinstance(row, dict)]
            for candidate in entries:
                if not self._match_entry_identity(candidate, entry):
                    continue
                merged = {
                    **candidate,
                    **self._entry_contract_fields(module),
                }
                merged["source_dir"] = merged.get("source_dir") or module.get("source_dir")
                return merged
        return {}

    def _effective_stage_item_downstream_status(
        self,
        item: BinarySecurityStageItem,
        *,
        result: dict[str, Any] | None = None,
    ) -> tuple[str | None, dict[str, Any], bool]:
        result_payload = dict(result or item.result or {})
        sync_observation = dict(result_payload.get("sync_observation") or {})
        display_status = (
            self._string_or_none(sync_observation.get("downstream_status"))
            or self._string_or_none(result_payload.get("downstream_status"))
            or self._string_or_none(dict(result_payload.get("downstream") or {}).get("status"))
        )
        normalized_display = self._normalize_downstream_status(display_status)
        normalized_item = self._normalize_downstream_status(item.status) or self._string_or_none(item.status)
        replacement_state = self._replacement_in_progress_state(item)
        sync_error_type = self._string_or_none(sync_observation.get("error_type"))
        sync_error_message = self._string_or_none(sync_observation.get("error_message"))
        repaired = False
        if (
            normalized_item in {"failed", "downstream_missing", "cancelled"}
            and normalized_display in {"pending", "dispatching", "running"}
            and sync_error_type == "StaleTaskExecution"
            and sync_error_message
            and ("token 已失效" in sync_error_message or "owner" in sync_error_message.lower())
        ):
            sync_observation["downstream_status"] = normalized_display
            sync_observation.setdefault("mapped_status", normalized_display)
            return normalized_display, sync_observation, repaired
        if (
            normalized_item in {"success", "failed", "cancelled", "partial_success", "downstream_missing"}
            and normalized_display in {"pending", "dispatching", "running"}
            and not replacement_state["replacement_in_progress"]
        ):
            display_status = normalized_item
            sync_observation["downstream_status"] = normalized_item
            sync_observation.setdefault("status_raw", normalized_display or display_status)
            sync_observation["mapped_status"] = normalized_item
            repaired = True
        elif replacement_state["replacement_in_progress"] and normalized_display in {"pending", "dispatching", "running"}:
            sync_observation["downstream_status"] = normalized_display
        if not display_status and str(item.downstream_task_id or "").strip():
            binding_state = self._downstream_binding_state(item)
            if binding_state == "created_pending_sync":
                display_status = "pending"
        return display_status, sync_observation, repaired

    def _downstream_binding_status_message(self: TaskManager, item: BinarySecurityStageItem) -> str | None:
        binding = self._downstream_binding_snapshot(item)
        explicit_message = self._string_or_none(binding.get("message"))
        binding_state = self._downstream_binding_state(item)
        if binding_state == "bound":
            return None
        if explicit_message:
            return explicit_message
        last_error = self._string_or_none(binding.get("last_error"))
        if binding_state == "created_pending_sync":
            return "下游已创建，状态待同步"
        if binding_state == "creating":
            return "下游创建中"
        if binding_state == "create_retrying":
            return last_error or "下游创建失败，等待重试"
        if binding_state == "create_failed":
            return last_error or "下游创建失败"
        return None

    def _item_has_pending_replacement_or_stale_child(self: TaskManager, item: BinarySecurityStageItem) -> bool:
        replacement_state = self._replacement_in_progress_state(item)
        if replacement_state["replacement_in_progress"]:
            return True
        if replacement_state["binding_cleared"] and replacement_state["verification_status"] != "succeeded":
            return True
        result = self._load_stage_item_result_payload(item)
        sync_observation = dict(result.get("sync_observation") or {})
        stale_child_task_id = str(sync_observation.get("old_downstream_task_id") or sync_observation.get("superseded_downstream_task_id") or "").strip()
        return bool(stale_child_task_id)

    async def _cleanup_downstream_refs(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        refs: list[dict[str, str]],
        token: str | None,
    ) -> None:
        if not refs:
            return
        await self._cancel_downstream_refs(db, task, refs, token)
        await self._ensure_downstream_refs_inactive(db, task, refs, token)
        await self._delete_downstream_refs(db, task, refs, token)

    def _trigger_entry_items_from_b2s_result(
        self,
        db: Session,
        task: BinarySecurityTask,
        b2s_result: dict[str, Any],
        *,
        upstream_item: BinarySecurityStageItem,
    ) -> BinarySecurityStageItem | None:
        if not self._streaming_mode_enabled(task):
            return None
        if "entry_analysis" not in self._streaming_tail_stage_names(task):
            return None
        module_key = str(b2s_result.get("module_key") or "").strip()
        if not module_key:
            return None
        normalized_input = self._normalize_entry_analysis_module_input(
            task,
            {
                **b2s_result,
                "upstream_item_id": upstream_item.id,
                "triggered_by_stage": upstream_item.stage_name,
            },
        )
        normalized_input["execution_fingerprint"] = self._entry_analysis_execution_fingerprint(normalized_input)
        existing = self._find_stage_item(
            db,
            task_id=task.id,
            stage_name="entry_analysis",
            item_key=module_key,
            parent_key=str(b2s_result.get("firmware_key") or "").strip() or None,
        )
        previous_fingerprint = None
        current_fingerprint = str(normalized_input.get("execution_fingerprint") or "").strip() or None
        should_reopen_stage_run = True
        if existing is not None:
            previous_fingerprint = str(
                dict(existing.input_ref or {}).get("execution_fingerprint")
                or self._load_stage_item_result_payload(existing).get("execution_fingerprint")
                or self._entry_analysis_execution_fingerprint(existing.input_ref or {})
            ).strip() or None
            should_reopen_stage_run = not (previous_fingerprint and current_fingerprint and previous_fingerprint == current_fingerprint)
        stage_run = self._streaming_stage_run_for_seed(
            db,
            task,
            "entry_analysis",
            reason="streaming_entry_item_materialization",
            reopen_terminal=should_reopen_stage_run,
        )
        if existing is None:
            item = self._upsert_stage_item(
                db,
                task=task,
                stage_run=stage_run,
                stage_name="entry_analysis",
                item_key=module_key,
                item_name=str(normalized_input.get("module_name") or b2s_result.get("module_name") or "").strip() or None,
                parent_key=str(b2s_result.get("firmware_key") or "").strip() or None,
                downstream_service="entry_analyse",
                input_ref=normalized_input,
                output_ref={},
                retrying=False,
                running_status="pending",
            )
            result = self._load_stage_item_result_payload(item)
            result["execution_fingerprint"] = normalized_input["execution_fingerprint"]
            item.result = result
        else:
            if previous_fingerprint and current_fingerprint and previous_fingerprint == current_fingerprint:
                item = self._update_stage_item_metadata_only(
                    existing,
                    item_name=str(normalized_input.get("module_name") or b2s_result.get("module_name") or "").strip() or None,
                    input_ref=normalized_input,
                    output_ref=dict(existing.output_ref or {}),
                )
                self._record_event(
                    db,
                    task,
                    "streaming_entry_item_metadata_refreshed",
                    f"binary-to-source 刷新未改变入口分析执行契约，已仅更新元数据: {module_key}",
                    stage_name="entry_analysis",
                    item=item,
                    payload={
                        "upstream_item_id": upstream_item.id,
                        "module_key": module_key,
                        "refresh_mode": "metadata_only",
                        "execution_fingerprint": current_fingerprint,
                    },
                )
            else:
                item = self._update_stage_item_metadata_only(
                    existing,
                    item_name=str(normalized_input.get("module_name") or b2s_result.get("module_name") or "").strip() or None,
                    input_ref=normalized_input,
                    output_ref=dict(existing.output_ref or {}),
                )
                changed_fields = self._payload_changed_fields(
                    self._entry_analysis_execution_fingerprint_payload(existing.input_ref or {}),
                    self._entry_analysis_execution_fingerprint_payload(normalized_input),
                )
                self._record_event(
                    db,
                    task,
                    "entry_analysis_execution_signature_changed",
                    f"binary-to-source 刷新改变了入口分析执行契约，已准备定点重建: {module_key}",
                    stage_name="entry_analysis",
                    item=item,
                    level="warning",
                    payload={
                        "upstream_item_id": upstream_item.id,
                        "module_key": module_key,
                        "item_id": item.id,
                        "old_execution_fingerprint": previous_fingerprint,
                        "new_execution_fingerprint": current_fingerprint,
                        "changed_fields": changed_fields,
                    },
                )
                self._prepare_entry_analysis_stage_item_for_signature_change(db, task, item)
        self._record_event(
            db,
            task,
            "streaming_entry_item_seeded" if existing is None else "streaming_entry_item_refreshed",
            (
                f"binary-to-source 成功后已创建入口分析待执行条目: {module_key}"
                if existing is None
                else f"binary-to-source 成功后已刷新入口分析待执行条目: {module_key}"
            ),
            stage_name="entry_analysis",
            item=item,
            payload={
                "upstream_item_id": upstream_item.id,
                "module_key": module_key,
                "pipeline_mode": self._pipeline_mode(task),
            },
        )
        return item

    def _trigger_dataflow_items_from_entry_result(
        self,
        db: Session,
        task: BinarySecurityTask,
        entry_result: dict[str, Any],
        *,
        upstream_item: BinarySecurityStageItem,
    ) -> list[BinarySecurityStageItem]:
        if not self._streaming_mode_enabled(task):
            return []
        if "dataflow_vuln_scan" not in self._streaming_tail_stage_names(task):
            return []
        if self._entry_selection_mode(task) == task_manager_module.ENTRY_SELECTION_MODE_MANUAL_CONFIRM:
            return []
        entries = task_manager_module._deduplicate_entry_keys(
            [dict(entry) for entry in (entry_result.get("entries") or []) if isinstance(entry, dict)]
        )
        if not entries:
            return []
        created_items: list[BinarySecurityStageItem] = []
        created_count = 0
        refreshed_count = 0
        metadata_only_count = 0
        recreate_count = 0
        materialized_any_work = False
        stage_run: BinarySecurityStageRun | None = None
        for entry in entries:
            entry_key = str(entry.get("entry_key") or "").strip()
            if not entry_key:
                continue
            existing = self._find_stage_item(
                db,
                task_id=task.id,
                stage_name="dataflow_vuln_scan",
                item_key=entry_key,
                parent_key=str(entry.get("module_key") or "").strip() or None,
            )
            merged_entry = {
                **self._entry_contract_fields(existing.input_ref if existing else None),
                **self._entry_contract_fields(upstream_item.result if isinstance(upstream_item.result, dict) else None),
                **self._entry_contract_fields(entry_result),
                **entry,
            }
            normalized_entry = {
                **merged_entry,
                "upstream_item_id": upstream_item.id,
                "triggered_by_stage": upstream_item.stage_name,
            }
            normalized_entry = self._decorate_dataflow_entry_with_execution_fingerprint(normalized_entry)
            if existing is None:
                if stage_run is None:
                    stage_run = self._streaming_stage_run_for_seed(
                        db,
                        task,
                        "dataflow_vuln_scan",
                        reason="streaming_dataflow_item_materialization",
                        reopen_terminal=True,
                    )
                item = self._upsert_stage_item(
                    db,
                    task=task,
                    stage_run=stage_run,
                    stage_name="dataflow_vuln_scan",
                    item_key=entry_key,
                    item_name=str(entry.get("function_name") or "").strip() or None,
                    parent_key=str(entry.get("module_key") or "").strip() or None,
                    downstream_service="dataflow_vuln_scan",
                    input_ref=normalized_entry,
                    output_ref={},
                    retrying=False,
                    running_status="pending",
                )
                result = self._load_stage_item_result_payload(item)
                result["execution_fingerprint"] = normalized_entry["execution_fingerprint"]
                item.result = result
                created_count += 1
                materialized_any_work = True
            else:
                previous_entry = dict(existing.input_ref or {})
                previous_fingerprint = self._dataflow_item_execution_fingerprint(existing)
                current_fingerprint = str(normalized_entry.get("execution_fingerprint") or "").strip() or None
                if previous_fingerprint and current_fingerprint and previous_fingerprint == current_fingerprint:
                    item = self._update_stage_item_metadata_only(
                        existing,
                        item_name=str(entry.get("function_name") or "").strip() or None,
                        input_ref=normalized_entry,
                        output_ref=dict(existing.output_ref or {}),
                    )
                    metadata_only_count += 1
                    self._record_event(
                        db,
                        task,
                        "streaming_dataflow_item_metadata_refreshed",
                        f"入口刷新未改变 DFVS 执行契约，已仅更新展示元数据: {entry_key}",
                        stage_name="dataflow_vuln_scan",
                        item=item,
                        payload={
                            "upstream_item_id": upstream_item.id,
                            "entry_key": entry_key,
                            "refresh_mode": "metadata_only",
                            "execution_fingerprint": current_fingerprint,
                        },
                    )
                else:
                    if stage_run is None:
                        stage_run = self._streaming_stage_run_for_seed(
                            db,
                            task,
                            "dataflow_vuln_scan",
                            reason="streaming_dataflow_item_materialization",
                            reopen_terminal=True,
                        )
                    item = self._update_stage_item_metadata_only(
                        existing,
                        item_name=str(entry.get("function_name") or "").strip() or None,
                        input_ref=normalized_entry,
                        output_ref=dict(existing.output_ref or {}),
                    )
                    changed_fields = self._dataflow_entry_execution_changed_fields(previous_entry, normalized_entry)
                    self._record_event(
                        db,
                        task,
                        "dataflow_entry_execution_signature_changed",
                        f"入口刷新改变了 DFVS 执行契约，已准备定点重建: {entry_key}",
                        stage_name="dataflow_vuln_scan",
                        item=item,
                        level="warning",
                        payload={
                            "upstream_item_id": upstream_item.id,
                            "entry_key": entry_key,
                            "item_id": item.id,
                            "old_execution_fingerprint": previous_fingerprint,
                            "new_execution_fingerprint": current_fingerprint,
                            "changed_fields": changed_fields,
                        },
                    )
                    self._prepare_dataflow_stage_item_for_signature_change(
                        db,
                        task,
                        item,
                    )
                    recreate_count += 1
                    materialized_any_work = True
            created_items.append(item)
            if existing is not None:
                refreshed_count += 1
        if stage_run is None and created_items and not materialized_any_work:
            stage_run = self._streaming_stage_run_for_seed(
                db,
                task,
                "dataflow_vuln_scan",
                reason="streaming_dataflow_item_materialization",
                reopen_terminal=False,
            )
        if created_items:
            self._record_event(
                db,
                task,
                "streaming_dataflow_vuln_scan_items_seeded",
                (
                    "入口分析成功后已生成数据流漏洞挖掘待执行条目: "
                    f"新增 {created_count}，刷新 {refreshed_count}，仅元数据更新 {metadata_only_count}，定点重建 {recreate_count}"
                ),
                stage_name="dataflow_vuln_scan",
                item=upstream_item,
                payload={
                    "upstream_item_id": upstream_item.id,
                    "created_count": created_count,
                    "refreshed_count": refreshed_count,
                    "metadata_only_count": metadata_only_count,
                    "recreate_count": recreate_count,
                    "entry_count": len(created_items),
                    "pipeline_mode": self._pipeline_mode(task),
                },
            )
        return created_items

    def _trigger_vuln_items_from_dataflow_result_legacy(
        self,
        db: Session,
        task: BinarySecurityTask,
        dataflow_result: dict[str, Any],
        *,
        upstream_item: BinarySecurityStageItem,
    ) -> BinarySecurityStageItem | None:
        if not self._streaming_mode_enabled(task):
            return None
        if "dataflow_vuln_scan" not in self._streaming_tail_stage_names(task):
            return None
        entry_key = str(dataflow_result.get("entry_key") or "").strip()
        if not entry_key:
            return None
        normalized_result = {
            **dataflow_result,
            "upstream_item_id": upstream_item.id,
            "triggered_by_stage": upstream_item.stage_name,
        }
        normalized_result["execution_fingerprint"] = self._legacy_vuln_execution_fingerprint(normalized_result)
        existing = self._find_stage_item(
            db,
            task_id=task.id,
            stage_name="dataflow_vuln_scan",
            item_key=entry_key,
            parent_key=str(dataflow_result.get("module_key") or "").strip() or None,
        )
        previous_fingerprint = self._dataflow_item_execution_fingerprint(existing) if existing is not None else None
        current_fingerprint = str(normalized_result.get("execution_fingerprint") or "").strip() or None
        if existing is None:
            stage_run = self._streaming_stage_run_for_seed(
                db,
                task,
                "dataflow_vuln_scan",
                reason="streaming_vuln_item_materialization",
                reopen_terminal=True,
            )
            item = self._upsert_stage_item(
                db,
                task=task,
                stage_run=stage_run,
                stage_name="dataflow_vuln_scan",
                item_key=entry_key,
                item_name=str(dataflow_result.get("function_name") or "").strip() or None,
                parent_key=str(dataflow_result.get("module_key") or "").strip() or None,
                downstream_service="dataflow_vuln_scan",
                input_ref=normalized_result,
                output_ref={},
                retrying=False,
                running_status="pending",
            )
            result = self._load_stage_item_result_payload(item)
            result["execution_fingerprint"] = normalized_result["execution_fingerprint"]
            item.result = result
        else:
            if previous_fingerprint and current_fingerprint and previous_fingerprint == current_fingerprint:
                item = self._update_stage_item_metadata_only(
                    existing,
                    item_name=str(dataflow_result.get("function_name") or "").strip() or None,
                    input_ref=normalized_result,
                    output_ref=dict(existing.output_ref or {}),
                )
                self._record_event(
                    db,
                    task,
                    "streaming_vuln_item_metadata_refreshed",
                    f"历史兼容路径刷新未改变 DFVS 执行契约，已仅更新元数据: {entry_key}",
                    stage_name="dataflow_vuln_scan",
                    item=item,
                    payload={
                        "upstream_item_id": upstream_item.id,
                        "entry_key": entry_key,
                        "refresh_mode": "metadata_only",
                        "execution_fingerprint": current_fingerprint,
                    },
                )
            else:
                stage_run = self._streaming_stage_run_for_seed(
                    db,
                    task,
                    "dataflow_vuln_scan",
                    reason="streaming_vuln_item_materialization",
                    reopen_terminal=True,
                )
                item = self._update_stage_item_metadata_only(
                    existing,
                    item_name=str(dataflow_result.get("function_name") or "").strip() or None,
                    input_ref=normalized_result,
                    output_ref=dict(existing.output_ref or {}),
                )
                changed_fields = self._payload_changed_fields(
                    self._legacy_vuln_execution_fingerprint_payload(existing.input_ref or {}),
                    self._legacy_vuln_execution_fingerprint_payload(normalized_result),
                )
                self._record_event(
                    db,
                    task,
                    "legacy_vuln_execution_signature_changed",
                    f"历史兼容路径改变了 DFVS 执行契约，已准备定点重建: {entry_key}",
                    stage_name="dataflow_vuln_scan",
                    item=item,
                    level="warning",
                    payload={
                        "upstream_item_id": upstream_item.id,
                        "entry_key": entry_key,
                        "item_id": item.id,
                        "old_execution_fingerprint": previous_fingerprint,
                        "new_execution_fingerprint": current_fingerprint,
                        "changed_fields": changed_fields,
                    },
                )
                self._prepare_dataflow_stage_item_for_signature_change(db, task, item)
        self._record_event(
            db,
            task,
            "streaming_vuln_item_seeded" if existing is None else "streaming_vuln_item_refreshed",
            (
                f"历史兼容路径：已创建数据流漏洞挖掘待执行条目: {entry_key}"
                if existing is None
                else f"历史兼容路径：已刷新数据流漏洞挖掘待执行条目: {entry_key}"
            ),
            stage_name="dataflow_vuln_scan",
            item=item,
            payload={
                "upstream_item_id": upstream_item.id,
                "entry_key": entry_key,
                "pipeline_mode": self._pipeline_mode(task),
            },
        )
        self._refresh_stage_from_authoritative_items(db, task, "dataflow_vuln_scan")
        return item

    def _trigger_vuln_items_from_dataflow_result(
        self,
        db: Session,
        task: BinarySecurityTask,
        dataflow_result: dict[str, Any],
        *,
        upstream_item: BinarySecurityStageItem,
    ) -> BinarySecurityStageItem | None:
        return self._trigger_vuln_items_from_dataflow_result_legacy(
            db,
            task,
            dataflow_result,
            upstream_item=upstream_item,
        )

    def _prepare_stage_items_for_execution(
        self,
        db: Session,
        *,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        inputs: list[dict[str, Any]],
        downstream_service: str,
        identity,
        output_ref,
    ) -> list[dict[str, Any]]:
        """Persist every intended stage item as queued before fan-out execution starts."""
        retry_plan = self._retry_plan(task)
        retry_item_keys = set(retry_plan.get("retry_item_keys") or [])
        target_stage = str(retry_plan.get("target_stage") or "").strip()
        retry_failed_only = (
            stage_run.stage_name == target_stage
            and str(retry_plan.get("mode") or "").strip() in {task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS, task_manager_module.TASK_ACTION_RETRY_STAGE_FAILED_ITEMS}
            and bool(retry_item_keys)
        )
        candidate_inputs: list[tuple[dict[str, Any], str, str | None, str | None, dict[str, Any], str]] = []
        for input_item in inputs:
            item_key, item_name, parent_key, input_ref = identity(input_item)
            if not str(item_key or "").strip():
                raise ValidationError(f"阶段 {stage_run.stage_name} 初始化阶段子任务失败: item_key 为空")
            identity_key = build_stage_item_identity_key(item_key, parent_key)
            if retry_failed_only and identity_key not in retry_item_keys:
                continue
            candidate_inputs.append((input_item, item_key, item_name, parent_key, input_ref, identity_key))
        executable_inputs = [row[0] for row in candidate_inputs]
        if not candidate_inputs:
            return executable_inputs
        existing_items_by_identity: dict[str, BinarySecurityStageItem] = {}
        for existing_item in self._stage_items(db, task.id, stage_run.stage_name):
            identity_key = str(existing_item.item_identity_key or "").strip() or build_stage_item_identity_key(
                str(existing_item.item_key or "").strip(),
                existing_item.parent_key,
            )
            if identity_key:
                existing_items_by_identity[identity_key] = existing_item
        processed_identities = set(existing_items_by_identity.keys())

        def _should_requeue_existing_streaming_item(existing_item: BinarySecurityStageItem) -> bool:
            if not self._streaming_mode_enabled(task):
                return False
            if not self._is_streaming_tail_stage(task, stage_run.stage_name):
                return False
            if self._task_runtime_phase(task) != task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION:
                return False
            if normalize_stage_name(task.current_stage) != normalize_stage_name(stage_run.stage_name):
                return False
            if self._task_is_waiting_for_manual_confirmation(task):
                return False
            normalized_status = str(existing_item.status or "").strip().lower()
            if normalized_status not in {"failed", "cancelled", "downstream_missing"}:
                return False
            claim_token = str(getattr(existing_item, "claim_execution_token", "") or "").strip() or None
            claim_owner = str(getattr(existing_item, "claim_owner_instance_id", "") or "").strip() or None
            current_token = self._dispatch_token(task)
            if claim_token and claim_token == current_token:
                return False
            if claim_owner and claim_owner == str(self.instance_id or "").strip() and claim_token == current_token:
                return False
            return True

        for identity_key, existing_item in existing_items_by_identity.items():
            if not _should_requeue_existing_streaming_item(existing_item):
                continue
            previous_status = str(existing_item.status or "").strip().lower() or None
            previous_downstream_task_id = str(existing_item.downstream_task_id or "").strip() or None
            observed_at = task_manager_module._now()
            existing_result = self._load_stage_item_result_payload(existing_item)
            sync_observation = dict(existing_result.get("sync_observation") or {})
            sync_observation.update(
                {
                    "sync_status": "recovered_for_redispatch",
                    "last_result": "recovered_for_redispatch",
                    "recovery_reason": "downstream_missing_requeue",
                    "last_missing_child_task_id": previous_downstream_task_id,
                    "last_missing_detected_at": observed_at.isoformat(),
                    "budget_exhausted": False,
                }
            )
            sync_observation.pop("next_retry_at", None)
            existing_result.update(
                {
                    "sync_observation": sync_observation,
                    "last_sync_result": "recovered_for_redispatch",
                    "sync_error_budget_exhausted": False,
                    "next_sync_retry_at": None,
                    "recovery_reason": "downstream_missing_requeue",
                    "last_missing_child_task_id": previous_downstream_task_id,
                    "last_missing_detected_at": observed_at.isoformat(),
                }
            )
            existing_item.stage_run_id = stage_run.id
            existing_item.status = "queued"
            existing_item.downstream_task_id = None
            existing_item.error_message = previous_status == "downstream_missing" and existing_item.error_message or None
            existing_item.finished_at = None
            existing_item.updated_at = observed_at
            self._clear_stage_item_claim(existing_item)
            self._persist_stage_item_result(
                task,
                existing_item,
                stage_name=stage_run.stage_name,
                result=existing_result,
            )
            self._record_event(
                db,
                task,
                "streaming_stage_item_requeued_after_downstream_missing",
                "当前执行实例已接管流式阶段，异常下游子任务已回退到 queued 等待重新派发",
                level="warning",
                stage_name=stage_run.stage_name,
                item=existing_item,
                payload={
                    "before_status": previous_status,
                    "after_status": "queued",
                    "downstream_task_id": previous_downstream_task_id,
                    "task_runtime_phase": self._task_runtime_phase(task),
                    "dispatcher_instance_id": task.dispatcher_instance_id,
                    "task_execution_token": self._dispatch_token(task),
                    "recovery_action": "requeued_pending",
                },
            )

        batch_size = min(100, max(25, int(task.policy.get("stage_item_seed_batch_size") or 100)))
        last_error: Exception | None = None
        max_attempts = self._retryable_write_attempts()
        for attempt in range(max_attempts):
            try:
                for offset in range(0, len(candidate_inputs), batch_size):
                    batch = candidate_inputs[offset : offset + batch_size]
                    for input_item, item_key, item_name, parent_key, input_ref, identity_key in batch:
                        if identity_key in processed_identities:
                            continue
                        item = existing_items_by_identity.get(identity_key)
                        if item is None:
                            item = self._find_stage_item(
                                db,
                                task_id=task.id,
                                stage_name=stage_run.stage_name,
                                item_key=item_key,
                                parent_key=parent_key,
                            )
                            if item is not None:
                                existing_items_by_identity[identity_key] = item
                                processed_identities.add(identity_key)
                        if item is None:
                            item = BinarySecurityStageItem(
                                id=f"si_{uuid.uuid4().hex[:20]}",
                                task_id=task.id,
                                project_id=task.project_id,
                                stage_run_id=stage_run.id,
                                stage_name=stage_run.stage_name,
                                item_key=item_key,
                                item_name=item_name,
                                parent_key=parent_key,
                                item_identity_key=identity_key,
                                status="queued",
                                downstream_service=downstream_service,
                            )
                            self._clear_stage_item_claim(item)
                            db.add(item)
                            if hasattr(db, "stage_items") and isinstance(getattr(db, "stage_items"), list):
                                stage_items_list = getattr(db, "stage_items")
                                if len(stage_items_list) >= 2 and stage_items_list[-1] is item and stage_items_list[-2] is item:
                                    stage_items_list.pop()
                            existing_items_by_identity[identity_key] = item
                            processed_identities.add(identity_key)
                        else:
                            item.stage_run_id = stage_run.id
                            item.item_name = item_name
                            item.parent_key = parent_key
                            item.item_identity_key = identity_key
                            item.status = "queued"
                            self._clear_stage_item_claim(item)
                            item.downstream_service = downstream_service
                            self._reset_child_runtime_payload(
                                item,
                                payload={},
                                keep_error=False,
                                reset_started_at=True,
                                reset_finished_at=True,
                            )
                        item.input_ref = input_ref
                        item.output_ref = output_ref(input_item)
                    db.commit()
                return executable_inputs
            except IntegrityError as exc:
                db.rollback()
                last_error = exc
                continue
            except OperationalError as exc:
                db.rollback()
                last_error = exc
                if not self._is_retryable_lock_error(exc) or attempt >= max_attempts - 1:
                    break
                self._sleep_after_retryable_lock_error(attempt + 1)
        raise last_error or ValidationError(f"阶段 {stage_run.stage_name} 初始化阶段子任务失败")

    def _invoke_existing_downstream_retry(
        self,
        stage_name: str,
        *,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        token: str | None,
    ):
        return self._downstream_tasks().invoke_retry_or_restart(
            stage_name=stage_name,
            task=task,
            item=item,
            token=token,
        )

    @staticmethod
    def _extract_downstream_error_text(exc: Exception) -> str:
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
    def _is_already_running_control_conflict(message: str) -> bool:
        normalized = re.sub(r"\s+", "", str(message or "").lower())
        if not normalized:
            return False
        running_tokens = (
            "仍在运行",
            "运行中",
            "已经在运行",
            "active",
            "alreadyrunning",
            "currentlyrunning",
            "stillrunning",
        )
        control_tokens = (
            "重启",
            "重试",
            "restart",
            "retry",
            "rerun",
            "cancel",
            "取消后再",
            "先取消",
        )
        return any(token in normalized for token in running_tokens) and any(token in normalized for token in control_tokens)

    async def _control_existing_downstream_task(
        self,
        stage_name: str,
        *,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        token: str | None,
    ) -> dict[str, Any]:
        normalized_status = str(item.status or "").strip().lower()
        if str(item.downstream_task_id or "").strip():
            if normalized_status in {"running", "dispatching", "failed", "cancelled"}:
                try:
                    payload = await self._fetch_downstream_task_payload(task, item, token or "")
                except Exception:
                    payload = None
                mapped = self._map_downstream_status(str((payload or {}).get("status") or ""))
                if payload and mapped == "running":
                    return {"outcome": "already_running", "payload": payload}
                if normalized_status in {"running", "dispatching"} and payload and mapped == "pending":
                    return {"outcome": "already_running", "payload": payload}
                if (
                    normalize_stage_name(stage_name) == "dataflow_vuln_scan"
                    and normalized_status in {"failed", "cancelled", "downstream_missing"}
                    and (payload is None or mapped in {None, "success", "partial_success", "failed", "cancelled", "downstream_missing"})
                ):
                    return {
                        "outcome": "already_terminal",
                        "payload": payload or {
                            "task_id": str(item.downstream_task_id or "").strip(),
                            "status": mapped or normalized_status,
                        },
                        "retry_outcome": "already_terminal",
                    }
            if normalized_status not in {"running", "dispatching"}:
                if normalize_stage_name(stage_name) == "dataflow_vuln_scan" and normalized_status in {"failed", "cancelled", "downstream_missing"}:
                    return {
                        "outcome": "already_terminal",
                        "payload": {
                            "task_id": str(item.downstream_task_id or "").strip(),
                            "status": normalized_status,
                        },
                        "retry_outcome": "already_terminal",
                    }
                try:
                    payload = await self._invoke_existing_downstream_retry(
                        stage_name,
                        task=task,
                        item=item,
                        token=token,
                    )
                    return {"outcome": "accepted", "payload": payload}
                except ValidationError as exc:
                    message = self._extract_downstream_error_text(exc) or str(exc)
                    if self._is_already_running_control_conflict(message):
                        try:
                            active_payload = await self._fetch_downstream_task_payload(task, item, token or "")
                        except Exception:
                            active_payload = None
                        mapped = self._map_downstream_status(str((active_payload or {}).get("status") or ""))
                        if active_payload and mapped == "running":
                            return {"outcome": "already_running", "payload": active_payload}
                    return {
                        "outcome": "invalid_transition",
                        "retry_outcome": "invalid_transition",
                        "error_message": message,
                        "http_status": self._extract_http_status_from_exception(exc),
                    }
                except UpstreamError as exc:
                    return {
                        "outcome": "transport_error",
                        "retry_outcome": "transport_error",
                        "error_message": self._extract_downstream_error_text(exc) or str(exc),
                        "http_status": self._extract_http_status_from_exception(exc),
                    }
        try:
            return await self._downstream_tasks().control_existing_child(
                None,
                stage_name=stage_name,
                task=task,
                item=item,
                token=token,
            )
        except UpstreamError as exc:
            return {
                "outcome": "transport_error",
                "retry_outcome": "transport_error",
                "error_message": self._extract_downstream_error_text(exc) or str(exc),
                "http_status": self._extract_http_status_from_exception(exc),
            }

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
        stage_name = str(task_manager_module._stage_item_attr(item, "stage_name") or "").strip() or None
        sync_payload = {
            "event_type": event_type,
            "message": message,
            "level": level,
            "downstream_service": task_manager_module._stage_item_attr(item, "downstream_service"),
            "downstream_task_id": task_manager_module._stage_item_attr(item, "downstream_task_id"),
            **(payload or {}),
        }
        operation = str(sync_payload.get("operation") or "downstream_sync").strip() or "downstream_sync"
        audit_event_type = str(sync_payload.get("audit_event_type") or event_type or "observed").strip() or "observed"
        audit_outcome = self._string_or_none(sync_payload.get("outcome"))
        audit_sync_status = self._string_or_none(sync_payload.get("sync_status")) or audit_outcome
        state_applied = sync_payload.get("state_applied")
        if audit_event_type in {"downstream_child_created", "retry_item_new_child_created"}:
            operation = "downstream_create"
            audit_event_type = "applied"
            audit_outcome = audit_outcome or "success"
            audit_sync_status = audit_sync_status or "observed"
            state_applied = True if state_applied is None else state_applied
        elif audit_event_type in {"downstream_retry_accepted", "downstream_retry_attached"}:
            operation = "retry_control"
            audit_event_type = "adopted"
            audit_outcome = audit_outcome or "success"
            audit_sync_status = audit_sync_status or "observed"
        elif audit_event_type in {"downstream_retry_terminal_reused"}:
            operation = "retry_control"
            audit_event_type = "observed"
            audit_outcome = audit_outcome or "success"
            audit_sync_status = audit_sync_status or "observed"
        elif audit_event_type in {"downstream_retry_fallback_recreated"}:
            operation = "retry_control"
            audit_event_type = "recreated"
            audit_outcome = audit_outcome or "success"
            audit_sync_status = audit_sync_status or "observed"
        elif audit_event_type in {"downstream_retry_target_missing"}:
            operation = "retry_control"
            audit_event_type = "failed"
            audit_outcome = audit_outcome or "missing_downstream_binding"
            audit_sync_status = audit_sync_status or "downstream_missing"
        elif audit_event_type in {"downstream_retry_deferred"}:
            operation = "retry_control"
            audit_event_type = "retry_scheduled"
            audit_outcome = audit_outcome or "error"
            audit_sync_status = audit_sync_status or "transport_error"
        self._record_event(
            db,
            task,
            event_type,
            message,
            level=level,
            stage_name=stage_name,
            item=item,
            payload=sync_payload,
        )
        if hasattr(self, "_record_downstream_sync_event"):
            try:
                self._record_stage_item_sync_audit(
                    db,
                    task=task,
                    item=item,
                    stage_name=stage_name,
                    downstream_service=self._string_or_none(sync_payload.get("downstream_service")),
                    operation=operation,
                    event_type=audit_event_type,
                    sync_status=audit_sync_status,
                    outcome=audit_outcome,
                    state_applied=state_applied,
                    error_type=self._string_or_none(sync_payload.get("error_type")),
                    error_message=self._string_or_none(sync_payload.get("error_message")) or message,
                    http_status=sync_payload.get("http_status"),
                    payload=sync_payload,
                )
            except Exception:
                pass

    def _record_downstream_control_outcome(
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
            "outcome": outcome,
            "http_status": control.get("http_status"),
            "error": control.get("error_message"),
            "payload": control.get("payload"),
        }
        if outcome == "accepted":
            self._record_downstream_item_disposition(
                db,
                task,
                item,
                event_type="downstream_retry_accepted",
                message=f"已请求下游重试并接管子任务: {item.downstream_service}:{item.downstream_task_id or '-'}",
                payload=payload,
            )
            return
        if outcome == "already_running":
            self._record_downstream_item_disposition(
                db,
                task,
                item,
                event_type="downstream_retry_attached",
                message=f"复用已在运行的下游子任务: {item.downstream_service}:{item.downstream_task_id or '-'}",
                payload=payload,
            )
            return
        if outcome == "already_terminal":
            self._record_downstream_item_disposition(
                db,
                task,
                item,
                event_type="downstream_retry_terminal_reused",
                message=f"复用已终态的下游子任务结果: {item.downstream_service}:{item.downstream_task_id or '-'}",
                payload=payload,
            )
            return
        if outcome == "not_found":
            self._record_downstream_item_disposition(
                db,
                task,
                item,
                event_type="downstream_retry_target_missing",
                message=f"下游重试目标不存在: {item.downstream_service}:{item.downstream_task_id or '-'}",
                level="warning",
                payload=payload,
            )
            return
        if outcome == "transport_error":
            self._record_downstream_item_disposition(
                db,
                task,
                item,
                event_type="downstream_retry_deferred",
                message=f"下游重试通信异常，保留当前子任务等待后续自动对账: {item.downstream_service}:{item.downstream_task_id or '-'}",
                level="warning",
                payload=payload,
            )
            return
        self._record_downstream_item_disposition(
            db,
            task,
            item,
            event_type="downstream_retry_rejected" if outcome == "invalid_transition" else "downstream_retry_failed",
            message=f"下游重试未被接受: {item.downstream_service}:{item.downstream_task_id or '-'}",
            level="warning",
            payload=payload,
        )

    def _defer_item_after_downstream_transport_error(
        self,
        session: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        operation: str,
        exc: Exception,
        response_item: dict[str, Any],
    ) -> dict[str, Any]:
        has_downstream_ref = bool(str(item.downstream_task_id or "").strip())
        if normalize_stage_name(item.stage_name) == "dataflow_vuln_scan" and not has_downstream_ref:
            self._mark_downstream_binding_retry(
                item,
                error_message=str(exc),
                error_type=self._classify_downstream_sync_error(exc),
                recoverable=True,
            )
        replacement_state = self._replacement_in_progress_state(item)
        deferred_mode = "reconcile" if has_downstream_ref else "redispatch"
        if replacement_state["replacement_in_progress"] and replacement_state["binding_cleared"] and not has_downstream_ref:
            deferred_status = "queued"
        else:
            deferred_status = "running" if has_downstream_ref else "queued"
        http_status = self._extract_http_status_from_exception(exc)
        is_http_429 = http_status == 429
        error_type = self._classify_downstream_sync_error(exc)
        state = self._build_next_http_429_failure_state(item) if is_http_429 else self._build_next_downstream_sync_failure_state(item)
        sync_status = "rate_limited" if is_http_429 else "transport_error"
        child_event_type = "downstream_http_429_retry_scheduled" if is_http_429 else "downstream_poll_retry_scheduled"
        child_change_source = "rate_limited" if is_http_429 else "transport_error"
        disposition_event_type = "downstream_http_429_retry_scheduled" if is_http_429 else "downstream_transport_deferred"
        disposition_message = (
            f"下游返回 429，智能体将在 {self._next_http_429_retry_backoff_seconds(state.consecutive_error_count)} 秒后重试"
            if is_http_429
            else (
                "下游通信异常，保留当前子任务等待后续自动对账"
                if has_downstream_ref
                else "下游通信异常，保留当前子任务等待重新调度创建"
            )
        )
        self._apply_child_task_status_change(
            session,
            task=task,
            item=item,
            change_source=child_change_source,
            after_status=deferred_status,
            sync_status=sync_status,
            downstream_status_raw=None,
            downstream_status_mapped=deferred_status,
            downstream_status=None,
            state_applied=False,
            error_message=str(exc),
            error_type=error_type,
            http_status=http_status,
            event_type=child_event_type,
            extra_payload={
                "operation": operation,
                "deferred_mode": deferred_mode,
                "retry_attempt_count": state.consecutive_error_count,
                "retry_delay_seconds": None if state.next_retry_at is None else self._next_http_429_retry_backoff_seconds(state.consecutive_error_count) if is_http_429 else self._next_stage_sync_retry_backoff_seconds(state.consecutive_error_count),
                "rate_limited": is_http_429,
            },
        )
        self._mark_stage_item_sync_observation(
            item,
            sync_status=sync_status,
            synced_at=task_manager_module._now(),
            error_message=str(exc),
            http_status=http_status,
            error_type=error_type,
            state_applied=False,
            consecutive_error_count=state.consecutive_error_count,
            budget_exhausted=state.budget_exhausted,
            next_retry_at=state.next_retry_at,
            last_sync_result="error",
        )
        if replacement_state["replacement_in_progress"]:
            self._mark_replacement_in_progress(
                item,
                old_downstream_task_id=replacement_state["old_downstream_task_id"],
                binding_cleared=replacement_state["binding_cleared"],
                verification_status=replacement_state["verification_status"] or "pending",
            )
        session.commit()
        self._record_downstream_item_disposition(
            session,
            task,
            item,
            event_type=disposition_event_type,
            message=disposition_message,
            level="warning",
            payload={
                "operation": operation,
                "error": str(exc),
                "http_status": http_status,
                "error_type": error_type,
                "error_type_detail": getattr(exc, "error_type_detail", None) or getattr(exc, "transport_error_kind", None),
                "transport_error_kind": getattr(exc, "transport_error_kind", None) or getattr(exc, "error_type_detail", None),
                "retry_attempted": bool(getattr(exc, "retry_attempted", False)),
                "client_recreated": bool(getattr(exc, "client_recreated", False)),
                "state_applied": False,
                "deferred_mode": deferred_mode,
                "item_status": item.status,
                "consecutive_sync_error_count": state.consecutive_error_count,
                "next_sync_retry_at": task_manager_module._isoformat_or_none(state.next_retry_at),
                "sync_error_budget_exhausted": state.budget_exhausted,
                "retry_attempt_count": state.consecutive_error_count,
                "retry_delay_seconds": self._next_http_429_retry_backoff_seconds(state.consecutive_error_count) if is_http_429 else self._next_stage_sync_retry_backoff_seconds(state.consecutive_error_count),
                "binding_state": self._downstream_binding_state(item),
                "binding_attempts": self._downstream_binding_attempts(item),
                "binding_next_retry_at": task_manager_module._isoformat_or_none(self._downstream_binding_time(item, "next_retry_at")),
            },
        )
        session.commit()
        return {
            "status": "running" if has_downstream_ref else "pending",
            "error": str(exc),
            "item": response_item,
            "deferred_mode": deferred_mode,
            "sync_degraded": True,
        }

    def _defer_item_after_orchestration_error(
        self,
        session: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        operation: str,
        exc: Exception,
        response_item: dict[str, Any],
        has_downstream_ref: bool | None = None,
    ) -> dict[str, Any]:
        if has_downstream_ref is None:
            has_downstream_ref = bool(str(item.downstream_task_id or "").strip())
        state = self._build_next_stage_item_orchestration_failure_state(item)
        deferred_mode = "reconcile" if has_downstream_ref else "redispatch"
        deferred_status = "running" if has_downstream_ref else "queued"
        item.status = deferred_status
        item.error_message = str(exc)
        item.finished_at = None
        self._mark_stage_item_orchestration_observation(
            item,
            source=operation,
            observed_at=task_manager_module._now(),
            error_message=str(exc),
            error_type=self._classify_orchestration_error(exc),
            last_result="error",
            consecutive_error_count=state.consecutive_error_count,
            budget_exhausted=state.budget_exhausted,
            next_retry_at=state.next_retry_at,
        )
        self._record_event(
            session,
            task,
            "stage_item_orchestration_error_budget_exhausted" if state.budget_exhausted else "stage_item_orchestration_retry_scheduled",
            "阶段子任务推进异常，已进入延迟恢复" if not state.budget_exhausted else "阶段子任务推进异常预算耗尽，等待后台恢复",
            level="warning",
            stage_name=item.stage_name,
            item=item,
            payload={
                "operation": operation,
                "error_type": self._classify_orchestration_error(exc),
                "error_message": str(exc),
                "consecutive_error_count": state.consecutive_error_count,
                "next_retry_at": task_manager_module._isoformat_or_none(state.next_retry_at),
                "budget_exhausted": state.budget_exhausted,
                "resolution_reason": "recoverable_orchestration_error",
                "deferred_mode": deferred_mode,
            },
        )
        session.commit()
        return {
            "status": "running" if has_downstream_ref else "pending",
            "error": str(exc),
            "item": response_item,
            "deferred_mode": deferred_mode,
            "sync_degraded": True,
            "orchestration_degraded": True,
        }

    def _status_from_downstream_payload(self, payload: dict[str, Any], *, success_statuses: set[str]) -> str:
        downstream_status = str(payload.get("status") or "").lower()
        if downstream_status in success_statuses:
            return "success"
        mapped_status = self._map_downstream_status(downstream_status)
        if mapped_status == "success":
            return "success"
        if mapped_status in {"pending", "queued", "dispatching", "running"}:
            return mapped_status
        if mapped_status == "cancelled":
            return "cancelled"
        if mapped_status == "downstream_missing":
            return "downstream_missing"
        return "failed"

    def _is_self_healing_downstream_failure_observation(
        self,
        *,
        mapped_status: str | None,
        downstream_status: str | None = None,
        payload: dict[str, Any] | None = None,
        error_message: str | None = None,
        error_type: str | None = None,
    ) -> bool:
        normalized_mapped = str(mapped_status or "").strip().lower()
        if normalized_mapped != "failed":
            return False
        raw_parts = [
            str(downstream_status or "").strip().lower(),
            str(error_message or "").strip().lower(),
            str(error_type or "").strip().lower(),
            str((payload or {}).get("message") or "").strip().lower(),
            str((payload or {}).get("error") or "").strip().lower(),
            str((payload or {}).get("error_message") or "").strip().lower(),
        ]
        joined = " ".join(part for part in raw_parts if part)
        self_healing_tokens = (
            "stale active runtime",
            "assumed failed",
            "awaiting recovery",
            "kept running by run evidence",
            "requeued",
            "pending recovery",
            "run_vuln_scan.py running",
            "http_5xx",
            "transport_error",
            "upstreamerror",
        )
        return any(token in joined for token in self_healing_tokens)

    def _latest_observed_downstream_status(self, item: BinarySecurityStageItem) -> str | None:
        result = self._load_stage_item_result_payload(item)
        observed, _sync_observation, _repaired = self._effective_stage_item_downstream_status(item, result=result)
        mapped = self._map_downstream_status(str(observed or ""))
        return mapped or (str(observed or "").strip().lower() or None)

    def _should_preserve_target_stage_downstream_ref(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
    ) -> bool:
        del db, task
        downstream_task_id = str(item.downstream_task_id or "").strip()
        if not downstream_task_id:
            return False
        replacement_state = self._replacement_in_progress_state(item)
        if replacement_state.get("replacement_in_progress"):
            verification_status = str(replacement_state.get("verification_status") or "").strip().lower()
            if verification_status in {"pending", "failed", "missing", "stale"}:
                return False
            if replacement_state.get("binding_cleared"):
                return False
        return True

    def _has_retryable_downstream_task(self, item: BinarySecurityStageItem) -> bool:
        if not str(item.downstream_task_id or "").strip():
            return False
        return str(item.status or "").strip().lower() != "downstream_missing"

    def _clear_item_downstream_runtime_state(self, item: BinarySecurityStageItem) -> None:
        item.downstream_task_id = None
        item.downstream_status = None
        item.sync_status = None
        item.last_synced_at = None
        item.downstream_raw_status = None
        item.downstream_mapped_status = None
        item.downstream_state_applied = False
        item.sync_observation_error_message = None
        item.sync_observation_error_type = None
        item.sync_observation_http_status = None
        item.error_message = None
        result = dict(item.result or {})
        for key in (
            "downstream_status_sync",
            "downstream_status_synced_at",
            "downstream_status",
            "sync_observation",
            "downstream",
            "sync_status",
        ):
            result.pop(key, None)
        item.result = result

    def _mark_superseded_downstream_state(
        self,
        item: BinarySecurityStageItem,
        *,
        old_downstream_task_id: str | None,
        message: str | None = None,
    ) -> None:
        result = dict(item.result or {})
        sync_observation = dict(result.get("sync_observation") or {})
        sync_observation["superseded_downstream_task_id"] = str(old_downstream_task_id or "").strip() or None
        for key in (
            "next_retry_at",
            "last_error_at",
            "consecutive_error_count",
            "budget_exhausted",
            "last_attempt_at",
            "sync_status",
            "error_message",
            "error_type",
            "http_status",
            "last_result",
            "verification_status",
            "replacement_in_progress",
            "binding_cleared",
            "old_downstream_task_id",
        ):
            sync_observation.pop(key, None)
        if message:
            sync_observation["message"] = message
        result["sync_observation"] = sync_observation
        item.result = result

    def _mark_replacement_in_progress(
        self,
        item: BinarySecurityStageItem,
        *,
        old_downstream_task_id: str | None,
        binding_cleared: bool,
        verification_status: str = "pending",
        transition_type: str | None = None,
    ) -> None:
        result = dict(item.result or {})
        sync_observation = dict(result.get("sync_observation") or {})
        sync_observation["replacement_in_progress"] = True
        sync_observation["old_downstream_task_id"] = str(old_downstream_task_id or "").strip() or None
        sync_observation["binding_cleared"] = bool(binding_cleared)
        sync_observation["verification_status"] = str(verification_status or "pending")
        normalized_transition_type = str(transition_type or self.CHILD_TRANSITION_DESTRUCTIVE_REBUILD).strip().lower()
        if normalized_transition_type not in {
            self.CHILD_TRANSITION_IN_PLACE_RESTART,
            self.CHILD_TRANSITION_DESTRUCTIVE_REBUILD,
        }:
            normalized_transition_type = self.CHILD_TRANSITION_DESTRUCTIVE_REBUILD
        sync_observation["transition_type"] = normalized_transition_type
        result["sync_observation"] = sync_observation
        item.result = result

    def _mark_downstream_binding_retry(
        self,
        item: BinarySecurityStageItem,
        *,
        error_message: str | None,
        error_type: str | None,
        recoverable: bool,
    ) -> None:
        result = dict(item.result or {})
        sync_observation = dict(result.get("sync_observation") or {})
        if error_message:
            sync_observation["error_message"] = str(error_message)
        if error_type:
            sync_observation["error_type"] = str(error_type)
        sync_observation["recoverable"] = bool(recoverable)
        sync_observation.setdefault("verification_status", "pending")
        result["sync_observation"] = sync_observation
        item.result = result

    def _replacement_in_progress_state(self, item: BinarySecurityStageItem) -> dict[str, Any]:
        result = dict(item.result or {})
        sync_observation = dict(result.get("sync_observation") or {})
        transition_type = str(sync_observation.get("transition_type") or "").strip().lower() or None
        if transition_type not in {
            self.CHILD_TRANSITION_IN_PLACE_RESTART,
            self.CHILD_TRANSITION_DESTRUCTIVE_REBUILD,
        }:
            transition_type = (
                self.CHILD_TRANSITION_DESTRUCTIVE_REBUILD
                if bool(sync_observation.get("replacement_in_progress")) or bool(sync_observation.get("binding_cleared"))
                else None
            )
        return {
            "replacement_in_progress": bool(sync_observation.get("replacement_in_progress")),
            "binding_cleared": bool(sync_observation.get("binding_cleared")),
            "verification_status": str(sync_observation.get("verification_status") or "").strip().lower() or None,
            "old_downstream_task_id": str(sync_observation.get("old_downstream_task_id") or "").strip() or None,
            "transition_type": transition_type,
        }

    def _clear_replacement_in_progress(self, item: BinarySecurityStageItem) -> None:
        result = dict(item.result or {})
        sync_observation = dict(result.get("sync_observation") or {})
        changed = False
        for key in ("replacement_in_progress", "binding_cleared", "verification_status", "old_downstream_task_id", "transition_type"):
            if key in sync_observation:
                sync_observation.pop(key, None)
                changed = True
        if changed:
            result["sync_observation"] = sync_observation
            item.result = result

    def _is_destructive_rebuild_transition(self, replacement_state: dict[str, Any] | None) -> bool:
        state = dict(replacement_state or {})
        if not (state.get("replacement_in_progress") or state.get("binding_cleared")):
            return False
        transition_type = str(state.get("transition_type") or "").strip().lower()
        return transition_type != self.CHILD_TRANSITION_IN_PLACE_RESTART

    def _mark_in_place_child_restart(
        self,
        item: BinarySecurityStageItem,
        *,
        downstream_task_id: str | None,
        verification_status: str = "pending",
    ) -> None:
        self._mark_replacement_in_progress(
            item,
            old_downstream_task_id=downstream_task_id,
            binding_cleared=False,
            verification_status=verification_status,
            transition_type=self.CHILD_TRANSITION_IN_PLACE_RESTART,
        )

    def _archive_job_is_active(self, archive_status: str | None) -> bool:
        return str(archive_status or "").strip() in {"pending", "running", "archived", "applying", "success"}

    def _archive_job_is_old_child_retire_candidate(
        self,
        job: BinarySecurityArchiveJob,
        *,
        old_downstream_task_id: str | None,
    ) -> bool:
        old_task_id = str(old_downstream_task_id or "").strip()
        if not old_task_id:
            return False
        if self._archive_job_bound_downstream_task_id(job) != old_task_id:
            return False
        return str(getattr(job, "archive_status", "") or "").strip() in {
            "pending",
            "running",
            "archived",
            "applying",
            "success",
        }

    def _supersede_archive_jobs_for_downstream_task(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        old_downstream_task_id: str | None,
        reason: str,
    ) -> list[BinarySecurityArchiveJob]:
        old_task_id = str(old_downstream_task_id or "").strip()
        if not old_task_id:
            return []
        jobs = (
            db.query(BinarySecurityArchiveJob)
            .filter(
                BinarySecurityArchiveJob.item_id == item.id,
            )
            .order_by(BinarySecurityArchiveJob.created_at.asc(), BinarySecurityArchiveJob.id.asc())
            .all()
        )
        superseded: list[BinarySecurityArchiveJob] = []
        now = task_manager_module._now()
        for job in jobs:
            if not self._archive_job_is_old_child_retire_candidate(
                job,
                old_downstream_task_id=old_task_id,
            ):
                continue
            job.archive_status = "superseded"
            job.error_message = None
            job.owner_id = None
            job.completed_at = job.completed_at or now
            job.updated_at = now
            payload = dict(job.payload or {})
            payload["superseded"] = True
            payload["superseded_reason"] = reason
            payload["superseded_downstream_task_id"] = old_task_id
            payload["superseded_at"] = now.isoformat()
            job.payload = payload
            superseded.append(job)
        if superseded:
            task_manager_module.logger.warning(
                "binary-security superseded archive jobs: task_id=%s stage=%s item_id=%s old_downstream_task_id=%s archive_job_ids=%s reason=%s",
                task.id,
                item.stage_name,
                item.id,
                old_task_id,
                ",".join(str(job.id) for job in superseded),
                reason,
            )
            self._record_event(
                db,
                task,
                "superseded_archive_jobs_cancelled",
                "旧 child 绑定的归档任务已废弃",
                stage_name=item.stage_name,
                item=item,
                level="warning",
                payload={
                    "old_downstream_task_id": old_task_id,
                    "archive_job_ids": [job.id for job in superseded],
                    "reason": reason,
                    "superseded": True,
                },
            )
        return superseded

    def _cleanup_superseded_archive_roots(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        old_downstream_task_id: str | None,
        new_downstream_task_id: str | None,
        superseded_jobs: list[BinarySecurityArchiveJob],
        reason: str,
    ) -> list[str]:
        deleted_roots = self._delete_archive_roots_for_jobs(task, superseded_jobs)
        deleted_set = set(deleted_roots)
        failed_roots = [
            str(getattr(job, "archive_root", "") or "").strip()
            for job in superseded_jobs
            if str(getattr(job, "archive_root", "") or "").strip()
            and str(getattr(job, "archive_root", "") or "").strip() not in deleted_set
        ]
        if deleted_roots:
            self._record_event(
                db,
                task,
                "superseded_archive_roots_deleted",
                "旧 child 绑定的归档目录已删除",
                stage_name=item.stage_name,
                item=item,
                level="warning",
                payload={
                    "old_downstream_task_id": str(old_downstream_task_id or "").strip() or None,
                    "new_downstream_task_id": str(new_downstream_task_id or "").strip() or None,
                    "archive_job_ids": [job.id for job in superseded_jobs],
                    "deleted_archive_roots": deleted_roots,
                    "reason": reason,
                },
            )
        if failed_roots:
            self._record_event(
                db,
                task,
                "superseded_archive_root_delete_failed",
                "旧 child 绑定的归档目录删除失败，后续将继续补偿清理",
                stage_name=item.stage_name,
                item=item,
                level="warning",
                payload={
                    "old_downstream_task_id": str(old_downstream_task_id or "").strip() or None,
                    "new_downstream_task_id": str(new_downstream_task_id or "").strip() or None,
                    "archive_job_ids": [job.id for job in superseded_jobs],
                    "failed_archive_roots": failed_roots,
                    "reason": reason,
                },
            )
        return deleted_roots

    async def _replace_active_child_binding(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        new_downstream_task_id: str | None,
        token: str | None,
        reason: str,
        transition_type: str | None = None,
    ) -> str | None:
        new_task_id = str(new_downstream_task_id or "").strip() or None
        old_task_id = str(item.downstream_task_id or "").strip() or None
        normalized_transition_type = str(transition_type or self.CHILD_TRANSITION_DESTRUCTIVE_REBUILD).strip().lower()
        if normalized_transition_type not in {
            self.CHILD_TRANSITION_IN_PLACE_RESTART,
            self.CHILD_TRANSITION_DESTRUCTIVE_REBUILD,
        }:
            normalized_transition_type = self.CHILD_TRANSITION_DESTRUCTIVE_REBUILD
        if not old_task_id:
            item.downstream_task_id = new_task_id or item.downstream_task_id
            self._clear_replacement_in_progress(item)
            return None
        if new_task_id and new_task_id == old_task_id:
            if normalized_transition_type == self.CHILD_TRANSITION_IN_PLACE_RESTART:
                self._mark_in_place_child_restart(
                    item,
                    downstream_task_id=old_task_id,
                    verification_status="pending",
                )
            else:
                self._clear_replacement_in_progress(item)
            return old_task_id

        task_manager_module.logger.warning(
            "binary-security child binding replace requested: task_id=%s stage=%s item_id=%s item_key=%s old_downstream_task_id=%s new_downstream_task_id=%s reason=%s",
            task.id,
            item.stage_name,
            item.id,
            item.item_key,
            old_task_id,
            new_task_id,
            reason,
        )

        self._mark_replacement_in_progress(
            item,
            old_downstream_task_id=old_task_id,
            binding_cleared=False,
            verification_status="pending",
            transition_type=normalized_transition_type,
        )
        superseded_jobs = self._supersede_archive_jobs_for_downstream_task(
            db,
            task,
            item,
            old_downstream_task_id=old_task_id,
            reason=reason,
        )
        self._mark_superseded_downstream_state(
            item,
            old_downstream_task_id=old_task_id,
            message="旧 child 已失效，等待新 child 接管",
        )

        refs = [{
            "service": item.downstream_service,
            "task_id": old_task_id,
            "project_id": task.project_id,
            "stage_name": item.stage_name,
            "item_id": item.id,
            "item_key": item.item_key,
        }]
        try:
            await self._downstream_cancel_refs(db, task, refs, token)
        except NotFoundError:
            pass
        except Exception:
            self._clear_replacement_in_progress(item)
            raise
        try:
            await self._delete_downstream_refs(db, task, refs, token, cleanup_scope="binding_replace")
        except NotFoundError:
            pass
        except Exception:
            self._clear_replacement_in_progress(item)
            raise

        item.downstream_task_id = new_task_id
        self._clear_replacement_in_progress(item)
        deleted_archive_roots = self._cleanup_superseded_archive_roots(
            db,
            task,
            item,
            old_downstream_task_id=old_task_id,
            new_downstream_task_id=new_task_id,
            superseded_jobs=superseded_jobs,
            reason=reason,
        )
        task_manager_module.logger.info(
            "binary-security child binding replaced: task_id=%s stage=%s item_id=%s item_key=%s old_downstream_task_id=%s new_downstream_task_id=%s reason=%s",
            task.id,
            item.stage_name,
            item.id,
            item.item_key,
            old_task_id,
            new_task_id,
            reason,
        )
        self._record_event(
            db,
            task,
            "child_binding_replaced",
            "阶段项已切换到新的 authoritative child",
            stage_name=item.stage_name,
            item=item,
            level="warning",
            payload={
                "old_downstream_task_id": old_task_id,
                "new_downstream_task_id": new_task_id,
                "reason": reason,
                "deleted_archive_roots": deleted_archive_roots,
            },
        )
        self._record_event(
            db,
            task,
            "superseded_downstream_sync_ignored",
            "旧 child 的后续同步与归档触发将被忽略",
            stage_name=item.stage_name,
            item=item,
            level="warning",
            payload={
                "old_downstream_task_id": old_task_id,
                "new_downstream_task_id": new_task_id,
                "reason": reason,
                "superseded": True,
            },
        )
        return old_task_id

    def _may_queue_archive_for_current_binding(
        self,
        item: BinarySecurityStageItem,
        *,
        payload: dict[str, Any],
        mapped_status: str,
    ) -> tuple[bool, str | None]:
        if mapped_status not in task_manager_module.ARCHIVE_SUCCESS_MAPPED_STATUSES:
            return False, "non_success_status"
        replacement_state = self._replacement_in_progress_state(item)
        if self._is_destructive_rebuild_transition(replacement_state):
            return False, "replacement_in_progress"
        current_downstream_task_id = self._current_downstream_task_id(item)
        payload_downstream_task_id = self._payload_downstream_task_id(payload)
        if current_downstream_task_id and payload_downstream_task_id and payload_downstream_task_id != current_downstream_task_id:
            return False, "stale_child_payload"
        return True, None

    def _should_preserve_terminal_status(
        self,
        item: BinarySecurityStageItem,
        *,
        mapped_status: str | None,
        current_item_status: str | None,
        payload: dict[str, Any],
    ) -> bool:
        if not mapped_status or not current_item_status or current_item_status == mapped_status:
            return False
        replacement_state = self._replacement_in_progress_state(item)
        if self._is_destructive_rebuild_transition(replacement_state) or replacement_state["verification_status"] == "pending":
            return normalize_stage_name(item.stage_name) != "dataflow_vuln_scan"
        observed_task_id = str(payload.get("task_id") or payload.get("id") or "").strip() or None
        current_task_id = str(item.downstream_task_id or "").strip() or None
        if normalize_stage_name(item.stage_name) != "dataflow_vuln_scan":
            if not observed_task_id or not current_task_id:
                return True
            if observed_task_id != current_task_id:
                return True
            if mapped_status in {"success", "partial_success"}:
                return False
            return True
        if observed_task_id and current_task_id and observed_task_id != current_task_id:
            return False
        return True
