from __future__ import annotations

import asyncio
import copy
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from sqlalchemy import func
from sqlalchemy.orm import Session, load_only

from app.exception import NotFoundError, ValidationError
from app.model import normalize_stage_name

from . import shared as task_shared

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


logger = logging.getLogger(__name__)


class TaskReadModelServiceMixin:
    def _manual_operation_state_from_active_operation(
        self: TaskManager,
        task,
        active_operation,
    ) -> dict[str, Any]:
        result_payload = dict(active_operation.result_payload or {})
        request_payload = dict(active_operation.request_payload or {})
        fallback_from = self._string_or_none(request_payload.get("fallback_from"))
        requested_stage = self._string_or_none(request_payload.get("requested_stage"))
        item_actions = [dict(row) for row in list(result_payload.get("item_actions") or []) if isinstance(row, dict)]
        validation = dict(result_payload.get("validation") or {})
        requeue = dict(result_payload.get("requeue") or {})
        cleanup_result = dict(result_payload.get("cleanup_result") or {})
        downstream_cleanup_results = [
            dict(row)
            for row in list(cleanup_result.get("downstream_cleanup_results") or result_payload.get("downstream_cleanup_results") or [])
            if isinstance(row, dict)
        ]
        downstream_cleanup_blocking_refs = [
            dict(row)
            for row in list(cleanup_result.get("downstream_cleanup_blocking_refs") or result_payload.get("downstream_cleanup_blocking_refs") or [])
            if isinstance(row, dict)
        ]
        downstream_cleanup_deferred_refs = [
            dict(row)
            for row in list(cleanup_result.get("downstream_cleanup_deferred_refs") or result_payload.get("downstream_cleanup_deferred_refs") or [])
            if isinstance(row, dict)
        ]
        cleanup_partial_failed = bool(cleanup_result.get("cleanup_partial_failed")) or bool(downstream_cleanup_deferred_refs)
        task_owner = str(task.dispatcher_instance_id or "").strip() or None
        age_seconds = self._task_operation_age_seconds(active_operation)
        is_stale = bool(age_seconds is not None and age_seconds >= float(self._operation_stale_threshold_seconds()))
        requeue_applied = bool(self._operation_requeue_applied(task, active_operation))
        auto_reconcile_candidate = bool(
            is_stale
            and str(getattr(active_operation, "operation_type", "") or "").strip() in self._operation_requeue_family_types()
        )
        if requeue_applied and is_stale:
            overall = "degraded"
            blocking_code = "stale_operation_finalize_pending"
            blocking_reason = "后台重试已生效，操作收口滞后，系统正在自动修复"
            summary = blocking_reason
        elif is_stale:
            overall = "blocked"
            blocking_code = "operation_stalled"
            blocking_reason = f"当前任务后台操作已停滞: {active_operation.operation_type}"
            summary = blocking_reason
        else:
            overall = "in_progress"
            blocking_code = "task_operation_in_progress"
            blocking_reason = f"当前任务正在执行 {active_operation.operation_type}，请稍后重试"
            summary = blocking_reason
        return {
            "overall": overall,
            "summary": summary,
            "blocking_code": blocking_code,
            "blocking_reason": blocking_reason,
            "operation_in_progress": not is_stale,
            "operation_stale": is_stale,
            "operation_reconcile_pending": bool(is_stale),
            "requeue_applied": requeue_applied,
            "auto_reconcile_candidate": auto_reconcile_candidate,
            "operation_id": active_operation.id,
            "operation_type": active_operation.operation_type,
            "requested_operation_type": fallback_from or active_operation.operation_type,
            "operation_status": active_operation.status,
            "operation_owner": task_owner,
            "operation_owner_model": "task_lease_owner" if task_owner else "owner_unknown",
            "operation_started_at": task_shared._isoformat_or_none(active_operation.started_at),
            "operation_updated_at": task_shared._isoformat_or_none(active_operation.updated_at),
            "operation_age_seconds": None if age_seconds is None else round(float(age_seconds), 3),
            "current_step": active_operation.current_step,
            "target_stage": active_operation.target_stage,
            "requested_stage": requested_stage or active_operation.target_stage,
            "fallback_from": fallback_from,
            "item_actions": item_actions,
            "item_actions_count": len(item_actions),
            "validation": validation,
            "issues": list(validation.get("issues") or []),
            "requeue": requeue,
            "error_code": active_operation.error_code,
            "error_message": active_operation.error_message,
            "downstream_cleanup_results": downstream_cleanup_results,
            "downstream_cleanup_blocking_refs": downstream_cleanup_blocking_refs,
            "downstream_cleanup_deferred_refs": downstream_cleanup_deferred_refs,
            "downstream_cleanup_result_count": len(downstream_cleanup_results),
            "downstream_cleanup_blocking_count": len(downstream_cleanup_blocking_refs),
            "downstream_cleanup_deferred_count": len(downstream_cleanup_deferred_refs),
            "cleanup_partial_failed": cleanup_partial_failed,
            "downstream_cleanup_warning_summary": (
                f"检测到 {len(downstream_cleanup_deferred_refs)} 个历史删除遗留引用，系统正在尝试恢复清理"
                if downstream_cleanup_deferred_refs else None
            ),
            "can_cancel": False,
            "can_continue": False,
            "can_retry": False,
            "can_retry_failed_items": False,
            "can_retry_stage": False,
            "can_retry_stage_failed_items": False,
            "can_retry_stage_full": False,
            "can_retry_archive": False,
            "can_retry_archive_failed_items": False,
            "can_retry_archive_full": False,
            "can_delete": False,
            "can_edit_policy": False,
            "can_confirm_modules": False,
        }

    def _active_reconcile_stage_name(self: TaskManager, task) -> str | None:
        from app.service import task_manager as task_manager_module

        if (
            str(getattr(task, "execution_mode", "") or "").strip() in task_manager_module.ACTIVE_RECONCILE_TARGET_STAGE_MODES
            and str(getattr(task, "target_stage_name", "") or "").strip()
        ):
            return str(task.target_stage_name).strip()
        if str(getattr(task, "current_stage", "") or "").strip():
            return str(task.current_stage).strip()
        return None

    def _task_queue_state(
        self: TaskManager,
        task,
        queue_info: dict[str, Any] | None = None,
        *,
        db: Session | None = None,
    ) -> tuple[str, str | None]:
        del db
        from app.service import task_manager as task_manager_module

        queue_info = queue_info or {}
        pending_positions = queue_info.get("pending_positions", {}) or {}
        status = str(task.status or "").strip().lower()
        runtime_phase = self._task_runtime_phase(task)
        if runtime_phase == task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
            return "tail_reconciling", "tail_reconciliation_active"
        if status in {"dispatching", "running"}:
            if task.dispatcher_instance_id or task.lease_expires_at:
                return "dispatching", None
            return "leased", "execution_owner_missing"
        if status == "pending":
            if task.id in pending_positions:
                return "queued", None
            return "db_pending_not_enqueued", "pending_task_not_present_in_redis_queue"
        return "idle", None

    def get_orchestration_observability(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
    ) -> dict[str, Any]:
        task = self._task_or_404(db, project_id, task_id)
        return self._build_orchestration_observability(db, task)

    def _build_orchestration_observability(self: TaskManager, db: Session, task) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        now_value = task_shared._now()
        queue_info = self._build_queue_info(db, project_id=task.project_id)
        queue_state, recoverable_reason = self._task_queue_state(task, queue_info, db=db)
        events = (
            db.query(task_manager_module.BinarySecurityStateEvent)
            .filter(task_manager_module.BinarySecurityStateEvent.task_id == task.id)
            .order_by(task_manager_module.BinarySecurityStateEvent.created_at.desc())
            .limit(50)
            .all()
        )
        status_counts: dict[str, int] = {}
        oldest_pending_at = None
        processing: list[dict[str, Any]] = []
        dead_letters: list[dict[str, Any]] = []
        recent_events: list[dict[str, Any]] = []
        for event in events:
            status = str(event.status or "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1
            if status in {"pending", "retryable", "processing"} and (
                oldest_pending_at is None or event.created_at < oldest_pending_at
            ):
                oldest_pending_at = event.created_at
            row = {
                "id": event.id,
                "event_type": event.event_type,
                "status": event.status,
                "stage_name": event.stage_name,
                "item_id": event.item_id,
                "archive_job_id": event.archive_job_id,
                "attempts": int(event.attempts or 0),
                "leased_by": event.leased_by,
                "lease_expires_at": event.lease_expires_at,
                "created_at": event.created_at,
                "processed_at": event.processed_at,
                "error_message": event.error_message,
            }
            recent_events.append(row)
            if status == "processing":
                processing.append(row)
            if status == "dead_letter":
                dead_letters.append(row)
        archive_rows = (
            db.query(
                task_manager_module.BinarySecurityArchiveJob.stage_name,
                task_manager_module.BinarySecurityArchiveJob.archive_status,
                task_manager_module.func.count(task_manager_module.BinarySecurityArchiveJob.id),
            )
            .filter(task_manager_module.BinarySecurityArchiveJob.task_id == task.id)
            .group_by(
                task_manager_module.BinarySecurityArchiveJob.stage_name,
                task_manager_module.BinarySecurityArchiveJob.archive_status,
            )
            .all()
        )
        archive_by_stage: dict[str, dict[str, int]] = {}
        for stage_name, status, count in archive_rows:
            stage_bucket = archive_by_stage.setdefault(str(stage_name or "unknown"), {})
            stage_bucket[str(status or "unknown")] = int(count or 0)
        lease = (
            db.query(task_manager_module.BinarySecurityTaskStateLease)
            .filter(task_manager_module.BinarySecurityTaskStateLease.task_id == task.id)
            .first()
        )
        latest_reconcile = (
            db.query(task_manager_module.BinarySecurityEvent)
            .filter(
                task_manager_module.BinarySecurityEvent.task_id == task.id,
                task_manager_module.BinarySecurityEvent.event_type.in_(
                    [
                        "downstream_status_synced",
                        "downstream_status_sync_skipped",
                        "downstream_archive_job_queued",
                        "downstream_archive_job_reused",
                        "child_transport_failed",
                        "child_observation_persist_failed",
                        "child_state_apply_failed",
                    ]
                ),
            )
            .order_by(task_manager_module.BinarySecurityEvent.created_at.desc())
            .first()
        )
        summary_payload = task.summary if isinstance(task.summary, dict) else {}
        runtime_task_keys = (
            summary_payload.get("runtime_task_keys")
            if isinstance(summary_payload.get("runtime_task_keys"), dict)
            else {}
        )
        return {
            "state_events": {
                "status_counts": status_counts,
                "oldest_active_age_seconds": max(0.0, (now_value - oldest_pending_at).total_seconds())
                if oldest_pending_at
                else 0.0,
                "processing": processing[:10],
                "dead_letters": dead_letters[:10],
                "recent": recent_events[:20],
            },
            "queue_runtime": {
                "queue_state": queue_state,
                "recoverable_reason": recoverable_reason,
                "last_reconcile_at": self._last_queue_reconcile_at,
            },
            "task_state_lock": {
                "active": bool(lease and lease.lease_expires_at and lease.lease_expires_at > now_value),
                "owner_id": lease.owner_id if lease else None,
                "operation": lease.operation if lease else None,
                "lease_expires_at": lease.lease_expires_at if lease else None,
                "heartbeat_at": lease.heartbeat_at if lease else None,
            },
            "archive": {
                "by_stage": archive_by_stage,
            },
            "reconcile": {
                "latest_event_type": latest_reconcile.event_type if latest_reconcile else None,
                "latest_event_at": latest_reconcile.created_at if latest_reconcile else None,
                "latest_message": latest_reconcile.message if latest_reconcile else None,
            },
            "files": {
                "summary_path": str(Path(task.workspace_root) / task_manager_module.BinarySecurityTask.SUMMARY_FILENAME)
                if task.workspace_root
                else None,
                "metadata_path": str(Path(task.workspace_root) / "input" / "task-metadata.json")
                if task.workspace_root
                else None,
            },
            "runtime_task_keys": {
                "root_task_key_secret": str(runtime_task_keys.get("root_task_key_secret") or "").strip() or None,
                "root_task_key_id": str(runtime_task_keys.get("root_task_key_id") or "").strip() or None,
                "root_task_key_name": str(runtime_task_keys.get("root_task_key_name") or "").strip() or None,
                "root_task_key_prefix": str(runtime_task_keys.get("root_task_key_prefix") or "").strip() or None,
                "task_key_source": str(runtime_task_keys.get("task_key_source") or "").strip() or None,
            },
        }

    def _runtime_task_keys_snapshot(self: TaskManager, task) -> dict[str, Any]:
        summary_payload = task.summary if isinstance(task.summary, dict) else {}
        runtime_task_keys = summary_payload.get("runtime_task_keys")
        return runtime_task_keys if isinstance(runtime_task_keys, dict) else {}

    def _task_summary_for_detail_response(self: TaskManager, task) -> dict[str, Any]:
        summary_payload = copy.deepcopy(task.summary if isinstance(task.summary, dict) else {})
        runtime_task_keys = summary_payload.get("runtime_task_keys")
        if isinstance(runtime_task_keys, dict):
            runtime_task_keys.pop("root_task_key_secret", None)
        return summary_payload

    def _build_task_key_snapshot(self: TaskManager, db: Session, task):
        from app.service import task_manager as task_manager_module

        runtime_task_keys = self._runtime_task_keys_snapshot(task)
        root_task_key_id = str(
            getattr(task, "root_task_key_id", "") or runtime_task_keys.get("root_task_key_id") or ""
        ).strip() or None
        root_task_key_name = str(
            getattr(task, "root_task_key_name", "") or runtime_task_keys.get("root_task_key_name") or ""
        ).strip() or None
        root_task_key_prefix = str(
            getattr(task, "root_task_key_prefix", "") or runtime_task_keys.get("root_task_key_prefix") or ""
        ).strip() or None
        root_task_key_source = str(
            getattr(task, "task_key_source", "") or runtime_task_keys.get("task_key_source") or ""
        ).strip() or None
        root_task_key_has_secret = bool(self._root_task_key_secret(task))
        root_task_key_used = bool(
            root_task_key_has_secret
            or root_task_key_id
            or root_task_key_name
            or root_task_key_prefix
            or root_task_key_source
        )

        created_rows = (
            db.query(task_manager_module.BinarySecurityEvent)
            .filter(
                task_manager_module.BinarySecurityEvent.task_id == task.id,
                task_manager_module.BinarySecurityEvent.event_type == "downstream_work_key_created",
            )
            .order_by(
                task_manager_module.BinarySecurityEvent.created_at.asc(),
                task_manager_module.BinarySecurityEvent.id.asc(),
            )
            .all()
        )
        item_ids: set[str] = set()
        for event in created_rows:
            payload = event.payload if isinstance(event.payload, dict) else {}
            stage_item_id = str(payload.get("stage_item_id") or event.item_id or "").strip()
            if stage_item_id:
                item_ids.add(stage_item_id)

        stage_items_by_id: dict[str, Any] = {}
        if item_ids:
            stage_item_rows = (
                db.query(task_manager_module.BinarySecurityStageItem)
                .options(
                    load_only(
                        task_manager_module.BinarySecurityStageItem.id,
                        task_manager_module.BinarySecurityStageItem.item_key,
                        task_manager_module.BinarySecurityStageItem.downstream_task_id,
                        task_manager_module.BinarySecurityStageItem.payload_json,
                    )
                )
                .filter(task_manager_module.BinarySecurityStageItem.id.in_(list(item_ids)))
                .all()
            )
            stage_items_by_id = {str(getattr(item, "id", "") or ""): item for item in stage_item_rows}

        downstream_task_ids_by_item: dict[str, str] = {}
        supplemental_rows = (
            db.query(task_manager_module.BinarySecurityEvent)
            .filter(
                task_manager_module.BinarySecurityEvent.task_id == task.id,
                task_manager_module.BinarySecurityEvent.event_type.in_(
                    ["downstream_create_with_agent_task_key", "child_task_retry_accepted"]
                ),
            )
            .order_by(
                task_manager_module.BinarySecurityEvent.created_at.asc(),
                task_manager_module.BinarySecurityEvent.id.asc(),
            )
            .all()
        )
        for event in supplemental_rows:
            payload = event.payload if isinstance(event.payload, dict) else {}
            stage_item_id = str(
                payload.get("stage_item_id")
                or payload.get("parent_stage_item_id")
                or event.item_id
                or ""
            ).strip()
            downstream_task_id = str(
                payload.get("downstream_task_id")
                or payload.get("task_id")
                or ""
            ).strip()
            if stage_item_id and downstream_task_id and not downstream_task_ids_by_item.get(stage_item_id):
                downstream_task_ids_by_item[stage_item_id] = downstream_task_id

        work_keys: list[Any] = []
        seen_work_key_dedupe: set[tuple[str, str, str]] = set()
        for event in created_rows:
            payload = event.payload if isinstance(event.payload, dict) else {}
            stage_item_id = str(payload.get("stage_item_id") or event.item_id or "").strip()
            service = str(payload.get("service") or "").strip() or None
            agent_task_key_id = str(payload.get("agent_task_key_id") or "").strip() or None
            dedupe_key = (stage_item_id, service or "", agent_task_key_id or "")
            if dedupe_key in seen_work_key_dedupe:
                continue
            seen_work_key_dedupe.add(dedupe_key)

            stage_item = stage_items_by_id.get(stage_item_id)
            stage_item_payload = stage_item.payload if stage_item is not None and isinstance(stage_item.payload, dict) else {}
            work_key_name = str(
                stage_item_payload.get("downstream_agent_task_key_name")
                or payload.get("agent_task_key_name")
                or ""
            ).strip() or None
            work_key_prefix = str(
                payload.get("agent_task_key_prefix")
                or stage_item_payload.get("downstream_agent_task_key_prefix")
                or ""
            ).strip() or None
            work_key_source = str(
                payload.get("agent_task_key_source")
                or stage_item_payload.get("downstream_key_source")
                or ""
            ).strip() or None
            downstream_task_id = None
            if stage_item is not None:
                downstream_task_id = str(getattr(stage_item, "downstream_task_id", "") or "").strip() or None
            if not downstream_task_id:
                downstream_task_id = downstream_task_ids_by_item.get(stage_item_id)
            work_key_has_secret = bool(
                agent_task_key_id
                or stage_item_payload.get("downstream_agent_task_key_id")
                or stage_item_payload.get("downstream_agent_task_key_name")
            )

            work_keys.append(
                task_manager_module.BinarySecurityWorkKeySnapshot(
                    stage_name=str(payload.get("stage_name") or event.stage_name or "").strip() or None,
                    service=service,
                    stage_item_id=stage_item_id or None,
                    stage_item_key=(
                        str(getattr(stage_item, "item_key", "") or "").strip() or None if stage_item is not None else None
                    ),
                    downstream_task_id=downstream_task_id,
                    agent_task_key_id=agent_task_key_id,
                    agent_task_key_name=work_key_name,
                    agent_task_key_prefix=work_key_prefix,
                    agent_task_key_source=work_key_source,
                    has_secret=work_key_has_secret,
                    created_at=event.created_at,
                )
            )

        return task_manager_module.BinarySecurityTaskKeySnapshot(
            root_task_key=task_manager_module.BinarySecurityRootTaskKeySnapshot(
                id=root_task_key_id,
                name=root_task_key_name,
                prefix=root_task_key_prefix,
                source=root_task_key_source,
                has_secret=root_task_key_has_secret,
                used=root_task_key_used,
            ),
            work_keys=work_keys,
        )

    def _stage_item_downstream_summary(
        self: TaskManager,
        item,
        *,
        result: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        candidates: list[dict[str, Any]] = []
        result_payload = dict(result or item.result or {})
        output_ref = dict(item.output_ref or {})
        for payload in (
            result_payload,
            output_ref,
            dict(result_payload.get("summary") or {}),
            dict(output_ref.get("summary") or {}),
            dict(result_payload.get("system_analysis_result") or {}),
            dict((result_payload.get("system_analysis_result") or {}).get("summary") or {}),
            dict(output_ref.get("system_analysis_result") or {}),
            dict((output_ref.get("system_analysis_result") or {}).get("summary") or {}),
        ):
            if payload:
                candidates.append(payload)

        summary: dict[str, Any] = {}
        metric_keys = (
            "high_risk_module_count",
            "medium_risk_module_count",
            "low_risk_module_count",
            "entry_count",
        )
        for key in metric_keys:
            for payload in candidates:
                value = payload.get(key)
                if value is None or value == "":
                    continue
                try:
                    summary[key] = int(value)
                    break
                except (TypeError, ValueError):
                    continue
        return summary or None

    def _stage_run_summary_path(self: TaskManager, task, stage_run) -> Path:
        from app.service import task_manager as task_manager_module

        return Path(task.workspace_root) / "run" / "stage-summaries" / f"{int(stage_run.sequence_no or 0):02d}_{stage_run.stage_name}.json"

    def _load_stage_run_output_summary_full(self: TaskManager, task, stage_run) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        db_summary = dict(stage_run.output_summary or {})
        summary_file = db_summary.get("summary_file")
        candidate = Path(str(summary_file)) if summary_file else self._stage_run_summary_path(task, stage_run)
        if candidate.is_file():
            try:
                payload = json.loads(task_shared._read_text(candidate) or "{}")
                if isinstance(payload, dict):
                    return payload
            except Exception:
                pass
        return {}

    def _compact_stage_output_item_preview(self: TaskManager, stage_name: str, item: dict[str, Any]) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        row = dict(item)
        if stage_name == "system_analysis":
            modules = [dict(module) for module in row.get("modules") or [] if isinstance(module, dict)]
            row["modules"] = self._lightweight_modules_for_storage(modules, limit=5)
            if "system_analysis_result" in row:
                result = dict(row.get("system_analysis_result") or {})
                result["modules"] = self._lightweight_modules_for_storage(list(result.get("modules") or []), limit=5)
                warnings = result.get("warnings") or []
                if isinstance(warnings, list):
                    result["warnings"] = warnings[:10]
                    result["warning_count"] = len(warnings)
                row["system_analysis_result"] = result
            return row
        if stage_name == "entry_analysis":
            entries = [dict(entry) for entry in row.get("entries") or row.get("entries_preview") or [] if isinstance(entry, dict)]
            return {
                "firmware_key": row.get("firmware_key"),
                "firmware_name": row.get("firmware_name"),
                "module_key": row.get("module_key"),
                "module_name": row.get("module_name"),
                "module_dir": row.get("module_dir"),
                "source_dir": row.get("source_dir"),
                "artifact_root": row.get("artifact_root"),
                "entry_count": row.get("entry_count") if row.get("entry_count") is not None else len(entries),
                "entries_preview": self._compact_entry_rows(entries[:5]),
            }
        if normalize_stage_name(stage_name) == "dataflow_vuln_scan":
            artifact_files = row.get("artifact_files_preview") or row.get("artifact_files") or []
            return {
                "entry_key": row.get("entry_key"),
                "module_key": row.get("module_key"),
                "module_name": row.get("module_name"),
                "function_name": row.get("function_name"),
                "file_name": row.get("file_name"),
                "line_no": row.get("line_no"),
                "source_dir": row.get("source_dir"),
                "data_flow_file": row.get("data_flow_file"),
                "workspace_root": row.get("workspace_root"),
                "archive_root": row.get("archive_root"),
                "artifact_file_count": row.get("artifact_file_count") if row.get("artifact_file_count") is not None else len(artifact_files),
                "artifact_files_preview": list(artifact_files[:5]) if isinstance(artifact_files, list) else [],
            }
        if normalize_stage_name(stage_name) == "dataflow_vuln_scan":
            return self._compact_vuln_summary_item(row)
        if stage_name == "binary_to_source":
            return self._compact_b2s_summary_item(row)
        if stage_name == "firmware_unpack":
            return self._compact_firmware_unpack_summary_item(row)
        return row

    def _compact_stage_output_summary_for_db(
        self: TaskManager,
        task,
        stage_run,
        full_summary: dict[str, Any] | None,
        *,
        summary_file: str | None = None,
    ) -> dict[str, Any]:
        summary = dict(full_summary or {})
        compact: dict[str, Any] = {
            "summary_externalized": bool(summary_file),
        }
        if summary_file:
            compact["summary_file"] = summary_file
        scalar_keys = [
            "status",
            "sync_status",
            "error",
            "reason",
            "failure_code",
            "failure_category",
            "failure_message",
            "reclaimed",
            "archive_blocked",
            "waiting_manual_confirmation",
            "success_count",
            "failed_count",
            "cancelled_count",
            "entry_count",
            "vuln_result_count",
            "module_count",
            "high_risk_module_count",
            "medium_risk_module_count",
            "low_risk_module_count",
            "candidate_module_count",
            "selected_module_count",
            "total_items",
            "success_items",
            "failed_items_count",
            "running_items",
            "cancelled_items_count",
            "skipped_items",
            "items_truncated",
            "failed_items_truncated",
            "cancelled_items_truncated",
            "status_synced",
            "streaming_completion_gate_ready",
            "expected_entry_count",
            "materialized_item_count",
            "missing_entry_count",
        ]
        for key in scalar_keys:
            value = summary.get(key)
            if value is not None:
                compact[key] = value
        for count_key, alias in (("failed_items", "failed_items_count"), ("cancelled_items", "cancelled_items_count")):
            rows = summary.get(count_key)
            if isinstance(rows, list):
                compact[alias] = len(rows)
        items = summary.get("items")
        if isinstance(items, list):
            compact["item_count"] = len(items)
            compact["items_preview"] = [
                self._compact_stage_output_item_preview(stage_run.stage_name, item)
                for item in items[:10]
                if isinstance(item, dict)
            ]
        failed_items = summary.get("failed_items")
        if isinstance(failed_items, list):
            compact["failed_items_preview"] = [
                self._lightweight_stage_failure(item if isinstance(item, dict) else {"item": {}, "error": str(item)})
                for item in failed_items[:10]
            ]
        cancelled_items = summary.get("cancelled_items")
        if isinstance(cancelled_items, list):
            compact["cancelled_items_preview"] = [
                self._lightweight_stage_failure(item if isinstance(item, dict) else {"item": {}, "error": str(item)})
                for item in cancelled_items[:10]
            ]
        return self._fit_stage_output_summary_for_db(compact)

    def _fit_stage_output_summary_for_db(self: TaskManager, compact: dict[str, Any], *, max_bytes: int = 32768) -> dict[str, Any]:
        payload = dict(compact or {})

        def encoded_size(value: dict[str, Any]) -> int:
            return len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))

        if encoded_size(payload) <= max_bytes:
            return payload

        items_preview = payload.get("items_preview")
        if isinstance(items_preview, list):
            shrunk_items: list[dict[str, Any]] = []
            for item in items_preview:
                if not isinstance(item, dict):
                    continue
                row = dict(item)
                entries_preview = row.get("entries_preview")
                if isinstance(entries_preview, list):
                    row["entries_preview_count"] = len(entries_preview)
                    row["entries_preview"] = entries_preview[:1]
                shrunk_items.append(row)
            payload["items_preview"] = shrunk_items[:5]
            payload["items_preview_truncated_for_db"] = True
        if encoded_size(payload) <= max_bytes:
            return payload

        for preview_key in ("failed_items_preview", "cancelled_items_preview"):
            rows = payload.get(preview_key)
            if isinstance(rows, list):
                payload[f"{preview_key}_count"] = len(rows)
                payload[preview_key] = rows[:3]
        if encoded_size(payload) <= max_bytes:
            return payload

        scalar_allowlist = {
            "summary_externalized",
            "summary_file",
            "status",
            "sync_status",
            "error",
            "reason",
            "failure_code",
            "failure_category",
            "failure_message",
            "reclaimed",
            "archive_blocked",
            "waiting_manual_confirmation",
            "success_count",
            "failed_count",
            "cancelled_count",
            "entry_count",
            "vuln_result_count",
            "module_count",
            "high_risk_module_count",
            "medium_risk_module_count",
            "low_risk_module_count",
            "candidate_module_count",
            "selected_module_count",
            "total_items",
            "success_items",
            "failed_items_count",
            "running_items",
            "cancelled_items_count",
            "skipped_items",
            "item_count",
            "items_truncated",
            "failed_items_truncated",
            "cancelled_items_truncated",
            "status_synced",
            "streaming_completion_gate_ready",
            "expected_entry_count",
            "materialized_item_count",
            "missing_entry_count",
        }
        fitted = {key: value for key, value in payload.items() if key in scalar_allowlist}
        fitted["db_summary_truncated"] = True
        if encoded_size(fitted) <= max_bytes:
            return fitted

        for verbose_key in ("error", "failure_message", "reason"):
            if isinstance(fitted.get(verbose_key), str):
                fitted[verbose_key] = str(fitted[verbose_key])[:1000]
        return fitted

    def _persist_stage_run_output_summary(
        self: TaskManager,
        task,
        stage_run,
        full_summary: dict[str, Any] | None,
    ) -> dict[str, Any]:
        summary_payload = dict(full_summary or {})
        summary_file: str | None = None
        try:
            path = self._stage_run_summary_path(task, stage_run)
            if self._guard_task_workspace_write(task, purpose="stage_run_summary", path=path):
                task_shared._write_json(path, summary_payload)
                summary_file = str(path)
        except Exception:
            summary_file = None
        compact = self._compact_stage_output_summary_for_db(task, stage_run, summary_payload, summary_file=summary_file)
        stage_run.output_summary = compact
        return compact

    def _update_task_stage_summary_entry(self: TaskManager, task, stage_run) -> None:
        task.stage_summary = {
            **(task.stage_summary or {}),
            stage_run.stage_name: {
                "status": stage_run.status,
                "counts": dict(stage_run.counts or {}),
                "finished_at": stage_run.finished_at.isoformat() if stage_run.finished_at else None,
                "last_error": stage_run.last_error,
            },
        }

    def _merge_task_stage_summary_entry(
        self: TaskManager,
        task,
        stage_run,
        extra: dict[str, Any] | None = None,
    ) -> None:
        self._update_task_stage_summary_entry(task, stage_run)
        task.stage_summary = {
            **(task.stage_summary or {}),
            stage_run.stage_name: {
                **dict((task.stage_summary or {}).get(stage_run.stage_name) or {}),
                **dict(extra or {}),
            },
        }

    async def _persist_stage_run_output_summary_async(
        self: TaskManager,
        task,
        stage_run,
        full_summary: dict[str, Any] | None,
    ) -> dict[str, Any]:
        summary_payload = dict(full_summary or {})
        summary_file: str | None = None
        try:
            path = self._stage_run_summary_path(task, stage_run)
            if self._guard_task_workspace_write(task, purpose="stage_run_summary", path=path):
                await asyncio.to_thread(task_shared._write_json, path, summary_payload)
                summary_file = str(path)
        except Exception:
            summary_file = None
        compact = self._compact_stage_output_summary_for_db(task, stage_run, summary_payload, summary_file=summary_file)
        stage_run.output_summary = compact
        return compact

    def _merge_stage_run_output_summary(
        self: TaskManager,
        task,
        stage_run,
        patch: dict[str, Any] | None,
    ) -> dict[str, Any]:
        merged = {**self._load_stage_run_output_summary_full(task, stage_run), **(patch or {})}
        return self._persist_stage_run_output_summary(task, stage_run, merged)

    async def _merge_stage_run_output_summary_async(
        self: TaskManager,
        task,
        stage_run,
        patch: dict[str, Any] | None,
    ) -> dict[str, Any]:
        merged = {**self._load_stage_run_output_summary_full(task, stage_run), **(patch or {})}
        return await self._persist_stage_run_output_summary_async(task, stage_run, merged)

    def _item_stats(self: TaskManager, items) -> dict[str, dict[str, int]]:
        stats: dict[str, dict[str, int]] = {}
        for item in items:
            entry = stats.setdefault(
                item.stage_name,
                {"total": 0, "success": 0, "failed": 0, "downstream_missing": 0, "skipped": 0, "running": 0, "cancelled": 0, "partial_success": 0},
            )
            entry["total"] += 1
            normalized_status = self._normalize_downstream_status(item.status) or item.status
            if normalized_status in entry:
                entry[normalized_status] += 1
            elif normalized_status in {"pending", "queued", "running", "dispatching"}:
                entry["running"] += 1
        return stats

    def _downstream_status_counts_from_items(
        self: TaskManager,
        items,
    ) -> dict[str, dict[str, int]]:
        counts: dict[str, dict[str, int]] = {}
        for item in items:
            stage_key = str(item.stage_name or "").strip()
            if not stage_key:
                continue
            item_result = self._load_stage_item_result_payload(item)
            sync_observation = dict(item_result.get("sync_observation") or {})
            downstream_status = (
                self._string_or_none(sync_observation.get("downstream_status"))
                or self._string_or_none(item_result.get("downstream_status"))
            )
            display_status = self._downstream_status_display_value(downstream_status)
            stage_counts = counts.setdefault(stage_key, {})
            stage_counts[display_status] = stage_counts.get(display_status, 0) + 1
        return counts

    def _stage_item_stats_from_db(
        self: TaskManager,
        db: Session,
        task_id: str,
    ) -> tuple[dict[str, dict[str, int]], dict[str, dict[str, int]]]:
        from app.service import task_manager as task_manager_module

        item_stats_rows = (
            db.query(
                task_manager_module.BinarySecurityStageItem.stage_name,
                task_manager_module.BinarySecurityStageItem.status,
                func.count(task_manager_module.BinarySecurityStageItem.id),
            )
            .filter(task_manager_module.BinarySecurityStageItem.task_id == task_id)
            .group_by(task_manager_module.BinarySecurityStageItem.stage_name, task_manager_module.BinarySecurityStageItem.status)
            .all()
        )
        item_stats: dict[str, dict[str, int]] = {}
        for stage_name, status, count in item_stats_rows:
            stage_key = str(stage_name or "").strip()
            if not stage_key:
                continue
            entry = item_stats.setdefault(
                stage_key,
                {
                    "total": 0,
                    "success": 0,
                    "failed": 0,
                    "downstream_missing": 0,
                    "skipped": 0,
                    "running": 0,
                    "cancelled": 0,
                    "partial_success": 0,
                },
            )
            normalized_status = self._normalize_downstream_status(status) or str(status or "").strip()
            entry["total"] += int(count or 0)
            if normalized_status in entry:
                entry[normalized_status] += int(count or 0)
            elif normalized_status in {"pending", "queued", "running", "dispatching"}:
                entry["running"] += int(count or 0)

        downstream_rows = (
            db.query(task_manager_module.BinarySecurityStageItem.stage_name, task_manager_module.BinarySecurityStageItem.result_json)
            .filter(task_manager_module.BinarySecurityStageItem.task_id == task_id)
            .all()
        )
        downstream_status_counts: dict[str, dict[str, int]] = {}
        for stage_name, result_json in downstream_rows:
            stage_key = str(stage_name or "").strip()
            if not stage_key:
                continue
            result_payload = {}
            if result_json:
                try:
                    result_payload = json.loads(result_json)
                except Exception:
                    result_payload = {}
            sync_observation = dict(result_payload.get("sync_observation") or {})
            downstream_status = (
                self._string_or_none(sync_observation.get("downstream_status"))
                or self._string_or_none(result_payload.get("downstream_status"))
            )
            display_status = self._downstream_status_display_value(downstream_status)
            counts = downstream_status_counts.setdefault(stage_key, {})
            counts[display_status] = counts.get(display_status, 0) + 1
        return item_stats, downstream_status_counts

    def _aggregate_stage_items(self: TaskManager, db: Session, task, results: list[dict[str, Any]], summary_key: str) -> tuple[str, dict[str, Any]]:
        from app.service import task_manager as task_manager_module

        success = [result["item"] for result in results if result.get("status") == "success"]
        normalized_summary_key = "dataflow_results" if summary_key == "vuln_results" else summary_key
        compact_success = self._compact_stage_success_items(summary_key, success)
        db_success = self._compact_stage_success_items_for_db(normalized_summary_key, compact_success)
        normalized_success = compact_success if summary_key != "vuln_results" else self._compact_stage_success_items("dataflow_results", success)
        has_sync_degraded = any(bool(result.get("sync_degraded")) for result in results)
        has_orchestration_degraded = any(bool(result.get("orchestration_degraded")) for result in results)
        active_results = [result for result in results if result.get("status") in {"pending", "queued", "running", "dispatching"}]
        reconcile_waiting = [result for result in active_results if result.get("deferred_mode") == "reconcile"]
        redispatch_waiting = [result for result in active_results if result.get("deferred_mode") == "redispatch"]
        archive_blocked = [result for result in results if result.get("status") == "archive_blocked" or result.get("archive_blocked")]
        if archive_blocked:
            summary = {
                "items": db_success,
                "failed_items": [],
                "cancelled_items": [],
                "success_count": len(compact_success),
                "failed_count": 0,
                "orchestration_failed_count": 0,
                "downstream_missing_count": 0,
                "downstream_status_counts": {},
                "entry_count": self._entry_count_for_summary(normalized_summary_key, normalized_success),
                "vuln_result_count": len(normalized_success) if normalized_summary_key == "dataflow_results" else 0,
                "items_truncated": len(db_success) < len(compact_success),
                "archive_blocked": True,
                "error": archive_blocked[0].get("error") or "总任务产物归档失败",
            }
            next_summary = {**task.summary, summary_key: compact_success}
            if summary_key == "vuln_results":
                next_summary["dataflow_results"] = list(normalized_success)
            task.summary = next_summary
            db.commit()
            return "success", summary
        failed_all = [self._lightweight_stage_failure(result) for result in results if result.get("status") == "failed"]
        downstream_missing_all = [self._lightweight_stage_failure(result) for result in results if result.get("status") == "downstream_missing"]
        cancelled_all = [self._lightweight_stage_failure(result) for result in results if result.get("status") == "cancelled"]
        failed_like_all = failed_all + downstream_missing_all
        downstream_status_counts: dict[str, int] = {}
        for result in results:
            item_payload = dict(result.get("item") or {})
            downstream = dict(item_payload.get("downstream") or {})
            raw_downstream_status = str(downstream.get("status") or "").strip().lower()
            if not raw_downstream_status:
                continue
            downstream_status_counts[raw_downstream_status] = downstream_status_counts.get(raw_downstream_status, 0) + 1
        failed = failed_like_all[:task_manager_module.DB_FAILURE_ITEM_LIMIT]
        cancelled = cancelled_all[:task_manager_module.DB_FAILURE_ITEM_LIMIT]
        running_active = [result for result in active_results if result.get("status") == "running" or result.get("deferred_mode") == "reconcile"]
        dispatching_active = [
            result
            for result in active_results
            if result.get("status") == "dispatching"
            and not result.get("failed")
            and not result.get("terminal")
        ]
        pending_active = [result for result in active_results if result.get("status") in {"pending", "queued"} or result.get("deferred_mode") == "redispatch"]
        if has_sync_degraded or has_orchestration_degraded:
            status = "running" if running_active or reconcile_waiting else "pending"
        elif reconcile_waiting:
            status = "running"
        elif running_active:
            status = "running"
        elif dispatching_active:
            status = "dispatching"
        elif pending_active or redispatch_waiting:
            status = "pending"
        elif failed_like_all and success:
            status = "success" if normalized_summary_key == "dataflow_results" else "partial_success"
        elif failed_like_all:
            status = "failed"
        elif cancelled and not success:
            status = "cancelled"
        else:
            status = "success"
        summary = {
            "items": db_success,
            "failed_items": failed,
            "cancelled_items": cancelled,
            "success_count": len(compact_success),
            "failed_count": len(failed_like_all),
            "orchestration_failed_count": len(failed_like_all),
            "downstream_missing_count": len(downstream_missing_all),
            "cancelled_count": len(cancelled_all),
            "downstream_status_counts": downstream_status_counts,
            "running_count": len(running_active),
            "dispatching_count": len(dispatching_active),
            "pending_count": len(pending_active),
            "entry_count": self._entry_count_for_summary(normalized_summary_key, normalized_success),
            "vuln_result_count": len(normalized_success) if normalized_summary_key == "dataflow_results" else 0,
            "items_truncated": len(db_success) < len(compact_success),
            "failed_items_truncated": len(failed) < len(failed_like_all),
            "cancelled_items_truncated": len(cancelled) < len(cancelled_all),
            "error": failed[0].get("error") if failed else cancelled[0].get("error") if cancelled else None,
        }
        next_summary = {**task.summary, summary_key: compact_success}
        if summary_key == "vuln_results":
            next_summary["dataflow_results"] = list(normalized_success)
        task.summary = next_summary
        db.commit()
        return status, summary

    def _compact_stage_success_items(self: TaskManager, summary_key: str, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        stage_name = {
            "firmware_unpack_results": "firmware_unpack",
            "b2s_results": "binary_to_source",
            "entry_results": "entry_analysis",
            "dataflow_results": "dataflow_vuln_scan",
            "vuln_results": "dataflow_vuln_scan",
        }.get(summary_key)
        handler = self._stage_handler(stage_name)
        if handler is not None and handler.manages_stage_compaction():
            return handler.compact_success_items(self, items, summary_key=summary_key)
        compactors = {
            "firmware_unpack_results": self._compact_firmware_unpack_summary_item,
            "b2s_results": self._compact_b2s_summary_item,
            "entry_results": self._compact_entry_summary_item,
            "dataflow_results": self._compact_dataflow_summary_item,
            "vuln_results": self._compact_vuln_summary_item,
        }
        compactor = compactors.get(summary_key)
        if compactor is None:
            return [dict(item) for item in items if isinstance(item, dict)]
        compacted = [compactor(item) for item in items if isinstance(item, dict)]
        if summary_key in {"dataflow_results", "vuln_results"}:
            deduped: dict[tuple[str, str], dict[str, Any]] = {}
            for row in compacted:
                key = (
                    str(row.get("entry_key") or "").strip(),
                    str(row.get("module_key") or "").strip(),
                )
                if key == ("", ""):
                    key = (str(len(deduped)), "")
                deduped[key] = row
            return list(deduped.values())
        return compacted

    def _compact_stage_success_items_for_db(self: TaskManager, summary_key: str, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        from app.service import task_manager as task_manager_module

        if summary_key == "entry_results":
            return [self._compact_entry_summary_item_for_db(item) for item in items[:task_manager_module.DB_SUMMARY_ITEM_LIMIT] if isinstance(item, dict)]
        return [dict(item) for item in items[:task_manager_module.DB_SUMMARY_ITEM_LIMIT] if isinstance(item, dict)]

    def _entry_count_for_summary(self: TaskManager, summary_key: str, items: list[dict[str, Any]]) -> int:
        if summary_key != "entry_results":
            return 0
        return sum(len(item.get("entries") or []) for item in items if isinstance(item, dict))

    def _compact_firmware_unpack_summary_item(self: TaskManager, item: dict[str, Any]) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        unpacked_root = item.get("unpacked_root")
        return {
            "firmware_key": item.get("firmware_key"),
            "firmware_name": item.get("firmware_name"),
            "filename": item.get("filename"),
            "input_path": item.get("input_path"),
            "unpacked_root": unpacked_root,
            "source_root": item.get("source_root") or unpacked_root,
            "task_type": item.get("task_type", task_manager_module.TASK_TYPE_BINARY),
        }

    def _compact_b2s_summary_item(self: TaskManager, item: dict[str, Any]) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        task_type = item.get("task_type")
        row = {
            "firmware_key": item.get("firmware_key"),
            "firmware_name": item.get("firmware_name"),
            "filename": item.get("filename"),
            "unpacked_root": item.get("unpacked_root"),
            "source_root": item.get("source_root"),
            "task_type": task_type,
            "module_key": item.get("module_key"),
            "module_name": item.get("module_name"),
            "module_dir": item.get("module_dir"),
            "source_dir": item.get("source_dir"),
            "module_report": item.get("module_report"),
            "files_list": item.get("files_list"),
            "entry_module_name": item.get("entry_module_name"),
            "entry_descriptor_root": item.get("entry_descriptor_root"),
            "entry_files_list": item.get("entry_files_list"),
            "entry_source_file_count": item.get("entry_source_file_count"),
            "entry_source_files_preview": item.get("entry_source_files_preview"),
            "entry_descriptor_ready": item.get("entry_descriptor_ready", False),
            "primary_result_kind": item.get("primary_result_kind"),
            "result_kinds": [str(kind).strip() for kind in (item.get("result_kinds") or []) if str(kind).strip()],
            "artifact_kind_summary": dict(item.get("artifact_kind_summary") or item.get("artifact_summary") or {}),
            "result_kind_summary": dict(item.get("result_kind_summary") or {}),
            "artifact_index_path": item.get("artifact_index_path"),
            "result_summary_version": item.get("result_summary_version") or 1,
        }
        if task_type in {task_manager_module.TASK_TYPE_SOURCE, task_manager_module.TASK_TYPE_BINARY_MODULE}:
            row["artifact_root"] = item.get("artifact_root")
            row["archive_root"] = item.get("archive_root")
            row["descriptor_root"] = item.get("descriptor_root")
            row["files_list_path"] = item.get("files_list_path")
        return row

    def _compact_entry_summary_item(self: TaskManager, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "firmware_key": item.get("firmware_key"),
            "firmware_name": item.get("firmware_name"),
            "filename": item.get("filename"),
            "unpacked_root": item.get("unpacked_root"),
            "source_root": item.get("source_root"),
            "module_key": item.get("module_key"),
            "module_name": item.get("module_name"),
            "module_dir": item.get("module_dir"),
            "source_dir": item.get("source_dir"),
            "artifact_root": item.get("artifact_root"),
            "entries": self._compact_entry_rows(item.get("entries") or []),
        }

    def _lightweight_stage_failure(self: TaskManager, result: dict[str, Any]) -> dict[str, Any]:
        item = result.get("item") or {}
        if not isinstance(item, dict):
            item = {}
        error = str(result.get("error") or "")[:1000]
        return {
            "status": result.get("status"),
            "error": error,
            "item": {
                "firmware_key": item.get("firmware_key"),
                "firmware_name": item.get("firmware_name"),
                "module_key": item.get("module_key"),
                "module_name": item.get("module_name"),
                "entry_key": item.get("entry_key"),
                "function_name": item.get("function_name"),
                "file_name": item.get("file_name"),
                "line_no": item.get("line_no"),
                "source_dir": item.get("source_dir"),
            },
        }

    def list_reducer_event_records(
        self: TaskManager,
        db: Session,
        *,
        page: int = 1,
        page_size: int = 50,
        sort_by: str = "processed_at",
        sort_order: str = "desc",
        statuses: list[str] | None = None,
        event_type: str | None = None,
        handler_pod: str | None = None,
        task_id: str | None = None,
        failed_only: bool = False,
        slow_only: bool = False,
    ):
        from app.service import task_manager as task_manager_module

        normalized_statuses = [
            str(value or "").strip()
            for value in (statuses or [])
            if str(value or "").strip() in {"pending", "processing", "retryable", "dead_letter", "processed"}
        ]
        events = (
            db.query(task_manager_module.BinarySecurityStateEvent)
            .order_by(task_manager_module.BinarySecurityStateEvent.created_at.desc())
            .limit(task_manager_module.REDUCER_EVENT_LIMIT_CAP)
            .all()
        )
        filtered_events = self._filter_reducer_events(
            events,
            statuses=normalized_statuses,
            event_type=event_type,
            handler_pod=handler_pod,
            task_id=task_id,
            failed_only=failed_only,
            slow_only=slow_only,
        )
        sort_descriptor = self._reducer_event_sort_key(sort_by=sort_by, sort_order=sort_order)
        filtered_events.sort(key=sort_descriptor["key"], reverse=sort_descriptor["reverse"])
        total = len(filtered_events)
        start = max(0, (page - 1) * page_size)
        end = start + page_size
        return task_manager_module.BinarySecurityReducerEventPageResponse(
            total=min(total, task_manager_module.REDUCER_EVENT_LIMIT_CAP),
            page=page,
            page_size=page_size,
            truncated=total >= task_manager_module.REDUCER_EVENT_LIMIT_CAP,
            items=[self._build_reducer_event_record(event) for event in filtered_events[start:end]],
            summary=self._build_reducer_event_summary(filtered_events),
        )

    def _filter_reducer_events(
        self: TaskManager,
        events,
        *,
        statuses: list[str],
        event_type: str | None,
        handler_pod: str | None,
        task_id: str | None,
        failed_only: bool,
        slow_only: bool,
    ):
        from app.service import task_manager as task_manager_module

        normalized_event_type = str(event_type or "").strip()
        normalized_handler = str(handler_pod or "").strip()
        normalized_task_id = str(task_id or "").strip()
        result = []
        for event in events:
            if statuses and str(event.status or "").strip() not in statuses:
                continue
            if normalized_event_type and str(event.event_type or "").strip() != normalized_event_type:
                continue
            handler = str(getattr(event, "processed_by", None) or event.leased_by or "").strip()
            if normalized_handler and handler != normalized_handler:
                continue
            if normalized_task_id and str(event.task_id or "").strip() != normalized_task_id:
                continue
            record = self._build_reducer_event_record(event)
            if failed_only and record.failure_kind == "none":
                continue
            if slow_only and (record.processing_duration_ms or 0) < task_manager_module.REDUCER_EVENT_SLOW_THRESHOLD_MS:
                continue
            result.append(event)
        return result

    def _reducer_event_sort_key(self: TaskManager, *, sort_by: str, sort_order: str) -> dict[str, Any]:
        normalized_sort_by = str(sort_by or "processed_at").strip()
        reverse = str(sort_order or "desc").strip().lower() != "asc"
        if normalized_sort_by == "duration_ms":
            return {
                "key": lambda event: (
                    self._event_processing_duration_ms(event) is None,
                    self._event_processing_duration_ms(event) or -1,
                    event.updated_at or event.created_at or datetime.min,
                    event.id,
                ),
                "reverse": reverse,
            }
        if normalized_sort_by == "created_at":
            return {
                "key": lambda event: (
                    event.created_at or datetime.min,
                    event.updated_at or datetime.min,
                    event.id,
                ),
                "reverse": reverse,
            }
        return {
            "key": lambda event: (
                self._event_processed_at(event) or event.created_at or datetime.min,
                event.created_at or datetime.min,
                event.id,
            ),
            "reverse": reverse,
        }

    def _build_reducer_event_summary(self: TaskManager, events):
        from app.service import task_manager as task_manager_module

        counts = {"pending": 0, "processing": 0, "retryable": 0, "dead_letter": 0, "processed": 0}
        durations: list[int] = []
        slow_count = 0
        failed_like_count = 0
        for event in events:
            status = str(event.status or "pending").strip()
            if status in counts:
                counts[status] += 1
            record = self._build_reducer_event_record(event)
            if record.failure_kind != "none":
                failed_like_count += 1
            if record.processing_duration_ms is not None:
                durations.append(record.processing_duration_ms)
                if record.processing_duration_ms >= task_manager_module.REDUCER_EVENT_SLOW_THRESHOLD_MS:
                    slow_count += 1
        durations.sort()
        avg_duration = round(sum(durations) / len(durations), 2) if durations else None
        p95_duration = durations[max(0, int(round((len(durations) - 1) * 0.95)))] if durations else None
        max_duration = durations[-1] if durations else None
        return task_manager_module.BinarySecurityReducerEventSummaryResponse(
            pending_count=counts["pending"],
            processing_count=counts["processing"],
            retryable_count=counts["retryable"],
            dead_letter_count=counts["dead_letter"],
            processed_count=counts["processed"],
            failed_like_count=failed_like_count,
            slow_event_count=slow_count,
            max_processing_duration_ms=max_duration,
            p95_processing_duration_ms=p95_duration,
            avg_processing_duration_ms=avg_duration,
        )

    def _build_reducer_event_record(self: TaskManager, event):
        from app.service import task_manager as task_manager_module

        processed_at = self._event_processed_at(event)
        processing_started_at = getattr(event, "processing_started_at", None)
        processing_duration_ms = self._event_processing_duration_ms(event)
        queue_wait_ms = self._duration_ms(event.created_at, processing_started_at)
        end_to_end_duration_ms = self._duration_ms(event.created_at, processed_at)
        handler = str(getattr(event, "processed_by", None) or event.leased_by or "").strip() or None
        return task_manager_module.BinarySecurityReducerEventRecordResponse(
            event_id=event.id,
            task_id=event.task_id,
            project_id=event.project_id,
            stage_name=event.stage_name,
            event_type=event.event_type,
            queue_status=str(event.status or "pending"),
            attempts=int(event.attempts or 0),
            leased_by=event.leased_by,
            processed_by=handler,
            available_at=event.available_at,
            created_at=event.created_at,
            processing_started_at=processing_started_at,
            processed_at=processed_at,
            processing_duration_ms=processing_duration_ms,
            queue_wait_ms=queue_wait_ms,
            end_to_end_duration_ms=end_to_end_duration_ms,
            result=self._event_result(event),
            failure_kind=self._event_failure_kind(event),
            failure_reason=self._event_failure_reason(event),
            last_error_message=event.last_error_message or event.error_message,
            idempotency_key=event.idempotency_key,
        )

    def _event_processed_at(self: TaskManager, event) -> datetime | None:
        return getattr(event, "processed_at", None) or getattr(event, "processing_finished_at", None)

    def _event_processing_duration_ms(self: TaskManager, event) -> int | None:
        return self._duration_ms(getattr(event, "processing_started_at", None), self._event_processed_at(event))

    def _duration_ms(self: TaskManager, started_at: datetime | None, finished_at: datetime | None) -> int | None:
        if started_at is None or finished_at is None:
            return None
        return max(0, int(round((finished_at - started_at).total_seconds() * 1000)))

    def _event_result(self: TaskManager, event) -> str:
        return str(
            getattr(event, "processing_result", None)
            or ("dead_letter" if str(event.status or "").strip() == "dead_letter" else str(event.status or "unknown"))
        ).strip()

    def _is_lock_busy_state_event(self: TaskManager, event) -> bool:
        if event is None:
            return False
        result = str(getattr(event, "processing_result", None) or "").strip()
        error = str(getattr(event, "last_error_message", None) or getattr(event, "error_message", None) or "").strip().lower()
        return result == "lock_busy_backoff" or error == "task state lease busy"

    def _lock_busy_backoff_seconds(self: TaskManager, event) -> int:
        attempts = max(1, int(getattr(event, "attempts", 1) or 1))
        return min(300, 2 ** attempts)

    def _event_failure_kind(self: TaskManager, event) -> str:
        status = str(getattr(event, "status", None) or "").strip()
        result = str(getattr(event, "processing_result", None) or "").strip()
        if status == "dead_letter":
            return "dead_letter"
        if self._is_lock_busy_state_event(event):
            return "lock_busy"
        if status == "retryable" or result == "retryable":
            return "retryable"
        if result in {"failed", "error"}:
            return "failed"
        return "none"

    def _event_failure_reason(self: TaskManager, event) -> str | None:
        if self._is_lock_busy_state_event(event):
            return "task state lease busy"
        return str(getattr(event, "last_error_message", None) or getattr(event, "error_message", None) or "").strip() or None

    def _normalize_module_report_ref(
        self: TaskManager,
        module: dict[str, Any],
        source_tag: str,
    ) -> dict[str, Any] | None:
        if not isinstance(module, dict):
            return None
        module_key = str(module.get("module_key") or "").strip()
        if not module_key:
            return None
        module_name = str(module.get("module_name") or module_key).strip() or module_key
        module_dir = str(module.get("module_dir") or module.get("source_dir") or "").strip()
        raw_report_path = str(module.get("module_report") or module.get("module_report_path") or "").strip()
        report_path = raw_report_path
        if not report_path and module_dir:
            report_path = str(Path(module_dir) / "module_report.md")
        return {
            "module_key": module_key,
            "module_name": module_name,
            "module_dir": module_dir or None,
            "module_report_path": report_path or None,
            "risk_level": task_shared._normalize_module_risk_level(module.get("risk_level"), module.get("risk_score")) or module.get("risk_level"),
            "risk_score": module.get("risk_score"),
            "file_count": module.get("file_count"),
            "files_list_path": str(module.get("files_list") or module.get("files_list_path") or "").strip() or None,
            "source_tags": [source_tag],
        }

    def _module_report_refs(self: TaskManager, task) -> dict[str, dict[str, Any]]:
        summary = task.summary or {}
        merged: dict[str, dict[str, Any]] = {}

        def absorb(modules: list[dict[str, Any]], source_tag: str) -> None:
            for module in modules:
                normalized = self._normalize_module_report_ref(module, source_tag)
                if not normalized:
                    continue
                module_key = normalized["module_key"]
                existing = merged.get(module_key)
                if existing is None:
                    merged[module_key] = normalized
                    continue
                existing_tags = existing.setdefault("source_tags", [])
                for tag in normalized.get("source_tags") or []:
                    if tag not in existing_tags:
                        existing_tags.append(tag)
                if not existing.get("module_report_path") and normalized.get("module_report_path"):
                    existing["module_report_path"] = normalized["module_report_path"]
                if not existing.get("module_dir") and normalized.get("module_dir"):
                    existing["module_dir"] = normalized["module_dir"]
                if existing.get("risk_level") in (None, "", "未知") and normalized.get("risk_level"):
                    existing["risk_level"] = normalized["risk_level"]
                if existing.get("risk_score") in (None, "") and normalized.get("risk_score") not in (None, ""):
                    existing["risk_score"] = normalized["risk_score"]
                if existing.get("file_count") in (None, "") and normalized.get("file_count") not in (None, ""):
                    existing["file_count"] = normalized["file_count"]
                if not existing.get("files_list_path") and normalized.get("files_list_path"):
                    existing["files_list_path"] = normalized["files_list_path"]

        absorb(list(summary.get("system_analysis_modules") or []), "系统分析")
        absorb(list(summary.get("candidate_modules") or []), "候选")
        absorb(list(summary.get("selected_modules") or []), "已选")
        return merged

    def _resolve_module_report_path(self: TaskManager, ref: dict[str, Any]) -> Path | None:
        candidates: list[Path] = []
        raw_report_path = str(ref.get("module_report_path") or "").strip()
        if raw_report_path:
            candidates.append(Path(raw_report_path))
        raw_module_dir = str(ref.get("module_dir") or "").strip()
        if raw_module_dir:
            module_dir = Path(raw_module_dir)
            candidates.append(module_dir / "module_report.md")
            candidates.append(module_dir / "modules_report.md")
        seen: set[str] = set()
        for candidate in candidates:
            key = str(candidate)
            if not key or key in seen:
                continue
            seen.add(key)
            if candidate.is_file():
                return candidate
        return candidates[0] if candidates else None

    def _infer_module_file_count(self: TaskManager, ref: dict[str, Any]) -> int | None:
        raw_count = ref.get("file_count")
        if raw_count not in (None, ""):
            try:
                return int(raw_count)
            except (TypeError, ValueError):
                pass
        files_list_path = str(ref.get("files_list_path") or "").strip()
        if not files_list_path:
            return None
        candidate = Path(files_list_path)
        if not candidate.is_file():
            return None
        try:
            return len([line for line in task_shared._read_text(candidate).splitlines() if line.strip()])
        except OSError:
            return None

    def get_module_report(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        module_key: str,
    ):
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        normalized_module_key = str(module_key or "").strip()
        if not normalized_module_key:
            raise ValidationError("module_key 不能为空")
        ref = self._module_report_refs(task).get(normalized_module_key)
        if ref is None:
            raise NotFoundError("模块不存在或不属于当前任务")
        report_path = self._resolve_module_report_path(ref)
        warning: str | None = None
        error_message: str | None = None
        markdown: str | None = None
        available = False
        if report_path is None:
            error_message = "该模块尚未记录可读取的模块报告路径"
        elif not report_path.is_file():
            error_message = "该模块尚未生成可展示的系统分析报告"
        else:
            try:
                markdown = task_shared._read_text(report_path)
                available = True
                if not markdown.strip():
                    warning = "模块报告文件为空"
            except OSError as exc:
                error_message = f"模块报告读取失败: {exc}"
        return task_manager_module.BinarySecurityModuleReportDetailResponse(
            task_id=task.id,
            module_key=normalized_module_key,
            module_name=str(ref.get("module_name") or normalized_module_key),
            module_report_path=str(report_path) if report_path else None,
            module_report_markdown=markdown,
            risk_level=str(ref.get("risk_level") or "").strip() or None,
            risk_score=float(ref["risk_score"]) if ref.get("risk_score") not in (None, "") else None,
            file_count=self._infer_module_file_count(ref),
            source_tags=list(ref.get("source_tags") or []),
            available=available,
            warning=warning,
            error_message=error_message,
        )

    def get_entry_selection(self: TaskManager, db: Session, *, project_id: str, task_id: str):
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        snapshot = self._entry_selection_snapshot(task)
        entry_results = self._entry_results(task)
        candidate_entries = self._entry_candidates(task)
        selected_entries = self._selected_entries(task)
        selected_keys = self._selected_entry_keys(task)
        confirmed_at = None
        raw_confirmed_at = snapshot.get("confirmed_at")
        if isinstance(raw_confirmed_at, str) and raw_confirmed_at.strip():
            try:
                confirmed_at = datetime.fromisoformat(raw_confirmed_at)
            except ValueError:
                confirmed_at = None
        return task_manager_module.BinarySecurityEntrySelectionResponse(
            task_id=task.id,
            status=task.status,
            selection_mode=self._entry_selection_mode(task),
            requires_confirmation=task.status == task_manager_module.TASK_STATUS_PENDING_ENTRY_CONFIRMATION,
            candidate_entries=candidate_entries,
            selected_entry_keys=selected_keys,
            selected_entries=selected_entries,
            entry_results=entry_results,
            confirmed_at=confirmed_at,
        )

    def _build_task_detail_context(self: TaskManager, db: Session, *, project_id: str, task_id: str):
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        stage_runs = (
            db.query(task_manager_module.BinarySecurityStageRun)
            .options(
                load_only(
                    task_manager_module.BinarySecurityStageRun.id,
                    task_manager_module.BinarySecurityStageRun.task_id,
                    task_manager_module.BinarySecurityStageRun.project_id,
                    task_manager_module.BinarySecurityStageRun.stage_name,
                    task_manager_module.BinarySecurityStageRun.sequence_no,
                    task_manager_module.BinarySecurityStageRun.status,
                    task_manager_module.BinarySecurityStageRun.retry_count,
                    task_manager_module.BinarySecurityStageRun.last_error,
                    task_manager_module.BinarySecurityStageRun.started_at,
                    task_manager_module.BinarySecurityStageRun.finished_at,
                    task_manager_module.BinarySecurityStageRun.created_at,
                    task_manager_module.BinarySecurityStageRun.updated_at,
                )
            )
            .filter(task_manager_module.BinarySecurityStageRun.task_id == task.id)
            .order_by(task_manager_module.BinarySecurityStageRun.sequence_no.asc())
            .all()
        )
        stage_items = (
            db.query(task_manager_module.BinarySecurityStageItem)
            .filter(task_manager_module.BinarySecurityStageItem.task_id == task.id)
            .order_by(
                task_manager_module.BinarySecurityStageItem.created_at.asc(),
                task_manager_module.BinarySecurityStageItem.id.asc(),
            )
            .all()
        )
        archive_jobs = (
            db.query(task_manager_module.BinarySecurityArchiveJob)
            .filter(task_manager_module.BinarySecurityArchiveJob.task_id == task.id)
            .order_by(
                task_manager_module.BinarySecurityArchiveJob.created_at.asc(),
                task_manager_module.BinarySecurityArchiveJob.id.asc(),
            )
            .all()
        )
        stage_sequence = self._stage_sequence_for_task(task)
        stage_summaries = self._build_stage_summaries_readonly(db, task, stage_sequence, stage_runs, stage_items)
        abnormal_reason = None
        if isinstance(task.latest_abnormal_reason, dict):
            try:
                abnormal_reason = task_manager_module.BinarySecurityAbnormalReason(**task.latest_abnormal_reason)
            except Exception:
                abnormal_reason = None
        if abnormal_reason is None:
            abnormal_reason = self._task_abnormal_reason(task, stage_summaries, stage_items, archive_jobs)
        (
            last_successful_sync_at,
            last_sync_attempt_at,
            last_sync_error_at,
            last_sync_error_type,
            last_sync_error_message,
            active_sync_error_item_count,
            never_synced_item_count,
            stale_synced_item_count,
        ) = self._task_sync_status_view(stage_items)
        return task_manager_module._TaskDetailContext(
            task=task,
            queue_info=self._build_queue_info(db, project_id=project_id),
            stage_sequence=stage_sequence,
            stage_runs=stage_runs,
            stage_items=stage_items,
            archive_jobs=archive_jobs,
            stage_summaries=stage_summaries,
            abnormal_reason=abnormal_reason,
            stage_items_total=len(stage_items),
            item_stats=self._item_stats(stage_items),
            last_successful_sync_at=last_successful_sync_at,
            last_sync_attempt_at=last_sync_attempt_at,
            last_sync_error_at=last_sync_error_at,
            last_sync_error_type=last_sync_error_type,
            last_sync_error_message=last_sync_error_message,
            active_sync_error_item_count=active_sync_error_item_count,
            never_synced_item_count=never_synced_item_count,
            stale_synced_item_count=stale_synced_item_count,
        )

    def _build_light_task_detail_context(self: TaskManager, db: Session, *, project_id: str, task_id: str):
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        stage_runs = (
            db.query(task_manager_module.BinarySecurityStageRun)
            .filter(task_manager_module.BinarySecurityStageRun.task_id == task.id)
            .order_by(task_manager_module.BinarySecurityStageRun.sequence_no.asc())
            .all()
        )
        stage_items = (
            db.query(task_manager_module.BinarySecurityStageItem)
            .options(
                load_only(
                    task_manager_module.BinarySecurityStageItem.id,
                    task_manager_module.BinarySecurityStageItem.task_id,
                    task_manager_module.BinarySecurityStageItem.project_id,
                    task_manager_module.BinarySecurityStageItem.stage_run_id,
                    task_manager_module.BinarySecurityStageItem.stage_name,
                    task_manager_module.BinarySecurityStageItem.item_key,
                    task_manager_module.BinarySecurityStageItem.item_name,
                    task_manager_module.BinarySecurityStageItem.parent_key,
                    task_manager_module.BinarySecurityStageItem.item_identity_key,
                    task_manager_module.BinarySecurityStageItem.status,
                    task_manager_module.BinarySecurityStageItem.error_message,
                    task_manager_module.BinarySecurityStageItem.downstream_service,
                    task_manager_module.BinarySecurityStageItem.downstream_task_id,
                    task_manager_module.BinarySecurityStageItem.input_ref_json,
                    task_manager_module.BinarySecurityStageItem.output_ref_json,
                    task_manager_module.BinarySecurityStageItem.result_json,
                    task_manager_module.BinarySecurityStageItem.started_at,
                    task_manager_module.BinarySecurityStageItem.finished_at,
                    task_manager_module.BinarySecurityStageItem.created_at,
                    task_manager_module.BinarySecurityStageItem.updated_at,
                )
            )
            .filter(task_manager_module.BinarySecurityStageItem.task_id == task.id)
            .order_by(
                task_manager_module.BinarySecurityStageItem.created_at.asc(),
                task_manager_module.BinarySecurityStageItem.id.asc(),
            )
            .limit(task_manager_module.DETAIL_STAGE_ITEMS_LIMIT)
            .all()
        )
        sync_items = (
            db.query(task_manager_module.BinarySecurityStageItem)
            .options(
                load_only(
                    task_manager_module.BinarySecurityStageItem.id,
                    task_manager_module.BinarySecurityStageItem.result_json,
                    task_manager_module.BinarySecurityStageItem.status,
                )
            )
            .filter(task_manager_module.BinarySecurityStageItem.task_id == task.id)
            .all()
        )
        stage_items_total = len(sync_items)
        item_stats = self._item_stats(sync_items)
        downstream_status_counts = self._downstream_status_counts_from_items(sync_items)
        sync_times = self._task_sync_status_view(sync_items)
        archive_jobs = (
            db.query(task_manager_module.BinarySecurityArchiveJob)
            .filter(task_manager_module.BinarySecurityArchiveJob.task_id == task.id)
            .order_by(
                task_manager_module.BinarySecurityArchiveJob.created_at.asc(),
                task_manager_module.BinarySecurityArchiveJob.id.asc(),
            )
            .all()
        )
        stage_sequence = self._stage_sequence_for_task(task)
        stage_summaries = self._build_stage_summaries_readonly(
            db,
            task,
            stage_sequence,
            stage_runs,
            stage_items,
            item_stats=item_stats,
            downstream_status_counts=downstream_status_counts,
            include_retry_support=False,
        )
        abnormal_reason = None
        if isinstance(task.latest_abnormal_reason, dict):
            try:
                abnormal_reason = task_manager_module.BinarySecurityAbnormalReason(**task.latest_abnormal_reason)
            except Exception:
                abnormal_reason = None
        if abnormal_reason is None:
            abnormal_reason = self._task_abnormal_reason(task, stage_summaries, stage_items, archive_jobs)
        return task_manager_module._TaskDetailContext(
            task=task,
            queue_info=self._build_queue_info(db, project_id=project_id),
            stage_sequence=stage_sequence,
            stage_runs=stage_runs,
            stage_items=stage_items,
            archive_jobs=archive_jobs,
            stage_summaries=stage_summaries,
            abnormal_reason=abnormal_reason,
            stage_items_total=int(stage_items_total),
            item_stats=item_stats,
            downstream_status_counts=downstream_status_counts,
            last_successful_sync_at=sync_times[0],
            last_sync_attempt_at=sync_times[1],
            last_sync_error_at=sync_times[2],
            last_sync_error_type=sync_times[3],
            last_sync_error_message=sync_times[4],
            active_sync_error_item_count=sync_times[5],
            never_synced_item_count=sync_times[6],
            stale_synced_item_count=sync_times[7],
        )

    def _task_response(
        self: TaskManager,
        db: Session,
        task,
        queue_info: dict[str, Any] | None = None,
        detail_ctx=None,
        *,
        projection_only: bool = False,
    ):
        from app.service import task_manager as task_manager_module

        if detail_ctx is None:
            active_stage_name = self._active_reconcile_stage_name(task)
            if active_stage_name and not projection_only:
                self._refresh_stage_from_authoritative_items(db, task, active_stage_name)
            stage_runs = (
                db.query(task_manager_module.BinarySecurityStageRun)
                .filter(task_manager_module.BinarySecurityStageRun.task_id == task.id)
                .order_by(task_manager_module.BinarySecurityStageRun.sequence_no.asc())
                .all()
            )
            items = db.query(task_manager_module.BinarySecurityStageItem).filter(task_manager_module.BinarySecurityStageItem.task_id == task.id).all()
            archive_jobs = db.query(task_manager_module.BinarySecurityArchiveJob).filter(task_manager_module.BinarySecurityArchiveJob.task_id == task.id).all()
            stage_sequence = self._stage_sequence_for_task(task)
            stage_summaries = (
                self._build_stage_summaries_readonly(db, task, stage_sequence, stage_runs, items)
                if projection_only
                else self._build_stage_summaries(db, task, stage_sequence, stage_runs, items)
            )
            abnormal_reason = None
            if isinstance(task.latest_abnormal_reason, dict):
                try:
                    abnormal_reason = task_manager_module.BinarySecurityAbnormalReason(**task.latest_abnormal_reason)
                except Exception:
                    abnormal_reason = None
            if abnormal_reason is None:
                abnormal_reason = self._task_abnormal_reason(task, stage_summaries, items, archive_jobs)
        else:
            stage_runs = detail_ctx.stage_runs
            items = detail_ctx.stage_items
            archive_jobs = detail_ctx.archive_jobs
            stage_sequence = detail_ctx.stage_sequence
            stage_summaries = detail_ctx.stage_summaries
            abnormal_reason = detail_ctx.abnormal_reason
        metrics = task.metrics or {}
        queue_info = queue_info or {"pending_positions": {}}
        queue_position = queue_info.get("pending_positions", {}).get(task.id)
        queue_state, recoverable_reason = self._task_queue_state(task, queue_info, db=db)
        task_retry_supported, task_retry_reason, _ = self._task_retry_support(db, task)
        task_continue_supported, task_continue_reason, _ = self._task_continue_support(db, task)
        task_retry_failed_supported, task_retry_failed_reason, _, _ = self._task_retry_failed_items_support(db, task)
        lease_owner, lease_expires_at, lease_source, lease_pod_uid, lease_boot_id, lease_generation = self._task_runtime_lease_view(db, task)
        runtime_phase = self._task_runtime_phase(task)
        task_control_mode = self._task_control_mode(task)
        base_policy = self._task_base_policy(task)
        runtime_override = self._task_runtime_override(task)
        effective_runtime_policy = self._effective_runtime_policy(task)
        if detail_ctx is not None:
            last_successful_sync_at = detail_ctx.last_successful_sync_at
            last_sync_attempt_at = detail_ctx.last_sync_attempt_at
            last_sync_error_at = detail_ctx.last_sync_error_at
            last_sync_error_type = detail_ctx.last_sync_error_type
            last_sync_error_message = detail_ctx.last_sync_error_message
            active_sync_error_item_count = detail_ctx.active_sync_error_item_count
            never_synced_item_count = detail_ctx.never_synced_item_count
            stale_synced_item_count = detail_ctx.stale_synced_item_count
        else:
            stage_items_for_sync = [item for stage_name in stage_sequence for item in self._stage_items(db, task.id, stage_name)]
            (
                last_successful_sync_at,
                last_sync_attempt_at,
                last_sync_error_at,
                last_sync_error_type,
                last_sync_error_message,
                active_sync_error_item_count,
                never_synced_item_count,
                stale_synced_item_count,
            ) = self._task_sync_status_view(stage_items_for_sync)
        manual_operation_state = self._build_manual_operation_state(
            db,
            task,
            task_retry_supported=task_retry_supported,
            task_retry_reason=task_retry_reason,
            task_continue_supported=task_continue_supported,
            task_continue_reason=task_continue_reason,
            task_retry_failed_supported=task_retry_failed_supported,
            task_retry_failed_reason=task_retry_failed_reason,
            stage_summaries=stage_summaries,
        )
        active_stage_run = next((run for run in stage_runs if str(run.stage_name or "").strip() == str(task.current_stage or "").strip()), None)
        tail_summary = self._tail_stage_work_summary(db, task)
        failure_snapshot = self._stage_failure_snapshot(task, active_stage_run)
        terminal_failure = self._task_status_is_terminal(task.status) and str(failure_snapshot.get("failure_category") or "").strip() == "business"
        workflow_snapshots = self._build_workflow_stage_snapshots(db, task, stage_runs=stage_runs)
        workflow_terminalization_ready = self._workflow_ready_for_finalization(workflow_snapshots)
        workflow_blocked_by_stage = self._workflow_blocked_on_stage(task, workflow_snapshots)
        kg_state = dict((task.summary or {}).get("knowledge_graph_state") or {})
        active_operation = self._active_operation(db, task.id)
        if (
            active_operation is not None
            and str(active_operation.operation_type or "").strip() != task_manager_module.TASK_ACTION_CANCEL
        ):
            cancel_operation = None
        else:
            cancel_operation = self._active_cancel_operation(db, task.id) or self._latest_cancel_operation(db, task.id)
        return task_manager_module.BinarySecurityTaskResponse(
            id=task.id,
            project_id=task.project_id,
            task_type=self._task_type(task),
            pipeline_profile=self._pipeline_profile(task),
            name=task.name,
            status=task.status,
            runtime_phase=runtime_phase,
            task_control_mode=task_control_mode,
            current_operation_id=task.current_operation_id,
            execution_epoch=int(getattr(task, "execution_epoch", 0) or 0),
            current_stage=task.current_stage,
            workflow_terminalization_ready=workflow_terminalization_ready,
            workflow_blocked_by_stage=workflow_blocked_by_stage,
            last_error=task.last_error,
            terminal_failure=terminal_failure,
            requeue_suppressed=terminal_failure,
            failure_code=self._string_or_none(failure_snapshot.get("failure_code")) if terminal_failure else None,
            failure_category=self._string_or_none(failure_snapshot.get("failure_category")) if terminal_failure else None,
            failure_message=self._string_or_none(failure_snapshot.get("failure_message") or failure_snapshot.get("error")) if terminal_failure else None,
            firmware_path=task.firmware_path,
            stage_sequence=stage_sequence,
            is_queued=queue_state == "queued",
            queue_position=queue_position,
            queue_state=queue_state,
            recoverable_reason=recoverable_reason,
            last_reconcile_at=queue_info.get("last_reconcile_at"),
            dispatcher_instance_id=task.dispatcher_instance_id,
            task_lease_owner_instance_id=lease_owner,
            task_lease_expires_at=lease_expires_at,
            task_lease_source=lease_source,
            tail_control_mode=str(tail_summary.get("tail_control_mode") or "idle"),
            tail_has_runnable_unbound_items=bool(tail_summary.get("has_runnable_unbound_items")),
            tail_unbound_runnable_item_count=int(tail_summary.get("unbound_runnable_item_count", 0) or 0),
            tail_bound_active_item_count=int(tail_summary.get("bound_active_item_count", 0) or 0),
            tail_has_downstream_refs=bool(tail_summary.get("has_downstream_refs")),
            tail_takeover_required=bool(tail_summary.get("takeover_required")),
            tail_takeover_reason=self._string_or_none(tail_summary.get("takeover_reason")),
            runtime_override_version=int(getattr(task, "runtime_override_version", 0) or 0),
            runtime_override_updated_at=getattr(task, "runtime_override_updated_at", None),
            runtime_override_updated_by=getattr(task, "runtime_override_updated_by", None),
            runtime_policy_effect_scope=self._runtime_policy_effect_scope(task),
            base_policy=base_policy,
            runtime_override=runtime_override,
            effective_runtime_policy=effective_runtime_policy,
            last_successful_downstream_sync_at=last_successful_sync_at,
            last_sync_attempt_at=last_sync_attempt_at,
            last_sync_error_at=last_sync_error_at,
            last_sync_error_type=last_sync_error_type,
            last_sync_error_message=last_sync_error_message,
            active_sync_error_item_count=active_sync_error_item_count,
            never_synced_item_count=never_synced_item_count,
            stale_synced_item_count=stale_synced_item_count,
            created_by=task.created_by,
            created_at=task.created_at,
            updated_at=task.updated_at,
            started_at=task.started_at,
            finished_at=task.finished_at,
            high_risk_module_count=int(metrics.get("high_risk_module_count", 0)),
            medium_risk_module_count=int(metrics.get("medium_risk_module_count", 0)),
            low_risk_module_count=int(metrics.get("low_risk_module_count", 0)),
            candidate_module_count=int(metrics.get("candidate_module_count", 0)),
            selected_module_count=int(metrics.get("selected_module_count", 0)),
            selected_risk_levels=task_shared._normalize_module_risk_levels(
                effective_runtime_policy.get("module_risk_levels")
            ),
            module_selection_mode=self._module_selection_mode(task),
            entry_selection_mode=self._entry_selection_mode(task),
            candidate_entry_count=len(self._entry_candidates(task)),
            selected_entry_count=len(self._effective_entry_inputs(task))
            if self._entry_selection_mode(task) == task_manager_module.ENTRY_SELECTION_MODE_MANUAL_CONFIRM
            else len(self._entry_candidates(task)),
            entry_count=int(metrics.get("entry_count", 0)),
            knowledge_graph_raw_entry_count=int(metrics.get("knowledge_graph_raw_entry_count", 0)),
            knowledge_graph_selected_entry_count=int(metrics.get("knowledge_graph_selected_entry_count", 0)),
            knowledge_graph_filtered_out_count=int(metrics.get("knowledge_graph_filtered_out_count", 0)),
            knowledge_graph_graph_status=self._string_or_none(kg_state.get("graph_status")),
            knowledge_graph_identification_state=self._string_or_none(kg_state.get("identification_state")),
            knowledge_graph_attack_status=self._string_or_none(kg_state.get("attack_status")),
            knowledge_graph_analysis_total=int(kg_state.get("knowledge_graph_analysis_total") or 0),
            knowledge_graph_analysis_identified=int(kg_state.get("knowledge_graph_analysis_identified") or 0),
            knowledge_graph_analysis_pending=int(kg_state.get("knowledge_graph_analysis_pending") or 0),
            knowledge_graph_analysis_confirmed=int(kg_state.get("knowledge_graph_analysis_confirmed") or 0),
            knowledge_graph_analysis_rejected=int(kg_state.get("knowledge_graph_analysis_rejected") or 0),
            vuln_result_count=int(metrics.get("vuln_result_count", 0)),
            firmware_item_count=int(metrics.get("firmware_item_count", 0)),
            unpacked_firmware_count=int(metrics.get("unpacked_firmware_count", 0)),
            failed_firmware_count=int(metrics.get("failed_firmware_count", 0)),
            task_retry_supported=task_retry_supported,
            task_retry_reason=task_retry_reason,
            task_continue_supported=task_continue_supported,
            task_continue_reason=task_continue_reason,
            task_retry_failed_items_supported=task_retry_failed_supported,
            task_retry_failed_items_reason=task_retry_failed_reason,
            abnormal_reason_title=abnormal_reason.title if abnormal_reason else None,
            abnormal_reason_code=abnormal_reason.code if abnormal_reason else None,
            abnormal_reason_category=abnormal_reason.category if abnormal_reason else None,
            abnormal_reason=abnormal_reason,
            stage_summaries=stage_summaries,
            manual_operation_state=manual_operation_state,
            cancel_state=self._cancel_state_from_operation(task, cancel_operation),
            cleanup_state=self._build_cleanup_state(task),
        )

    def _runtime_health_age_status(
        self: TaskManager,
        age_seconds: float | None,
        *,
        healthy_threshold_seconds: int,
        degraded_threshold_seconds: int,
    ) -> str:
        if age_seconds is None:
            return "unknown"
        if age_seconds <= max(1, int(healthy_threshold_seconds)):
            return "healthy"
        if age_seconds <= max(healthy_threshold_seconds, int(degraded_threshold_seconds)):
            return "degraded"
        return "unhealthy"

    def _runtime_health_summary_message(self: TaskManager, overall_status: str) -> str:
        if overall_status == "healthy":
            return "当前父任务相关线程/协程运行正常"
        if overall_status == "degraded":
            return "存在保活老化或轻微状态漂移，建议关注 owner/heartbeat"
        if overall_status == "unhealthy":
            return "存在任务相关运行单元异常，可能影响当前阶段推进或收口"
        if overall_status in {"idle", "terminal"}:
            return "当前任务没有需要持续运行的父任务级线程/协程"
        return "当前无法可靠判断父任务相关线程/协程状态"

    def _build_runtime_health_unit(
        self: TaskManager,
        *,
        unit_key: str,
        unit_label: str,
        unit_kind: str,
        status: str,
        owner_instance_id: str | None = None,
        started_at: datetime | None = None,
        last_heartbeat_at: datetime | None = None,
        detail: str | None = None,
        reason: str | None = None,
        evidence: list[tuple[str, Any]] | None = None,
    ) -> dict[str, Any]:
        rendered_evidence = []
        for label, value in evidence or []:
            if value is None:
                continue
            if isinstance(value, datetime):
                rendered_value = task_shared._isoformat_or_none(value)
            else:
                rendered_value = str(value)
            rendered_evidence.append({"label": label, "value": rendered_value})
        reference_at = last_heartbeat_at
        return {
            "unit_key": unit_key,
            "unit_label": unit_label,
            "unit_kind": unit_kind,
            "status": status,
            "task_scoped": True,
            "owner_instance_id": owner_instance_id,
            "started_at": started_at,
            "last_heartbeat_at": last_heartbeat_at,
            "age_seconds": task_shared._elapsed_seconds_since(reference_at),
            "detail": detail,
            "reason": reason,
            "evidence": rendered_evidence,
        }

    def _runtime_health_group_definition(self: TaskManager, unit_key: str) -> tuple[str, str, str]:
        normalized = str(unit_key or "").strip().lower()
        if normalized == "task_worker":
            return ("execution", "任务执行", "主任务执行协程与 owner/lease 一致性")
        if normalized == "task_heartbeat":
            return ("lease", "保活与心跳", "任务级保活单元、lease 与心跳新鲜度")
        if normalized == "downstream_sync":
            return ("tail", "Tail 收口", "下游同步、tail reconcile 与最终收口推进")
        if normalized == "stage_workers":
            return ("stage_workers", "阶段子协程", "当前活跃 stage item 对应的父任务侧协程观察")
        if normalized == "archive_workers":
            return ("archive", "归档执行", "归档 worker 与归档任务活动状态")
        if normalized == "task_operation":
            return ("operation", "任务操作", "continue/retry/cancel 等任务操作协程与锁")
        return ("other", "其他单元", "未归类的任务 scoped 运行单元")

    def _runtime_health_group_status(self: TaskManager, units: list[dict[str, Any]]) -> str:
        statuses = {str(unit.get("status") or "").strip().lower() for unit in units}
        if "unhealthy" in statuses:
            return "unhealthy"
        if "degraded" in statuses:
            return "degraded"
        if "healthy" in statuses:
            return "healthy"
        if "unknown" in statuses:
            return "unknown"
        if "idle" in statuses:
            return "idle"
        if "done" in statuses or "terminal" in statuses:
            return "terminal"
        return "unknown"

    def _build_runtime_health_groups(self: TaskManager, units: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}
        for unit in units:
            group_key, group_label, description = self._runtime_health_group_definition(str(unit.get("unit_key") or ""))
            bucket = grouped.setdefault(
                group_key,
                {
                    "group_key": group_key,
                    "group_label": group_label,
                    "description": description,
                    "units": [],
                },
            )
            bucket["units"].append(unit)
        groups: list[dict[str, Any]] = []
        for group in grouped.values():
            group_units = list(group["units"])
            groups.append(
                {
                    "group_key": group["group_key"],
                    "group_label": group["group_label"],
                    "description": group["description"],
                    "status": self._runtime_health_group_status(group_units),
                    "active_unit_count": sum(
                        1
                        for unit in group_units
                        if str(unit.get("status") or "").strip().lower() in {"healthy", "degraded", "unhealthy"}
                    ),
                    "units": group_units,
                }
            )
        groups.sort(
            key=lambda group: (
                task_shared._runtime_health_status_rank(str(group.get("status") or "")),
                str(group.get("group_label") or ""),
            ),
            reverse=True,
        )
        return groups

    def _build_runtime_health_spotlight(self: TaskManager, units: list[dict[str, Any]]) -> list[dict[str, Any]]:
        preferred_slots = [
            ("task_worker", "主任务执行协程", "当前父任务推进主协程"),
            ("task_heartbeat", "任务保活/心跳", "任务 lease 与心跳保活"),
            ("downstream_sync", "Tail 收口协程", "下游同步与 tail reconcile"),
            ("stage_workers", "阶段子协程", "活跃 stage item 对应的父任务侧协程"),
            ("task_operation", "任务操作协程", "retry/continue/cancel 操作"),
            ("archive_workers", "归档协程", "产物归档执行单元"),
        ]
        by_key = {str(unit.get("unit_key") or ""): unit for unit in units}
        spotlight: list[dict[str, Any]] = []
        for slot_key, title, subtitle in preferred_slots:
            unit = by_key.get(slot_key)
            if unit is None:
                continue
            spotlight.append(
                {
                    "slot_key": slot_key,
                    "title": title,
                    "subtitle": subtitle,
                    "status": unit.get("status") or "unknown",
                    "unit_key": unit.get("unit_key"),
                    "owner_instance_id": unit.get("owner_instance_id"),
                    "last_heartbeat_at": unit.get("last_heartbeat_at"),
                    "age_seconds": unit.get("age_seconds"),
                    "reason": unit.get("reason"),
                    "evidence": list(unit.get("evidence") or [])[:4],
                }
            )
        return spotlight

    def _runtime_health_snapshot_status(self: TaskManager, *, active: bool, warning: bool = False, error: bool = False) -> str:
        if error:
            return "unhealthy"
        if warning:
            return "degraded"
        if active:
            return "healthy"
        return "idle"

    def _build_runtime_health_snapshot_cards(
        self: TaskManager,
        *,
        task_id: str,
        local_worker_alive: bool,
        last_task_heartbeat_at: datetime | None,
        has_local_owner: bool,
        fake_local_owner: bool,
        owner_count: int,
        local_stage_worker_count: int,
        active_stage_item_count: int,
        local_archive_job_count: int,
        active_archive_job_count: int,
        local_operation_alive: bool,
        operation_lock_owner: str | None,
        operation_lock_heartbeat_at: datetime | None,
    ) -> list[dict[str, Any]]:
        worker_handle = self._workers.get(task_id)
        operation_handle = None
        for candidate in self._operation_workers.values():
            if candidate is not None and not candidate.done():
                operation_handle = candidate
                break
        cards = [
            {
                "card_key": "local_task_runtime",
                "title": "本地任务运行句柄",
                "subtitle": "当前 Pod 内父任务主协程 / heartbeat handle 快照",
                "status": self._runtime_health_snapshot_status(
                    active=local_worker_alive or has_local_owner,
                    warning=bool((not local_worker_alive and has_local_owner) or fake_local_owner),
                    error=fake_local_owner,
                ),
                "message": (
                    "当前 Pod 持有本地父任务执行句柄"
                    if local_worker_alive
                    else "当前 Pod 被标记为任务 owner，但没有本地执行句柄，owner 元数据发生漂移"
                    if fake_local_owner
                    else "当前 Pod 仅持有执行 owner 标记，没有观测到活跃主协程"
                    if has_local_owner
                    else "当前 Pod 未持有该任务的本地父任务执行句柄"
                ),
                "rows": [
                    {"label": "task_id", "value": task_id},
                    {"label": "local_worker_alive", "value": str(local_worker_alive).lower()},
                    {"label": "worker_handle_present", "value": str(worker_handle is not None).lower()},
                    {"label": "worker_done", "value": None if worker_handle is None else str(worker_handle.done()).lower()},
                    {"label": "worker_cancel_requested", "value": None if worker_handle is None else str(bool(worker_handle.cancel_requested)).lower()},
                    {"label": "worker_execution_token", "value": None if worker_handle is None else worker_handle.execution_token},
                    {"label": "worker_lease_owner_instance_id", "value": None if worker_handle is None else worker_handle.lease_owner_instance_id},
                    {"label": "worker_claimed_at", "value": None if worker_handle is None else task_shared._isoformat_or_none(worker_handle.claimed_at)},
                    {"label": "worker_last_progress_at", "value": None if worker_handle is None else task_shared._isoformat_or_none(worker_handle.last_progress_at)},
                    {"label": "runner_task_name", "value": None if worker_handle is None else worker_handle.runner_task.get_name()},
                    {"label": "heartbeat_task_present", "value": None if worker_handle is None else str(worker_handle.heartbeat_task is not None).lower()},
                    {"label": "heartbeat_task_name", "value": None if worker_handle is None or worker_handle.heartbeat_task is None else worker_handle.heartbeat_task.get_name()},
                    {"label": "heartbeat_task_done", "value": None if worker_handle is None or worker_handle.heartbeat_task is None else str(worker_handle.heartbeat_task.done()).lower()},
                    {"label": "local_owner", "value": str(has_local_owner).lower()},
                    {"label": "fake_local_owner", "value": str(fake_local_owner).lower()},
                    {"label": "local_owner_count", "value": str(owner_count)},
                    {"label": "last_local_heartbeat_at", "value": task_shared._isoformat_or_none(last_task_heartbeat_at)},
                ],
            },
            {
                "card_key": "local_stage_workers",
                "title": "本地阶段子协程",
                "subtitle": "当前 Pod 内 stage-item worker 句柄快照",
                "status": self._runtime_health_snapshot_status(
                    active=local_stage_worker_count > 0,
                    warning=bool(local_stage_worker_count == 0 and active_stage_item_count > 0),
                ),
                "message": (
                    f"当前 Pod 观测到 {local_stage_worker_count} 个活跃 stage-item worker"
                    if local_stage_worker_count > 0
                    else "当前 Pod 没有观测到活跃 stage-item worker"
                ),
                "rows": [
                    {"label": "local_stage_worker_count", "value": str(local_stage_worker_count)},
                    {"label": "active_stage_item_count", "value": str(active_stage_item_count)},
                    {"label": "stage_item_worker_handles", "value": str(len(self._stage_item_workers))},
                ],
            },
            {
                "card_key": "local_archive_workers",
                "title": "本地归档协程",
                "subtitle": "当前 Pod 内 archive worker 与活跃归档任务快照",
                "status": self._runtime_health_snapshot_status(
                    active=local_archive_job_count > 0,
                    warning=bool(local_archive_job_count == 0 and active_archive_job_count > 0),
                ),
                "message": (
                    f"当前 Pod 持有 {local_archive_job_count} 个活跃归档任务"
                    if local_archive_job_count > 0
                    else "当前 Pod 没有持有活跃归档任务"
                ),
                "rows": [
                    {"label": "local_archive_job_count", "value": str(local_archive_job_count)},
                    {"label": "active_archive_job_count", "value": str(active_archive_job_count)},
                    {"label": "archive_worker_handles", "value": str(len(self._archive_workers))},
                ],
            },
            {
                "card_key": "local_operation_worker",
                "title": "本地任务操作协程",
                "subtitle": "continue / retry / cancel 对应的 operation worker 与 lock 快照",
                "status": self._runtime_health_snapshot_status(
                    active=local_operation_alive,
                    warning=bool(not local_operation_alive and operation_lock_owner),
                ),
                "message": (
                    "当前 Pod 持有活跃任务操作协程"
                    if local_operation_alive
                    else "当前存在 operation lock，但当前 Pod 没有活跃本地 operation worker"
                    if operation_lock_owner
                    else "当前没有活跃任务操作协程"
                ),
                "rows": [
                    {"label": "local_operation_alive", "value": str(local_operation_alive).lower()},
                    {"label": "operation_handle_present", "value": str(operation_handle is not None).lower()},
                    {"label": "operation_handle_name", "value": None if operation_handle is None else operation_handle.get_name()},
                    {"label": "operation_handle_done", "value": None if operation_handle is None else str(operation_handle.done()).lower()},
                    {"label": "operation_lock_owner", "value": operation_lock_owner},
                    {"label": "operation_lock_heartbeat_at", "value": task_shared._isoformat_or_none(operation_lock_heartbeat_at)},
                    {"label": "operation_worker_handles", "value": str(len(self._operation_workers))},
                ],
            },
        ]
        return cards

    def _runtime_health_loop_snapshot_label(self: TaskManager, loop_key: str) -> str:
        return {
            "task_dispatch": "任务分发 loop",
            "stage_item_dispatch": "阶段子项分发 loop",
            "task_heartbeat": "任务保活 loop",
            "downstream_reconcile": "下游收口 loop",
            "stage_item_sync_reconcile": "阶段同步 reconcile loop",
            "archive_dispatch": "归档分发 loop",
            "archive_runtime_reconcile": "归档 reconcile loop",
            "state_repair_reconcile": "状态修复 loop",
            "state_reducer": "状态归约 reducer loop",
            "readless_reconcile": "readless reconcile loop",
        }.get(str(loop_key or "").strip(), loop_key)

    def _runtime_health_loop_snapshot_status(self: TaskManager, detail: dict[str, Any] | None) -> str:
        if not detail:
            return "unknown"
        if bool(detail.get("task_running")) and bool(detail.get("heartbeat_alive")):
            return "healthy"
        if bool(detail.get("alive")):
            return "degraded"
        return "unhealthy"

    def _build_runtime_health_related_loops(self: TaskManager) -> list[dict[str, Any]]:
        loop_sources = {
            "task_dispatch": getattr(self, "_loop_task", None),
            "stage_item_dispatch": getattr(self, "_stage_item_loop_task", None),
            "task_heartbeat": getattr(self, "_task_heartbeat_loop_task", None),
            "downstream_reconcile": getattr(self, "_downstream_reconcile_task", None),
            "archive_dispatch": getattr(self, "_archive_loop_task", None),
            "archive_runtime_reconcile": getattr(self, "_archive_runtime_reconcile_task", None),
            "stage_item_sync_reconcile": getattr(self, "_stage_item_sync_reconcile_task", None),
            "state_repair_reconcile": getattr(self, "_state_repair_reconcile_task", None),
            "state_reducer": getattr(self, "_state_reducer_loop_task", None),
            "readless_reconcile": getattr(self, "_readless_reconcile_task", None),
        }
        loops: list[dict[str, Any]] = []
        for loop_key, task in loop_sources.items():
            detail = self._loop_runtime_detail(loop_key, task)
            status = self._runtime_health_loop_snapshot_status(detail)
            loops.append(
                {
                    "loop_key": loop_key,
                    "loop_label": self._runtime_health_loop_snapshot_label(loop_key),
                    "status": status,
                    "alive": bool(detail.get("alive")),
                    "task_running": bool(detail.get("task_running")),
                    "heartbeat_alive": bool(detail.get("heartbeat_alive")),
                    "heartbeat_at": task_shared._parse_iso_datetime(detail.get("heartbeat_at")),
                    "heartbeat_age_seconds": detail.get("heartbeat_age_seconds"),
                    "stale_after_seconds": detail.get("stale_after_seconds"),
                    "message": (
                        "loop task 与 heartbeat 都处于活跃窗口"
                        if status == "healthy"
                        else "loop 尚存活，但 task 或 heartbeat 信号不完整"
                        if status == "degraded"
                        else "当前没有观测到稳定的 loop task / heartbeat"
                    ),
                }
            )
        loops.sort(
            key=lambda item: (
                task_shared._runtime_health_status_rank(str(item.get("status") or "")),
                str(item.get("loop_label") or ""),
            ),
            reverse=True,
        )
        return loops

    def _build_task_runtime_health(
        self: TaskManager,
        db: Session,
        task,
        *,
        ctx=None,
    ) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        task_status = str(task.status or "").strip().lower()
        runtime_phase = self._task_runtime_phase(task)
        terminal_statuses = {
            "success",
            "partial_success",
            "failed",
            "cancelled",
            "downstream_missing",
            task_manager_module.TASK_STATUS_CANCEL_FAILED,
        }
        active_task_statuses = {"pending", "dispatching", "running"}
        heartbeat_interval_seconds = max(5, int(getattr(self.cfg.scheduler, "heartbeat_update_interval_seconds", 15) or 15))
        task_operation_lock_heartbeat_interval_seconds = max(
            5,
            int(getattr(self.cfg.scheduler, "task_operation_lock_heartbeat_interval_seconds", 15) or 15),
        )
        worker_stale_seconds = max(
            heartbeat_interval_seconds * 3,
            int(getattr(self.cfg.scheduler, "worker_ready_loop_stale_seconds", 90) or 90),
        )
        sync_stale_seconds = max(60, int(getattr(self.cfg.scheduler, "stage_item_sync_stale_seconds", 300) or 300))
        stage_items = list(ctx.stage_items) if ctx is not None else self._stage_items(db, task.id, task.current_stage or "")
        last_successful_sync_at = ctx.last_successful_sync_at if ctx is not None else None
        last_sync_attempt_at = ctx.last_sync_attempt_at if ctx is not None else None
        last_sync_error_at = ctx.last_sync_error_at if ctx is not None else None
        active_sync_error_item_count = int(ctx.active_sync_error_item_count or 0) if ctx is not None else 0
        never_synced_item_count = int(ctx.never_synced_item_count or 0) if ctx is not None else 0
        stale_synced_item_count = int(ctx.stale_synced_item_count or 0) if ctx is not None else 0
        active_operation = self._active_operation(db, task.id)
        lease_owner, lease_expires_at, lease_source, lease_pod_uid, lease_boot_id, lease_generation = self._task_runtime_lease_view(db, task)
        del lease_pod_uid, lease_boot_id, lease_generation
        local_worker = self._workers.get(task.id)
        local_worker_alive = bool(local_worker is not None and not local_worker.done())
        runtime_lease = self._runtime_lease_for_task(db, task.id)
        last_task_heartbeat_at = getattr(runtime_lease, "heartbeat_at", None)
        has_local_owner = self._has_local_task_execution_owner(task.id)
        owner_count = self._task_execution_owner_count(task.id)
        operation_lock_owner = str(task.operation_lock_owner or "").strip() or None
        operation_lock_heartbeat_at = task.operation_lock_heartbeat_at
        operation_lock_expires_at = task.operation_lock_expires_at
        local_operation_alive = False
        row_owner_is_local = bool(str(task.dispatcher_instance_id or "").strip() == str(self.instance_id or "").strip())
        runtime_supported_locally = self._task_owner_runtime_supported_locally(task, active_operation=active_operation)
        fake_local_owner = bool(
            row_owner_is_local
            and task_status in active_task_statuses
            and not runtime_supported_locally
        )
        active_stage_items = [
            item
            for item in stage_items
            if str(item.status or "").strip().lower() in {"pending", "queued", "dispatching", "running"}
        ]
        local_stage_worker_count = sum(
            1
            for item in active_stage_items
            if (worker := self._stage_item_workers.get(str(item.id or ""))) is not None and not worker.done()
        )
        stage_worker_reference = max(
            (
                timestamp
                for timestamp in (
                    *[item.updated_at for item in active_stage_items if getattr(item, "updated_at", None) is not None],
                    *[item.started_at for item in active_stage_items if getattr(item, "started_at", None) is not None],
                )
                if timestamp is not None
            ),
            default=None,
        )
        active_archive_jobs = (
            db.query(task_manager_module.BinarySecurityArchiveJob)
            .filter(
                task_manager_module.BinarySecurityArchiveJob.task_id == task.id,
                task_manager_module.BinarySecurityArchiveJob.archive_status.in_(["pending", "running", "archived", "applying"]),
            )
            .all()
        )
        local_archive_jobs = [job for job in active_archive_jobs if str(job.owner_id or "").strip() == self.instance_id]
        latest_archive_heartbeat_at = max(
            (job.updated_at or job.started_at for job in active_archive_jobs if (job.updated_at or job.started_at) is not None),
            default=None,
        )
        archive_worker_alive = bool(local_archive_jobs) and any(not worker.done() for worker in self._archive_workers)
        tail_summary = self._tail_stage_work_summary(db, task)
        tail_stage_name = tail_summary.get("active_stage_name")
        tail_unbound_runnable_item_count = int(tail_summary.get("unbound_runnable_item_count", 0) or 0)
        tail_bound_active_item_count = int(tail_summary.get("bound_active_item_count", 0) or 0)
        tail_active_item_count = tail_unbound_runnable_item_count + tail_bound_active_item_count
        tail_has_downstream_refs = bool(tail_summary.get("has_downstream_refs"))
        tail_control_mode = str(tail_summary.get("tail_control_mode") or "idle")
        tail_takeover_required = bool(tail_summary.get("takeover_required"))
        tail_takeover_reason = self._string_or_none(tail_summary.get("takeover_reason"))
        lease_active = bool(lease_expires_at is not None and (task_shared._seconds_until(lease_expires_at) or 0) > 0)
        remote_owner_active = bool(lease_owner and lease_owner != self.instance_id and lease_active)
        units: list[dict[str, Any]] = []

        if task_status in active_task_statuses:
            if runtime_phase == task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
                if lease_active and tail_active_item_count > 0:
                    task_worker_status = "healthy"
                elif lease_active or tail_active_item_count > 0 or tail_has_downstream_refs:
                    task_worker_status = "degraded"
                else:
                    task_worker_status = "unhealthy"
                task_worker_label = "Tail 收敛协程"
                task_worker_detail = "负责流式 tail 的对账、同步与终态收敛"
                task_worker_reason = (
                    "tail runtime lease 与活跃 tail 子项均存在"
                    if task_worker_status == "healthy"
                    else "tail 收敛仍在继续，但 lease 或活跃子项证据不完整"
                    if task_worker_status == "degraded"
                    else "tail 收敛期缺少有效 lease 或活跃 tail 证据"
                )
            else:
                task_worker_status = (
                    "healthy"
                    if (local_worker_alive and has_local_owner)
                    else "degraded"
                    if (local_worker_alive or has_local_owner or lease_expires_at or remote_owner_active)
                    else "unhealthy"
                )
                if fake_local_owner:
                    task_worker_status = "unhealthy"
                if not local_worker_alive and not has_local_owner and lease_expires_at is None:
                    task_worker_status = "unhealthy"
                elif remote_owner_active and not local_worker_alive and not has_local_owner:
                    task_worker_status = "degraded"
                task_worker_label = "主任务执行协程"
                task_worker_detail = "负责当前父任务阶段推进与调度衔接"
                task_worker_reason = (
                    "任务 row owner 指向当前 Pod，但没有本地执行句柄，owner 元数据与真实执行已脱节"
                    if fake_local_owner
                    else
                    "本地任务协程与执行 owner 正常存在"
                    if task_worker_status == "healthy"
                    else "当前任务由远端 owner 持有，本 Pod 仅观察到有效 lease"
                    if remote_owner_active and not local_worker_alive and not has_local_owner
                    else "主任务协程存在但 owner/lease 信号不完整"
                    if task_worker_status == "degraded"
                    else "任务处于活动态，但当前看不到稳定的本地执行协程或 owner"
                )
            units.append(
                self._build_runtime_health_unit(
                    unit_key="task_worker",
                    unit_label=task_worker_label,
                    unit_kind="coroutine",
                    status=task_worker_status,
                    owner_instance_id=str(task.dispatcher_instance_id or "").strip() or lease_owner,
                    started_at=task.started_at,
                    last_heartbeat_at=last_task_heartbeat_at,
                    detail=task_worker_detail,
                    reason=task_worker_reason,
                    evidence=[
                        ("runtime_phase", runtime_phase),
                        ("local_worker_alive", local_worker_alive),
                        ("local_owner_count", owner_count),
                        ("lease_owner", lease_owner),
                        ("lease_source", lease_source),
                        ("lease_expires_at", lease_expires_at),
                        ("tail_stage_name", tail_stage_name),
                        ("tail_active_item_count", tail_active_item_count),
                        ("tail_has_downstream_refs", tail_has_downstream_refs),
                    ],
                )
            )
        else:
            units.append(
                self._build_runtime_health_unit(
                    unit_key="task_worker",
                    unit_label="主任务执行协程",
                    unit_kind="coroutine",
                    status="done" if task_status in terminal_statuses else "idle",
                    owner_instance_id=str(task.dispatcher_instance_id or "").strip() or None,
                    started_at=task.started_at,
                    last_heartbeat_at=last_task_heartbeat_at,
                    detail="负责当前父任务阶段推进与调度衔接",
                    reason="任务当前不要求持续持有主执行协程",
                    evidence=[("task_status", task_status or "-")],
                )
            )

        if active_stage_items:
            stage_age_seconds = task_shared._elapsed_seconds_since(stage_worker_reference)
            if local_stage_worker_count > 0:
                stage_status = self._runtime_health_age_status(
                    stage_age_seconds,
                    healthy_threshold_seconds=heartbeat_interval_seconds * 2,
                    degraded_threshold_seconds=worker_stale_seconds,
                )
            elif runtime_phase == task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
                stage_status = self._runtime_health_age_status(
                    stage_age_seconds,
                    healthy_threshold_seconds=heartbeat_interval_seconds * 2,
                    degraded_threshold_seconds=worker_stale_seconds,
                )
                if stage_status == "unknown":
                    stage_status = "degraded"
            elif remote_owner_active or lease_active:
                stage_status = self._runtime_health_age_status(
                    stage_age_seconds,
                    healthy_threshold_seconds=heartbeat_interval_seconds * 2,
                    degraded_threshold_seconds=worker_stale_seconds,
                )
                if stage_status in {"unknown", "unhealthy"}:
                    stage_status = "degraded"
            else:
                stage_status = "unhealthy" if task_status in {"dispatching", "running"} else "degraded"
            units.append(
                self._build_runtime_health_unit(
                    unit_key="stage_workers",
                    unit_label="阶段子任务协程",
                    unit_kind="coroutine",
                    status=stage_status,
                    owner_instance_id=self.instance_id if local_stage_worker_count > 0 else None,
                    started_at=min((item.started_at for item in active_stage_items if item.started_at is not None), default=None),
                    last_heartbeat_at=stage_worker_reference,
                    detail=f"当前有 {len(active_stage_items)} 个活跃阶段子任务，{local_stage_worker_count} 个由本实例协程驱动",
                    reason=(
                        "阶段子任务协程活跃，最近状态刷新正常"
                        if stage_status == "healthy"
                        else "当前活跃阶段子任务由远端 owner 推进，本 Pod 未持有本地协程"
                        if (remote_owner_active or lease_active) and local_stage_worker_count == 0
                        else "阶段子任务仍在推进，但最近活动已接近陈旧窗口"
                        if stage_status == "degraded"
                        else "存在活跃阶段子任务，但当前没有看到对应的本地协程驱动"
                    ),
                    evidence=[
                        ("active_stage_items", len(active_stage_items)),
                        ("local_stage_worker_count", local_stage_worker_count),
                        ("current_stage", task.current_stage),
                    ],
                )
            )
        else:
            units.append(
                self._build_runtime_health_unit(
                    unit_key="stage_workers",
                    unit_label="阶段子任务协程",
                    unit_kind="coroutine",
                    status="done" if task_status in terminal_statuses else "idle",
                    detail="当前没有需要父任务驱动的活跃阶段子任务",
                    reason="阶段子任务协程当前未启用",
                    evidence=[("current_stage", task.current_stage or "-")],
                )
            )

        if active_archive_jobs:
            archive_age_seconds = task_shared._elapsed_seconds_since(latest_archive_heartbeat_at)
            archive_status = "healthy" if archive_worker_alive else self._runtime_health_age_status(
                archive_age_seconds,
                healthy_threshold_seconds=heartbeat_interval_seconds * 2,
                degraded_threshold_seconds=worker_stale_seconds,
            )
            if archive_status == "healthy" and not local_archive_jobs:
                archive_status = "degraded"
            units.append(
                self._build_runtime_health_unit(
                    unit_key="archive_workers",
                    unit_label="产物归档协程",
                    unit_kind="archive",
                    status=archive_status,
                    owner_instance_id=self.instance_id if local_archive_jobs else (str(active_archive_jobs[0].owner_id or "").strip() or None),
                    started_at=min((job.started_at for job in active_archive_jobs if job.started_at is not None), default=None),
                    last_heartbeat_at=latest_archive_heartbeat_at,
                    detail=f"当前有 {len(active_archive_jobs)} 个归档单元处于活跃链路",
                    reason=(
                        "归档协程与归档任务记录保持一致"
                        if archive_status == "healthy"
                        else "存在归档链路，但当前由其它实例持有或心跳接近陈旧"
                        if archive_status == "degraded"
                        else "归档任务仍处于活跃态，但当前缺少稳定的运行协程证据"
                    ),
                    evidence=[
                        ("active_archive_jobs", len(active_archive_jobs)),
                        ("local_archive_jobs", len(local_archive_jobs)),
                    ],
                )
            )
        else:
            units.append(
                self._build_runtime_health_unit(
                    unit_key="archive_workers",
                    unit_label="产物归档协程",
                    unit_kind="archive",
                    status="done" if task_status in terminal_statuses else "idle",
                    detail="当前没有活跃的归档收口任务",
                    reason="归档协程当前未启用",
                )
            )

        if active_operation is not None or operation_lock_owner or operation_lock_expires_at:
            operation_heartbeat = operation_lock_heartbeat_at
            operation_age_status = self._runtime_health_age_status(
                task_shared._elapsed_seconds_since(operation_heartbeat),
                healthy_threshold_seconds=task_operation_lock_heartbeat_interval_seconds * 2,
                degraded_threshold_seconds=max(task_operation_lock_heartbeat_interval_seconds * 4, worker_stale_seconds),
            )
            local_operation_alive = bool(
                active_operation is not None
                and (worker := self._operation_workers.get(str(active_operation.id or ""))) is not None
                and not worker.done()
            )
            operation_status = operation_age_status
            if local_operation_alive and operation_status == "unknown":
                operation_status = "healthy"
            if active_operation is None and operation_lock_owner and operation_status != "healthy":
                operation_status = "degraded"
            if (
                active_operation is not None
                and str(getattr(active_operation, "status", "") or "").strip().lower() in {"accepted", "queued", "claimed"}
                and not local_operation_alive
            ):
                operation_status = "unhealthy"
            units.append(
                self._build_runtime_health_unit(
                    unit_key="task_operation",
                    unit_label="任务操作协程 / 锁",
                    unit_kind="operation",
                    status=operation_status,
                    owner_instance_id=(str(operation_lock_owner or "").strip() if operation_lock_owner else (self.instance_id if local_operation_alive else None)) or None,
                    started_at=active_operation.started_at if active_operation is not None else None,
                    last_heartbeat_at=operation_heartbeat,
                    detail=(f"当前操作类型：{active_operation.operation_type}" if active_operation is not None else "当前存在任务级 operation lock"),
                    reason=(
                        "当前 operation 仍处于 queued/claimed，但本地没有活跃 operation worker"
                        if (
                            active_operation is not None
                            and str(getattr(active_operation, "status", "") or "").strip().lower() in {"accepted", "queued", "claimed"}
                            and not local_operation_alive
                        )
                        else
                        "任务级操作协程和锁状态正常"
                        if operation_status == "healthy"
                        else "当前仍有操作中的锁或 worker，但心跳已有老化"
                        if operation_status == "degraded"
                        else "任务级操作存在明显的锁/心跳漂移"
                    ),
                    evidence=[
                        ("operation_type", active_operation.operation_type if active_operation is not None else None),
                        ("operation_status", active_operation.status if active_operation is not None else None),
                        ("operation_lock_owner", operation_lock_owner),
                        ("operation_lock_expires_at", operation_lock_expires_at),
                    ],
                )
            )
        else:
            units.append(
                self._build_runtime_health_unit(
                    unit_key="task_operation",
                    unit_label="任务操作协程 / 锁",
                    unit_kind="operation",
                    status="done" if task_status in terminal_statuses else "idle",
                    detail="当前没有活跃的手工操作或任务级 operation lock",
                    reason="任务操作协程当前未启用",
                )
            )

        if task_status in active_task_statuses or has_local_owner or lease_expires_at is not None:
            heartbeat_status = self._runtime_health_age_status(
                task_shared._elapsed_seconds_since(last_task_heartbeat_at),
                healthy_threshold_seconds=heartbeat_interval_seconds * 2,
                degraded_threshold_seconds=max(worker_stale_seconds, heartbeat_interval_seconds * 4),
            )
            if last_task_heartbeat_at is None and lease_expires_at is not None:
                heartbeat_status = (
                    "degraded"
                    if task_shared._seconds_until(lease_expires_at) and task_shared._seconds_until(lease_expires_at) > 0
                    else "unhealthy"
                )
            if fake_local_owner:
                heartbeat_status = "unhealthy"
            if remote_owner_active and not has_local_owner and last_task_heartbeat_at is None:
                heartbeat_status = "degraded"
            if runtime_phase == task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
                if lease_expires_at is not None and (task_shared._seconds_until(lease_expires_at) or 0) > 0 and tail_active_item_count > 0:
                    heartbeat_status = "healthy"
                elif lease_expires_at is not None and (task_shared._seconds_until(lease_expires_at) or 0) > 0:
                    heartbeat_status = "degraded"
            if (
                remote_owner_active
                and not has_local_owner
                and heartbeat_status == "healthy"
                and runtime_phase != task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
            ):
                heartbeat_status = "degraded"
            units.append(
                self._build_runtime_health_unit(
                    unit_key="task_heartbeat",
                    unit_label="任务保活单元",
                    unit_kind="task_owner",
                    status=heartbeat_status,
                    owner_instance_id=lease_owner,
                    started_at=task.started_at,
                    last_heartbeat_at=last_task_heartbeat_at,
                    detail="维护任务级 lease 与保活心跳",
                    reason=(
                        "任务 row owner 指向当前 Pod，但本地没有执行句柄，lease 处于漂移状态"
                        if fake_local_owner
                        else
                        "心跳与 lease 都在有效窗口内"
                        if heartbeat_status == "healthy"
                        else "当前 lease 由远端 owner 保持活跃，本 Pod 未直接持有心跳内存态"
                        if remote_owner_active and heartbeat_status == "degraded" and last_task_heartbeat_at is None
                        else "当前仍有 lease/owner 证据，但心跳已接近阈值"
                        if heartbeat_status == "degraded"
                        else "任务保活信号已经明显老化或缺失"
                    ),
                    evidence=[
                        ("runtime_phase", runtime_phase),
                        ("tail_control_mode", tail_control_mode),
                        ("tail_unbound_runnable_item_count", tail_unbound_runnable_item_count),
                        ("tail_bound_active_item_count", tail_bound_active_item_count),
                        ("tail_takeover_required", tail_takeover_required),
                        ("tail_takeover_reason", tail_takeover_reason),
                        ("lease_owner", lease_owner),
                        ("lease_source", lease_source),
                        ("lease_expires_at", lease_expires_at),
                        ("local_owner_count", owner_count),
                        ("tail_active_item_count", tail_active_item_count),
                    ],
                )
            )
        else:
            units.append(
                self._build_runtime_health_unit(
                    unit_key="task_heartbeat",
                    unit_label="任务保活单元",
                    unit_kind="task_owner",
                    status="done" if task_status in terminal_statuses else "idle",
                    detail="当前没有需要持续保活的任务级 lease",
                    reason="任务保活单元当前未启用",
                )
            )

        if task_manager_module.normalize_stage_name(task.current_stage) in {"entry_analysis", "dataflow_vuln_scan"} or last_sync_attempt_at or last_successful_sync_at or active_sync_error_item_count > 0:
            sync_age_reference = last_successful_sync_at or last_sync_attempt_at
            if active_sync_error_item_count > 0 and task_status in active_task_statuses:
                sync_status = "degraded"
            else:
                sync_status = self._runtime_health_age_status(
                    task_shared._elapsed_seconds_since(sync_age_reference),
                    healthy_threshold_seconds=max(30, sync_stale_seconds // 3),
                    degraded_threshold_seconds=sync_stale_seconds,
                )
            if sync_age_reference is None and never_synced_item_count > 0:
                sync_status = "degraded"
            if runtime_phase == task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION and sync_status == "unknown" and tail_active_item_count > 0:
                sync_status = "degraded"
            units.append(
                self._build_runtime_health_unit(
                    unit_key="downstream_sync",
                    unit_label="下游同步/收口协程",
                    unit_kind="sync",
                    status=sync_status,
                    owner_instance_id=str(task.dispatcher_instance_id or "").strip() or lease_owner,
                    started_at=task.started_at,
                    last_heartbeat_at=sync_age_reference,
                    detail="负责父任务对子任务状态的同步与收口观察",
                    reason=(
                        "最近一次下游同步仍在新鲜窗口内"
                        if sync_status == "healthy"
                        else "存在同步错误、未同步项或同步时间接近陈旧窗口"
                        if sync_status == "degraded"
                        else "下游同步长时间没有新鲜进展"
                    ),
                    evidence=[
                        ("runtime_phase", runtime_phase),
                        ("tail_control_mode", tail_control_mode),
                        ("tail_unbound_runnable_item_count", tail_unbound_runnable_item_count),
                        ("tail_bound_active_item_count", tail_bound_active_item_count),
                        ("tail_takeover_required", tail_takeover_required),
                        ("tail_takeover_reason", tail_takeover_reason),
                        ("last_successful_sync_at", last_successful_sync_at),
                        ("last_sync_attempt_at", last_sync_attempt_at),
                        ("last_sync_error_at", last_sync_error_at),
                        ("active_sync_error_item_count", active_sync_error_item_count),
                        ("never_synced_item_count", never_synced_item_count),
                        ("stale_synced_item_count", stale_synced_item_count),
                    ],
                )
            )
        else:
            units.append(
                self._build_runtime_health_unit(
                    unit_key="downstream_sync",
                    unit_label="下游同步/收口协程",
                    unit_kind="sync",
                    status="done" if task_status in terminal_statuses else "idle",
                    detail="当前阶段不要求父任务持续执行下游同步收口",
                    reason="下游同步单元当前未启用",
                )
            )

        healthy_unit_count = sum(1 for unit in units if unit["status"] == "healthy")
        degraded_unit_count = sum(1 for unit in units if unit["status"] == "degraded")
        unhealthy_unit_count = sum(1 for unit in units if unit["status"] == "unhealthy")
        active_unit_count = sum(1 for unit in units if unit["status"] in {"healthy", "degraded", "unhealthy"})
        overall_status = "idle"
        if unhealthy_unit_count > 0:
            overall_status = "unhealthy"
        elif degraded_unit_count > 0:
            overall_status = "degraded"
        elif healthy_unit_count > 0:
            overall_status = "healthy"
        elif task_status in terminal_statuses:
            overall_status = "terminal"
        elif any(unit["status"] == "unknown" for unit in units):
            overall_status = "unknown"
        elif any(unit["status"] == "idle" for unit in units):
            overall_status = "idle"
        units.sort(
            key=lambda unit: (task_shared._runtime_health_status_rank(unit["status"]), unit["unit_label"]),
            reverse=True,
        )
        groups = self._build_runtime_health_groups(units)
        spotlight = self._build_runtime_health_spotlight(units)
        snapshot_cards = self._build_runtime_health_snapshot_cards(
            task_id=task.id,
            local_worker_alive=local_worker_alive,
            last_task_heartbeat_at=last_task_heartbeat_at,
            has_local_owner=has_local_owner,
            fake_local_owner=fake_local_owner,
            owner_count=owner_count,
            local_stage_worker_count=local_stage_worker_count,
            active_stage_item_count=len(active_stage_items),
            local_archive_job_count=len(local_archive_jobs),
            active_archive_job_count=len(active_archive_jobs),
            local_operation_alive=local_operation_alive,
            operation_lock_owner=operation_lock_owner,
            operation_lock_heartbeat_at=operation_lock_heartbeat_at,
        )
        related_loops = self._build_runtime_health_related_loops()
        return {
            "summary": {
                "overall_status": overall_status,
                "active_unit_count": active_unit_count,
                "healthy_unit_count": healthy_unit_count,
                "degraded_unit_count": degraded_unit_count,
                "unhealthy_unit_count": unhealthy_unit_count,
                "last_updated_at": task_shared._now(),
                "message": self._runtime_health_summary_message(overall_status),
            },
            "spotlight": spotlight,
            "snapshot_cards": snapshot_cards,
            "related_loops": related_loops,
            "groups": groups,
            "units": units,
        }

    def _build_queue_info(self: TaskManager, db: Session, *, project_id: str) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        running_count = int(
            db.query(task_manager_module.func.count(task_manager_module.BinarySecurityTask.id))
            .filter(
                task_manager_module.BinarySecurityTask.project_id == project_id,
                task_manager_module.BinarySecurityTask.status.in_(["dispatching", "running"]),
            )
            .scalar()
            or 0
        )
        queued_rows = (
            db.query(task_manager_module.BinarySecurityTask.id)
            .filter(
                task_manager_module.BinarySecurityTask.project_id == project_id,
                task_manager_module.BinarySecurityTask.status == "pending",
            )
            .order_by(
                task_manager_module.BinarySecurityTask.created_at.asc(),
                task_manager_module.BinarySecurityTask.id.asc(),
            )
            .all()
        )
        pending_positions = {row[0]: index + 1 for index, row in enumerate(queued_rows)}
        return {
            "running_count": running_count,
            "queued_count": len(queued_rows),
            "pending_positions": pending_positions,
            "last_reconcile_at": self._last_queue_reconcile_at,
        }

    def _task_list_stage_state_by_task(
        self: TaskManager,
        db: Session,
        tasks,
    ) -> tuple[dict[str, list[Any]], dict[str, list[Any]]]:
        from app.service import task_manager as task_manager_module

        task_ids = [str(task.id) for task in tasks if getattr(task, "id", None)]
        if not task_ids:
            return {}, {}
        stage_runs = (
            db.query(task_manager_module.BinarySecurityStageRun)
            .filter(task_manager_module.BinarySecurityStageRun.task_id.in_(task_ids))
            .all()
        )
        stage_items = (
            db.query(task_manager_module.BinarySecurityStageItem)
            .filter(task_manager_module.BinarySecurityStageItem.task_id.in_(task_ids))
            .all()
        )
        stage_runs_by_task: dict[str, list[Any]] = {}
        stage_items_by_task: dict[str, list[Any]] = {}
        for run in stage_runs:
            task_id = str(getattr(run, "task_id", "") or "")
            if task_id:
                stage_runs_by_task.setdefault(task_id, []).append(run)
        for item in stage_items:
            task_id = str(getattr(item, "task_id", "") or "")
            if task_id:
                stage_items_by_task.setdefault(task_id, []).append(item)
        return stage_runs_by_task, stage_items_by_task

    def _build_task_list_stage_summaries(
        self: TaskManager,
        db: Session,
        task,
        stage_sequence: list[str],
        *,
        stage_runs=None,
        stage_items=None,
    ):
        resolved_stage_runs = list(stage_runs or [])
        resolved_stage_items = list(stage_items or [])
        if resolved_stage_runs or resolved_stage_items:
            return self._build_stage_summaries(
                db,
                task,
                stage_sequence,
                resolved_stage_runs,
                resolved_stage_items,
                include_retry_support=False,
            )
        return self._build_stage_summaries_from_snapshot(task, stage_sequence)

    def _build_stage_summaries_from_snapshot(self: TaskManager, task, stage_sequence: list[str]):
        from app.service import task_manager as task_manager_module

        snapshot = task.stage_summary if isinstance(task.stage_summary, dict) else {}
        summaries = []
        for index, stage_name in enumerate(stage_sequence, start=1):
            payload = snapshot.get(stage_name) if isinstance(snapshot.get(stage_name), dict) else {}
            summary = task_manager_module.BinarySecurityStageSummary(
                stage_name=stage_name,
                sequence_no=int(payload.get("sequence_no") or index),
                status=str(payload.get("status") or ("pending" if stage_name != task.current_stage else task.status or "pending")),
                retry_count=int(payload.get("retry_count") or 0),
                retry_supported=False,
                retry_reason=None,
                retry_failed_supported=False,
                retry_failed_reason=None,
                retry_full_supported=False,
                retry_full_reason=None,
                total_items=int(payload.get("total_items") or 0),
                success_items=int(payload.get("success_items") or 0),
                failed_items=int(payload.get("failed_items") or 0),
                orchestration_failed_items=int(payload.get("orchestration_failed_items") or payload.get("failed_items") or 0),
                downstream_missing_items=int(payload.get("downstream_missing_items") or 0),
                skipped_items=int(payload.get("skipped_items") or 0),
                running_items=int(payload.get("running_items") or 0),
                cancelled_items=int(payload.get("cancelled_items") or 0),
                downstream_status_counts=dict(payload.get("downstream_status_counts") or {}),
                started_at=payload.get("started_at"),
                finished_at=payload.get("finished_at"),
                last_error=payload.get("last_error"),
            )
            abnormal_payload = payload.get("abnormal_reason") if isinstance(payload.get("abnormal_reason"), dict) else None
            if abnormal_payload:
                try:
                    summary.abnormal_reason = task_manager_module.BinarySecurityAbnormalReason(**abnormal_payload)
                except Exception:
                    summary.abnormal_reason = None
            summaries.append(summary)
        return summaries

    def _build_task_list_manual_operation_state(
        self: TaskManager,
        task,
        *,
        stage_summaries,
        active_operation=None,
    ) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        if active_operation is not None:
            return self._manual_operation_state_from_active_operation(task, active_operation)
        running_statuses = {"pending", "dispatching", "running"}
        running = str(task.status or "").strip() in running_statuses
        has_failed_stage = any(summary.status in {"failed", "downstream_missing", "cancelled"} for summary in stage_summaries)
        return {
            "overall": "blocked" if running else "ready",
            "summary": "当前任务正在运行，详细手工操作能力请进入详情页查看" if running else ("当前任务存在失败阶段，可进入详情页执行重试/继续" if has_failed_stage else "可进入详情页查看详细操作"),
            "blocking_code": "task_running" if running else None,
            "blocking_reason": "当前任务正在运行，列表页不做实时重试能力判断" if running else None,
            "operation_in_progress": False,
            "operation_type": None,
            "operation_owner": None,
            "operation_owner_model": None,
            "can_cancel": False,
            "can_continue": False,
            "can_retry": False,
            "can_retry_failed_items": False,
            "can_retry_stage": False,
            "can_retry_stage_failed_items": False,
            "can_retry_stage_full": False,
            "can_retry_archive": False,
            "can_retry_archive_failed_items": False,
            "can_retry_archive_full": False,
            "can_delete": True,
            "can_edit_policy": not running,
            "can_confirm_modules": str(task.status or "").strip() in {task_manager_module.TASK_STATUS_PENDING_MODULE_CONFIRMATION, "waiting_confirmation"},
        }

    def _cancel_state_operation_visible(
        self: TaskManager,
        task,
        operation,
    ) -> bool:
        from app.service import task_manager as task_manager_module

        if operation is None:
            return False
        if str(operation.operation_type or "").strip() != task_manager_module.TASK_ACTION_CANCEL:
            return False
        if str(operation.status or "").strip() in task_manager_module.TASK_OPERATION_ACTIVE_STATUSES:
            return True
        return str(task.status or "").strip() in {
            task_manager_module.TASK_STATUS_CANCELLING,
            "cancelled",
            task_manager_module.TASK_STATUS_CANCEL_FAILED,
        }

    def _cancel_state_from_operation(
        self: TaskManager,
        task,
        operation,
    ) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        if not self._cancel_state_operation_visible(task, operation):
            return {}
        result_payload = self._operation_result_data(operation)
        targets = [
            dict(target)
            for target in list(result_payload.get("cancel_targets") or [])
            if isinstance(target, dict)
        ]
        blocking_targets = [
            dict(target)
            for target in targets
            if bool(target.get("blocking")) and str(target.get("terminal_observation_status") or "") not in {"cancelled", "success", "failed", "missing"}
        ]
        blocking_preview = blocking_targets[: task_manager_module.TASK_CANCEL_BLOCKING_TARGETS_PREVIEW_LIMIT]
        return {
            "operation_id": operation.id,
            "operation_type": operation.operation_type,
            "operation_status": operation.status,
            "current_step": operation.current_step,
            "task_status": str(task.status or ""),
            "targets_total": len(targets),
            "targets_terminal": sum(
                1
                for target in targets
                if str(target.get("terminal_observation_status") or "") in {"cancelled", "success", "failed", "missing"}
            ),
            "targets_blocking": len(blocking_targets),
            "blocking_targets": blocking_preview,
            "blocking_targets_preview_count": len(blocking_preview),
            "blocking_targets_truncated": len(blocking_targets) > len(blocking_preview),
            "last_progress_at": result_payload.get("last_progress_at") or task_shared._isoformat_or_none(operation.updated_at),
        }

    def _build_cleanup_state(self: TaskManager, task) -> dict[str, Any]:
        snapshot = dict(task.cleanup_snapshot or {})
        deferred_refs = [dict(ref) for ref in list(snapshot.get("deferred_downstream_refs") or []) if isinstance(ref, dict)]
        blocking_refs = [dict(ref) for ref in list(snapshot.get("downstream_cleanup_blocking_refs") or []) if isinstance(ref, dict)]
        partial_failed = bool(snapshot.get("cleanup_partial_failed")) or bool(deferred_refs)
        raw_status = str(snapshot.get("deferred_cleanup_status") or "").strip()
        status = raw_status or ("legacy_recovery_pending" if partial_failed else "succeeded")
        last_attempt_at = task_shared._parse_iso_datetime(snapshot.get("deferred_cleanup_last_attempt_at"))
        next_retry_at = task_shared._parse_iso_datetime(snapshot.get("deferred_cleanup_next_retry_at"))
        return {
            "status": status,
            "partial_failed": partial_failed,
            "legacy_recovery": partial_failed,
            "deferred_ref_count": len(deferred_refs),
            "blocking_ref_count": len(blocking_refs),
            "last_error": self._string_or_none(snapshot.get("deferred_cleanup_last_error")),
            "last_attempt_at": task_shared._isoformat_or_none(last_attempt_at),
            "next_retry_at": task_shared._isoformat_or_none(next_retry_at),
        }

    def _build_manual_operation_state(
        self: TaskManager,
        db: Session,
        task,
        *,
        task_retry_supported: bool,
        task_retry_reason: str | None,
        task_continue_supported: bool,
        task_continue_reason: str | None,
        task_retry_failed_supported: bool,
        task_retry_failed_reason: str | None,
        stage_summaries,
    ) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        active_operation = self._active_operation(db, task.id)
        if active_operation is not None:
            return self._manual_operation_state_from_active_operation(task, active_operation)
        has_stage_retry = any(bool(summary.retry_full_supported) for summary in stage_summaries)
        has_stage_retry_failed = any(bool(summary.retry_failed_supported) for summary in stage_summaries)
        has_item_level_stage_retry_failed = self._has_retryable_failed_stage_items(db, task)
        streaming_auto_progressing = self._streaming_tail_auto_progressing(db, task)
        running = task.status in {"dispatching", "running"} or streaming_auto_progressing
        waiting_modules = task.status in {task_manager_module.TASK_STATUS_PENDING_MODULE_CONFIRMATION, "waiting_confirmation"}
        can_retry_archive = not running and any(
            self._archive_retry_support(db, task, summary.stage_name)[0] or self._archive_full_retry_support(db, task, summary.stage_name)[0]
            for summary in stage_summaries
        )

        can_cancel = task.status not in task_manager_module.TASK_TERMINAL_STATUSES
        can_continue = bool(task_continue_supported)
        can_retry = bool(task_retry_supported)
        can_retry_failed_items = bool(task_retry_failed_supported)
        can_retry_stage = (has_stage_retry or has_stage_retry_failed) and not running
        can_retry_stage_failed_items = (has_stage_retry_failed or has_item_level_stage_retry_failed) and not streaming_auto_progressing
        can_delete = True
        blocked_policy_statuses = {"dispatching", "running"}
        can_edit_policy = task.status not in blocked_policy_statuses
        can_confirm_modules = waiting_modules

        blocking_code: str | None = None
        blocking_reason: str | None = None
        overall = "ready"
        summary = "当前任务允许手工操作"
        if waiting_modules:
            blocking_code = "pending_module_confirmation"
            blocking_reason = "当前任务等待模块确认，请先确认模块后再执行其他操作"
            overall = "blocked"
            summary = blocking_reason
        elif streaming_auto_progressing:
            blocking_code = "task_running"
            blocking_reason = "当前任务处于 streaming tail 自动推进中，当前仅建议等待系统继续收敛或执行取消/同步状态"
            overall = "blocked"
            summary = blocking_reason
        elif running and not can_retry_stage_failed_items:
            blocking_code = "task_running"
            blocking_reason = (
                "当前任务处于 streaming tail 自动推进中，当前仅建议等待系统继续收敛或执行取消/同步状态"
                if streaming_auto_progressing and task.status == "pending"
                else f"当前任务正在执行中，当前状态 {task.status} 下仅支持取消或同步状态"
            )
            overall = "blocked"
            summary = blocking_reason
        elif not any([can_cancel, can_continue, can_retry, can_retry_failed_items, can_retry_stage, can_retry_archive, can_delete, can_edit_policy, can_confirm_modules]):
            blocking_code = "no_manual_operation"
            blocking_reason = task_retry_failed_reason or task_continue_reason or task_retry_reason or "当前任务暂无可执行的手工操作"
            overall = "blocked"
            summary = blocking_reason

        cleanup_state = self._build_cleanup_state(task)
        deferred_count = int(cleanup_state.get("deferred_ref_count") or 0)
        cleanup_warning_summary = (
            f"检测到 {deferred_count} 个历史删除遗留引用，系统正在尝试恢复清理"
            if bool(cleanup_state.get("partial_failed")) and deferred_count > 0
            else None
        )

        return {
            "overall": overall,
            "summary": summary,
            "blocking_code": blocking_code,
            "blocking_reason": blocking_reason,
            "operation_in_progress": False,
            "operation_type": None,
            "operation_owner": None,
            "operation_owner_model": None,
            "can_cancel": can_cancel,
            "can_continue": can_continue,
            "can_retry": can_retry,
            "can_retry_failed_items": can_retry_failed_items,
            "can_retry_stage": can_retry_stage,
            "can_retry_stage_failed_items": can_retry_stage_failed_items,
            "can_retry_stage_full": has_stage_retry and not running,
            "can_retry_archive": can_retry_archive,
            "can_retry_archive_failed_items": can_retry_archive,
            "can_retry_archive_full": can_retry_archive,
            "can_delete": can_delete,
            "can_edit_policy": can_edit_policy,
            "can_confirm_modules": can_confirm_modules,
            "cleanup_partial_failed": bool(cleanup_state.get("partial_failed")),
            "downstream_cleanup_deferred_count": deferred_count,
            "downstream_cleanup_warning_summary": cleanup_warning_summary,
            "downstream_cleanup_deferred_refs": [
                dict(row)
                for row in list(dict(task.cleanup_snapshot or {}).get("deferred_downstream_refs") or [])
                if isinstance(row, dict)
            ],
        }

    def _task_list_response(
        self: TaskManager,
        db: Session,
        task,
        *,
        queue_info: dict[str, Any] | None = None,
        stage_runs=None,
        stage_items=None,
        active_operation=None,
        cancel_operation=None,
    ):
        from app.service import task_manager as task_manager_module

        metrics = task.metrics or {}
        queue_info = queue_info or {"pending_positions": {}}
        queue_position = queue_info.get("pending_positions", {}).get(task.id)
        queue_state, recoverable_reason = self._task_queue_state(task, queue_info, db=db)
        stage_sequence = self._stage_sequence_for_task(task)
        stage_summaries = self._build_task_list_stage_summaries(
            db,
            task,
            stage_sequence,
            stage_runs=stage_runs,
            stage_items=stage_items,
        )
        abnormal_reason = None
        if isinstance(task.latest_abnormal_reason, dict):
            try:
                abnormal_reason = task_manager_module.BinarySecurityAbnormalReason(**task.latest_abnormal_reason)
            except Exception:
                abnormal_reason = None
        tail_summary = self._tail_stage_work_summary(db, task)
        lease_owner, lease_expires_at, lease_source, reconcile_pod_uid_unused, reconcile_boot_id_unused, reconcile_generation_unused = self._task_runtime_lease_view(db, task)
        del reconcile_pod_uid_unused, reconcile_boot_id_unused, reconcile_generation_unused
        runtime_phase = self._task_runtime_phase(task)
        task_control_mode = self._task_control_mode(task)
        base_policy = self._task_base_policy(task)
        runtime_override = self._task_runtime_override(task)
        effective_runtime_policy = self._effective_runtime_policy(task)
        (
            last_successful_sync_at,
            last_sync_attempt_at,
            last_sync_error_at,
            last_sync_error_type,
            last_sync_error_message,
            active_sync_error_item_count,
            never_synced_item_count,
            stale_synced_item_count,
        ) = self._task_sync_status_view(stage_items)
        manual_operation_state = self._build_task_list_manual_operation_state(
            task,
            stage_summaries=stage_summaries,
            active_operation=active_operation,
        )
        kg_state = dict((task.summary or {}).get("knowledge_graph_state") or {})
        failure_snapshot = self._stage_failure_snapshot(
            task,
            next(
                (
                    run
                    for run in stage_runs or []
                    if str(run.stage_name or "").strip() == str(task.current_stage or "").strip()
                ),
                None,
            ),
        )
        terminal_failure = self._task_status_is_terminal(task.status) and str(failure_snapshot.get("failure_category") or "").strip() == "business"
        return task_manager_module.BinarySecurityTaskResponse(
            id=task.id,
            project_id=task.project_id,
            task_type=self._task_type(task),
            name=task.name,
            status=task.status,
            runtime_phase=runtime_phase,
            task_control_mode=task_control_mode,
            current_operation_id=task.current_operation_id,
            execution_epoch=int(getattr(task, "execution_epoch", 0) or 0),
            current_stage=task.current_stage,
            last_error=task.last_error,
            terminal_failure=terminal_failure,
            requeue_suppressed=terminal_failure,
            failure_code=self._string_or_none(failure_snapshot.get("failure_code")) if terminal_failure else None,
            failure_category=self._string_or_none(failure_snapshot.get("failure_category")) if terminal_failure else None,
            failure_message=self._string_or_none(failure_snapshot.get("failure_message") or failure_snapshot.get("error")) if terminal_failure else None,
            firmware_path=task.firmware_path,
            stage_sequence=stage_sequence,
            is_queued=queue_state == "queued",
            queue_position=queue_position,
            queue_state=queue_state,
            recoverable_reason=recoverable_reason,
            last_reconcile_at=queue_info.get("last_reconcile_at"),
            dispatcher_instance_id=task.dispatcher_instance_id,
            task_lease_owner_instance_id=lease_owner,
            task_lease_expires_at=lease_expires_at,
            task_lease_source=lease_source,
            tail_control_mode=str(tail_summary.get("tail_control_mode") or "idle"),
            tail_has_runnable_unbound_items=bool(tail_summary.get("has_runnable_unbound_items")),
            tail_unbound_runnable_item_count=int(tail_summary.get("unbound_runnable_item_count", 0) or 0),
            tail_bound_active_item_count=int(tail_summary.get("bound_active_item_count", 0) or 0),
            tail_has_downstream_refs=bool(tail_summary.get("has_downstream_refs")),
            tail_takeover_required=bool(tail_summary.get("takeover_required")),
            tail_takeover_reason=self._string_or_none(tail_summary.get("takeover_reason")),
            tail_reconcile_state=self._tail_reconcile_state(task),
            runtime_override_version=int(getattr(task, "runtime_override_version", 0) or 0),
            runtime_override_updated_at=getattr(task, "runtime_override_updated_at", None),
            runtime_override_updated_by=getattr(task, "runtime_override_updated_by", None),
            runtime_policy_effect_scope=self._runtime_policy_effect_scope(task),
            base_policy=base_policy,
            runtime_override=runtime_override,
            effective_runtime_policy=effective_runtime_policy,
            last_successful_downstream_sync_at=last_successful_sync_at,
            last_sync_attempt_at=last_sync_attempt_at,
            last_sync_error_at=last_sync_error_at,
            last_sync_error_type=last_sync_error_type,
            last_sync_error_message=last_sync_error_message,
            active_sync_error_item_count=active_sync_error_item_count,
            never_synced_item_count=never_synced_item_count,
            stale_synced_item_count=stale_synced_item_count,
            created_by=task.created_by,
            created_at=task.created_at,
            updated_at=task.updated_at,
            started_at=task.started_at,
            finished_at=task.finished_at,
            high_risk_module_count=int(metrics.get("high_risk_module_count", 0)),
            medium_risk_module_count=int(metrics.get("medium_risk_module_count", 0)),
            low_risk_module_count=int(metrics.get("low_risk_module_count", 0)),
            candidate_module_count=int(metrics.get("candidate_module_count", 0)),
            selected_module_count=int(metrics.get("selected_module_count", 0)),
            selected_risk_levels=task_shared._normalize_module_risk_levels(effective_runtime_policy.get("module_risk_levels")),
            module_selection_mode=self._module_selection_mode(task),
            entry_selection_mode=self._entry_selection_mode(task),
            candidate_entry_count=len(self._entry_candidates(task)),
            selected_entry_count=len(self._effective_entry_inputs(task)) if self._entry_selection_mode(task) == task_shared.ENTRY_SELECTION_MODE_MANUAL_CONFIRM else len(self._entry_candidates(task)),
            entry_count=int(metrics.get("entry_count", 0)),
            knowledge_graph_raw_entry_count=int(metrics.get("knowledge_graph_raw_entry_count", 0)),
            knowledge_graph_selected_entry_count=int(metrics.get("knowledge_graph_selected_entry_count", 0)),
            knowledge_graph_filtered_out_count=int(metrics.get("knowledge_graph_filtered_out_count", 0)),
            knowledge_graph_graph_status=self._string_or_none(kg_state.get("graph_status")),
            knowledge_graph_identification_state=self._string_or_none(kg_state.get("identification_state")),
            knowledge_graph_attack_status=self._string_or_none(kg_state.get("attack_status")),
            knowledge_graph_analysis_total=int(kg_state.get("knowledge_graph_analysis_total") or 0),
            knowledge_graph_analysis_identified=int(kg_state.get("knowledge_graph_analysis_identified") or 0),
            knowledge_graph_analysis_pending=int(kg_state.get("knowledge_graph_analysis_pending") or 0),
            knowledge_graph_analysis_confirmed=int(kg_state.get("knowledge_graph_analysis_confirmed") or 0),
            knowledge_graph_analysis_rejected=int(kg_state.get("knowledge_graph_analysis_rejected") or 0),
            vuln_result_count=int(metrics.get("vuln_result_count", 0)),
            firmware_item_count=int(metrics.get("firmware_item_count", 0)),
            unpacked_firmware_count=int(metrics.get("unpacked_firmware_count", 0)),
            failed_firmware_count=int(metrics.get("failed_firmware_count", 0)),
            task_retry_supported=False,
            task_retry_reason=None,
            task_continue_supported=False,
            task_continue_reason=None,
            task_retry_failed_items_supported=False,
            task_retry_failed_items_reason=None,
            abnormal_reason_title=abnormal_reason.title if abnormal_reason else None,
            abnormal_reason_code=abnormal_reason.code if abnormal_reason else None,
            abnormal_reason_category=abnormal_reason.category if abnormal_reason else None,
            abnormal_reason=abnormal_reason,
            stage_summaries=stage_summaries,
            manual_operation_state=manual_operation_state,
            cancel_state=self._cancel_state_from_operation(task, cancel_operation),
            cleanup_state=self._build_cleanup_state(task),
        )

    def _task_list_operation_maps(self: TaskManager, db: Session, tasks) -> tuple[dict[str, Any], dict[str, Any]]:
        from app.service import task_manager as task_manager_module

        task_ids = [str(task.id) for task in tasks if getattr(task, "id", None)]
        if not task_ids:
            return {}, {}
        operations = (
            db.query(task_manager_module.BinarySecurityTaskOperation)
            .filter(task_manager_module.BinarySecurityTaskOperation.task_id.in_(task_ids))
            .order_by(
                task_manager_module.BinarySecurityTaskOperation.created_at.desc(),
                task_manager_module.BinarySecurityTaskOperation.id.desc(),
            )
            .all()
        )
        active_operations_by_task: dict[str, Any] = {}
        cancel_operations_by_task: dict[str, Any] = {}
        for operation in operations:
            task_id = str(getattr(operation, "task_id", "") or "")
            if not task_id:
                continue
            status_value = str(getattr(operation, "status", "") or "").strip()
            operation_type = str(getattr(operation, "operation_type", "") or "").strip()
            if task_id not in active_operations_by_task and status_value in task_manager_module.TASK_OPERATION_ACTIVE_STATUSES:
                active_operations_by_task[task_id] = operation
            if task_id not in cancel_operations_by_task and operation_type == task_manager_module.TASK_ACTION_CANCEL:
                if task_id in active_operations_by_task and str(active_operations_by_task[task_id].operation_type or "").strip() != task_manager_module.TASK_ACTION_CANCEL:
                    continue
                cancel_operations_by_task[task_id] = operation
        return active_operations_by_task, cancel_operations_by_task

    def _load_task_list_cached_value(
        self: TaskManager,
        *,
        cache_group: str,
        project_id: str,
        task_type: str | None,
        pipeline_profile: str | None,
        ttl_seconds: float,
        loader,
        fallback,
    ):
        cache_key = (cache_group, project_id, str(task_type or "all"), str(pipeline_profile or "all"))
        now_ts = time.monotonic()
        with self._task_list_cache_lock:
            cached = self._task_list_cache.get(cache_key)
            if cached and now_ts < cached[0]:
                return copy.deepcopy(cached[1])
        try:
            value = loader()
        except Exception:
            logger.warning(
                "binary-security task list cache loader failed group=%s project_id=%s task_type=%s",
                cache_group,
                project_id,
                task_type or "all",
                exc_info=True,
            )
            with self._task_list_cache_lock:
                cached = self._task_list_cache.get(cache_key)
                if cached:
                    return copy.deepcopy(cached[1])
            return copy.deepcopy(fallback)
        with self._task_list_cache_lock:
            self._task_list_cache[cache_key] = (now_ts + max(0.1, float(ttl_seconds)), copy.deepcopy(value))
        return value

    def _load_readonly_projection_cached_value(
        self: TaskManager,
        *,
        cache_group: str,
        project_id: str,
        task_id: str,
        ttl_seconds: float,
        loader: Callable[[], Any],
    ) -> tuple[Any, bool]:
        if self._service_role() != "api":
            return loader(), False
        cache_key = (cache_group, project_id, task_id)
        now_ts = time.monotonic()
        with self._readonly_projection_cache_lock:
            cached = self._readonly_projection_cache.get(cache_key)
            if cached and now_ts < cached[0]:
                return copy.deepcopy(cached[1]), True
        value = loader()
        with self._readonly_projection_cache_lock:
            self._readonly_projection_cache[cache_key] = (
                now_ts + max(0.1, float(ttl_seconds)),
                copy.deepcopy(value),
            )
        return value, False

    def _task_abnormal_reason(self: TaskManager, task, stage_summaries, items, archive_jobs):
        status = str(task.status or "")
        if self._task_is_waiting_for_manual_confirmation(task, stage_summaries):
            return None
        if status in {"success", "pending", "queued", "running", "dispatching", "ready_to_start", "pending_upload", "uploading"}:
            return None
        if status == "cancelled":
            return self._build_abnormal_reason(
                category="cancel",
                code="user_cancelled",
                title="任务已取消",
                message=self._abnormal_reason_message(task.last_error, "用户或编排器已取消当前任务。"),
                source_layer="task",
                status=status,
                service="binary-security",
                stage_name=task.current_stage,
                first_seen_at=task.started_at,
                last_seen_at=task.finished_at,
                evidence=[
                    self._abnormal_reason_evidence("current_stage", "当前阶段", task.current_stage),
                    self._abnormal_reason_evidence("last_error", "原始错误", task.last_error),
                ],
                recommended_action="检查取消来源，必要时查看时间线中的取消与下游同步事件。",
            )
        failed_archive = next((job for job in reversed(archive_jobs) if str(job.archive_status or "") == "failed"), None)
        if failed_archive is not None:
            archive_reason = self._archive_job_abnormal_reason(failed_archive)
            if archive_reason is not None:
                return archive_reason.model_copy(update={"source_layer": "task", "status": status})
        failed_item = next(
            (item for item in reversed(items) if (self._normalize_downstream_status(item.status) or item.status) in {"failed", "cancelled", "downstream_missing"}),
            None,
        )
        if failed_item is not None:
            item_reason = self._stage_item_abnormal_reason(failed_item, task=task)
            if item_reason is not None:
                return item_reason.model_copy(update={"source_layer": "task", "status": status})
        failed_stage = next(
            (summary for summary in reversed(stage_summaries) if summary.status in {"failed", "partial_success", "downstream_missing", "cancelled"}),
            None,
        )
        if failed_stage is not None:
            stage_reason = self._stage_abnormal_reason(
                task,
                failed_stage.stage_name,
                failed_stage,
                [item for item in items if item.stage_name == failed_stage.stage_name],
            )
            if stage_reason is not None:
                return stage_reason.model_copy(update={"source_layer": "task", "status": status})
        next_stage = None
        if status == "failed":
            next_stage = next(
                (
                    summary.stage_name
                    for summary in stage_summaries
                    if summary.status not in {"success", "failed", "partial_success", "downstream_missing", "cancelled", "skipped"}
                ),
                None,
            )
        if next_stage:
            return self._build_abnormal_reason(
                category="orchestration",
                code="stage_incomplete_terminated",
                title="任务在最终阶段前终止",
                message=f"任务在 {next_stage} 前终止，未完成所有已启用阶段。",
                source_layer="task",
                status=status,
                service="binary-security",
                stage_name=next_stage,
                first_seen_at=task.started_at,
                last_seen_at=task.finished_at,
                evidence=[
                    self._abnormal_reason_evidence("current_stage", "当前阶段", task.current_stage),
                    self._abnormal_reason_evidence("next_stage", "未完成阶段", next_stage),
                    self._abnormal_reason_evidence("last_error", "原始错误", task.last_error),
                ],
                recommended_action="优先查看最后失败阶段、异常时间线和下游子任务详情。",
            )
        return self._build_abnormal_reason(
            category="orchestration",
            code="unknown_abnormal" if status != "partial_success" else "result_inconsistent",
            title="任务异常结束" if status != "partial_success" else "任务带异常完成",
            message=self._abnormal_reason_message(task.last_error, "任务以非正常状态结束，但未提取到更具体的根因。"),
            source_layer="task",
            status=status,
            service="binary-security",
            stage_name=task.current_stage,
            first_seen_at=task.started_at,
            last_seen_at=task.finished_at,
            evidence=[
                self._abnormal_reason_evidence("current_stage", "当前阶段", task.current_stage),
                self._abnormal_reason_evidence("last_error", "原始错误", task.last_error),
            ],
            recommended_action="查看时间线与编排观测，确认失败首先发生在哪个阶段或下游任务。",
        )

    def _build_stage_summaries(
        self: TaskManager,
        db: Session,
        task,
        stage_sequence,
        stage_runs,
        items,
        *,
        item_stats=None,
        downstream_status_counts=None,
        include_retry_support=True,
    ):
        from app.service import task_manager as task_manager_module

        runs_by_stage = {run.stage_name: run for run in stage_runs if run.stage_name in stage_sequence}
        items_by_stage = {stage_name: [] for stage_name in stage_sequence}
        for item in items:
            if item.stage_name in items_by_stage:
                items_by_stage[item.stage_name].append(item)
        stage_retry_support = (
            {stage_name: self._stage_retry_support(db, task, stage_name) for stage_name in stage_sequence if stage_name in runs_by_stage}
            if include_retry_support
            else {}
        )
        stage_retry_failed_support = (
            {stage_name: self._stage_retry_failed_items_support(db, task, stage_name) for stage_name in stage_sequence if stage_name in runs_by_stage}
            if include_retry_support
            else {}
        )
        workflow_snapshots = {
            str(snapshot.get("stage_name") or "").strip(): snapshot
            for snapshot in self._build_workflow_stage_snapshots(db, task, stage_runs=stage_runs)
        }
        summaries = []
        for index, stage_name in enumerate(stage_sequence, start=1):
            run = runs_by_stage.get(stage_name)
            stage_items = items_by_stage.get(stage_name, [])
            stage_snapshot = workflow_snapshots.get(stage_name, {})
            current_downstream_status_counts = dict((downstream_status_counts or {}).get(stage_name, {}))
            if not current_downstream_status_counts:
                for item in stage_items:
                    item_result = self._load_stage_item_result_payload(item)
                    sync_observation = dict(item_result.get("sync_observation") or {})
                    downstream_status = self._string_or_none(sync_observation.get("downstream_status")) or self._string_or_none(item_result.get("downstream_status"))
                    display_downstream_status = self._downstream_status_display_value(downstream_status)
                    current_downstream_status_counts[display_downstream_status] = current_downstream_status_counts.get(display_downstream_status, 0) + 1

            stage_counts_payload = (item_stats or {}).get(stage_name, {})

            def _count(name: str, fallback: int) -> int:
                if name in stage_counts_payload:
                    return int(stage_counts_payload.get(name) or 0)
                return int(fallback)

            counts = {
                "total_items": _count("total", len(stage_items)),
                "success_items": _count("success", len([item for item in stage_items if (self._normalize_downstream_status(item.status) or item.status) == "success"])),
                "failed_items": _count("failed", len([item for item in stage_items if (self._normalize_downstream_status(item.status) or item.status) == "failed"])),
                "downstream_missing_items": _count("downstream_missing", len([item for item in stage_items if (self._normalize_downstream_status(item.status) or item.status) == "downstream_missing"])),
                "skipped_items": _count("skipped", 0),
                "running_items": _count(
                    "running",
                    len([item for item in stage_items if (self._normalize_downstream_status(item.status) or item.status) in {"pending", "queued", "running", "dispatching"}]),
                ),
            }
            stage_summary = task_manager_module.BinarySecurityStageSummary(
                stage_name=stage_name,
                sequence_no=run.sequence_no if run else index,
                status=self._business_stage_status(task, stage_name, run, stage_items, db=db),
                stage_terminalization_ready=bool(stage_snapshot.get("ready_for_terminalization")),
                stage_failure_escalation_ready=bool(stage_snapshot.get("ready_for_failure_escalation")),
                previous_stages_terminal=bool(stage_snapshot.get("previous_stages_terminal")),
                has_unresolved_expected_outputs=bool(stage_snapshot.get("has_unresolved_expected_outputs")),
                retry_count=int(run.retry_count or 0) if run else 0,
                retry_supported=stage_retry_support.get(stage_name, (False, None))[0],
                retry_reason=stage_retry_support.get(stage_name, (False, None))[1],
                retry_failed_supported=stage_retry_failed_support.get(stage_name, (False, None, []))[0],
                retry_failed_reason=stage_retry_failed_support.get(stage_name, (False, None, []))[1],
                retry_full_supported=stage_retry_support.get(stage_name, (False, None))[0],
                retry_full_reason=stage_retry_support.get(stage_name, (False, None))[1],
                total_items=counts["total_items"],
                success_items=counts["success_items"],
                failed_items=counts["failed_items"],
                orchestration_failed_items=counts["failed_items"] + counts["downstream_missing_items"],
                downstream_missing_items=counts["downstream_missing_items"],
                skipped_items=counts["skipped_items"],
                running_items=counts["running_items"],
                cancelled_items=_count("cancelled", len([item for item in stage_items if (self._normalize_downstream_status(item.status) or item.status) == "cancelled"])),
                downstream_status_counts=current_downstream_status_counts,
                started_at=run.started_at if run else None,
                finished_at=run.finished_at if run else None,
                last_error=(
                    run.last_error
                    if run and run.last_error
                    else (
                        next((item.error_message for item in stage_items if item.error_message), None)
                        if self._business_stage_status(task, stage_name, run, stage_items, db=db) in {"failed", "partial_success", "downstream_missing", "cancelled"}
                        else None
                    )
                ),
            )
            stage_summary.abnormal_reason = self._stage_abnormal_reason(task, stage_name, stage_summary, stage_items)
            summaries.append(stage_summary)
        return summaries

    def _build_stage_summaries_readonly(
        self: TaskManager,
        db: Session,
        task,
        stage_sequence,
        stage_runs,
        items,
        *,
        item_stats=None,
        downstream_status_counts=None,
        include_retry_support=True,
    ):
        return self._build_stage_summaries(
            db,
            task,
            stage_sequence,
            stage_runs,
            items,
            item_stats=item_stats,
            downstream_status_counts=downstream_status_counts,
            include_retry_support=include_retry_support,
        )

    def _build_stage_overview_nodes(
        self: TaskManager,
        db: Session,
        task,
        stage_summaries,
        archive_jobs,
        stage_items,
    ):
        from app.service import task_manager as task_manager_module

        stage_sequence = self._stage_sequence_for_task(task)
        summaries_by_stage = {summary.stage_name: summary for summary in stage_summaries}
        jobs_by_stage = {}
        items_by_stage = {}
        for job in archive_jobs:
            jobs_by_stage.setdefault(job.stage_name, []).append(job)
        for item in stage_items:
            items_by_stage.setdefault(item.stage_name, []).append(item)
        nodes = []
        for index, stage_name in enumerate(stage_sequence, start=1):
            summary = summaries_by_stage.get(stage_name) or task_manager_module.BinarySecurityStageSummary(stage_name=stage_name, sequence_no=index, status="pending")
            stage_jobs = jobs_by_stage.get(stage_name, [])
            current_stage_items = items_by_stage.get(stage_name, [])
            downstream_status_counts = {}
            for item in current_stage_items:
                item_result = self._load_stage_item_result_payload(item)
                sync_observation = dict(item_result.get("sync_observation") or {})
                raw_downstream_status = self._string_or_none(sync_observation.get("downstream_status")) or self._string_or_none(item_result.get("downstream_status"))
                display_status = self._downstream_status_display_value(raw_downstream_status)
                downstream_status_counts[display_status] = downstream_status_counts.get(display_status, 0) + 1
            business_detail = task_manager_module.BinarySecurityOverviewBusinessDetail(
                total_items=summary.total_items,
                success_items=summary.success_items,
                failed_items=summary.failed_items,
                orchestration_failed_items=summary.orchestration_failed_items or summary.failed_items,
                downstream_missing_items=summary.downstream_missing_items,
                skipped_items=summary.skipped_items,
                running_items=summary.running_items,
                cancelled_items=summary.cancelled_items or downstream_status_counts.get("cancelled", 0),
                downstream_status_counts=downstream_status_counts,
                downstream_services=sorted({str(item.downstream_service) for item in current_stage_items if item.downstream_service}),
                representative_item_key=next((item.item_key for item in current_stage_items if item.item_key), None),
                representative_downstream_task_id=next((item.downstream_task_id for item in current_stage_items if item.downstream_task_id), None),
            )
            nodes.append(
                task_manager_module.BinarySecurityOverviewNode(
                    node_id=f"business:{stage_name}",
                    node_type="business",
                    stage_name=stage_name,
                    sequence_no=summary.sequence_no or index,
                    title=task_manager_module.STAGE_TITLES.get(stage_name, stage_name),
                    status=summary.status,
                    status_label=self._status_label(summary.status),
                    started_at=summary.started_at,
                    finished_at=summary.finished_at,
                    updated_at=summary.finished_at or summary.started_at,
                    last_error=summary.last_error,
                    abnormal_reason=summary.abnormal_reason or self._stage_abnormal_reason(task, stage_name, summary, current_stage_items),
                    retry_supported=summary.retry_supported,
                    retry_reason=summary.retry_reason,
                    retry_failed_supported=summary.retry_failed_supported,
                    retry_failed_reason=summary.retry_failed_reason,
                    retry_full_supported=summary.retry_full_supported,
                    retry_full_reason=summary.retry_full_reason,
                    detail=business_detail,
                )
            )
            first_created_at = min((job.created_at for job in stage_jobs if job.created_at), default=None)
            last_updated_at = max(
                (job.completed_at or job.updated_at or job.started_at or job.created_at for job in stage_jobs if (job.completed_at or job.updated_at or job.started_at or job.created_at)),
                default=None,
            )
            duration_seconds = None
            if first_created_at and last_updated_at:
                duration_seconds = max(0.0, (last_updated_at - first_created_at).total_seconds())
            archive_detail = task_manager_module.BinarySecurityOverviewArchiveDetail(
                job_count=len(stage_jobs),
                success_count=len([job for job in stage_jobs if job.archive_status == "success"]),
                failed_count=len([job for job in stage_jobs if job.archive_status == "failed"]),
                running_count=len([job for job in stage_jobs if job.archive_status == "running"]),
                applying_count=len([job for job in stage_jobs if job.archive_status in {"archived", "applying"}]),
                pending_count=len([job for job in stage_jobs if job.archive_status == "pending"]),
                first_created_at=first_created_at,
                last_updated_at=last_updated_at,
                duration_seconds=duration_seconds,
                latest_error=next((job.error_message for job in reversed(stage_jobs) if job.archive_status == "failed" and job.error_message), None),
                jobs=stage_jobs,
            )
            archive_status = self._aggregate_archive_stage_status([job.archive_status for job in stage_jobs])
            terminal_item_count = sum(
                1 for item in current_stage_items if (self._normalize_downstream_status(item.status) or item.status) in {"success", "failed", "partial_success", "cancelled"}
            )
            has_non_terminal_items = any(
                (self._normalize_downstream_status(item.status) or item.status) not in {"success", "failed", "partial_success", "cancelled"}
                for item in current_stage_items
            )
            if archive_status == "success" and (has_non_terminal_items or len(stage_jobs) < terminal_item_count):
                archive_status = "pending"
            if stage_name == "system_analysis" and summary.status == "waiting_confirmation":
                archive_status = "pending"
            archive_retry_supported, archive_retry_reason, _ = self._archive_retry_support(db, task, stage_name)
            archive_retry_full_supported, archive_retry_full_reason, _, _ = self._archive_full_retry_support(db, task, stage_name)
            archive_abnormal_reason = next((job.abnormal_reason for job in reversed(stage_jobs) if job.abnormal_reason), None)
            nodes.append(
                task_manager_module.BinarySecurityOverviewNode(
                    node_id=f"archive:{stage_name}",
                    node_type="archive",
                    stage_name=stage_name,
                    sequence_no=summary.sequence_no or index,
                    title="产物归档",
                    status=archive_status,
                    status_label=self._status_label(archive_status),
                    started_at=first_created_at,
                    finished_at=last_updated_at if archive_status == "success" else None,
                    updated_at=last_updated_at,
                    last_error=archive_detail.latest_error,
                    abnormal_reason=archive_abnormal_reason,
                    retry_supported=archive_retry_supported,
                    retry_reason=archive_retry_reason,
                    retry_failed_supported=archive_retry_supported,
                    retry_failed_reason=archive_retry_reason,
                    retry_full_supported=archive_retry_full_supported,
                    retry_full_reason=archive_retry_full_reason,
                    detail=archive_detail,
                )
            )
        return nodes

    def _stage_item_sync_freshness_state(
        self: TaskManager,
        item,
        *,
        last_attempt_at: datetime | None,
        last_success_at: datetime | None,
        last_error_at: datetime | None,
    ) -> str:
        if not item.downstream_task_id:
            return "not_applicable"
        if last_success_at is None and last_error_at is not None:
            return "never_succeeded"
        if last_success_at is not None and last_error_at is not None and last_error_at > last_success_at:
            return "failing_after_success"
        if last_success_at is not None:
            stale_after_seconds = max(60, int(self.cfg.scheduler.downstream_reconcile_interval_seconds or 30) * 3)
            if (task_shared._now() - last_success_at).total_seconds() >= stale_after_seconds:
                return "stale_success"
            return "healthy"
        if last_attempt_at is not None:
            return "never_succeeded"
        return "not_applicable"

    def _format_downstream_status_label(self: TaskManager, status: str | None) -> str:
        normalized = str(status or "").strip().lower()
        mapping = {
            "pending": "待处理",
            "queued": "排队中",
            "running": "运行中",
            "passed": "已通过",
            "success": "已成功",
            "failed": "已失败",
            "cancelled": "已取消",
            "downstream_missing": "下游不存在",
            "not_applicable": "不适用",
            "unknown": "未知",
            "": "未知",
        }
        return mapping.get(normalized, str(status or "未知"))

    def _stage_item_display_downstream_status(self: TaskManager, item) -> str:
        binding_state = str(item.downstream_binding_state or "").strip().lower()
        if item.downstream_task_id and not item.downstream_status:
            return "下游已创建，状态待同步"
        if binding_state == "creating":
            return "下游任务创建中"
        if binding_state == "create_retrying":
            return "下游任务创建重试中"
        if binding_state == "create_failed":
            return "下游任务创建失败"
        return self._format_downstream_status_label(item.downstream_status)

    def _stage_item_response_sort_value(self: TaskManager, item, sort_by: str) -> int | None:
        normalized_sort = str(sort_by or "").strip().lower()
        if normalized_sort == "duration":
            started_at = item.started_at
            if not isinstance(started_at, datetime):
                return None
            finished_at = item.finished_at if isinstance(item.finished_at, datetime) else task_shared._now()
            return max(0, int((finished_at - started_at).total_seconds() * 1000))
        value = getattr(item, normalized_sort, None)
        if not isinstance(value, datetime):
            return None
        return int(value.timestamp() * 1000)

    def _filter_stage_item_responses(
        self: TaskManager,
        items,
        *,
        downstream_status: str | None = None,
        sync_status: str | None = None,
    ):
        normalized_downstream_status = str(downstream_status or "").strip()
        normalized_sync_status = str(sync_status or "").strip().lower()
        filtered = []
        for item in items:
            if normalized_downstream_status and self._stage_item_display_downstream_status(item) != normalized_downstream_status:
                continue
            current_sync_status = str(item.sync_status or "unknown").strip().lower()
            if normalized_sync_status and current_sync_status != normalized_sync_status:
                continue
            filtered.append(item)
        return filtered

    def _sort_stage_item_responses(
        self: TaskManager,
        items,
        *,
        sort_by: str | None = None,
        sort_direction: str = "desc",
    ):
        normalized_sort = str(sort_by or "").strip().lower()
        if normalized_sort not in {
            "started_at",
            "finished_at",
            "duration",
            "last_sync_attempt_at",
            "last_sync_success_at",
            "last_sync_error_at",
        }:
            return items
        ascending = str(sort_direction or "desc").strip().lower() == "asc"
        return sorted(
            items,
            key=lambda item: (
                self._stage_item_response_sort_value(item, normalized_sort) is None,
                (
                    self._stage_item_response_sort_value(item, normalized_sort) or -1
                    if ascending
                    else -(self._stage_item_response_sort_value(item, normalized_sort) or 0)
                ),
                str(item.id or ""),
            ),
        )

    def _stage_item_response(
        self: TaskManager,
        task,
        item=None,
        *,
        archive_jobs=None,
    ):
        from app.service import task_manager as task_manager_module

        if item is None:
            if not isinstance(task, task_manager_module.BinarySecurityStageItem):
                raise TypeError("item is required when the first argument is not a BinarySecurityStageItem")
            item = task
            task = task_manager_module.BinarySecurityTask(
                id=str(item.task_id or ""),
                project_id=str(item.project_id or ""),
                current_stage=str(item.stage_name or "") or None,
                status="running",
            )
        result = self._load_stage_item_result_payload(item)
        output_ref = dict(item.output_ref or {})
        resolved_archive_refs = self._resolved_stage_item_archive_refs(item, archive_jobs=archive_jobs)
        for key in ("artifact_root", "archive_root", "archive_copy_stats", "archive_job_id", "archive_status"):
            value = resolved_archive_refs.get(key)
            if value is None:
                continue
            output_ref.setdefault(key, value)
        for key in ("artifact_root", "archive_root", "archive_copy_stats"):
            value = resolved_archive_refs.get(key)
            if value is None:
                continue
            result.setdefault(key, value)
        downstream_status, sync_observation, repaired = self._effective_stage_item_downstream_status(item, result=result)
        downstream_payload = dict(result.get("downstream") or {})
        last_synced_at = result.get("last_sync_success_at") or result.get("downstream_status_synced_at")
        last_attempt_at = result.get("last_sync_attempt_at") or sync_observation.get("last_attempt_at") or sync_observation.get("last_synced_at")
        last_error_at = result.get("last_sync_error_at") or sync_observation.get("last_error_at")
        raw_sync_status = result.get("sync_status")
        sync_status = str(raw_sync_status).strip().lower() if raw_sync_status is not None else None
        if sync_status == "transport_error" and (downstream_status or last_synced_at):
            sync_status = "synced"
        if not sync_status:
            if item.downstream_task_id and (downstream_status or last_synced_at):
                sync_status = "synced" if last_synced_at else "pending"
                if downstream_status and not last_synced_at:
                    sync_status = "synced"
            else:
                sync_status = "not_applicable"
        if repaired and sync_status in {None, "", "pending"}:
            sync_status = "synced"
        parsed_last_synced_at = last_synced_at
        if isinstance(last_synced_at, str):
            try:
                parsed_last_synced_at = datetime.fromisoformat(last_synced_at)
            except ValueError:
                parsed_last_synced_at = None
        parsed_last_attempt_at = last_attempt_at
        if isinstance(last_attempt_at, str):
            try:
                parsed_last_attempt_at = datetime.fromisoformat(last_attempt_at)
            except ValueError:
                parsed_last_attempt_at = None
        parsed_last_error_at = last_error_at
        if isinstance(last_error_at, str):
            try:
                parsed_last_error_at = datetime.fromisoformat(last_error_at)
            except ValueError:
                parsed_last_error_at = None
        first_started_at = self._stage_item_first_started_at(item)
        latest_started_at = item.started_at
        total_retry_count = int(item.retry_count or 0) + int(item.rerun_count or 0)
        binding = self._downstream_binding_snapshot(item)
        binding_state = self._downstream_binding_state(item)
        binding_message = self._string_or_none(binding.get("message"))
        if binding_state != "created_pending_sync":
            binding_message = None
        latest_binding_mismatch = dict(result.get("latest_binding_mismatch") or {}) or None
        archive_bound_downstream_task_id = None
        if archive_jobs:
            for job in reversed(archive_jobs):
                archive_bound_downstream_task_id = self._archive_job_bound_downstream_task_id(job) or archive_bound_downstream_task_id
                if archive_bound_downstream_task_id:
                    break
        freshness_state = self._stage_item_sync_freshness_state(
            item,
            last_attempt_at=parsed_last_attempt_at if isinstance(parsed_last_attempt_at, datetime) else None,
            last_success_at=parsed_last_synced_at if isinstance(parsed_last_synced_at, datetime) else None,
            last_error_at=parsed_last_error_at if isinstance(parsed_last_error_at, datetime) else None,
        )
        return task_manager_module.BinarySecurityStageItemResponse(
            id=item.id,
            stage_name=item.stage_name,
            item_key=item.item_key,
            item_name=item.item_name,
            parent_key=item.parent_key,
            status=item.status,
            retry_count=int(item.retry_count or 0),
            rerun_count=int(item.rerun_count or 0),
            auto_retry_count=int(item.retry_count or 0),
            total_retry_count=total_retry_count,
            downstream_service=item.downstream_service,
            downstream_task_id=item.downstream_task_id,
            archive_bound_downstream_task_id=archive_bound_downstream_task_id,
            latest_binding_mismatch=latest_binding_mismatch,
            downstream_status=downstream_status,
            downstream_binding_state=binding_state,
            downstream_create_attempts=max(0, int(binding.get("attempts") or 0)),
            downstream_create_last_attempt_at=self._parse_comparable_datetime(binding.get("last_attempt_at")),
            downstream_create_next_retry_at=self._parse_comparable_datetime(binding.get("next_retry_at")),
            downstream_create_last_error=self._string_or_none(binding.get("last_error")),
            downstream_create_last_error_type=self._string_or_none(binding.get("last_error_type")),
            downstream_create_recoverable=self._bool_or_none(binding.get("recoverable")),
            downstream_binding_message=binding_message or self._downstream_binding_status_message(item),
            downstream_cancel_phase=self._string_or_none(downstream_payload.get("cancel_phase")),
            downstream_summary=self._stage_item_downstream_summary(item, result=result),
            input_ref=item.input_ref,
            output_ref=output_ref,
            result=result,
            error_message=item.error_message,
            abnormal_reason=self._stage_item_abnormal_reason(item, task=task),
            sync_status=str(sync_status) if sync_status is not None else None,
            last_synced_at=parsed_last_synced_at,
            last_sync_attempt_at=parsed_last_attempt_at if isinstance(parsed_last_attempt_at, datetime) else None,
            last_sync_success_at=parsed_last_synced_at if isinstance(parsed_last_synced_at, datetime) else None,
            last_sync_error_at=parsed_last_error_at if isinstance(parsed_last_error_at, datetime) else None,
            last_sync_error_message=self._string_or_none(sync_observation.get("error_message")) or self._string_or_none(result.get("last_sync_error_message")),
            last_sync_error_type=self._string_or_none(sync_observation.get("error_type")) or self._string_or_none(result.get("last_sync_error_type")),
            sync_freshness_state=freshness_state,
            downstream_raw_status=self._string_or_none(sync_observation.get("status_raw")),
            downstream_mapped_status=self._string_or_none(sync_observation.get("mapped_status")),
            downstream_state_applied=self._bool_or_none(sync_observation.get("state_applied")),
            sync_observation_error_message=self._string_or_none(sync_observation.get("error_message")),
            sync_observation_error_type=self._string_or_none(sync_observation.get("error_type")),
            sync_observation_http_status=self._int_or_none(sync_observation.get("http_status")),
            first_started_at=first_started_at,
            latest_started_at=latest_started_at,
            started_at=item.started_at,
            finished_at=item.finished_at,
        )

    def _log_task_read_projection_built(
        self: TaskManager,
        *,
        projection_kind: str,
        task: Any,
        stage_items_count: int,
        active_stage_name: str | None,
        used_cached_projection: bool,
    ) -> None:
        logger.info(
            "binary-security %s projection_only=true task_id=%s active_stage_name=%s stage_items_count=%s used_cached_projection=%s",
            projection_kind,
            task.id,
            str(active_stage_name or "").strip() or "-",
            int(stage_items_count or 0),
            bool(used_cached_projection),
        )

    def _log_task_list_query(
        self: TaskManager,
        *,
        project_id: str,
        task_type: str,
        page: int,
        page_size: int,
        total: int | None,
        item_count: int | None,
        duration_seconds: float,
        stage_durations: dict[str, float],
        result: str = "success",
    ) -> None:
        stage_summary = " ".join(
            f"{name}={duration:.3f}s" for name, duration in sorted(stage_durations.items(), key=lambda item: item[0])
        )
        level = logging.INFO
        if duration_seconds > 3.0:
            level = logging.ERROR
        elif duration_seconds > 1.0:
            level = logging.WARNING
        logger.log(
            level,
            "binary-security task list query result=%s project_id=%s task_type=%s page=%s page_size=%s total=%s item_count=%s duration=%.3fs stages=%s",
            result,
            project_id,
            task_type,
            page,
            page_size,
            total if total is not None else "-",
            item_count if item_count is not None else "-",
            duration_seconds,
            stage_summary or "-",
        )
