from __future__ import annotations

import json
import os
import socket
import uuid
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.model import BinarySecurityStageItem, BinarySecuritySyncEvent, BinarySecurityTask

from . import shared as task_shared

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class TaskEventServiceMixin:
    def _defer_inline_event_trim_for_task(
        self: TaskManager,
        task: BinarySecurityTask | None,
    ) -> bool:
        if task is None:
            return False
        normalized_status = str(getattr(task, "status", "") or "").strip().lower()
        return normalized_status in {"pending", "dispatching", "running", "cancelling"}

    def _suppress_event_trim_lock_error(
        self: TaskManager,
        exc: OperationalError,
        *,
        task_id: str,
        trim_kind: str,
    ) -> bool:
        from app.service import task_manager as task_manager_module

        if not self._is_retryable_lock_error(exc):
            return False
        task_manager_module.logger.warning(
            "binary-security %s trim skipped due to retryable db lock conflict: task_id=%s error_type=%s error=%s",
            trim_kind,
            str(task_id or "").strip() or None,
            exc.__class__.__name__,
            exc,
        )
        return True

    def _sync_event_item_bucket_key(
        self: TaskManager,
        *,
        item: BinarySecurityStageItem | dict[str, Any] | None = None,
        stage_name: str | None = None,
        downstream_service: str | None = None,
    ) -> str | None:
        item_id = str(task_shared._stage_item_attr(item, "id") or "").strip()
        if item_id:
            return f"item:{item_id}"
        normalized_stage = str(stage_name or task_shared._stage_item_attr(item, "stage_name") or "").strip()
        normalized_service = str(downstream_service or task_shared._stage_item_attr(item, "downstream_service") or "").strip()
        normalized_item_key = str(task_shared._stage_item_attr(item, "item_key") or "").strip()
        if normalized_stage or normalized_service or normalized_item_key:
            return f"fallback:{normalized_stage}:{normalized_service}:{normalized_item_key}"
        return None

    def _normalize_event_payload_value(self: TaskManager, value: Any) -> Any:
        if isinstance(value, datetime):
            return task_shared._isoformat_or_none(value)
        if isinstance(value, dict):
            return {str(key): self._normalize_event_payload_value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._normalize_event_payload_value(item) for item in value]
        if isinstance(value, tuple):
            return [self._normalize_event_payload_value(item) for item in value]
        if isinstance(value, set):
            return [self._normalize_event_payload_value(item) for item in sorted(value, key=lambda item: str(item))]
        return value

    def _set_task_status(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        new_status: str,
        *,
        reason: str,
        source: str,
        event_type: str = "task_status_changed",
        message: str | None = None,
        level: str = "info",
        stage_name: str | None = None,
        payload: dict[str, Any] | None = None,
        operation_id: str | None = None,
        record_event: bool = True,
        allow_noop: bool = False,
    ) -> bool:
        previous_status = str(getattr(task, "status", "") or "").strip()
        next_status = str(new_status or "").strip()
        if not next_status:
            return False
        if not allow_noop and previous_status == next_status:
            return False
        task.status = next_status
        if not record_event:
            return previous_status != next_status or allow_noop
        self._record_event(
            db,
            task,
            event_type,
            message or f"任务状态变更: {previous_status or '-'} -> {next_status}",
            level=level,
            stage_name=stage_name,
            payload={
                "from_status": previous_status or None,
                "to_status": next_status,
                "reason": str(reason or "").strip() or None,
                "source": str(source or "").strip() or None,
                **(payload or {}),
            },
            operation_id=operation_id,
        )
        return True

    def _event_hostname(self: TaskManager) -> str | None:
        hostname = str(os.environ.get("HOSTNAME") or "").strip()
        if hostname:
            return hostname
        try:
            resolved = str(socket.gethostname() or "").strip()
        except Exception:
            resolved = ""
        return resolved or None

    def _event_pod_name(self: TaskManager) -> str | None:
        pod_name = str(os.environ.get("POD_NAME") or "").strip()
        if pod_name:
            return pod_name
        return self._event_hostname()

    def _event_node_name(self: TaskManager) -> str | None:
        node_name = str(os.environ.get("NODE_NAME") or "").strip()
        return node_name or None

    def _event_runtime_role(self: TaskManager) -> str:
        normalized = str(self._service_role() or "").strip().lower()
        if normalized == "api":
            return "api"
        if normalized == "worker":
            return "worker"
        return "worker"

    def _build_event_recorder_metadata(
        self: TaskManager,
        *,
        role: str | None = None,
    ) -> dict[str, Any]:
        normalized_role = str(role or "").strip().lower() or self._event_runtime_role()
        return {
            "service": "binary-security",
            "role": normalized_role,
            "instance_id": str(self.instance_id or "").strip() or None,
            "hostname": self._event_hostname(),
            "pod_name": self._event_pod_name(),
            "node_name": self._event_node_name(),
        }

    def _merge_event_recorder_metadata(
        self: TaskManager,
        payload: dict[str, Any] | None,
        *,
        role: str | None = None,
    ) -> dict[str, Any]:
        normalized_payload = dict(payload or {})
        existing = normalized_payload.get("recorder")
        normalized_payload["recorder"] = {
            **(existing if isinstance(existing, dict) else {}),
            **self._build_event_recorder_metadata(role=role),
        }
        return normalized_payload

    def _build_event_origin_metadata_from_state_event(
        self: TaskManager,
        state_event: Any | None,
    ) -> dict[str, Any] | None:
        if state_event is None:
            return None
        payload = dict(getattr(state_event, "payload", None) or {})
        emitted_by = dict(payload.get("emitted_by") or {})
        origin = {
            "kind": "state_event",
            "state_event_id": str(getattr(state_event, "id", "") or "").strip() or None,
            "emitted_by_instance_id": str(emitted_by.get("instance_id") or "").strip() or None,
            "emitted_by_hostname": str(emitted_by.get("hostname") or "").strip() or None,
            "emitted_by_pod_name": str(emitted_by.get("pod_name") or "").strip() or None,
            "emitted_by_node_name": str(emitted_by.get("node_name") or "").strip() or None,
            "emitted_by_role": str(emitted_by.get("role") or payload.get("runtime_role") or "worker").strip().lower() or "worker",
            "processed_by_instance_id": str(self.instance_id or "").strip() or None,
            "processed_by_hostname": self._event_hostname(),
            "processed_by_pod_name": self._event_pod_name(),
            "processed_by_node_name": self._event_node_name(),
            "processed_by_role": "owner",
        }
        meaningful = {key: value for key, value in origin.items() if key != "kind" and value}
        return origin if meaningful else None

    def _merge_event_origin_metadata(
        self: TaskManager,
        payload: dict[str, Any] | None,
        *,
        state_event: Any | None,
    ) -> dict[str, Any]:
        normalized_payload = dict(payload or {})
        origin = self._build_event_origin_metadata_from_state_event(state_event)
        if not origin:
            return normalized_payload
        existing = normalized_payload.get("event_origin")
        normalized_payload["event_origin"] = {
            **(existing if isinstance(existing, dict) else {}),
            **origin,
        }
        return normalized_payload

    def _record_event(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        event_type: str,
        message: str,
        *,
        level: str = "info",
        stage_name: str | None = None,
        item: BinarySecurityStageItem | None = None,
        payload: dict[str, Any] | None = None,
        operation_id: str | None = None,
    ) -> None:
        normalized_payload = self._merge_event_recorder_metadata(payload, role=self._event_runtime_role())
        normalized_payload = self._merge_event_origin_metadata(
            normalized_payload,
            state_event=getattr(self, "_active_timeline_origin_state_event", None),
        )
        if self._should_skip_duplicate_event(
            db,
            task=task,
            event_type=event_type,
            message=message,
            stage_name=stage_name,
            item=item,
            payload=normalized_payload,
            operation_id=operation_id,
        ):
            return
        from app.service import task_manager as task_manager_module

        event = task_manager_module.BinarySecurityEvent(
            id=f"evt_{uuid.uuid4().hex[:24]}",
            task_id=task.id,
            project_id=task.project_id,
            operation_id=operation_id,
            stage_name=stage_name,
            item_id=task_shared._stage_item_attr(item, "id"),
            item_key=task_shared._stage_item_attr(item, "item_key"),
            level=level,
            event_type=event_type,
            message=message,
        )
        event.payload = self._prepare_event_payload_for_db(
            db,
            task=task,
            event_id=event.id,
            event_type=event_type,
            stage_name=stage_name,
            payload=normalized_payload,
            state_event=False,
        )
        db.add(event)
        if not self._defer_inline_event_trim_for_task(task):
            self._trim_task_timeline_events(db, task_id=task.id)

    def _sync_event_origin_value(self: TaskManager, payload: dict[str, Any] | None, key: str) -> str | None:
        origin = dict((payload or {}).get("event_origin") or {})
        value = origin.get(key)
        normalized = str(value or "").strip()
        return normalized or None

    def _trim_task_sync_events(self: TaskManager, db: Session, *, task_id: str, keep_limit: int | None = None) -> None:
        from app.service import task_manager as task_manager_module

        effective_limit = task_manager_module.DB_SYNC_EVENT_LIMIT if keep_limit is None else int(keep_limit)
        if effective_limit <= 0 or not hasattr(db, "query") or not hasattr(db, "delete"):
            return
        try:
            current_count = 0
            if hasattr(db, "sync_events"):
                current_count = len(getattr(db, "sync_events") or [])
            else:
                current_count = (
                    db.query(task_manager_module.BinarySecuritySyncEvent)
                    .filter(task_manager_module.BinarySecuritySyncEvent.task_id == task_id)
                    .count()
                )
            overflow = (
                current_count - effective_limit
            )
            if overflow <= 0:
                return
            stale_rows = (
                db.query(task_manager_module.BinarySecuritySyncEvent)
                .filter(task_manager_module.BinarySecuritySyncEvent.task_id == task_id)
                .order_by(task_manager_module.BinarySecuritySyncEvent.created_at.asc(), task_manager_module.BinarySecuritySyncEvent.id.asc())
                .limit(overflow)
                .all()
            )
            for stale_row in stale_rows:
                db.delete(stale_row)
        except OperationalError as exc:
            if self._suppress_event_trim_lock_error(exc, task_id=task_id, trim_kind="sync event"):
                return
            raise

    def _trim_stage_item_sync_events(
        self: TaskManager,
        db: Session,
        *,
        task_id: str,
        item_bucket_key: str | None,
        keep_limit: int = 20,
    ) -> None:
        from app.service import task_manager as task_manager_module

        normalized_bucket = str(item_bucket_key or "").strip()
        effective_limit = max(1, int(keep_limit or 20))
        if not normalized_bucket or not hasattr(db, "query") or not hasattr(db, "delete"):
            return
        try:
            if hasattr(db, "sync_events"):
                bucket_rows = [
                    row for row in (getattr(db, "sync_events") or [])
                    if str(getattr(row, "task_id", "") or "").strip() == task_id
                    and str(getattr(row, "item_bucket_key", "") or "").strip() == normalized_bucket
                ]
                current_count = len(bucket_rows)
            else:
                current_count = (
                    db.query(task_manager_module.BinarySecuritySyncEvent)
                    .filter(task_manager_module.BinarySecuritySyncEvent.task_id == task_id)
                    .filter(task_manager_module.BinarySecuritySyncEvent.item_bucket_key == normalized_bucket)
                    .count()
                )
            overflow = current_count - effective_limit
            if overflow <= 0:
                return
            stale_rows = (
                db.query(task_manager_module.BinarySecuritySyncEvent)
                .filter(task_manager_module.BinarySecuritySyncEvent.task_id == task_id)
                .filter(task_manager_module.BinarySecuritySyncEvent.item_bucket_key == normalized_bucket)
                .order_by(task_manager_module.BinarySecuritySyncEvent.created_at.asc(), task_manager_module.BinarySecuritySyncEvent.id.asc())
                .limit(overflow)
                .all()
            )
            for stale_row in stale_rows:
                db.delete(stale_row)
        except OperationalError as exc:
            if self._suppress_event_trim_lock_error(
                exc,
                task_id=task_id,
                trim_kind="stage item sync event",
            ):
                return
            raise

    def _record_stage_item_sync_audit(
        self: TaskManager,
        db: Session | None,
        *,
        task: BinarySecurityTask | None,
        item: BinarySecurityStageItem | dict[str, Any] | None = None,
        stage_name: str | None = None,
        downstream_service: str | None = None,
        operation: str | None = None,
        event_type: str,
        sync_status: str | None = None,
        outcome: str | None = None,
        state_applied: bool | None = None,
        error_type: str | None = None,
        error_message: str | None = None,
        http_status: int | None = None,
        payload: dict[str, Any] | None = None,
        role: str | None = None,
    ) -> None:
        if db is None or task is None:
            return
        try:
            from app.service import task_manager as task_manager_module

            normalized_stage = str(stage_name or task_shared._stage_item_attr(item, "stage_name") or "").strip() or None
            normalized_service = str(downstream_service or task_shared._stage_item_attr(item, "downstream_service") or "").strip() or None
            normalized_payload = self._merge_event_recorder_metadata(payload, role=role or self._event_runtime_role())
            normalized_payload = self._merge_event_origin_metadata(
                normalized_payload,
                state_event=getattr(self, "_active_timeline_origin_state_event", None),
            )
            item_bucket_key = self._sync_event_item_bucket_key(
                item=item,
                stage_name=normalized_stage,
                downstream_service=normalized_service,
            )
            row = task_manager_module.BinarySecuritySyncEvent(
                id=f"syncevt_{uuid.uuid4().hex[:24]}",
                project_id=task.project_id,
                task_id=task.id,
                stage_name=normalized_stage,
                item_id=task_shared._stage_item_attr(item, "id"),
                item_bucket_key=item_bucket_key,
                item_key=task_shared._stage_item_attr(item, "item_key"),
                item_name=task_shared._stage_item_attr(item, "item_name"),
                downstream_service=normalized_service,
                downstream_task_id=task_shared._stage_item_attr(item, "downstream_task_id"),
                operation=str(operation or "").strip() or None,
                event_type=str(event_type or "").strip() or "observed",
                sync_status=str(sync_status or "").strip() or None,
                outcome=str(outcome or "").strip() or None,
                state_applied=state_applied,
                error_type=str(error_type or "").strip() or None,
                error_message=str(error_message or "").strip() or None,
                http_status=http_status,
                recorder_instance_id=str((normalized_payload.get("recorder") or {}).get("instance_id") or "").strip() or None,
                recorder_hostname=str((normalized_payload.get("recorder") or {}).get("hostname") or "").strip() or None,
                recorder_pod_name=str((normalized_payload.get("recorder") or {}).get("pod_name") or "").strip() or None,
                recorder_node_name=str((normalized_payload.get("recorder") or {}).get("node_name") or "").strip() or None,
                recorder_role=str((normalized_payload.get("recorder") or {}).get("role") or "").strip() or None,
                origin_instance_id=self._sync_event_origin_value(normalized_payload, "emitted_by_instance_id"),
                origin_hostname=self._sync_event_origin_value(normalized_payload, "emitted_by_hostname"),
                origin_pod_name=self._sync_event_origin_value(normalized_payload, "emitted_by_pod_name"),
                origin_node_name=self._sync_event_origin_value(normalized_payload, "emitted_by_node_name"),
                origin_role=self._sync_event_origin_value(normalized_payload, "emitted_by_role"),
            )
            row.payload = self._prepare_event_payload_for_db(
                db,
                task=task,
                event_id=row.id,
                event_type=f"sync_{row.event_type}",
                stage_name=row.stage_name,
                payload=normalized_payload,
                state_event=False,
            )
            db.add(row)
            if not self._defer_inline_event_trim_for_task(task):
                self._trim_stage_item_sync_events(
                    db,
                    task_id=task.id,
                    item_bucket_key=item_bucket_key,
                    keep_limit=20,
                )
                self._trim_task_sync_events(db, task_id=task.id)
        except Exception:
            if hasattr(self, "_logger"):
                self._logger.exception("record downstream sync event failed")

    def _record_downstream_sync_event(
        self: TaskManager,
        db: Session | None,
        *,
        task: BinarySecurityTask | None,
        item: BinarySecurityStageItem | dict[str, Any] | None = None,
        stage_name: str | None = None,
        operation: str | None = None,
        event_type: str,
        sync_status: str | None = None,
        outcome: str | None = None,
        state_applied: bool | None = None,
        error_type: str | None = None,
        error_message: str | None = None,
        http_status: int | None = None,
        payload: dict[str, Any] | None = None,
        role: str | None = None,
    ) -> None:
        if db is None or task is None:
            return
        self._record_stage_item_sync_audit(
            db,
            task=task,
            item=item,
            stage_name=stage_name,
            operation=operation,
            event_type=event_type,
            sync_status=sync_status,
            outcome=outcome,
            state_applied=state_applied,
            error_type=error_type,
            error_message=error_message,
            http_status=http_status,
            payload=payload,
            role=role,
        )

    def _event_dedupe_window_seconds(self: TaskManager, event_type: str) -> int:
        if str(event_type or "").strip() in {
            "owned_execution_takeover_requeued",
            "streaming_stage_item_observation_gap_detected",
        }:
            return 10
        return 0

    def _should_skip_duplicate_event(
        self: TaskManager,
        db: Session,
        *,
        task: BinarySecurityTask,
        event_type: str,
        message: str,
        stage_name: str | None,
        item: BinarySecurityStageItem | None,
        payload: dict[str, Any],
        operation_id: str | None,
    ) -> bool:
        within_seconds = self._event_dedupe_window_seconds(event_type)
        if within_seconds <= 0 or not hasattr(db, "query"):
            return False
        return self._has_recent_matching_task_event(
            db,
            task,
            event_type=event_type,
            stage_name=stage_name,
            message=message,
            payload_keys={
                "downstream_task_id": payload.get("downstream_task_id"),
                "takeover_action": payload.get("takeover_action"),
                "takeover_reason": payload.get("takeover_reason"),
                "recovery_action": payload.get("recovery_action"),
                "task_execution_token": payload.get("task_execution_token"),
                "runtime_lease_owner": payload.get("runtime_lease_owner"),
                "operation_id": operation_id,
                "item_id": task_shared._stage_item_attr(item, "id"),
                "item_key": task_shared._stage_item_attr(item, "item_key"),
            },
            within_seconds=within_seconds,
        )

    def _trim_task_timeline_events(self: TaskManager, db: Session, *, task_id: str, keep_limit: int | None = None) -> None:
        from app.service import task_manager as task_manager_module

        effective_limit = task_manager_module.DB_TIMELINE_EVENT_LIMIT if keep_limit is None else int(keep_limit)
        if effective_limit <= 0:
            return
        if not hasattr(db, "query") or not hasattr(db, "delete"):
            return
        try:
            current_count = 0
            if hasattr(db, "events"):
                current_count = len(getattr(db, "events") or [])
            else:
                current_count = (
                    db.query(task_manager_module.BinarySecurityEvent)
                    .filter(task_manager_module.BinarySecurityEvent.task_id == task_id)
                    .count()
                )
            overflow = (
                current_count - effective_limit
            )
            if overflow <= 0:
                return
            stale_events = (
                db.query(task_manager_module.BinarySecurityEvent)
                .filter(task_manager_module.BinarySecurityEvent.task_id == task_id)
                .order_by(task_manager_module.BinarySecurityEvent.created_at.asc(), task_manager_module.BinarySecurityEvent.id.asc())
                .limit(overflow)
                .all()
            )
            for stale_event in stale_events:
                db.delete(stale_event)
        except OperationalError as exc:
            if self._suppress_event_trim_lock_error(exc, task_id=task_id, trim_kind="timeline event"):
                return
            raise

    @staticmethod
    def _json_payload_size_bytes(value: Any) -> int:
        return len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))

    def _event_payload_path(
        self: TaskManager,
        task: BinarySecurityTask,
        *,
        event_id: str,
        event_type: str,
        state_event: bool,
    ) -> Path:
        folder_name = "state-event-payloads" if state_event else "timeline-event-payloads"
        return Path(task.workspace_root) / "run" / folder_name / f"{event_id}_{task_shared._slug(event_type)}.json"

    def _event_payload_preview_value(self: TaskManager, value: Any, *, depth: int = 0) -> Any:
        if depth >= 2:
            if isinstance(value, dict):
                return {"field_count": len(value)}
            if isinstance(value, list):
                return {"item_count": len(value)}
            if isinstance(value, str):
                return value[:200]
            return value
        if isinstance(value, dict):
            preview: dict[str, Any] = {}
            for index, (key, current) in enumerate(value.items()):
                if index >= 8:
                    preview["preview_truncated"] = True
                    break
                if isinstance(current, (dict, list)):
                    preview[f"{key}_count"] = len(current)
                    preview[f"{key}_preview"] = self._event_payload_preview_value(current, depth=depth + 1)
                elif isinstance(current, str):
                    preview[key] = current[:500]
                else:
                    preview[key] = current
            return preview
        if isinstance(value, list):
            return [self._event_payload_preview_value(current, depth=depth + 1) for current in value[:3]]
        if isinstance(value, str):
            return value[:500]
        return value

    def _fit_event_payload_for_db(
        self: TaskManager,
        compact: dict[str, Any],
        *,
        max_bytes: int | None = None,
    ) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        effective_max = task_manager_module.DB_EVENT_PAYLOAD_LIMIT_BYTES if max_bytes is None else int(max_bytes)
        payload = dict(compact or {})
        if self._json_payload_size_bytes(payload) <= effective_max:
            return payload
        for key in list(payload.keys()):
            value = payload.get(key)
            if isinstance(value, list):
                payload[f"{key}_count"] = len(value)
                payload[key] = value[:1]
            elif isinstance(value, dict) and key.endswith("_preview"):
                payload[key] = self._event_payload_preview_value(value, depth=1)
            elif isinstance(value, str) and len(value) > 1000:
                payload[key] = value[:1000]
        if self._json_payload_size_bytes(payload) <= effective_max:
            return payload
        minimal = {
            key: value
            for key, value in payload.items()
            if key in {
                "payload_externalized",
                "payload_file",
                "summary_externalized",
                "summary_file",
                "stage_name",
                "status",
                "stage_retry_mode",
                "task_retry_mode",
                "target_stage_name",
                "error",
                "reason",
            }
        }
        minimal["db_payload_truncated"] = True
        return minimal

    def _resolve_task_for_event_payload(
        self: TaskManager,
        db: Session,
        *,
        task: BinarySecurityTask | None,
        task_id: str | None,
        project_id: str | None,
    ) -> BinarySecurityTask | None:
        from app.service import task_manager as task_manager_module

        if task is not None:
            return task
        if not task_id or not project_id:
            return None
        return db.query(task_manager_module.BinarySecurityTask).filter(
            task_manager_module.BinarySecurityTask.id == task_id,
            task_manager_module.BinarySecurityTask.project_id == project_id,
        ).first()

    def _compact_state_terminal_payload_for_db(
        self: TaskManager,
        db: Session,
        *,
        task: BinarySecurityTask,
        stage_name: str | None,
        payload: dict[str, Any],
        payload_file: str | None,
    ) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        compact = {
            "stage_name": payload.get("stage_name") or stage_name,
            "status": payload.get("status"),
            "stage_retry_mode": bool(payload.get("stage_retry_mode")),
            "task_retry_mode": bool(payload.get("task_retry_mode")),
            "target_stage_name": payload.get("target_stage_name"),
            "payload_externalized": bool(payload_file),
        }
        if payload_file:
            compact["payload_file"] = payload_file
        summary = dict(payload.get("summary") or {})
        stage_run = None
        effective_stage_name = str(compact.get("stage_name") or "").strip()
        if effective_stage_name:
            stage_run = db.query(task_manager_module.BinarySecurityStageRun).filter(
                task_manager_module.BinarySecurityStageRun.task_id == task.id,
                task_manager_module.BinarySecurityStageRun.stage_name == effective_stage_name,
            ).first()
        if stage_run is not None:
            summary_compact = self._compact_stage_output_summary_for_db(
                task,
                stage_run,
                summary,
                summary_file=payload_file,
            )
        else:
            summary_compact = self._fit_event_payload_for_db(
                {
                    "summary_externalized": bool(payload_file),
                    "summary_file": payload_file,
                    "summary_preview": self._event_payload_preview_value(summary),
                }
            )
        compact["summary"] = summary_compact
        return self._fit_event_payload_for_db(compact)

    def _compact_generic_event_payload_for_db(
        self: TaskManager,
        payload: dict[str, Any],
        *,
        payload_file: str | None,
    ) -> dict[str, Any]:
        compact: dict[str, Any] = {
            "payload_externalized": bool(payload_file),
        }
        if payload_file:
            compact["payload_file"] = payload_file
        for key, value in (payload or {}).items():
            if isinstance(value, (str, int, float, bool)) or value is None:
                compact[key] = value[:1000] if isinstance(value, str) else value
            elif isinstance(value, list):
                compact[f"{key}_count"] = len(value)
                compact[f"{key}_preview"] = self._event_payload_preview_value(value)
            elif isinstance(value, dict):
                compact[f"{key}_preview"] = self._event_payload_preview_value(value)
        return self._fit_event_payload_for_db(compact)

    def _prepare_event_payload_for_db(
        self: TaskManager,
        db: Session,
        *,
        task: BinarySecurityTask | None,
        event_id: str,
        event_type: str,
        stage_name: str | None,
        payload: dict[str, Any],
        state_event: bool,
        task_id: str | None = None,
        project_id: str | None = None,
    ) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        normalized_payload = self._normalize_event_payload_value(dict(payload or {}))
        if self._json_payload_size_bytes(normalized_payload) <= task_manager_module.DB_EVENT_PAYLOAD_LIMIT_BYTES:
            return normalized_payload
        resolved_task = self._resolve_task_for_event_payload(
            db,
            task=task,
            task_id=task_id,
            project_id=project_id,
        )
        payload_file: str | None = None
        if resolved_task is not None and str(resolved_task.workspace_root or "").strip():
            try:
                path = self._event_payload_path(
                    resolved_task,
                    event_id=event_id,
                    event_type=event_type,
                    state_event=state_event,
                )
                if self._guard_task_workspace_write(
                    resolved_task,
                    purpose="event_payload" if not state_event else "state_event_payload",
                    path=path,
                ):
                    task_shared._write_json(path, normalized_payload)
                    payload_file = str(path)
            except Exception:
                payload_file = None
        if state_event and event_type == "stage_worker_terminal_observed" and resolved_task is not None:
            return self._compact_state_terminal_payload_for_db(
                db,
                task=resolved_task,
                stage_name=stage_name,
                payload=normalized_payload,
                payload_file=payload_file,
            )
        return self._compact_generic_event_payload_for_db(normalized_payload, payload_file=payload_file)

    def _load_externalized_event_payload(
        self: TaskManager,
        task: BinarySecurityTask,
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]:
        normalized_payload = dict(payload or {})
        payload_file = str(normalized_payload.get("payload_file") or "").strip()
        if not payload_file:
            return normalized_payload
        candidate = Path(payload_file)
        if not candidate.is_absolute():
            candidate = Path(task.workspace_root) / candidate
        try:
            if candidate.is_file():
                loaded = json.loads(candidate.read_text(encoding="utf-8") or "{}")
                if isinstance(loaded, dict):
                    return loaded
        except Exception:
            return normalized_payload
        return normalized_payload
