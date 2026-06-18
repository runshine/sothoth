from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from app.model import BinarySecurityStageItem, BinarySecurityTask

from . import shared as task_shared

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class TaskEventServiceMixin:
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
        normalized_payload = payload or {}
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
        self._trim_task_timeline_events(db, task_id=task.id)

    def _event_dedupe_window_seconds(self: TaskManager, event_type: str) -> int:
        if str(event_type or "").strip() in {
            "owned_execution_takeover_requeued",
            "streaming_stage_item_requeued_after_downstream_missing",
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
                "dispatcher_instance_id": payload.get("dispatcher_instance_id"),
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
        overflow = (
            db.query(task_manager_module.BinarySecurityEvent)
            .filter(task_manager_module.BinarySecurityEvent.task_id == task_id)
            .count()
            - effective_limit
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

        normalized_payload = dict(payload or {})
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
