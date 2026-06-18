from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

import httpx
from sqlalchemy.exc import OperationalError, TimeoutError as SATimeoutError
from sqlalchemy.orm import Session

from app.exception import ConflictError, NotFoundError, UpstreamError, ValidationError
from app.model import BinarySecurityStageItem, BinarySecurityStageRun, BinarySecurityTask, TASK_RUNTIME_PHASE_TAIL_RECONCILIATION, normalize_stage_name
from app.observability import observe_downstream_reconcile_observation, observe_task_readless_reconcile
from app.service.readless_sync import ReadlessSyncStats
from app.schemas import BinarySecurityActionResponse

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager, _TaskStateSnapshot


class TaskItemSyncServiceMixin:
    def _task_sync_cooldown_elapsed(self: TaskManager, db: Session, task: BinarySecurityTask) -> bool:
        candidates = self._task_reconcile_candidate_items(db, task, force=True)
        if not candidates and hasattr(db, "stage_items"):
            candidates = [
                item
                for item in list(getattr(db, "stage_items", []) or [])
                if str(getattr(item, "task_id", "") or "").strip() == str(task.id or "").strip()
                and str(getattr(item, "downstream_service", "") or "").strip()
            ]
        if not candidates:
            return False
        stale_threshold_seconds = self._stage_item_sync_stale_seconds()
        now_value = datetime.now()
        for item in candidates:
            sync_at = self._stage_item_sync_attempt_at_value(item)
            if sync_at is None:
                sync_at = self._stage_item_next_sync_retry_at_value(item)
            if sync_at is None:
                raw = dict(getattr(item, "result", {}) or {}).get("downstream_status_synced_at")
                if isinstance(raw, str) and raw.strip():
                    try:
                        sync_at = datetime.fromisoformat(raw)
                    except ValueError:
                        sync_at = None
            if sync_at is None:
                continue
            if (now_value - sync_at).total_seconds() >= stale_threshold_seconds:
                return True
        return any(True for _ in candidates)

    def _task_has_stale_active_reconcile_items(self: TaskManager, db: Session, task: BinarySecurityTask) -> bool:
        candidates = self._task_reconcile_candidate_items(db, task, force=False)
        if not candidates:
            return False
        return any(
            (self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower())
            in {"pending", "queued", "dispatching", "running"}
            or self._item_needs_downstream_binding_reconcile(item)
            for item in candidates
        )

    def _list_tasks_needing_downstream_sync(self: TaskManager, db: Session) -> list[dict[str, str]]:
        refs: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for task in db.query(BinarySecurityTask).all():
            task_id = str(getattr(task, "id", "") or "").strip()
            project_id = str(getattr(task, "project_id", "") or "").strip()
            if not task_id or not project_id:
                continue
            if self._task_runtime_phase(task) == TASK_RUNTIME_PHASE_TAIL_RECONCILIATION and not self._is_reducer_role():
                continue
            if not self._task_needs_downstream_reconcile(db, task):
                continue
            ref = (project_id, task_id)
            if ref in seen:
                continue
            seen.add(ref)
            refs.append({"project_id": project_id, "task_id": task_id})
        return refs

    def _task_stage_items_with_downstream_refs(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_name: str | None = None,
    ) -> list[BinarySecurityStageItem]:
        query = db.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.task_id == task.id,
            BinarySecurityStageItem.downstream_service.isnot(None),
            BinarySecurityStageItem.downstream_task_id.isnot(None),
        )
        if stage_name:
            query = query.filter(BinarySecurityStageItem.stage_name == stage_name)
        return query.order_by(
            BinarySecurityStageItem.updated_at.asc(),
            BinarySecurityStageItem.created_at.asc(),
            BinarySecurityStageItem.id.asc(),
        ).all()

    def _item_missing_recorded_downstream_status(self: TaskManager, item: BinarySecurityStageItem) -> bool:
        result = self._load_stage_item_result_payload(item)
        if self._string_or_none(result.get("downstream_status")):
            return False
        downstream_payload = dict(result.get("downstream") or {})
        return not self._string_or_none(downstream_payload.get("status"))

    def _task_reconcile_candidate_items(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_name: str | None = None,
        item_id: str | None = None,
        force: bool = False,
        include_failed_terminal_items: bool = False,
    ) -> list[BinarySecurityStageItem]:
        query = db.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.task_id == task.id,
            BinarySecurityStageItem.downstream_service.isnot(None),
        )
        if stage_name:
            query = query.filter(BinarySecurityStageItem.stage_name == stage_name)
        items = query.order_by(
            BinarySecurityStageItem.updated_at.asc(),
            BinarySecurityStageItem.created_at.asc(),
            BinarySecurityStageItem.id.asc(),
        ).all()
        if item_id:
            items = [item for item in items if str(item.id or "").strip() == str(item_id or "").strip()]
        if force:
            return items
        candidates: list[BinarySecurityStageItem] = []
        for item in items:
            normalized_status = self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower()
            if (
                str(task.status or "").strip().lower() == "failed"
                and normalized_status in {"failed", "cancelled", "downstream_missing", "partial_success", "success"}
                and not include_failed_terminal_items
                and not self._item_needs_downstream_binding_reconcile(item)
                and not self._item_missing_recorded_downstream_status(item)
            ):
                continue
            if (
                normalize_stage_name(item.stage_name) == "dataflow_vuln_scan"
                and not str(item.downstream_task_id or "").strip()
                and self._item_needs_downstream_binding_reconcile(item)
            ):
                candidates.append(item)
                continue
            if self._item_needs_downstream_sync(
                item,
                for_task_status=str(task.status or "").strip().lower() or None,
            ):
                candidates.append(item)
                continue
            if self._item_missing_recorded_downstream_status(item):
                candidates.append(item)
                continue
            if include_failed_terminal_items and normalized_status in {
                "failed",
                "cancelled",
                "downstream_missing",
                "partial_success",
                "success",
            }:
                candidates.append(item)
        return candidates

    def _stage_item_sync_observation(self: TaskManager, item: BinarySecurityStageItem) -> dict[str, Any]:
        result = self._load_stage_item_result_payload(item)
        observation = result.get("sync_observation") or {}
        return dict(observation) if isinstance(observation, dict) else {}

    def _stage_item_orchestration_observation(self: TaskManager, item: BinarySecurityStageItem) -> dict[str, Any]:
        result = self._load_stage_item_result_payload(item)
        observation = result.get("orchestration_observation") or {}
        return dict(observation) if isinstance(observation, dict) else {}

    def _stage_item_sync_attempt_at_value(self: TaskManager, item: BinarySecurityStageItem) -> datetime | None:
        result = self._load_stage_item_result_payload(item)
        sync_observation = self._stage_item_sync_observation(item)
        raw = (
            sync_observation.get("last_attempt_at")
            or result.get("last_sync_attempt_at")
            or sync_observation.get("last_synced_at")
            or result.get("downstream_status_synced_at")
        )
        if not isinstance(raw, str) or not raw.strip():
            return None
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None

    def _stage_item_sync_status_value(self: TaskManager, item: BinarySecurityStageItem) -> str | None:
        result = self._load_stage_item_result_payload(item)
        sync_status = result.get("sync_status")
        if sync_status is None:
            sync_status = dict(result.get("sync_observation") or {}).get("sync_status")
        value = str(sync_status or "").strip().lower()
        return value or None

    def _stage_item_sync_error_budget_exhausted(self: TaskManager, item: BinarySecurityStageItem) -> bool:
        result = self._load_stage_item_result_payload(item)
        sync_observation = self._stage_item_sync_observation(item)
        raw = sync_observation.get("budget_exhausted")
        if raw is None:
            raw = result.get("sync_error_budget_exhausted")
        return bool(raw)

    def _stage_item_next_sync_retry_at_value(self: TaskManager, item: BinarySecurityStageItem) -> datetime | None:
        result = self._load_stage_item_result_payload(item)
        sync_observation = self._stage_item_sync_observation(item)
        raw = sync_observation.get("next_retry_at") or result.get("next_sync_retry_at")
        if not isinstance(raw, str) or not raw.strip():
            return None
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None

    def _stage_item_last_synced_at_value(self: TaskManager, item: BinarySecurityStageItem) -> datetime | None:
        result = self._load_stage_item_result_payload(item)
        raw = result.get("downstream_status_synced_at")
        if not isinstance(raw, str) or not raw.strip():
            raw = dict(result.get("sync_observation") or {}).get("last_synced_at")
        if not isinstance(raw, str) or not raw.strip():
            return None
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None

    def _stage_item_sync_error_type_value(self: TaskManager, item: BinarySecurityStageItem) -> str | None:
        result = self._load_stage_item_result_payload(item)
        observation = self._stage_item_sync_observation(item)
        return self._string_or_none(observation.get("last_error_type")) or self._string_or_none(result.get("last_sync_error_type"))

    def _stage_item_sync_error_message_value(self: TaskManager, item: BinarySecurityStageItem) -> str | None:
        result = self._load_stage_item_result_payload(item)
        observation = self._stage_item_sync_observation(item)
        return self._string_or_none(observation.get("last_error_message")) or self._string_or_none(result.get("last_sync_error_message"))

    def _stage_item_sync_consecutive_error_count(self: TaskManager, item: BinarySecurityStageItem) -> int:
        result = self._load_stage_item_result_payload(item)
        sync_observation = self._stage_item_sync_observation(item)
        raw = sync_observation.get("consecutive_error_count")
        if raw is None:
            raw = result.get("consecutive_sync_error_count")
        try:
            return max(0, int(raw or 0))
        except Exception:
            return 0

    def _stage_item_orchestration_attempt_at_value(
        self: TaskManager,
        item: BinarySecurityStageItem,
    ) -> datetime | None:
        result = self._load_stage_item_result_payload(item)
        observation = self._stage_item_orchestration_observation(item)
        raw = observation.get("last_attempt_at") or result.get("last_orchestration_attempt_at")
        if not isinstance(raw, str) or not raw.strip():
            return None
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None

    def _stage_item_next_orchestration_retry_at_value(
        self: TaskManager,
        item: BinarySecurityStageItem,
    ) -> datetime | None:
        result = self._load_stage_item_result_payload(item)
        observation = self._stage_item_orchestration_observation(item)
        raw = observation.get("next_retry_at") or result.get("next_orchestration_retry_at")
        if not isinstance(raw, str) or not raw.strip():
            return None
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None

    def _stage_item_orchestration_in_retry_backoff(
        self: TaskManager,
        item: BinarySecurityStageItem,
        now_value: datetime | None = None,
    ) -> bool:
        next_retry_at = self._stage_item_next_orchestration_retry_at_value(item)
        if next_retry_at is None:
            return False
        from app.service import task_manager as task_manager_module

        return next_retry_at > (now_value or task_manager_module._now())

    def _stage_item_orchestration_error_budget_exhausted(self: TaskManager, item: BinarySecurityStageItem) -> bool:
        result = self._load_stage_item_result_payload(item)
        observation = self._stage_item_orchestration_observation(item)
        raw = observation.get("budget_exhausted")
        if raw is None:
            raw = result.get("orchestration_error_budget_exhausted")
        return bool(raw)

    def _stage_item_orchestration_consecutive_error_count(self: TaskManager, item: BinarySecurityStageItem) -> int:
        result = self._load_stage_item_result_payload(item)
        observation = self._stage_item_orchestration_observation(item)
        raw = observation.get("consecutive_error_count")
        if raw is None:
            raw = result.get("consecutive_orchestration_error_count")
        try:
            return max(0, int(raw or 0))
        except Exception:
            return 0

    def _next_stage_orchestration_retry_backoff_seconds(self: TaskManager, consecutive_error_count: int) -> int:
        exponent = max(0, int(consecutive_error_count) - 1)
        backoff = self._stage_orchestration_backoff_base_seconds() * (2 ** exponent)
        return min(self._stage_orchestration_backoff_max_seconds(), max(1, int(backoff)))

    def _read_stage_item_orchestration_state(self: TaskManager, item: BinarySecurityStageItem):
        from app.service import task_manager as task_manager_module

        result = self._load_stage_item_result_payload(item)
        observation = self._stage_item_orchestration_observation(item)
        consecutive = observation.get("consecutive_error_count")
        if consecutive is None:
            consecutive = result.get("consecutive_orchestration_error_count")
        exhausted = observation.get("budget_exhausted")
        if exhausted is None:
            exhausted = result.get("orchestration_error_budget_exhausted")
        last_result = self._string_or_none(observation.get("last_result")) or self._string_or_none(
            result.get("last_orchestration_result")
        )
        return task_manager_module.OrchestrationSupervisorState(
            consecutive_error_count=max(0, int(consecutive or 0)),
            budget_exhausted=bool(exhausted),
            next_retry_at=self._stage_item_next_orchestration_retry_at_value(item),
            last_result=last_result,
        )

    def _mark_stage_item_orchestration_observation(
        self: TaskManager,
        item: BinarySecurityStageItem,
        *,
        source: str,
        observed_at: datetime | None = None,
        error_message: str | None = None,
        error_type: str | None = None,
        last_result: str | None = None,
        consecutive_error_count: int | None = None,
        budget_exhausted: bool | None = None,
        next_retry_at: datetime | None = None,
    ) -> None:
        from app.service import task_manager as task_manager_module

        result = dict(item.result or {})
        observation = dict(result.get("orchestration_observation") or {})
        now_value = observed_at or task_manager_module._now()
        observed_at_iso = now_value.isoformat()
        if last_result is None:
            last_result = "error" if error_message or error_type else "success"
        observation.update(
            {
                "source": source,
                "last_attempt_at": observed_at_iso,
                "last_result": last_result,
                "error_message": error_message,
                "error_type": error_type,
            }
        )
        if consecutive_error_count is not None:
            observation["consecutive_error_count"] = max(0, int(consecutive_error_count))
        if budget_exhausted is not None:
            observation["budget_exhausted"] = bool(budget_exhausted)
        if next_retry_at is not None:
            observation["next_retry_at"] = next_retry_at.isoformat()
        elif last_result == "success":
            observation["next_retry_at"] = None
        if last_result == "success":
            observation["last_success_at"] = observed_at_iso
            observation["last_error_at"] = None
            observation["error_message"] = None
            observation["error_type"] = None
            observation["consecutive_error_count"] = 0
            observation["budget_exhausted"] = False
            observation["next_retry_at"] = None
        else:
            observation["last_error_at"] = observed_at_iso
        result.update(
            {
                "orchestration_observation": observation,
                "last_orchestration_attempt_at": observed_at_iso,
                "last_orchestration_success_at": observation.get("last_success_at"),
                "last_orchestration_error_at": observation.get("last_error_at"),
                "last_orchestration_error_type": observation.get("error_type"),
                "last_orchestration_error_message": observation.get("error_message"),
                "consecutive_orchestration_error_count": observation.get("consecutive_error_count"),
                "orchestration_error_budget_exhausted": observation.get("budget_exhausted"),
                "next_orchestration_retry_at": observation.get("next_retry_at"),
                "last_orchestration_result": observation.get("last_result"),
            }
        )
        item.result = result

    def _extract_http_status_from_exception(self: TaskManager, exc: Exception) -> int | None:
        message = str(exc or "")
        if not message:
            return None
        leading = re.match(r"^\s*(?:http\s+)?(\d{3})\b", message, re.IGNORECASE)
        if leading:
            try:
                return int(leading.group(1))
            except Exception:
                return None
        match = re.search(r"(?:状态码|status(?:_code)?)[:= ]+(\d{3})", message, re.IGNORECASE)
        if match:
            try:
                return int(match.group(1))
            except Exception:
                return None
        return None

    def _is_http_429_exception(self: TaskManager, exc: Exception) -> bool:
        return self._extract_http_status_from_exception(exc) == 429

    def _classify_downstream_sync_error(self: TaskManager, exc: Exception) -> str:
        if isinstance(exc, SATimeoutError):
            return "db_connection_lost"
        if isinstance(exc, OperationalError):
            lowered_operational = str(exc or "").strip().lower()
            if "connection refused" in lowered_operational or "[errno 111]" in lowered_operational:
                return "db_connection_refused"
            if any(token in lowered_operational for token in {"lost connection", "server has gone away", "closed the connection"}):
                return "db_connection_lost"
            return "db_session_invalid"
        http_status = self._extract_http_status_from_exception(exc)
        lowered = str(exc or "").strip().lower()
        detail = str(getattr(exc, "error_type_detail", "") or getattr(exc, "transport_error_kind", "")).strip().lower()
        if detail == "connection_reused_stale":
            return "connection_reused_stale"
        if http_status == 429:
            return "http_429_rate_limited"
        if http_status is not None and http_status >= 500:
            return "http_5xx"
        if "timeout" in lowered or "超时" in lowered:
            return "timeout"
        if "server disconnected without sending a response" in lowered:
            return "connection_reused_stale"
        if any(token in lowered for token in {"connect", "connection", "连接", "refused"}):
            return "connection_error"
        if any(token in lowered for token in {"auth", "unauthorized", "forbidden", "认证"}):
            return "auth_error"
        if isinstance(exc, (TypeError, ValueError, KeyError, AssertionError)):
            return "downstream_payload_invalid"
        return exc.__class__.__name__

    def _is_retryable_downstream_transport_error(self: TaskManager, exc: Exception) -> bool:
        if self._is_http_429_exception(exc):
            return True
        if isinstance(exc, UpstreamError):
            return True
        if isinstance(exc, (NotFoundError, ValidationError, ConflictError)):
            return False
        if isinstance(exc, httpx.RequestError):
            return True
        return self._classify_downstream_sync_error(exc) in {
            "timeout",
            "connection_error",
            "http_5xx",
            "http_429_rate_limited",
        }

    def _is_recoverable_orchestration_error(self: TaskManager, exc: Exception) -> bool:
        if isinstance(exc, (OperationalError, SATimeoutError, UpstreamError, httpx.RequestError, FileNotFoundError, OSError)):
            return True
        lowered = str(exc or "").strip().lower()
        if self._is_retryable_lock_error(exc):
            return True
        if any(token in lowered for token in {"metadata", "task-metadata.json", "state event", "state reducer"}):
            return True
        return self._classify_downstream_sync_error(exc) in {
            "db_connection_refused",
            "db_connection_lost",
            "db_session_invalid",
            "downstream_payload_invalid",
            "connection_error",
            "timeout",
            "http_5xx",
            "http_429_rate_limited",
        }

    def _build_next_stage_item_orchestration_failure_state(
        self: TaskManager,
        item: BinarySecurityStageItem,
        *,
        observed_at: datetime | None = None,
    ):
        from app.service import task_manager as task_manager_module

        previous = self._read_stage_item_orchestration_state(item)
        consecutive = previous.consecutive_error_count + 1
        budget_exhausted = consecutive >= self._stage_orchestration_max_consecutive_errors()
        retry_at = (observed_at or task_manager_module._now()) + timedelta(
            seconds=self._next_stage_orchestration_retry_backoff_seconds(consecutive)
        )
        return task_manager_module.OrchestrationSupervisorState(
            consecutive_error_count=consecutive,
            budget_exhausted=budget_exhausted,
            next_retry_at=retry_at,
            last_result="error",
        )

    def _item_downstream_sync_stale(
        self: TaskManager,
        item: BinarySecurityStageItem,
        now_value: datetime | None = None,
    ) -> bool:
        item_status = str(item.status or "").strip().lower()
        if item_status not in {"pending", "queued", "running", "dispatching"}:
            return False
        from app.service import task_manager as task_manager_module

        current_now = now_value or task_manager_module._now()
        last_attempt_at = self._stage_item_sync_attempt_at_value(item)
        if last_attempt_at is None:
            return True
        return (current_now - last_attempt_at).total_seconds() >= self._stage_item_sync_stale_seconds()

    def _item_needs_initial_downstream_sync(self: TaskManager, item: BinarySecurityStageItem) -> bool:
        sync_status = self._stage_item_sync_status_value(item)
        if sync_status in {None, "", "pending", "transport_error"}:
            return True
        return self._stage_item_sync_attempt_at_value(item) is None

    def _item_needs_downstream_sync(
        self: TaskManager,
        item: BinarySecurityStageItem,
        *,
        for_task_status: str | None = None,
        now_value: datetime | None = None,
    ) -> bool:
        if not str(item.downstream_service or "").strip() or not str(item.downstream_task_id or "").strip():
            return False
        if self._stage_item_sync_in_retry_backoff(item, now_value):
            return False
        item_status = str(item.status or "").strip().lower()
        if item_status in {"pending", "queued", "running", "dispatching"}:
            return self._item_needs_initial_downstream_sync(item) or self._item_downstream_sync_stale(item, now_value)
        if item_status == "failed":
            return (for_task_status or "") in {"dispatching", "running", "failed"} or self._item_needs_initial_downstream_sync(item)
        if item_status in {"success", "cancelled", "downstream_missing", "partial_success"}:
            return self._item_needs_initial_downstream_sync(item)
        return False

    def _stage_item_sync_priority(
        self: TaskManager,
        item: BinarySecurityStageItem,
        now_value: datetime | None = None,
    ) -> tuple[int, datetime, str]:
        item_status = str(item.status or "").strip().lower()
        sync_status = self._stage_item_sync_status_value(item)
        last_synced_at = self._stage_item_last_synced_at_value(item) or datetime.min
        stale = self._item_downstream_sync_stale(item, now_value)
        missing_recorded_downstream_status = self._item_missing_recorded_downstream_status(item)
        if sync_status == "transport_error":
            priority = 0
        elif item_status in {"running", "dispatching", "queued", "pending"} and sync_status in {None, "", "pending"}:
            priority = 1
        elif item_status in {"running", "dispatching", "queued", "pending"} and stale:
            priority = 2
        elif item_status in {"success", "cancelled", "downstream_missing", "partial_success", "failed"} and (
            sync_status in {None, "", "pending"} or missing_recorded_downstream_status
        ):
            priority = 3
        elif missing_recorded_downstream_status:
            priority = 4
        else:
            priority = 9
        return priority, last_synced_at, str(item.id or "")

    def _stage_item_sync_in_retry_backoff(
        self: TaskManager,
        item: BinarySecurityStageItem,
        now_value: datetime | None = None,
    ) -> bool:
        next_retry_at = self._stage_item_next_sync_retry_at_value(item)
        if next_retry_at is None:
            return False
        from app.service import task_manager as task_manager_module

        return next_retry_at > (now_value or task_manager_module._now())

    def _task_needs_downstream_reconcile(self: TaskManager, db: Session, task: BinarySecurityTask) -> bool:
        status = str(task.status or "").strip().lower()
        if status == "pending":
            return True
        if status == "failed":
            return bool(self._task_reconcile_candidate_items(db, task, force=False, include_failed_terminal_items=False))
        if status not in {"dispatching", "running"}:
            return False
        if self._streaming_mode_enabled(task) and self._is_streaming_tail_stage(task, task.current_stage):
            return False
        if self._task_has_active_streaming_stage_workers(task.id):
            return False
        if self._has_local_task_execution_owner(task.id):
            return self._task_has_stale_active_reconcile_items(db, task)
        if not str(task.dispatcher_instance_id or "").strip():
            return True
        if not self._lease_is_active(task, db=db):
            return True
        lease = self._runtime_lease_for_task(db, task.id)
        heartbeat_at = (lease.heartbeat_at if lease is not None else None) or task.updated_at or task.dispatch_started_at
        from app.service import task_manager as task_manager_module

        elapsed_seconds = task_manager_module._elapsed_seconds_since(heartbeat_at)
        if elapsed_seconds is None:
            return False
        grace_seconds = max(
            int(getattr(self.cfg.scheduler, "downstream_reconcile_grace_seconds", 0) or 0),
            int(getattr(self.cfg.scheduler, "heartbeat_update_interval_seconds", 0) or 15) * 2,
            30,
        )
        return elapsed_seconds >= grace_seconds

    def _next_stage_sync_retry_backoff_seconds(self: TaskManager, consecutive_error_count: int) -> int:
        exponent = max(0, int(consecutive_error_count) - 1)
        backoff = self._stage_downstream_sync_backoff_base_seconds() * (2 ** exponent)
        return min(self._stage_downstream_sync_backoff_max_seconds(), max(1, int(backoff)))

    def _next_http_429_retry_backoff_seconds(self: TaskManager, consecutive_error_count: int) -> int:
        del consecutive_error_count
        return 30

    def _should_emit_http_429_timeline_event(self: TaskManager, consecutive_error_count: int) -> bool:
        streak = max(0, int(consecutive_error_count or 0))
        return streak == 1 or (streak > 0 and streak % 10 == 0)

    def _should_emit_api_retry_timeline_event(
        self: TaskManager,
        consecutive_error_count: int,
        retry_delay_seconds: int | None,
    ) -> bool:
        streak = max(0, int(consecutive_error_count or 0))
        delay = max(0, int(retry_delay_seconds or 0))
        return delay >= 30 and streak > 0 and streak % 10 == 0

    def _should_record_downstream_sync_skip_event(
        self: TaskManager,
        *,
        should_apply: bool,
        skip_reason_code: str | None,
        mapped_status: str | None,
        before_status: str | None,
        apply_state: bool,
    ) -> bool:
        if should_apply:
            return True
        if skip_reason_code == "noop_same_state":
            return False
        if mapped_status != before_status:
            return True
        if not apply_state:
            return True
        return False

    def _classify_downstream_sync_skip_reason(
        self: TaskManager,
        *,
        mapped_status: str | None,
        before_status: str | None,
        apply_state: bool,
        intermediate_blocked: bool = False,
        status_recognized: bool = True,
        binding_mismatch: bool = False,
        archive_pending: bool = False,
        archive_failed_manual_intervention: bool = False,
        self_healing_failure: bool = False,
    ) -> tuple[str, str]:
        if not status_recognized:
            return "downstream_status_unrecognized", "state_mapping"
        if binding_mismatch:
            return "downstream_binding_mismatch", "binding"
        if archive_failed_manual_intervention:
            return "downstream_archive_failed_manual_intervention", "archive"
        if archive_pending:
            return "downstream_archive_pending", "archive"
        if self_healing_failure:
            return "downstream_failed_self_healing_observed", "runtime"
        if intermediate_blocked:
            return "intermediate_state_write_blocked", "state_transition"
        if mapped_status == before_status and apply_state:
            return "noop_same_state", "observation"
        if not apply_state:
            return "observation_only", "policy"
        return "state_write_skipped", "state_transition"

    def _refresh_stage_item_downstream_observation(
        self: TaskManager,
        item: BinarySecurityStageItem,
        *,
        sync_status: str,
        synced_at: datetime | None = None,
        error_message: str | None = None,
        http_status: int | None = None,
        error_type: str | None = None,
        status_raw: str | None = None,
        mapped_status: str | None = None,
        downstream_status: str | None = None,
        state_applied: bool | None = None,
        downstream_payload: dict[str, Any] | None = None,
        last_sync_result: str | None = None,
        clear_error_state: bool = False,
    ) -> None:
        self._apply_child_task_sync_observation(
            item,
            sync_status=sync_status,
            synced_at=synced_at,
            error_message=error_message,
            http_status=http_status,
            error_type=error_type,
            downstream_status_raw=status_raw,
            downstream_status_mapped=mapped_status,
            downstream_status=downstream_status,
            state_applied=state_applied,
            downstream_payload=downstream_payload,
            last_sync_result=last_sync_result,
            clear_error_state=clear_error_state,
        )

    def _record_downstream_sync_skip_event_if_needed(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        message: str,
        payload: dict[str, Any],
        reason_code: str,
        reason_category: str,
    ) -> None:
        payload = {
            **payload,
            "reason_code": reason_code,
            "reason_category": reason_category,
        }
        dedupe_window_seconds = max(60, self._stage_item_sync_stale_seconds())
        if self._has_recent_matching_task_event(
            db,
            task,
            event_type="downstream_status_sync_skipped",
            stage_name=item.stage_name,
            message=message,
            payload_keys={
                "reason_code": reason_code,
                "downstream_task_id": item.downstream_task_id,
                "mapped_status": payload.get("mapped_status"),
                "state_applied": payload.get("state_applied"),
            },
            within_seconds=dedupe_window_seconds,
        ):
            return
        self._record_event(
            db,
            task,
            "downstream_status_sync_skipped",
            message,
            stage_name=item.stage_name,
            item=item,
            payload=payload,
        )

    def _read_stage_item_sync_supervisor_state(self: TaskManager, item: BinarySecurityStageItem):
        from app.service import task_manager as task_manager_module

        result = self._load_stage_item_result_payload(item)
        sync_observation = self._stage_item_sync_observation(item)
        consecutive = sync_observation.get("consecutive_error_count")
        if consecutive is None:
            consecutive = result.get("consecutive_sync_error_count")
        exhausted = sync_observation.get("budget_exhausted")
        if exhausted is None:
            exhausted = result.get("sync_error_budget_exhausted")
        last_result = self._string_or_none(sync_observation.get("last_result")) or self._string_or_none(result.get("last_sync_result"))
        return task_manager_module.DownstreamSyncSupervisorState(
            consecutive_error_count=max(0, int(consecutive or 0)),
            budget_exhausted=bool(exhausted),
            next_retry_at=self._stage_item_next_sync_retry_at_value(item),
            last_result=last_result,
        )

    def _downstream_sync_failure_payload(
        self: TaskManager,
        item: BinarySecurityStageItem,
        *,
        error_type: str,
        error_message: str,
        state,
    ) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        return {
            "item_id": str(item.id or ""),
            "stage_name": str(item.stage_name or ""),
            "downstream_task_id": str(item.downstream_task_id or ""),
            "consecutive_sync_error_count": state.consecutive_error_count,
            "last_sync_error_type": error_type,
            "last_sync_error_message": error_message,
            "next_sync_retry_at": task_manager_module._isoformat_or_none(state.next_retry_at),
            "sync_error_budget_exhausted": state.budget_exhausted,
        }

    def _build_next_downstream_sync_failure_state(
        self: TaskManager,
        item: BinarySecurityStageItem,
        *,
        observed_at: datetime | None = None,
    ):
        from app.service import task_manager as task_manager_module

        previous = self._read_stage_item_sync_supervisor_state(item)
        consecutive = previous.consecutive_error_count + 1
        retry_at = (observed_at or task_manager_module._now()) + timedelta(
            seconds=self._next_stage_sync_retry_backoff_seconds(consecutive)
        )
        return task_manager_module.DownstreamSyncSupervisorState(
            consecutive_error_count=consecutive,
            budget_exhausted=False,
            next_retry_at=retry_at,
            last_result="error",
        )

    def _build_next_http_429_failure_state(
        self: TaskManager,
        item: BinarySecurityStageItem,
        *,
        observed_at: datetime | None = None,
    ):
        from app.service import task_manager as task_manager_module

        previous = self._read_stage_item_sync_supervisor_state(item)
        consecutive = previous.consecutive_error_count + 1
        retry_at = (observed_at or task_manager_module._now()) + timedelta(
            seconds=self._next_http_429_retry_backoff_seconds(consecutive)
        )
        return task_manager_module.DownstreamSyncSupervisorState(
            consecutive_error_count=consecutive,
            budget_exhausted=False,
            next_retry_at=retry_at,
            last_result="error",
        )

    def _sleep_after_retryable_lock_error(self: TaskManager, attempt: int) -> None:
        attempt_no = max(1, int(attempt))
        backoff_seconds = {1: 1.0, 2: 3.0, 3: 5.0}.get(attempt_no, 5.0)
        time.sleep(backoff_seconds)

    def _refresh_polled_child_sync_snapshot(
        self: TaskManager,
        *,
        task_id: str,
        item_id: str,
        payload: dict[str, Any],
    ) -> None:
        from app.service import task_manager as task_manager_module

        session = task_manager_module.get_session_factory()()
        try:
            item = (
                session.query(BinarySecurityStageItem)
                .filter(BinarySecurityStageItem.task_id == task_id, BinarySecurityStageItem.id == item_id)
                .first()
            )
            task = session.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if item is None or task is None:
                session.rollback()
                return
            downstream_status = str(payload.get("status") or "").strip().lower() or None
            mapped_status = self._map_downstream_status(downstream_status or "")
            if not mapped_status:
                self._refresh_stage_item_downstream_observation(
                    item,
                    sync_status="observed",
                    synced_at=task_manager_module._now(),
                    status_raw=downstream_status,
                    mapped_status=None,
                    downstream_status=downstream_status,
                    state_applied=False,
                    downstream_payload=payload,
                )
                session.commit()
                return
            before_status = self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower() or None
            should_apply = (
                before_status in {"running", "queued"}
                or (before_status == "dispatching" and mapped_status not in {"pending", "queued"})
            )
            if should_apply:
                self._apply_downstream_status_inline(
                    item,
                    mapped_status=mapped_status,
                    downstream_payload=payload,
                    error_message=None,
                    synced_at=task_manager_module._now(),
                )
                self._mark_stage_item_sync_observation(
                    item,
                    sync_status="synced",
                    synced_at=task_manager_module._now(),
                    status_raw=downstream_status,
                    mapped_status=mapped_status,
                    downstream_status=downstream_status,
                    state_applied=True,
                    downstream_payload=payload,
                    clear_error_state=True,
                )
            else:
                self._refresh_stage_item_downstream_observation(
                    item,
                    sync_status="observed",
                    synced_at=task_manager_module._now(),
                    status_raw=downstream_status,
                    mapped_status=mapped_status,
                    downstream_status=downstream_status,
                    state_applied=False,
                    downstream_payload=payload,
                    clear_error_state=True,
                )
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def _record_polled_child_sync_failure(
        self: TaskManager,
        *,
        task_id: str,
        item_id: str,
        error_message: str,
        error_type: str | None,
        http_status: int | None,
    ) -> None:
        from app.service import task_manager as task_manager_module

        session = task_manager_module.get_session_factory()()
        try:
            item = (
                session.query(BinarySecurityStageItem)
                .filter(BinarySecurityStageItem.task_id == task_id, BinarySecurityStageItem.id == item_id)
                .first()
            )
            task = session.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if item is None or task is None:
                session.rollback()
                return
            if self._is_tail_control_plane_stale_error(error_message=error_message, error_type=error_type):
                self._record_event(
                    session,
                    task,
                    "tail_reconcile_owner_lost",
                    "tail 收敛 owner 已丢失，等待新的 reducer 接管",
                    level="warning",
                    stage_name=item.stage_name,
                    item=item,
                    payload={
                        "task_id": task.id,
                        "item_id": item.id,
                        "error_message": error_message,
                        "error_type": error_type,
                        "http_status": http_status,
                    },
                )
                session.commit()
                return
            self._record_event(
                session,
                task,
                "owned_execution_owner_lost",
                "当前执行 owner 已丢失，等待 worker 重新接管",
                level="warning",
                stage_name=item.stage_name,
                item=item,
                payload={
                    "task_id": task.id,
                    "item_id": item.id,
                    "error_message": error_message,
                    "error_type": error_type,
                    "http_status": http_status,
                },
            )
            state = self._read_stage_item_sync_supervisor_state(item)
            self._record_event(
                session,
                task,
                "child_owner_lost_detected",
                "检测到下游 owner 丢失，已记录恢复观测",
                level="warning",
                stage_name=item.stage_name,
                item=item,
                payload={
                    "task_id": task.id,
                    "item_id": item.id,
                    "error_message": error_message,
                    "error_type": error_type,
                    "http_status": http_status,
                    "retry_count": int(item.retry_count or 0),
                    "retry_exhausted": False,
                },
            )
            item.retry_count = int(item.retry_count or 0) + 1
            item.error_message = error_message
            exhausted = self._owner_lost_retry_exhausted(task, item)
            if exhausted:
                item.status = "failed"
                item.error_message = "owner_lost_retry_exhausted"
                self._record_event(
                    session,
                    task,
                    "child_owner_lost_retry_exhausted",
                    "下游 owner 丢失且重试已耗尽",
                    level="warning",
                    stage_name=item.stage_name,
                    item=item,
                    payload={
                        "task_id": task.id,
                        "item_id": item.id,
                        "error_message": error_message,
                        "error_type": error_type,
                        "http_status": http_status,
                        "retry_count": int(item.retry_count or 0),
                    },
                )
            else:
                self._record_event(
                    session,
                    task,
                    "child_owner_lost_requeue_scheduled",
                    "下游 owner 丢失，已安排重试",
                    level="warning",
                    stage_name=item.stage_name,
                    item=item,
                    payload={
                        "task_id": task.id,
                        "item_id": item.id,
                        "error_message": error_message,
                        "error_type": error_type,
                        "http_status": http_status,
                        "retry_count": int(item.retry_count or 0),
                    },
                )
            self._persist_child_sync_observation(
                session,
                task=task,
                item=item,
                change_source="poll_transport_error",
                sync_status="transport_error",
                synced_at=task_manager_module._now(),
                error_message=error_message,
                http_status=http_status,
                error_type=error_type,
                state_applied=False,
                consecutive_error_count=state.consecutive_error_count,
                budget_exhausted=state.budget_exhausted,
                next_retry_at=state.next_retry_at,
                last_sync_result=state.last_result,
                extra_payload={"operation": "poll_until_terminal"},
            )
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def _mark_stage_item_sync_observation(
        self: TaskManager,
        item: BinarySecurityStageItem,
        *,
        sync_status: str,
        synced_at: datetime | None = None,
        error_message: str | None = None,
        http_status: int | None = None,
        error_type: str | None = None,
        status_raw: str | None = None,
        mapped_status: str | None = None,
        downstream_status: str | None = None,
        state_applied: bool | None = None,
        downstream_payload: dict[str, Any] | None = None,
        archive_root: str | None = None,
        archive_copy_stats: dict[str, Any] | None = None,
        consecutive_error_count: int | None = None,
        budget_exhausted: bool | None = None,
        next_retry_at: datetime | None = None,
        last_sync_result: str | None = None,
        clear_error_state: bool = False,
    ) -> list[str]:
        return self._apply_child_task_sync_observation(
            item,
            sync_status=sync_status,
            synced_at=synced_at,
            error_message=error_message,
            http_status=http_status,
            error_type=error_type,
            downstream_status_raw=status_raw,
            downstream_status_mapped=mapped_status,
            downstream_status=downstream_status,
            state_applied=state_applied,
            downstream_payload=downstream_payload,
            archive_root=archive_root,
            archive_copy_stats=archive_copy_stats,
            consecutive_error_count=consecutive_error_count,
            budget_exhausted=budget_exhausted,
            next_retry_at=next_retry_at,
            last_sync_result=last_sync_result,
            clear_error_state=clear_error_state,
        )

    def _requeue_stage_item_after_downstream_missing(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        observed_at: datetime,
        previous_downstream_task_id: str | None,
        error_message: str | None,
        http_status: int | None = None,
    ) -> bool:
        if self._task_runtime_phase(task) == TASK_RUNTIME_PHASE_TAIL_RECONCILIATION and self._is_reducer_role():
            return False
        before_status = str(item.status or "").strip().lower()
        item.status = "downstream_missing"
        item.error_message = error_message
        item.finished_at = None
        item.updated_at = observed_at
        self._clear_stage_item_claim(item)
        self._mark_stage_item_sync_observation(
            item,
            sync_status="synced",
            synced_at=observed_at,
            error_message=error_message,
            http_status=http_status,
            error_type="not_found",
            status_raw="downstream_missing",
            mapped_status="downstream_missing",
            downstream_status="downstream_missing",
            state_applied=True,
            last_sync_result="success",
        )
        self._record_event(
            db,
            task,
            "streaming_stage_item_requeued_after_downstream_missing",
            "下游子任务不存在，当前阶段项已标记为 downstream_missing",
            level="warning",
            stage_name=item.stage_name,
            item=item,
            payload={
                "before_status": before_status,
                "after_status": "downstream_missing",
                "downstream_task_id": previous_downstream_task_id,
                "task_runtime_phase": self._task_runtime_phase(task),
                "recovery_action": "marked_downstream_missing",
            },
        )
        return True

    async def sync_downstream_status(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        stage_name: str | None = None,
        item_id: str | None = None,
        item_ids: list[str] | None = None,
        force: bool = False,
        token: str | None = None,
        record_request_event: bool = True,
        record_noop_events: bool = True,
        apply_state: bool = False,
    ) -> BinarySecurityActionResponse:
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        ownership_required = bool(
            str(getattr(task, "dispatcher_instance_id", "") or "").strip()
            or self._lease_is_active(task, db=db)
        )
        if apply_state and ownership_required:
            self._ensure_task_write_ownership(task, db=db, allow_dispatching=True)
        if (
            self._task_runtime_phase(task) == TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
            and self._is_reducer_role()
            and str(task.status or "").strip().lower() in {"pending", "running", "dispatching"}
        ):
            active_stage_name, active_item_count, has_downstream_refs = self._streaming_tail_active_context(db, task)
            if self._tail_requires_execution_takeover(db, task):
                task.status = "pending"
                task.current_stage = active_stage_name or task.current_stage
                task.dispatcher_instance_id = None
                task.dispatch_started_at = None
                task.lease_expires_at = None
                task.finished_at = None
                task.last_error = None
                self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
                task.tail_reconcile_state = "idle"
                self._clear_runtime_lease(db, task.id)
                self._release_tail_reconcile_owner(task.id)
                self._record_event(
                    db,
                    task,
                    "tail_execution_takeover_resumed",
                    "检测到尾段阶段尚未完成，已退出 reducer 收口并重新交给 worker 继续执行",
                    level="warning",
                    stage_name=task.current_stage,
                    payload={"reason": "incomplete_tail_stage"},
                )
                self._clear_task_abnormal_reason_snapshot(db, task)
                db.commit()
                self._enqueue_task(task.id)
                return BinarySecurityActionResponse(
                    task_id=task.id,
                    status="accepted",
                    accepted=True,
                    action="resume_owned_execution",
                    message="已退出 tail 收口并重新交给 worker 继续执行",
                )
            if active_item_count > 0 or has_downstream_refs:
                task.status = "running"
                task.current_stage = active_stage_name or task.current_stage
                task.dispatcher_instance_id = None
                task.dispatch_started_at = None
                task.lease_expires_at = None
                task.finished_at = None
                task.last_error = None
                lease = self._activate_tail_reconciliation(
                    db,
                    task,
                    now_value=task_manager_module._now(),
                    fallback_status="pending",
                    takeover_result="sync_reclaim",
                )
                if self._runtime_lease_is_active(lease):
                    self._clear_task_abnormal_reason_snapshot(db, task)
                    db.commit()
                    task = self._task_or_404(db, project_id, task_id)

        batch_size = max(1, int(getattr(self.cfg.scheduler, "downstream_sync_batch_size", 50) or 50))
        if stage_name and stage_name not in self._stage_sequence_for_task(task):
            raise ValidationError(f"无效阶段: {stage_name}")
        if item_id and item_ids:
            raise ValidationError("item_id 与 item_ids 不能同时指定")
        items = self._task_reconcile_candidate_items(
            db,
            task,
            stage_name=stage_name,
            item_id=item_id,
            force=force,
        )
        selected_by_item_ids = bool(item_ids)
        if item_ids:
            ordered_ids = [str(current_id).strip() for current_id in list(item_ids or []) if str(current_id).strip()]
            matched = {str(item.id): item for item in items if str(item.id or "").strip()}
            items = [matched[current_id] for current_id in ordered_ids if current_id in matched]
        scoped_retry_item_ids = getattr(task, "_retry_prepare_scoped_item_ids", None)
        scoped_retry_stage_name = str(getattr(task, "_retry_prepare_scoped_stage_name", "") or "").strip()
        if scoped_retry_item_ids and scoped_retry_stage_name:
            items = [
                item
                for item in items
                if str(item.stage_name or "").strip() == scoped_retry_stage_name
                and str(item.id or "").strip() in scoped_retry_item_ids
            ]
        if item_id and not items:
            raise NotFoundError("阶段子任务不存在")
        if item_ids and not items:
            raise NotFoundError("阶段子任务不存在")
        if not item_id and not item_ids and items:
            items = sorted(items, key=lambda current_item: self._stage_item_sync_priority(current_item))[:batch_size]

        if record_request_event:
            self._record_event(
                db,
                task,
                "downstream_status_sync_requested",
                "请求同步下游子任务状态",
                stage_name=stage_name,
                payload={
                    "stage_name": stage_name,
                    "item_id": item_id,
                    "item_ids": [str(item.id) for item in items] if item_ids else None,
                    "force": force,
                    "batch_size": batch_size,
                    "candidate_item_count": len(items),
                    "selected_stage_names": sorted({str(item.stage_name or "") for item in items if str(item.stage_name or "").strip()}),
                    "selected_items": len(items),
                },
            )
            db.commit()

        synced_count = 0
        skipped_count = 0
        failed_count = 0
        binding_mismatch_count = 0
        revived_count = 0
        revival_rejected_count = 0
        touched_stages: set[str] = set()
        stage_takeover_candidates: set[str] = set()
        auth_token = token or self._service_token()
        ready_items: list[BinarySecurityStageItem] = []
        for item in items:
            if self._item_needs_downstream_binding_reconcile(item):
                recovered, outcome = await self._attempt_vuln_downstream_binding_recovery(
                    db,
                    task,
                    item,
                    token=auth_token,
                    force=force,
                )
                if recovered:
                    synced_count += 1
                    touched_stages.add(item.stage_name)
                else:
                    if outcome in {"retry_not_due", "invalid_input", "failed_final", "create_failed"}:
                        skipped_count += 1
                    else:
                        failed_count += 1
                if not str(item.downstream_task_id or "").strip():
                    continue
            if not item.downstream_service or not item.downstream_task_id:
                skipped_count += 1
                if record_noop_events:
                    self._record_event(
                        db,
                        task,
                        "downstream_status_sync_skipped",
                        "跳过同步：子任务缺少下游服务或任务ID",
                        level="warning",
                        stage_name=item.stage_name,
                        item=item,
                        payload={"binding_state": self._downstream_binding_state(item)},
                    )
                continue
            ready_items.append(item)

        fetch_results = await self._run_with_limits(
            ready_items,
            lambda current_item: self._fetch_downstream_task_payload(task, current_item, auth_token),
            concurrency=self.cfg.scheduler.downstream_sync_concurrency,
            timeout_seconds=self.cfg.scheduler.downstream_request_timeout_seconds,
        )
        for item, payload, exc in fetch_results:
            item_stage_name = item.stage_name
            item_downstream_service = item.downstream_service
            item_downstream_task_id = item.downstream_task_id
            before_status = item.status
            observed_apply_state = bool(apply_state)
            sync_observed_at = task_manager_module._now()
            if force:
                observed_apply_state = True
            try:
                if exc is not None:
                    raise exc
                assert isinstance(payload, dict)
                if observed_apply_state and ownership_required:
                    self._ensure_task_write_ownership(task, db=db, allow_dispatching=True)
                if item.downstream_service == "entry_analyse":
                    payload, rebound_notice_payload = await self._reconcile_entry_payload_binding(task, item, payload, auth_token)
                    if rebound_notice_payload is not None:
                        self._record_event(
                            db,
                            task,
                            "downstream_parent_mismatch",
                            "下游子任务绑定到旧轮次阶段项，已阻断旧轮次状态回写",
                            level="warning",
                            stage_name=item.stage_name,
                            item=item,
                            payload=rebound_notice_payload,
                        )
                    if payload is None:
                        if not self._persist_child_sync_observation(
                            db,
                            task=task,
                            item=item,
                            change_source="downstream_sync",
                            sync_status="binding_mismatch",
                            synced_at=sync_observed_at,
                            error_message="下游子任务仍绑定旧轮次阶段项",
                            error_type="parent_mismatch",
                            state_applied=False,
                            extra_payload={"operation": "downstream_sync"},
                        ):
                            failed_count += 1
                            continue
                        skipped_count += 1
                        continue
                if not self._payload_matches_current_child(item, payload):
                    replacement_state = self._replacement_in_progress_state(item)
                    if not self._persist_child_sync_observation(
                        db,
                        task=task,
                        item=item,
                        change_source="downstream_sync",
                        sync_status="binding_mismatch",
                        synced_at=sync_observed_at,
                        error_message="下游状态来自旧 child，本次仅记录观测",
                        error_type="binding_mismatch",
                        state_applied=False,
                        extra_payload={"operation": "downstream_sync"},
                    ):
                        failed_count += 1
                        continue
                    binding_mismatch_count += 1
                    skipped_count += 1
                    mismatch_payload = self._binding_mismatch_payload(
                        source="task_owner",
                        expected_downstream_task_id=self._current_downstream_task_id(item),
                        actual_downstream_task_id=self._payload_downstream_task_id(payload),
                        current_downstream_task_id=self._current_downstream_task_id(item),
                        payload_downstream_task_id=self._payload_downstream_task_id(payload),
                        replacement_state=replacement_state,
                    )
                    if self._replacement_window_active_for_stale_ignore(item):
                        self._record_binding_mismatch_event(
                            db,
                            task,
                            item,
                            event_type="stale_downstream_payload_ignored",
                            message="旧 child 的下游状态已忽略，不再回写当前阶段项",
                            payload={
                                **mismatch_payload,
                                "ignored_reason": "replacement_window_active",
                            },
                        )
                        payload_status = str(payload.get("status") or "").strip().lower()
                        payload_mapped_status = self._map_downstream_status(payload_status) or payload_status
                        if payload_mapped_status in {"success", "partial_success", "failed", "cancelled", "downstream_missing"}:
                            self._record_event(
                                db,
                                task,
                                "stale_downstream_terminal_ignored",
                                "旧 child 终态在重建切换期间晚到，已忽略",
                                stage_name=item.stage_name,
                                item=item,
                                level="warning",
                                payload={
                                    **mismatch_payload,
                                    "downstream_service": item.downstream_service,
                                    "ignored_reason": "replacement_window_active",
                                    "superseded": True,
                                },
                            )
                    else:
                        self._record_binding_mismatch_event(
                            db,
                            task,
                            item,
                            event_type="downstream_binding_mismatch_detected",
                            message="下游状态来自非 authoritative child，本次仅记录绑定不匹配观测",
                            payload=mismatch_payload,
                        )
                    continue
                downstream_status = str(payload.get("status") or "").lower()
                mapped_status = self._map_downstream_status(downstream_status)
                current_item_status = self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower() or None
                if not observed_apply_state and stage_name and not item_id:
                    observed_apply_state = bool(
                        force
                        or str(before_status or "").strip().lower() in {"queued", "running", "dispatching", "cancelled"}
                        or mapped_status == "downstream_missing"
                    )
                observe_downstream_reconcile_observation(
                    stage=item_stage_name,
                    service=item_downstream_service,
                    result=mapped_status or downstream_status or "unknown",
                )
                if not mapped_status:
                    self._refresh_stage_item_downstream_observation(
                        item,
                        sync_status="skipped",
                        synced_at=sync_observed_at,
                        status_raw=downstream_status or None,
                        mapped_status=None,
                        downstream_status=downstream_status or None,
                        state_applied=False,
                        downstream_payload=payload,
                    )
                    skipped_count += 1
                    if record_noop_events:
                        self._record_downstream_sync_skip_event_if_needed(
                            db,
                            task,
                            item=item,
                            message=f"跳过同步：无法识别下游状态 {downstream_status or '-'}",
                            payload={
                                "downstream_service": item.downstream_service,
                                "downstream_task_id": item.downstream_task_id,
                                "http_status": None,
                                "error_type": None,
                                "status_raw": downstream_status or None,
                                "mapped_status": None,
                                "state_applied": False,
                                "downstream_status": downstream_status,
                            },
                            reason_code="downstream_status_unrecognized",
                            reason_category="state_mapping",
                        )
                    continue
                terminal_status = mapped_status in {"success", "partial_success", "failed", "cancelled", "downstream_missing"}
                replacement_state = self._replacement_in_progress_state(item)
                if (
                    terminal_status
                    and current_item_status in {"success", "partial_success", "failed", "cancelled", "downstream_missing"}
                    and self._should_preserve_terminal_status(
                        item,
                        mapped_status=mapped_status,
                        current_item_status=current_item_status,
                        payload=payload,
                    )
                ):
                    mapped_status = current_item_status
                    downstream_status = current_item_status
                if terminal_status and current_item_status in {"success", "partial_success", "failed", "cancelled", "downstream_missing"} and mapped_status != current_item_status:
                    revival_rejected_count += 1
                if terminal_status:
                    observed_error_message = (
                        payload.get("error") or payload.get("error_message") or payload.get("message") or item.error_message
                        if mapped_status in {"failed", "cancelled", "downstream_missing"}
                        else None
                    )
                    self_healing_failure = self._is_self_healing_downstream_failure_observation(
                        mapped_status=mapped_status,
                        downstream_status=downstream_status,
                        payload=payload,
                        error_message=observed_error_message,
                        error_type=None,
                    )
                    if self_healing_failure:
                        self._refresh_stage_item_downstream_observation(
                            item,
                            sync_status="observed",
                            synced_at=sync_observed_at,
                            error_message=observed_error_message,
                            status_raw=downstream_status,
                            mapped_status=mapped_status,
                            downstream_status=downstream_status,
                            state_applied=False,
                            downstream_payload=payload,
                        )
                        if force or mapped_status != before_status or record_noop_events:
                            self._record_downstream_sync_skip_event_if_needed(
                                db,
                                task,
                                item=item,
                                message="下游 failed 观测属于自愈/恢复态，本次仅记录观测，不回写父任务失败状态",
                                payload={
                                    "downstream_service": item.downstream_service,
                                    "downstream_task_id": item.downstream_task_id,
                                    "http_status": None,
                                    "error_type": None,
                                    "status_raw": downstream_status,
                                    "mapped_status": mapped_status,
                                    "state_applied": False,
                                    "before_status": before_status,
                                    "downstream_status": downstream_status,
                                    "after_status": before_status,
                                    "self_healing_failure": True,
                                },
                                reason_code="downstream_failed_self_healing_observed",
                                reason_category="runtime",
                            )
                        skipped_count += 1
                        continue
                    if mapped_status == "downstream_missing":
                        if normalize_stage_name(item.stage_name) == "dataflow_vuln_scan" and (
                            replacement_state["replacement_in_progress"] or replacement_state["binding_cleared"]
                        ):
                            if not self._persist_child_sync_observation(
                                db,
                                task=task,
                                item=item,
                                change_source="downstream_sync",
                                sync_status="binding_missing_during_recreate",
                                synced_at=sync_observed_at,
                                error_message="旧下游绑定在重建期间已失效，本次仅记录观测",
                                status_raw=downstream_status,
                                mapped_status="downstream_missing",
                                downstream_status=downstream_status,
                                state_applied=False,
                            ):
                                failed_count += 1
                                continue
                            skipped_count += 1
                            if force or mapped_status != before_status or record_noop_events:
                                self._record_event(
                                    db,
                                    task,
                                    "downstream_status_sync_skipped",
                                    "旧下游绑定在重建期间已失效，本次不将不存在状态回写到父任务",
                                    stage_name=item.stage_name,
                                    item=item,
                                    level="warning",
                                    payload={
                                        "downstream_service": item.downstream_service,
                                        "downstream_task_id": item.downstream_task_id,
                                        "http_status": None,
                                        "error_type": "binding_missing_during_recreate",
                                        "status_raw": downstream_status,
                                        "mapped_status": mapped_status,
                                        "state_applied": False,
                                        "before_status": before_status,
                                        "downstream_status": downstream_status,
                                        "after_status": before_status,
                                        "replacement_in_progress": True,
                                        "old_downstream_task_id": replacement_state["old_downstream_task_id"],
                                    },
                                )
                            continue
                        if self._requeue_stage_item_after_downstream_missing(
                            db,
                            task,
                            item,
                            observed_at=sync_observed_at,
                            previous_downstream_task_id=str(item.downstream_task_id or "").strip() or None,
                            error_message="下游子任务不存在",
                            http_status=404,
                        ):
                            touched_stages.add(item.stage_name)
                            revived_count += 1
                            synced_count += 1
                            continue
                        should_apply = observed_apply_state and (mapped_status != before_status or force)
                        if should_apply:
                            if not self._apply_child_state_with_savepoint(
                                db,
                                task=task,
                                item=item,
                                change_source="downstream_sync",
                                target_status=mapped_status,
                                sync_status="synced",
                                downstream_status_raw=downstream_status,
                                downstream_status_mapped=mapped_status,
                                downstream_status=downstream_status,
                                error_message="下游子任务不存在",
                                http_status=404,
                                error_type="not_found",
                                apply_fn=lambda: (
                                    self._enqueue_downstream_terminal_event(
                                        db,
                                        task=task,
                                        item=item,
                                        mapped_status=mapped_status,
                                        before_status=before_status,
                                        downstream_status=downstream_status,
                                        payload=payload,
                                        error_message="下游子任务不存在",
                                        http_status=None,
                                        error_type=None,
                                        status_raw=downstream_status,
                                        force=force,
                                    ),
                                    self._apply_downstream_status_inline(
                                        item,
                                        mapped_status=mapped_status,
                                        downstream_payload=payload,
                                        error_message="下游子任务不存在",
                                        synced_at=sync_observed_at,
                                    ),
                                    self._refresh_stage_run_from_items(db, task, item.stage_name),
                                    self._mark_stage_item_sync_observation(
                                        item,
                                        sync_status="synced",
                                        synced_at=sync_observed_at,
                                        status_raw=downstream_status,
                                        mapped_status=mapped_status,
                                        downstream_status=downstream_status,
                                        state_applied=True,
                                    ),
                                ),
                            ):
                                failed_count += 1
                                continue
                            touched_stages.add(item.stage_name)
                            synced_count += 1
                            if current_item_status in {"pending", "queued", "dispatching", "running"}:
                                revived_count += 1
                        else:
                            self._refresh_stage_item_downstream_observation(
                                item,
                                sync_status="skipped",
                                synced_at=sync_observed_at,
                                error_message=observed_error_message,
                                status_raw=downstream_status,
                                mapped_status=mapped_status,
                                downstream_status=downstream_status,
                                state_applied=False,
                                downstream_payload=payload,
                            )
                            skipped_count += 1
                        skip_reason_code, skip_reason_category = self._classify_downstream_sync_skip_reason(
                            mapped_status=mapped_status,
                            before_status=before_status,
                            apply_state=apply_state,
                        )
                        if self._should_record_downstream_sync_skip_event(
                            should_apply=bool(should_apply),
                            skip_reason_code=skip_reason_code,
                            mapped_status=mapped_status,
                            before_status=before_status,
                            apply_state=apply_state,
                        ):
                            if should_apply:
                                self._record_event(
                                    db,
                                    task,
                                    "downstream_status_synced",
                                    "下游子任务不存在，已更新当前阶段子任务状态",
                                    stage_name=item.stage_name,
                                    item=item,
                                    level="warning",
                                    payload={
                                        "downstream_service": item.downstream_service,
                                        "downstream_task_id": item.downstream_task_id,
                                        "http_status": None,
                                        "error_type": None,
                                        "status_raw": downstream_status,
                                        "mapped_status": mapped_status,
                                        "state_applied": True,
                                        "before_status": before_status,
                                        "downstream_status": downstream_status,
                                        "after_status": mapped_status,
                                    },
                                )
                            else:
                                self._record_downstream_sync_skip_event_if_needed(
                                    db,
                                    task,
                                    item,
                                    message="下游子任务不存在，本次仅观测未写回状态",
                                    payload={
                                        "downstream_service": item.downstream_service,
                                        "downstream_task_id": item.downstream_task_id,
                                        "http_status": None,
                                        "error_type": None,
                                        "status_raw": downstream_status,
                                        "mapped_status": mapped_status,
                                        "state_applied": False,
                                        "before_status": before_status,
                                        "downstream_status": downstream_status,
                                        "after_status": mapped_status,
                                    },
                                    reason_code=skip_reason_code,
                                    reason_category=skip_reason_category,
                                )
                        continue
                    if mapped_status not in task_manager_module.ARCHIVE_SUCCESS_MAPPED_STATUSES:
                        sync_supervisor_state = self._read_stage_item_sync_supervisor_state(item)
                        recovered_after_errors = (
                            sync_supervisor_state.consecutive_error_count > 0
                            and str(sync_supervisor_state.last_result or "").strip() == "error"
                            and mapped_status not in {"failed", "cancelled", "downstream_missing"}
                        )
                        recovery_applied = self._should_apply_current_child_intermediate_recovery(
                            item,
                            mapped_status=mapped_status,
                            payload=payload,
                        )
                        error_message = None if recovery_applied else observed_error_message
                        should_apply = observed_apply_state and (mapped_status != before_status or force)
                        if should_apply:
                            if not self._apply_child_state_with_savepoint(
                                db,
                                task=task,
                                item=item,
                                change_source="downstream_sync",
                                target_status=mapped_status,
                                sync_status="synced",
                                downstream_status_raw=downstream_status,
                                downstream_status_mapped=mapped_status,
                                downstream_status=downstream_status,
                                error_message=error_message,
                                http_status=None,
                                error_type=None,
                                apply_fn=lambda: (
                                    self._enqueue_downstream_terminal_event(
                                        db,
                                        task=task,
                                        item=item,
                                        mapped_status=mapped_status,
                                        before_status=before_status,
                                        downstream_status=downstream_status,
                                        payload=payload,
                                        error_message=error_message,
                                        http_status=None,
                                        error_type=None,
                                        status_raw=downstream_status,
                                        force=force,
                                    ),
                                    self._apply_downstream_status_inline(
                                        item,
                                        mapped_status=mapped_status,
                                        downstream_payload=payload,
                                        error_message=error_message,
                                        synced_at=sync_observed_at,
                                    ),
                                    self._refresh_stage_run_from_items(db, task, item.stage_name),
                                    self._mark_stage_item_sync_observation(
                                        item,
                                        sync_status="synced",
                                        synced_at=sync_observed_at,
                                        error_message=error_message,
                                        status_raw=downstream_status,
                                        mapped_status=mapped_status,
                                        downstream_status=downstream_status,
                                        state_applied=True,
                                        clear_error_state=recovery_applied,
                                    ),
                                ),
                                clear_error_state=recovery_applied,
                            ):
                                failed_count += 1
                                continue
                            touched_stages.add(item.stage_name)
                            synced_count += 1
                            if recovery_applied:
                                self._record_event(
                                    db,
                                    task,
                                    "downstream_intermediate_state_recovered",
                                    "当前有效 child 已恢复到中间态，父任务状态已回写",
                                    stage_name=item.stage_name,
                                    item=item,
                                    level="warning",
                                    payload={
                                        "downstream_service": item.downstream_service,
                                        "downstream_task_id": item.downstream_task_id,
                                        "before_status": before_status,
                                        "after_status": mapped_status,
                                        "status_raw": downstream_status,
                                        "mapped_status": mapped_status,
                                        "state_applied": True,
                                        "recovery_applied": True,
                                        "recovery_reason": "current_child_intermediate_recovery",
                                    },
                                )
                        else:
                            skipped_count += 1
                        if recovered_after_errors:
                            self._record_event(
                                db,
                                task,
                                "downstream_poll_recovered_after_errors",
                                "下游状态同步已从异常中恢复",
                                stage_name=item.stage_name,
                                item=item,
                                payload={
                                    "downstream_status": downstream_status,
                                    "downstream_task_id": item.downstream_task_id,
                                    "consecutive_error_count_before_recovery": sync_supervisor_state.consecutive_error_count,
                                },
                            )
                        skip_reason_code, skip_reason_category = self._classify_downstream_sync_skip_reason(
                            mapped_status=mapped_status,
                            before_status=before_status,
                            apply_state=apply_state,
                        )
                        if self._should_record_downstream_sync_skip_event(
                            should_apply=bool(should_apply),
                            skip_reason_code=skip_reason_code,
                            mapped_status=mapped_status,
                            before_status=before_status,
                            apply_state=apply_state,
                        ):
                            if should_apply:
                                self._record_event(
                                    db,
                                    task,
                                    "downstream_status_synced",
                                    "下游终态已同步，当前终态不属于产物归档范围",
                                    stage_name=item.stage_name,
                                    item=item,
                                    level="warning" if mapped_status in {"failed", "cancelled"} else "info",
                                    payload={
                                        "downstream_service": item.downstream_service,
                                        "downstream_task_id": item.downstream_task_id,
                                        "http_status": None,
                                        "error_type": None,
                                        "status_raw": downstream_status,
                                        "mapped_status": mapped_status,
                                        "state_applied": True,
                                        "before_status": before_status,
                                        "downstream_status": downstream_status,
                                        "after_status": mapped_status,
                                        "archive_skipped": True,
                                    },
                                )
                            else:
                                self._record_downstream_sync_skip_event_if_needed(
                                    db,
                                    task,
                                    item,
                                    message="下游终态已观测，当前终态不属于产物归档范围，本次仅观测未写回状态",
                                    payload={
                                        "downstream_service": item.downstream_service,
                                        "downstream_task_id": item.downstream_task_id,
                                        "http_status": None,
                                        "error_type": None,
                                        "status_raw": downstream_status,
                                        "mapped_status": mapped_status,
                                        "state_applied": False,
                                        "before_status": before_status,
                                        "downstream_status": downstream_status,
                                        "after_status": mapped_status,
                                        "archive_skipped": True,
                                    },
                                    reason_code=skip_reason_code,
                                    reason_category=skip_reason_category,
                                )
                        continue
                    if (
                        selected_by_item_ids
                        and stage_name
                        and str(item.stage_name or "").strip() == str(stage_name or "").strip()
                        and mapped_status in task_manager_module.ARCHIVE_SUCCESS_MAPPED_STATUSES
                        and current_item_status in task_manager_module.ARCHIVE_SUCCESS_MAPPED_STATUSES
                        and not apply_state
                    ):
                        self._refresh_stage_item_downstream_observation(
                            item,
                            sync_status="synced",
                            synced_at=sync_observed_at,
                            status_raw=downstream_status,
                            mapped_status=mapped_status,
                            downstream_status=downstream_status,
                            state_applied=False,
                            downstream_payload=payload,
                        )
                        self._record_downstream_sync_skip_event_if_needed(
                            db,
                            task,
                            item,
                            message="同阶段成功项已同步，本次失败项重试预同步不再补偿归档",
                            payload={
                                "downstream_service": item.downstream_service,
                                "downstream_task_id": item.downstream_task_id,
                                "http_status": None,
                                "error_type": None,
                                "status_raw": downstream_status,
                                "mapped_status": mapped_status,
                                "state_applied": False,
                                "before_status": before_status,
                                "downstream_status": downstream_status,
                                "after_status": mapped_status,
                                "archive_skipped": True,
                                "skip_archive_compensation": True,
                                "selected_by_item_ids": True,
                            },
                            reason_code="same_stage_success_archive_compensation_skipped",
                            reason_category="retry_prepare",
                        )
                        skipped_count += 1
                        continue
                    job = self._ensure_downstream_archive_job(
                        db,
                        task,
                        item,
                        payload=payload,
                        mapped_status=mapped_status,
                        before_status=before_status,
                        force=force,
                    )
                    if job.archive_status == "success":
                        db.commit()
                        await self._apply_archive_job_status(job.id, job.archive_root)
                        db.expire_all()
                        refreshed_item = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.id == item.id).first()
                        if refreshed_item is not None:
                            if not self._persist_child_sync_observation(
                                db,
                                task=task,
                                item=refreshed_item,
                                change_source="downstream_sync",
                                sync_status="synced",
                                synced_at=sync_observed_at,
                                status_raw=downstream_status,
                                mapped_status=mapped_status,
                                downstream_status=downstream_status,
                                state_applied=True,
                            ):
                                failed_count += 1
                                continue
                        touched_stages.add(item.stage_name)
                        stage_takeover_candidates.add(str(item.stage_name or "").strip())
                        synced_count += 1
                        continue
                    if job.archive_status == "failed":
                        self._refresh_stage_item_downstream_observation(
                            item,
                            sync_status="skipped",
                            synced_at=sync_observed_at,
                            status_raw=downstream_status,
                            mapped_status=mapped_status,
                            downstream_status=downstream_status,
                            state_applied=False,
                            downstream_payload=payload,
                        )
                        if force or mapped_status != before_status or record_noop_events:
                            self._record_downstream_sync_skip_event_if_needed(
                                db,
                                task,
                                item=item,
                                message="下游状态已获取，但当前阶段的归档失败需要人工处理；不会自动重新排队",
                                payload={
                                    "archive_job_id": job.id,
                                    "archive_status": job.archive_status,
                                    "downstream_service": item.downstream_service,
                                    "downstream_task_id": item.downstream_task_id,
                                    "http_status": None,
                                    "error_type": None,
                                    "status_raw": downstream_status,
                                    "mapped_status": mapped_status,
                                    "state_applied": False,
                                    "downstream_status": downstream_status,
                                    "archive_retry_required": True,
                                },
                                reason_code="downstream_archive_failed_manual_intervention",
                                reason_category="archive",
                            )
                        skipped_count += 1
                        continue
                    if record_noop_events or force or mapped_status != before_status:
                        self._refresh_stage_item_downstream_observation(
                            item,
                            sync_status="skipped",
                            synced_at=sync_observed_at,
                            status_raw=downstream_status,
                            mapped_status=mapped_status,
                            downstream_status=downstream_status,
                            state_applied=False,
                            downstream_payload=payload,
                        )
                        self._record_event(
                            db,
                            task,
                            "downstream_archive_job_queued" if job.archive_status in {"pending", "running"} else "downstream_archive_job_reused",
                            "下游状态已获取，等待产物归档完成后更新状态",
                            stage_name=item.stage_name,
                            item=item,
                            payload={
                                "archive_job_id": job.id,
                                "archive_status": job.archive_status,
                                "downstream_service": item.downstream_service,
                                "downstream_task_id": item.downstream_task_id,
                                "http_status": None,
                                "error_type": None,
                                "status_raw": downstream_status,
                                "mapped_status": mapped_status,
                                "state_applied": False,
                                "downstream_status": downstream_status,
                            },
                        )
                    touched_stages.add(item.stage_name)
                    stage_takeover_candidates.add(str(item.stage_name or "").strip())
                    skipped_count += 1
                    continue
                should_apply = observed_apply_state and mapped_status != before_status
                if should_apply and mapped_status in {"pending", "queued", "running"}:
                    should_apply = self._should_apply_downstream_intermediate_status(
                        item,
                        mapped_status=mapped_status,
                        payload=payload,
                    )
                recovery_applied = should_apply and self._should_apply_current_child_intermediate_recovery(
                    item,
                    mapped_status=mapped_status,
                    payload=payload,
                )
                if should_apply:
                    apply_error_message = None if mapped_status in {"queued", "running", "success"} else (
                        payload.get("error") or payload.get("error_message") or payload.get("message") or item.error_message
                    )
                    if not self._apply_child_state_with_savepoint(
                        db,
                        task=task,
                        item=item,
                        change_source="downstream_sync",
                        target_status=mapped_status,
                        sync_status="synced",
                        downstream_status_raw=downstream_status,
                        downstream_status_mapped=mapped_status,
                        downstream_status=downstream_status,
                        error_message=apply_error_message,
                        http_status=None,
                        error_type=None,
                        apply_fn=lambda: (
                            self._enqueue_downstream_status_event(
                                db,
                                task=task,
                                item=item,
                                mapped_status=mapped_status,
                                before_status=before_status,
                                downstream_status=downstream_status,
                                payload=payload,
                                error_message=apply_error_message,
                                http_status=None,
                                error_type=None,
                                status_raw=downstream_status,
                                force=force,
                            ),
                            self._apply_downstream_status_inline(
                                item,
                                mapped_status=mapped_status,
                                downstream_payload=payload,
                                error_message=apply_error_message,
                                synced_at=sync_observed_at,
                            ),
                            self._refresh_stage_run_from_items(db, task, item.stage_name),
                            self._mark_stage_item_sync_observation(
                                item,
                                sync_status="synced",
                                synced_at=sync_observed_at,
                                error_message=apply_error_message,
                                status_raw=downstream_status,
                                mapped_status=mapped_status,
                                downstream_status=downstream_status,
                                state_applied=True,
                                clear_error_state=recovery_applied,
                            ),
                        ),
                        clear_error_state=recovery_applied,
                    ):
                        failed_count += 1
                        continue
                    touched_stages.add(item.stage_name)
                    stage_takeover_candidates.add(str(item.stage_name or "").strip())
                    synced_count += 1
                    if recovery_applied:
                        self._record_event(
                            db,
                            task,
                            "downstream_intermediate_state_recovered",
                            "当前有效 child 已恢复到中间态，父任务状态已回写",
                            stage_name=item.stage_name,
                            item=item,
                            level="warning",
                            payload={
                                "downstream_service": item.downstream_service,
                                "downstream_task_id": item.downstream_task_id,
                                "before_status": before_status,
                                "after_status": mapped_status,
                                "status_raw": downstream_status,
                                "mapped_status": mapped_status,
                                "state_applied": True,
                                "recovery_applied": True,
                                "recovery_reason": "current_child_intermediate_recovery",
                            },
                        )
                else:
                    intermediate_blocked = bool(
                        observed_apply_state
                        and mapped_status in {"pending", "queued", "running", "dispatching"}
                        and mapped_status != before_status
                    )
                    self._refresh_stage_item_downstream_observation(
                        item,
                        sync_status="skipped",
                        synced_at=sync_observed_at,
                        status_raw=downstream_status,
                        mapped_status=mapped_status,
                        downstream_status=downstream_status,
                        state_applied=False,
                        downstream_payload=payload,
                    )
                    skipped_count += 1
                skip_reason_code, skip_reason_category = self._classify_downstream_sync_skip_reason(
                    mapped_status=mapped_status,
                    before_status=before_status,
                    apply_state=apply_state,
                    intermediate_blocked=intermediate_blocked if not should_apply else False,
                )
                if self._should_record_downstream_sync_skip_event(
                    should_apply=bool(should_apply),
                    skip_reason_code=skip_reason_code,
                    mapped_status=mapped_status,
                    before_status=before_status,
                    apply_state=apply_state,
                ):
                    if should_apply:
                        self._record_event(
                            db,
                            task,
                            "downstream_status_synced",
                            "下游子任务状态已同步",
                            stage_name=item.stage_name,
                            item=item,
                            payload={
                                "downstream_service": item.downstream_service,
                                "downstream_task_id": item.downstream_task_id,
                                "http_status": None,
                                "error_type": None,
                                "status_raw": downstream_status,
                                "mapped_status": mapped_status,
                                "state_applied": True,
                                "before_status": before_status,
                                "downstream_status": downstream_status,
                                "after_status": mapped_status,
                            },
                        )
                    else:
                        skip_message = (
                            "下游子任务状态已观测，但中间态回写策略阻断，本次未写回"
                            if skip_reason_code == "intermediate_state_write_blocked"
                            else "下游子任务状态已观测，本次未写回"
                        )
                        self._record_downstream_sync_skip_event_if_needed(
                            db,
                            task,
                            item,
                            message=skip_message,
                            payload={
                                "downstream_service": item.downstream_service,
                                "downstream_task_id": item.downstream_task_id,
                                "http_status": None,
                                "error_type": None,
                                "status_raw": downstream_status,
                                "mapped_status": mapped_status,
                                "state_applied": False,
                                "before_status": before_status,
                                "downstream_status": downstream_status,
                                "after_status": mapped_status,
                            },
                            reason_code=skip_reason_code,
                            reason_category=skip_reason_category,
                        )
            except NotFoundError:
                replacement_state = self._replacement_in_progress_state(item)
                if normalize_stage_name(item.stage_name) == "dataflow_vuln_scan" and (
                    replacement_state["replacement_in_progress"] or replacement_state["binding_cleared"]
                ):
                    if not self._persist_child_sync_observation(
                        db,
                        task=task,
                        item=item,
                        change_source="downstream_sync",
                        sync_status="binding_missing_during_recreate",
                        error_message="旧下游绑定在重建期间已失效，本次仅记录观测",
                        http_status=404,
                        error_type="binding_missing_during_recreate",
                        status_raw="downstream_missing",
                        mapped_status="downstream_missing",
                        downstream_status="downstream_missing",
                        state_applied=False,
                    ):
                        failed_count += 1
                        continue
                    skipped_count += 1
                    self._record_event(
                        db,
                        task,
                        "downstream_status_sync_skipped",
                        "旧下游绑定在重建期间已失效，本次不将不存在状态回写到父任务",
                        level="warning",
                        stage_name=item_stage_name,
                        item=item,
                        payload={
                            "downstream_service": item_downstream_service,
                            "downstream_task_id": item_downstream_task_id,
                            "http_status": 404,
                            "error_type": "binding_missing_during_recreate",
                            "status_raw": "downstream_missing",
                            "mapped_status": "downstream_missing",
                            "state_applied": False,
                            "before_status": before_status,
                            "downstream_status": "downstream_missing",
                            "after_status": before_status,
                            "replacement_in_progress": True,
                            "old_downstream_task_id": replacement_state["old_downstream_task_id"],
                        },
                    )
                    continue
                notfound_apply_state = bool(apply_state)
                if not notfound_apply_state and stage_name and not item_id:
                    notfound_apply_state = bool(force or str(before_status or "").strip().lower() in {"queued", "running", "dispatching"})
                if notfound_apply_state:
                    if self._requeue_stage_item_after_downstream_missing(
                        db,
                        task,
                        item,
                        observed_at=task_manager_module._now(),
                        previous_downstream_task_id=str(item.downstream_task_id or "").strip() or None,
                        error_message="下游子任务不存在",
                        http_status=404,
                    ):
                        touched_stages.add(item.stage_name)
                        revived_count += 1
                        synced_count += 1
                        continue
                    if not self._apply_child_state_with_savepoint(
                        db,
                        task=task,
                        item=item,
                        change_source="downstream_sync",
                        target_status="downstream_missing",
                        sync_status="synced",
                        downstream_status_raw="downstream_missing",
                        downstream_status_mapped="downstream_missing",
                        downstream_status="downstream_missing",
                        error_message="下游子任务不存在",
                        http_status=404,
                        error_type="not_found",
                        apply_fn=lambda: (
                            self._enqueue_downstream_terminal_event(
                                db,
                                task=task,
                                item=item,
                                mapped_status="downstream_missing",
                                before_status=before_status,
                                downstream_status="downstream_missing",
                                payload={"status": "downstream_missing", "error": "下游子任务不存在"},
                                error_message="下游子任务不存在",
                                http_status=404,
                                error_type="not_found",
                                status_raw="downstream_missing",
                                force=True,
                            ),
                            self._apply_downstream_status_inline(
                                item,
                                mapped_status="downstream_missing",
                                downstream_payload={"status": "downstream_missing", "error": "下游子任务不存在"},
                                error_message="下游子任务不存在",
                            ),
                            self._refresh_stage_run_from_items(db, task, item.stage_name),
                            self._mark_stage_item_sync_observation(
                                item,
                                sync_status="synced",
                                error_message="下游子任务不存在",
                                http_status=404,
                                error_type="not_found",
                                status_raw="downstream_missing",
                                mapped_status="downstream_missing",
                                downstream_status="downstream_missing",
                                state_applied=True,
                            ),
                        ),
                    ):
                        failed_count += 1
                        continue
                    touched_stages.add(item.stage_name)
                    synced_count += 1
                else:
                    skipped_count += 1
                if notfound_apply_state:
                    self._record_event(
                        db,
                        task,
                        "downstream_status_synced",
                        "下游子任务不存在，已投递 reducer 串行更新事件",
                        level="warning",
                        stage_name=item_stage_name,
                        item=item,
                        payload={
                            "downstream_service": item_downstream_service,
                            "downstream_task_id": item_downstream_task_id,
                            "http_status": 404,
                            "error_type": "not_found",
                            "status_raw": "downstream_missing",
                            "mapped_status": "downstream_missing",
                            "state_applied": True,
                            "before_status": before_status,
                            "downstream_status": "downstream_missing",
                            "after_status": "downstream_missing",
                        },
                    )
            except Exception as exc:
                failed_count += 1
                repair_applied = False
                current_item_status = self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower() or None
                item_result = self._load_stage_item_result_payload(item)
                current_observed = self._normalize_downstream_status(
                    self._string_or_none(dict(item_result.get("sync_observation") or {}).get("downstream_status"))
                )
                if current_item_status in {"success", "partial_success", "failed", "cancelled", "downstream_missing"} and current_observed in {"pending", "dispatching", "running"}:
                    repair_applied = self._repair_stage_item_terminal_downstream_observation(
                        db,
                        task,
                        item,
                        reason="sync_fetch_failed_but_item_terminal",
                    )
                    if repair_applied:
                        touched_stages.add(item.stage_name)
                if repair_applied:
                    state = task_manager_module.DownstreamSyncSupervisorState(
                        consecutive_error_count=0,
                        budget_exhausted=False,
                        next_retry_at=None,
                        last_result="success",
                    )
                    if not self._persist_child_sync_observation(
                        db,
                        task=task,
                        item=item,
                        change_source="transport_error",
                        sync_status="synced",
                        error_message=str(exc),
                        http_status=self._extract_http_status_from_exception(exc),
                        error_type=self._classify_downstream_sync_error(exc),
                        state_applied=True,
                        extra_payload={"operation": "downstream_sync"},
                        consecutive_error_count=state.consecutive_error_count,
                        budget_exhausted=state.budget_exhausted,
                        next_retry_at=state.next_retry_at,
                        last_sync_result=state.last_result,
                    ):
                        failed_count += 1
                        continue
                elif not self._persist_downstream_sync_failure(
                    db,
                    task=task,
                    item=item,
                    error=exc,
                    change_source="transport_error",
                    operation="downstream_sync",
                    before_status=before_status,
                ):
                    failed_count += 1
                    continue
                if repair_applied:
                    self._log_child_status_event(
                        db,
                        task=task,
                        item=item,
                        event_type="child_transport_failed",
                        change_source="transport_error",
                        before_status=before_status,
                        after_status=str(item.status or "").strip().lower() or before_status,
                        sync_status="synced",
                        downstream_status_raw=None,
                        downstream_status_mapped=None,
                        downstream_status=None,
                        state_applied=True,
                        error_message=str(exc),
                        error_type=self._classify_downstream_sync_error(exc),
                        http_status=self._extract_http_status_from_exception(exc),
                        extra_payload={
                            "operation": "downstream_sync",
                            "repair_applied": True,
                        },
                    )
                    stage_takeover_candidates.add(str(item.stage_name or "").strip())
        for current_stage in touched_stages:
            if current_stage == "system_analysis":
                self._refresh_system_analysis_stage_from_synced_items(db, task)
            else:
                self._refresh_stage_run_from_items(db, task, current_stage)
        task_layer_decision = task_manager_module._TaskLayerDecision()
        if touched_stages:
            self._refresh_task_status_after_sync(db, task)
            task_layer_decision = self._decide_owned_execution_requeue(
                db,
                task,
                preferred_stage_name="system_analysis" if "system_analysis" in stage_takeover_candidates else None,
                reason="system_analysis_sync_next_stage_active_without_owner",
                message="系统分析同步完成，检测到后续阶段已处于活跃态，任务已重新排队等待 worker 接管",
                payload={"source": "system_analysis_sync_success"} if "system_analysis" in stage_takeover_candidates else {"source": "downstream_sync"},
            )
            self._apply_task_layer_decision(
                db,
                task,
                task_layer_decision,
                event_type="owned_execution_takeover_requeued",
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
        db.commit()
        response_synced_count = synced_count if apply_state else min(synced_count, len(touched_stages))
        return BinarySecurityActionResponse(
            task_id=task.id,
            message=f"下游状态同步完成：更新 {response_synced_count} 个，跳过 {skipped_count} 个，失败 {failed_count} 个，绑定不匹配 {binding_mismatch_count} 个",
            synced_downstream_count=response_synced_count,
            skipped_downstream_count=skipped_count,
            failed_downstream_count=failed_count,
            binding_mismatch_count=binding_mismatch_count,
            revived_count=revived_count,
            revival_rejected_count=revival_rejected_count,
        )

    def _load_readless_reconcile_candidate_ids(self: TaskManager) -> list[str]:
        from app.service import task_manager as task_manager_module

        candidate_session = task_manager_module.get_session_factory()()
        try:
            return [
                str(task_id)
                for (task_id,) in candidate_session.query(BinarySecurityTask.id)
                .filter(BinarySecurityTask.status.in_(["pending", "running", "dispatching"]))
                .order_by(BinarySecurityTask.updated_at.asc(), BinarySecurityTask.created_at.asc())
                .limit(64)
                .all()
            ]
        finally:
            candidate_session.close()

    def _process_readless_reconcile_task_sync(self: TaskManager, task_id: str) -> tuple[bool, bool]:
        from app.service import task_manager as task_manager_module

        session = task_manager_module.get_session_factory()()
        try:
            task = session.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if task is None:
                return False, False
            if (
                self._task_runtime_phase(task) == TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
                and not self._is_reducer_role()
                and not self._tail_requires_execution_takeover(session, task)
            ):
                session.rollback()
                return True, False
            if self._should_skip_readless_reconcile_for_active_task(task):
                session.rollback()
                return True, False
            before = self._task_state_snapshot(task)
        finally:
            session.close()

        self._readless_reconcile_item_layer(task_id)
        touched_stages = self._readless_reconcile_stage_layer(task_id)
        after = self._readless_reconcile_task_layer(task_id)
        if after is None:
            return False, False
        self._readless_reconcile_tail_takeover(task_id)
        changed = self._task_state_snapshot_changed(before, after) or bool(touched_stages)
        return True, changed

    def _task_state_snapshot(self: TaskManager, task: BinarySecurityTask) -> _TaskStateSnapshot:
        from app.service import task_manager as task_manager_module

        return task_manager_module._TaskStateSnapshot(
            status=str(task.status or "").strip(),
            current_stage=str(task.current_stage or "").strip(),
            runtime_phase=self._task_runtime_phase(task),
        )

    def _task_state_snapshot_changed(self: TaskManager, before: _TaskStateSnapshot, after: _TaskStateSnapshot) -> bool:
        return (
            before.status != after.status
            or before.current_stage != after.current_stage
            or before.runtime_phase != after.runtime_phase
        )

    def _run_retryable_layer(self: TaskManager, func: Callable[[], Any]) -> Any:
        attempts = self._retryable_write_attempts()
        for attempt in range(attempts):
            try:
                return func()
            except Exception as exc:
                if not self._is_retryable_lock_error(exc) or attempt >= attempts - 1:
                    raise
                self._sleep_after_retryable_lock_error(attempt + 1)
        return func()

    def _readless_reconcile_candidate_stage_names(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> list[str]:
        stage_names: set[str] = set()
        for item in self._task_reconcile_candidate_items(db, task, force=False):
            normalized = normalize_stage_name(item.stage_name)
            if normalized:
                stage_names.add(normalized)
        for stage_name in self._stage_sequence_for_task(task):
            if self._stage_items(db, task.id, stage_name):
                stage_names.add(stage_name)
        return [stage_name for stage_name in self._stage_sequence_for_task(task) if stage_name in stage_names]

    def _sync_stage_item_downstream_fact(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
    ) -> bool:
        from app.service import task_manager as task_manager_module

        observed_status = self._latest_observed_downstream_status(item)
        if not observed_status:
            return False
        current_result = self._load_stage_item_result_payload(item)
        current_recorded_status = self._string_or_none(current_result.get("downstream_status"))
        current_recorded_mapped = self._normalize_downstream_status(current_recorded_status)
        observed_mapped = self._normalize_downstream_status(observed_status) or observed_status
        if (
            not self._item_missing_recorded_downstream_status(item)
            and current_recorded_status == observed_status
            and current_recorded_mapped == observed_mapped
        ):
            return False
        sync_status = self._stage_item_sync_status_value(item) or "observed"
        return self._persist_child_sync_observation(
            db,
            task=task,
            item=item,
            change_source="readless_reconcile",
            sync_status=sync_status,
            synced_at=self._stage_item_sync_attempt_at_value(item) or self._stage_item_last_synced_at_value(item) or task_manager_module._now(),
            error_message=self._stage_item_sync_error_message_value(item),
            error_type=self._stage_item_sync_error_type_value(item),
            status_raw=observed_status,
            mapped_status=observed_mapped,
            downstream_status=observed_status,
            state_applied=False,
        )

    def _readless_reconcile_item_layer(self: TaskManager, task_id: str) -> set[str]:
        from app.service import task_manager as task_manager_module

        touched_stages: set[str] = set()

        def _run() -> set[str]:
            session = task_manager_module.get_session_factory()()
            try:
                task = session.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
                if task is None:
                    return set()
                candidates = self._task_reconcile_candidate_items(
                    session,
                    task,
                    force=False,
                    include_failed_terminal_items=True,
                )
                current_touched: set[str] = set()
                for item in candidates:
                    if self._sync_stage_item_downstream_fact(session, task, item):
                        current_touched.add(normalize_stage_name(item.stage_name))
                session.commit()
                return current_touched
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

        touched_stages.update(self._run_retryable_layer(_run))
        return touched_stages

    def _reconcile_stage_domain(self: TaskManager, task_id: str, stage_name: str) -> bool:
        from app.service import task_manager as task_manager_module

        def _run() -> bool:
            session = task_manager_module.get_session_factory()()
            try:
                task = session.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
                if task is None:
                    return False
                previous = session.query(BinarySecurityStageRun).filter(
                    BinarySecurityStageRun.task_id == task_id,
                    BinarySecurityStageRun.stage_name == stage_name,
                ).first()
                previous_status = str(previous.status or "").strip() if previous is not None else ""
                previous_counts = dict(previous.counts or {}) if previous is not None else {}
                previous_error = str(previous.last_error or "").strip() if previous is not None and previous.last_error else ""
                if stage_name == "system_analysis":
                    self._refresh_system_analysis_stage_from_synced_items(session, task)
                else:
                    self._refresh_stage_run_from_items(session, task, stage_name)
                current = session.query(BinarySecurityStageRun).filter(
                    BinarySecurityStageRun.task_id == task_id,
                    BinarySecurityStageRun.stage_name == stage_name,
                ).first()
                changed = False
                if current is not None:
                    changed = (
                        str(current.status or "").strip() != previous_status
                        or dict(current.counts or {}) != previous_counts
                        or str(current.last_error or "").strip() != previous_error
                    )
                session.commit()
                return changed
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

        return bool(self._run_retryable_layer(_run))

    def _readless_reconcile_stage_layer(self: TaskManager, task_id: str) -> set[str]:
        from app.service import task_manager as task_manager_module

        session = task_manager_module.get_session_factory()()
        try:
            task = session.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if task is None:
                return set()
            candidate_stages = self._readless_reconcile_candidate_stage_names(session, task)
        finally:
            session.close()
        touched: set[str] = set()
        for stage_name in candidate_stages:
            if self._reconcile_stage_domain(task_id, stage_name):
                touched.add(stage_name)
        return touched

    def _readless_reconcile_tail_takeover(self: TaskManager, task_id: str) -> None:
        from app.service import task_manager as task_manager_module

        session = task_manager_module.get_session_factory()()
        try:
            task = session.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if task is None:
                return
            if not self._tail_requires_execution_takeover(session, task):
                session.rollback()
                return
            tail_summary = self._tail_stage_work_summary(session, task)
            takeover_reason = str(tail_summary.get("takeover_reason") or "").strip() or "runnable_unbound_tail_items"
            if takeover_reason == "incomplete_tail_stage":
                message = "检测到流式尾段阶段尚未完成，任务将回到 worker 接管继续执行"
            else:
                message = "检测到流式尾段仍有未绑定子项，任务将回到 worker 接管继续执行"
            self._record_event(
                session,
                task,
                "tail_execution_takeover_required",
                message,
                level="warning",
                stage_name=task.current_stage,
                payload={
                    "tail_control_mode": "execution_takeover",
                    "reason": takeover_reason,
                },
            )
            self._merge_task_runtime_signal(
                task,
                "pending_operation_repair",
                source="lease_auditor_signal",
                reason="tail_execution_takeover_required",
                stage_name=str(task.current_stage or "").strip() or None,
                extra={
                    "tail_control_mode": "execution_takeover",
                    "takeover_reason": takeover_reason,
                },
            )
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
        self._enqueue_task(task_id)

    async def _process_readless_reconcile_task(self: TaskManager, task_id: str) -> tuple[bool, bool]:
        result = await asyncio.to_thread(self._process_readless_reconcile_task_sync, task_id)
        self._mark_loop_heartbeat("readless_reconcile")
        return result

    def _observe_readless_reconcile_stats(self: TaskManager, stats: ReadlessSyncStats) -> None:
        observe_task_readless_reconcile(
            attempted=stats.attempted,
            changed=stats.changed,
            failed=stats.failed,
            candidates=stats.candidates,
        )
