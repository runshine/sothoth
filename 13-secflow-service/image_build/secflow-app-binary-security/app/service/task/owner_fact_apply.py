from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

from sqlalchemy.orm import Session

from app.exception import ValidationError
from app.model import (
    BinarySecurityStageItem,
    BinarySecurityStateEvent,
    TASK_TERMINAL_STATUSES,
    normalize_stage_name,
)
from app.observability import observe_stage_duration

from . import shared as task_shared

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class TaskOwnerFactApplyServiceMixin:
    async def _apply_compat_state_event_via_owner_fact_apply(
        self: TaskManager,
        db: Session,
        event: BinarySecurityStateEvent,
    ) -> None:
        from app.service import task_manager as task_manager_module

        previous_origin = getattr(self, "_active_timeline_origin_state_event", None)
        self._active_timeline_origin_state_event = event
        try:
            payload = dict(event.payload or {})
            if event.event_type == "archive_job_copied":
                await self._apply_archive_job_status_locked(
                    db,
                    event.archive_job_id or "",
                    payload.get("archive_root"),
                    state_event_id=event.id,
                )
                return
            if event.event_type == "archive_job_copy_failed":
                self._apply_archive_job_copy_failed_locked(db, event)
                return
            if event.event_type in {"downstream_status_observed", "downstream_terminal_observed"}:
                await self._apply_downstream_status_event_locked(db, event)
                return
            if event.event_type == "stage_worker_terminal_observed":
                await self._apply_stage_worker_terminal_event_locked(db, event)
                return
            if event.event_type == "task_execution_failed":
                await self._apply_task_execution_failed_locked(db, event)
                return
            if event.event_type == "stage_worker_start_requested":
                self._apply_stage_worker_start_requested_locked(db, event)
                return
            if event.event_type == "manual_policy_update_requested":
                self._apply_manual_policy_update_requested_locked(db, event)
                return
            task_manager_module.logger.info("binary-security compat state event apply ignored event type: %s", event.event_type)
        finally:
            self._active_timeline_origin_state_event = previous_origin

    def _apply_stage_worker_start_requested_payload_locked(
        self: TaskManager,
        db: Session,
        task,
        *,
        stage_name: str,
        stage_retry_mode: bool = False,
        task_retry_mode: bool = False,
        target_stage_name: str | None = None,
        state_event_id: str | None = None,
        source_event_type: str = "stage_worker_start_requested",
    ) -> None:
        if not stage_name:
            return
        sequence = self._stage_sequence_for_task(task)
        current_stage = str(getattr(task, "current_stage", "") or "").strip()
        if current_stage and current_stage in sequence and stage_name in sequence and sequence.index(current_stage) > sequence.index(stage_name):
            return
        if self._task_runtime_transition_guard_active(task):
            guard = self._task_runtime_transition_guard(task)
            self._record_event(
                db,
                task,
                "stage_worker_start_observed_during_guard",
                "阶段启动事实已落库，任务仍处于 owner 接管保护窗口，暂不记录主状态阻塞或 takeover 信号",
                level="info",
                stage_name=stage_name,
                payload={
                    "state_event_id": state_event_id,
                    "stage_name": stage_name,
                    "guard_id": guard.get("guard_id"),
                    "takeover_suppressed": True,
                    "stage_retry_mode": bool(stage_retry_mode),
                    "task_retry_mode": bool(task_retry_mode),
                    "target_stage_name": target_stage_name,
                },
            )
            return
        stage_gate = self._evaluate_stage_start_gate(
            db,
            task,
            stage_name,
            allow_entry_rebuild=False,
        )
        if not bool(stage_gate.get("allowed")):
            self._record_main_state_write_blocked(
                db,
                task,
                source="owner_fact_apply",
                attempted_stage_name=stage_name,
                attempted_status="running",
                reason="stage_worker_start_requested_not_materialized",
            )
            self._request_task_layer_reconcile(
                db,
                task,
                stage_name=stage_name,
                source_event_type=source_event_type,
                state_event_id=state_event_id,
                reconcile_reason="stage_worker_start_requested",
                message="阶段启动请求已收到，但当前阶段尚无真实可执行输入，已等待 owner worker 后续接管",
                event_payload={
                    "stage_start_allowed": False,
                    "blocked_reason": stage_gate.get("blocked_reason"),
                    "stage_retry_mode": bool(stage_retry_mode),
                    "task_retry_mode": bool(task_retry_mode),
                    "target_stage_name": target_stage_name,
                },
            )
            return
        stage_run = self._ensure_stage_run(db, task, stage_name)
        if str(getattr(stage_run, "status", "") or "").strip() in TASK_TERMINAL_STATUSES and getattr(stage_run, "finished_at", None):
            return
        now_value = task_shared._now()
        stage_run.status = "running"
        stage_run.started_at = stage_run.started_at or now_value
        stage_run.finished_at = None
        stage_run.updated_at = now_value
        stage_run.counts = self._stage_counts(db, stage_run)
        task.started_at = task.started_at or now_value
        task.updated_at = now_value
        stage_summary = dict(task.stage_summary or {})
        stage_summary[stage_name] = {
            **dict(stage_summary.get(stage_name) or {}),
            "status": "running",
            "counts": stage_run.counts,
            "started_at": task_shared._isoformat_or_none(stage_run.started_at),
            "finished_at": None,
        }
        task.stage_summary = stage_summary
        self._record_main_state_write_blocked(
            db,
            task,
            source="owner_fact_apply",
            attempted_stage_name=stage_name,
            attempted_status="running",
            reason="stage_worker_start_requested_requires_owner_worker",
        )
        self._request_task_layer_reconcile(
            db,
            task,
            stage_name=stage_name,
            source_event_type=source_event_type,
            state_event_id=state_event_id,
            reconcile_reason="stage_worker_start_requested",
            message="阶段启动事实已落库，等待 owner worker 接管并推进任务主状态",
            event_payload={
                "stage_retry_mode": bool(stage_retry_mode),
                "task_retry_mode": bool(task_retry_mode),
                "target_stage_name": target_stage_name,
            },
        )

    def _apply_stage_worker_start_requested_locked(self: TaskManager, db: Session, event: BinarySecurityStateEvent) -> None:
        from app.service import task_manager as task_manager_module

        task = db.query(task_manager_module.BinarySecurityTask).filter(task_manager_module.BinarySecurityTask.id == event.task_id).first()
        if task is None:
            return
        payload = dict(event.payload or {})
        self._apply_stage_worker_start_requested_payload_locked(
            db,
            task,
            stage_name=str(payload.get("stage_name") or event.stage_name or "").strip(),
            stage_retry_mode=bool(payload.get("stage_retry_mode")),
            task_retry_mode=bool(payload.get("task_retry_mode")),
            target_stage_name=str(payload.get("target_stage_name") or "").strip() or None,
            state_event_id=event.id,
            source_event_type=event.event_type,
        )

    async def _apply_stage_worker_terminal_direct_locked(
        self: TaskManager,
        db: Session,
        task,
        *,
        stage_name: str,
        status: str,
        summary: dict[str, object] | None = None,
        stage_retry_mode: bool = False,
        task_retry_mode: bool = False,
        target_stage_name: str | None = None,
        execution_token: str | None = None,
        stage_generation: str | None = None,
        state_event_id: str | None = None,
        source_event_type: str = "stage_worker_terminal_observed",
    ) -> None:
        terminal_event = SimpleNamespace(
            id=state_event_id,
            event_type=source_event_type,
            task_id=str(getattr(task, "id", "") or "").strip(),
            project_id=str(getattr(task, "project_id", "") or "").strip(),
            stage_name=stage_name,
            payload={
                "stage_name": stage_name,
                "status": status,
                "summary": dict(summary or {}),
                "stage_retry_mode": bool(stage_retry_mode),
                "task_retry_mode": bool(task_retry_mode),
                "target_stage_name": target_stage_name,
                "execution_token": execution_token,
                "stage_generation": stage_generation,
            },
        )
        await self._apply_stage_worker_terminal_event_locked(db, terminal_event)  # type: ignore[arg-type]

    async def _apply_downstream_status_event_locked(self: TaskManager, db: Session, event: BinarySecurityStateEvent) -> None:
        from app.service import task_manager as task_manager_module

        task = db.query(task_manager_module.BinarySecurityTask).filter(task_manager_module.BinarySecurityTask.id == event.task_id).first()
        item = db.query(task_manager_module.BinarySecurityStageItem).filter(task_manager_module.BinarySecurityStageItem.id == event.item_id).first()
        if task is None or item is None:
            return
        payload = dict(event.payload or {})
        if task.status == "cancelled":
            self._record_event(
                db,
                task,
                "downstream_status_event_ignored",
                "下游状态事件晚于取消事件到达，已忽略以避免恢复已取消任务",
                level="warning",
                stage_name=item.stage_name,
                item=item,
                payload={
                    "state_event_id": event.id,
                    "downstream_service": item.downstream_service,
                    "downstream_task_id": item.downstream_task_id,
                    "ignored_status": payload.get("mapped_status") or payload.get("downstream_status"),
                },
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        mapped_status = str(payload.get("mapped_status") or "").strip()
        if not mapped_status:
            return
        mapped_status = self._map_downstream_status(mapped_status) or mapped_status
        downstream_payload = dict(payload.get("downstream_payload") or {})
        payload_downstream_task_id = self._payload_downstream_task_id(downstream_payload) or self._payload_downstream_task_id(payload)
        current_downstream_task_id = self._current_downstream_task_id(item)
        if payload_downstream_task_id and current_downstream_task_id and payload_downstream_task_id != current_downstream_task_id:
            self._mark_stage_item_sync_observation(
                item,
                sync_status="binding_mismatch",
                synced_at=task_shared._now(),
                error_message="旧 child 的下游状态事件已被忽略",
                error_type="binding_mismatch",
                status_raw=self._string_or_none(payload.get("downstream_status") or downstream_payload.get("status")),
                mapped_status=mapped_status,
                downstream_status=self._string_or_none(payload.get("downstream_status") or downstream_payload.get("status")),
                state_applied=False,
                last_sync_result="error",
            )
            self._record_binding_mismatch_event(
                db,
                task,
                item,
                event_type="downstream_binding_mismatch_detected",
                message="旧 child 的下游状态事件已被忽略，未回写当前阶段项",
                payload=self._binding_mismatch_payload(
                    source="downstream_status_event",
                    expected_downstream_task_id=current_downstream_task_id,
                    actual_downstream_task_id=payload_downstream_task_id,
                    payload_downstream_task_id=payload_downstream_task_id,
                ),
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        if not self._payload_matches_current_child(item, downstream_payload or payload):
            self._mark_stage_item_sync_observation(
                item,
                sync_status="binding_mismatch",
                synced_at=task_shared._now(),
                error_message="旧 child 的下游状态事件已被忽略",
                error_type="binding_mismatch",
                status_raw=self._string_or_none(payload.get("downstream_status") or downstream_payload.get("status")),
                mapped_status=mapped_status,
                downstream_status=self._string_or_none(payload.get("downstream_status") or downstream_payload.get("status")),
                state_applied=False,
                last_sync_result="error",
            )
            self._record_binding_mismatch_event(
                db,
                task,
                item,
                event_type="downstream_binding_mismatch_detected",
                message="旧 child 的下游状态事件已被忽略，未回写当前阶段项",
                payload=self._binding_mismatch_payload(
                    source="downstream_status_event",
                    expected_downstream_task_id=current_downstream_task_id,
                    actual_downstream_task_id=payload_downstream_task_id,
                    payload_downstream_task_id=payload_downstream_task_id,
                ),
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        self._apply_child_task_status_change(
            db,
            task=task,
            item=item,
            change_source="owner_fact_apply",
            after_status=mapped_status,
            downstream_payload=downstream_payload,
            sync_status="synced",
            downstream_status_raw=self._string_or_none(payload.get("status_raw") or payload.get("downstream_status")),
            downstream_status_mapped=mapped_status,
            downstream_status=self._string_or_none(payload.get("downstream_status") or downstream_payload.get("status")),
            state_applied=True,
            error_message=(
                payload.get("error_message")
                or downstream_payload.get("error")
                or downstream_payload.get("error_message")
                or downstream_payload.get("message")
                or item.error_message
            ),
            error_type=self._string_or_none(payload.get("error_type")),
            http_status=self._int_or_none(payload.get("http_status")),
            state_event_id=event.id,
            extra_payload={"downstream_payload": self._lightweight_downstream_payload(downstream_payload)},
        )
        stage_run = self._reconcile_stage_domain_in_session(db, task, item.stage_name)
        if str(task.status or "").strip() not in TASK_TERMINAL_STATUSES:
            self._request_task_layer_reconcile(
                db,
                task,
                stage_name=item.stage_name,
                source_event_type=event.event_type,
                state_event_id=event.id,
                reconcile_reason="downstream_status_event_applied",
                message="下游状态事实已更新，等待 owner worker 串行收口任务层决策",
                event_payload={
                    "item_id": item.id,
                    "downstream_task_id": item.downstream_task_id,
                    "stage_status": str(getattr(stage_run, "status", "") or "").strip() or None,
                },
            )
        self._record_event(
            db,
            task,
            "downstream_status_event_applied",
            "下游状态事件已由 owner worker 串行应用",
            level="warning" if mapped_status in {"failed", "cancelled", "downstream_missing"} else "info",
            stage_name=item.stage_name,
            item=item,
            payload={
                "state_event_id": event.id,
                "before_status": payload.get("before_status"),
                "after_status": mapped_status,
                "http_status": payload.get("http_status"),
                "error_type": payload.get("error_type"),
                "status_raw": payload.get("status_raw") or payload.get("downstream_status"),
                "mapped_status": mapped_status,
                "state_applied": True,
                "downstream_status": payload.get("downstream_status"),
                "downstream_service": item.downstream_service,
                "downstream_task_id": item.downstream_task_id,
            },
        )
        await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)

    async def _apply_downstream_terminal_observed_locked(
        self: TaskManager,
        db: Session,
        event: BinarySecurityStateEvent,
    ) -> None:
        await self._apply_downstream_status_event_locked(db, event)

    def _apply_downstream_status_inline(
        self: TaskManager,
        item: BinarySecurityStageItem,
        *,
        mapped_status: str,
        downstream_payload: dict[str, object] | None,
        error_message: str | None,
        synced_at: object | None = None,
    ) -> None:
        self._apply_child_task_status_change(
            None,
            task=None,
            item=item,
            change_source="downstream_sync",
            after_status=mapped_status,
            downstream_payload=downstream_payload,
            sync_status="synced",
            downstream_status_raw=self._string_or_none((downstream_payload or {}).get("status")),
            downstream_status_mapped=self._map_downstream_status(mapped_status) or mapped_status,
            downstream_status=self._string_or_none((downstream_payload or {}).get("status")),
            state_applied=True,
            error_message=error_message,
            synced_at=synced_at,
        )

    def _should_apply_downstream_intermediate_status(
        self: TaskManager,
        item: BinarySecurityStageItem,
        *,
        mapped_status: str,
        payload: dict[str, object] | None,
    ) -> bool:
        before_status = str(item.status or "").strip().lower()
        if self._should_apply_current_child_intermediate_recovery(item, mapped_status=mapped_status, payload=payload):
            return True
        if mapped_status == "running":
            return before_status in {"pending", "queued", "running", "dispatching", "success", "failed"}
        if mapped_status in {"queued", "dispatching"}:
            return before_status in {"pending", "queued", "dispatching", "running", "success", "failed", "cancelled"}
        if mapped_status == "pending":
            if before_status != "running":
                return False
            if str(item.downstream_service or "").strip() == "entry_analyse":
                return self._entry_payload_matches_stage_item(item, payload)
            return True
        return False

    async def _apply_stage_worker_terminal_event_locked(self: TaskManager, db: Session, event: BinarySecurityStateEvent) -> None:
        from app.service import task_manager as task_manager_module

        payload = dict(event.payload or {})
        stage_name = str(event.stage_name or payload.get("stage_name") or "").strip()
        status = str(payload.get("status") or "").strip()
        task = db.query(task_manager_module.BinarySecurityTask).filter(task_manager_module.BinarySecurityTask.id == event.task_id).first()
        if task is None or not stage_name or not status:
            return
        payload = self._load_externalized_event_payload(task, payload)
        stage_name = str(event.stage_name or payload.get("stage_name") or stage_name).strip()
        status = str(payload.get("status") or status).strip()
        observed_terminal_status = status
        terminal_failure_statuses = {"failed", "downstream_missing", "cancelled"}
        summary = dict(payload.get("summary") or {})
        if task.status == "cancelled":
            self._record_event(
                db,
                task,
                "stage_worker_terminal_ignored",
                "阶段终态事件晚于取消事件到达，已忽略以避免恢复已取消任务",
                level="warning",
                stage_name=stage_name,
                payload={"state_event_id": event.id, "ignored_status": status},
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        active_stage_status = status in {"pending", "queued", "running", "dispatching"}
        stage_run = db.query(task_manager_module.BinarySecurityStageRun).filter(
            task_manager_module.BinarySecurityStageRun.task_id == task.id,
            task_manager_module.BinarySecurityStageRun.stage_name == stage_name,
        ).first()
        if stage_run is None:
            stage_run = self._ensure_stage_run(db, task, stage_name)
        ignore_terminal, ignore_reason = self._should_ignore_stage_terminal_event(
            db,
            task,
            stage_name=stage_name,
            event=event,
            payload=payload,
            stage_run=stage_run,
        )
        if ignore_terminal:
            self._record_event(
                db,
                task,
                "stage_worker_terminal_stale_generation_ignored" if ignore_reason == "stale_generation" else "stage_worker_terminal_duplicate_ignored",
                "历史阶段终态事件已忽略，避免重复推进父任务",
                level="warning",
                stage_name=stage_name,
                payload={
                    "state_event_id": event.id,
                    "ignored_reason": ignore_reason,
                    "event_stage_generation": payload.get("stage_generation"),
                    "current_stage_generation": self._stage_terminal_generation_key(task, stage_name, db=db, stage_run=stage_run),
                    "current_stage": task.current_stage,
                },
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        if stage_name == "system_analysis":
            stage_run = self._refresh_stage_from_authoritative_items(db, task, stage_name) or stage_run
            summary = dict(stage_run.output_summary or summary)
            status = str(stage_run.status or status).strip() or status
            active_stage_status = status in {"pending", "queued", "running", "dispatching"}
        elif self._is_streaming_tail_stage(task, stage_name):
            existing_items = self._stage_items(db, task.id, stage_name)
            if existing_items:
                stage_run = self._refresh_stage_from_authoritative_items(db, task, stage_name) or stage_run
                summary = dict(stage_run.output_summary or summary)
                status = str(stage_run.status or status).strip() or status
                active_stage_status = status in {"pending", "queued", "running", "dispatching"}
                has_live_downstream_child = self._stage_has_live_downstream_children(existing_items)
                if observed_terminal_status in terminal_failure_statuses and active_stage_status and has_live_downstream_child:
                    self._record_event(
                        db,
                        task,
                        "stage_worker_terminal_deferred",
                        "阶段终态事件与活跃子项冲突，已按权威子项状态延后收敛",
                        level="warning",
                        stage_name=stage_name,
                        payload={
                            "state_event_id": event.id,
                            "observed_status": observed_terminal_status,
                            "authoritative_stage_status": status,
                        },
                    )
                    observed_terminal_status = status
            else:
                if (
                    observed_terminal_status in terminal_failure_statuses
                    and self._is_streaming_tail_stage(task, stage_name)
                    and normalize_stage_name(stage_name) != "entry_analysis"
                    and not bool(payload.get("stage_retry_mode"))
                    and not bool(payload.get("task_retry_mode"))
                ):
                    stage_run.status = "pending"
                    stage_run.finished_at = None
                    stage_run.last_error = None
                    self._merge_stage_run_output_summary(task, stage_run, {"status_synced": True, "sync_status": "pending"})
                    self._update_task_stage_summary_entry(task, stage_run)
                    self._record_event(
                        db,
                        task,
                        "stage_worker_terminal_ignored_for_empty_streaming_tail",
                        "空流式尾段的历史终态事件已忽略，等待真实子项状态收敛",
                        level="warning",
                        stage_name=stage_name,
                        payload={
                            "state_event_id": event.id,
                            "observed_status": observed_terminal_status,
                        },
                    )
                    active_stage_status = True
                    status = "pending"
                    observed_terminal_status = "pending"
                else:
                    stage_run.status = "waiting_confirmation" if task.status == task_manager_module.TASK_STATUS_PENDING_MODULE_CONFIRMATION else ("running" if active_stage_status else status)
                    stage_run.finished_at = None if active_stage_status else task_shared._now()
                    if not active_stage_status:
                        observe_stage_duration(
                            stage=stage_name,
                            result=stage_run.status,
                            duration_seconds=task_shared._elapsed_seconds_since(stage_run.started_at),
                        )
                    await self._persist_stage_run_output_summary_async(task, stage_run, summary)
                    stage_run.counts = self._stage_counts(db, stage_run)
                    if status in {"failed", "partial_success", "downstream_missing"}:
                        stage_run.last_error = summary.get("error")
                    self._merge_task_stage_summary_entry(
                        task,
                        stage_run,
                        {
                            **(
                                {
                                    "failure_code": summary.get("failure_code"),
                                    "failure_category": summary.get("failure_category"),
                                    "failure_message": summary.get("failure_message"),
                                }
                                if summary.get("failure_code")
                                else {}
                            ),
                        },
                    )
        else:
            existing_items = self._stage_items(db, task.id, stage_name)
            if existing_items:
                stage_run = self._refresh_stage_from_authoritative_items(db, task, stage_name) or stage_run
                summary = dict(stage_run.output_summary or summary)
                status = str(stage_run.status or status).strip() or status
                active_stage_status = status in {"pending", "queued", "running", "dispatching"}
                has_live_downstream_child = self._stage_has_live_downstream_children(existing_items)
                if observed_terminal_status in terminal_failure_statuses and active_stage_status and has_live_downstream_child:
                    self._record_event(
                        db,
                        task,
                        "stage_worker_terminal_deferred",
                        "阶段终态事件与活跃下游子任务冲突，已按权威子项状态延后收敛",
                        level="warning",
                        stage_name=stage_name,
                        payload={
                            "state_event_id": event.id,
                            "observed_status": observed_terminal_status,
                            "authoritative_stage_status": status,
                        },
                    )
                    observed_terminal_status = status
            else:
                stage_run.status = "waiting_confirmation" if task.status == task_manager_module.TASK_STATUS_PENDING_MODULE_CONFIRMATION else ("running" if active_stage_status else status)
                stage_run.finished_at = None if active_stage_status else task_shared._now()
                if not active_stage_status:
                    observe_stage_duration(
                        stage=stage_name,
                        result=stage_run.status,
                        duration_seconds=task_shared._elapsed_seconds_since(stage_run.started_at),
                    )
                await self._persist_stage_run_output_summary_async(task, stage_run, summary)
                stage_run.counts = self._stage_counts(db, stage_run)
                if status in {"failed", "partial_success", "downstream_missing"}:
                    stage_run.last_error = summary.get("error")
                self._merge_task_stage_summary_entry(
                    task,
                    stage_run,
                    {
                        **(
                            {
                                "failure_code": summary.get("failure_code"),
                                "failure_category": summary.get("failure_category"),
                                "failure_message": summary.get("failure_message"),
                            }
                            if summary.get("failure_code")
                            else {}
                        ),
                    },
                )
        if stage_name == "firmware_unpack":
            task.metrics = {**task.metrics, "unpacked_firmware_count": int(summary.get("success_count", 0)), "failed_firmware_count": int(summary.get("failed_count", 0))}
        elif stage_name == "system_analysis":
            stage_summary = dict(stage_run.output_summary or {})
            task.metrics = {
                **task.metrics,
                "high_risk_module_count": int(stage_summary.get("high_risk_module_count", summary.get("high_risk_module_count", 0)) or 0),
                "medium_risk_module_count": int(stage_summary.get("medium_risk_module_count", summary.get("medium_risk_module_count", 0)) or 0),
                "low_risk_module_count": int(stage_summary.get("low_risk_module_count", summary.get("low_risk_module_count", 0)) or 0),
                "candidate_module_count": int(stage_summary.get("candidate_module_count", summary.get("candidate_module_count", 0)) or 0),
                "selected_module_count": int(stage_summary.get("selected_module_count", summary.get("selected_module_count", 0)) or 0),
            }
            task_summary = dict(task.summary or {})
            if self._normalize_downstream_status(stage_run.status) == "success" and not task_summary.get("selected_modules"):
                self._refresh_system_analysis_stage_from_synced_items(db, task)
                task_summary = dict(task.summary or {})
                if task_summary.get("selected_modules"):
                    stage_run = db.query(task_manager_module.BinarySecurityStageRun).filter(
                        task_manager_module.BinarySecurityStageRun.task_id == task.id,
                        task_manager_module.BinarySecurityStageRun.stage_name == stage_name,
                    ).first() or stage_run
                    stage_summary = dict(stage_run.output_summary or stage_summary)
                    task.metrics = {
                        **task.metrics,
                        "high_risk_module_count": int(stage_summary.get("high_risk_module_count", summary.get("high_risk_module_count", 0)) or 0),
                        "medium_risk_module_count": int(stage_summary.get("medium_risk_module_count", summary.get("medium_risk_module_count", 0)) or 0),
                        "low_risk_module_count": int(stage_summary.get("low_risk_module_count", summary.get("low_risk_module_count", 0)) or 0),
                        "candidate_module_count": int(stage_summary.get("candidate_module_count", summary.get("candidate_module_count", 0)) or 0),
                        "selected_module_count": int(stage_summary.get("selected_module_count", summary.get("selected_module_count", 0)) or 0),
                    }
        elif stage_name == "entry_analysis":
            task.metrics = {**task.metrics, "entry_count": int(summary.get("entry_count", 0))}
        elif normalize_stage_name(stage_name) == "dataflow_vuln_scan":
            task.metrics = {**task.metrics, "vuln_result_count": int(summary.get("vuln_result_count", summary.get("success_count", 0)) or 0)}
        if observed_terminal_status in terminal_failure_statuses:
            status = observed_terminal_status
            active_stage_status = False
            for item in self._stage_items(db, task.id, stage_name):
                if str(item.status or "").strip() not in {"pending", "queued", "running", "dispatching"}:
                    continue
                item.status = status
                item.finished_at = item.finished_at or task_shared._now()
                item.error_message = summary.get("failure_message") or summary.get("error") or item.error_message
            stage_run.status = status
            stage_run.finished_at = stage_run.finished_at or task_shared._now()
            stage_run.last_error = summary.get("failure_message") or summary.get("error") or stage_run.last_error
        if active_stage_status:
            self._record_main_state_write_blocked(
                db,
                task,
                source="owner_fact_apply",
                attempted_stage_name=stage_name,
                attempted_status="running",
                reason="stage_waiting_downstream_progress_requires_owner_worker",
            )
            self._record_event(
                db,
                task,
                "stage_waiting_downstream_progress",
                "阶段仍在等待下游明确状态，已保留在当前阶段继续跟进",
                stage_name=stage_name,
                payload={
                    "state_event_id": event.id,
                    "stage_status": status,
                    "deferred_mode": "redispatch" if status == "pending" else "reconcile",
                },
            )
            self._request_task_layer_reconcile(
                db,
                task,
                stage_name=stage_name,
                source_event_type=event.event_type,
                state_event_id=event.id,
                reconcile_reason="stage_waiting_downstream_progress",
                message="阶段事实已更新，等待 owner worker 串行继续推进",
                event_payload={"stage_status": status},
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        if task.status == task_manager_module.TASK_STATUS_PENDING_MODULE_CONFIRMATION:
            self._invalidate_task_execution(task)
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        if bool(payload.get("stage_retry_mode")) and stage_name == str(payload.get("target_stage_name") or ""):
            self._record_event(
                db,
                task,
                "stage_retry_finished",
                f"阶段重试完成: {stage_name}",
                stage_name=stage_name,
                payload={"status": status, "state_event_id": event.id},
            )
        if status == "failed":
            if bool(payload.get("stage_retry_mode")) or bool(payload.get("task_retry_mode")):
                self._clear_retry_execution_context(db, task, stage_name=stage_name, payload={"status": status, "state_event_id": event.id})
            self._record_event(
                db,
                task,
                "stage_failed",
                f"阶段失败，停止后续推进: {stage_name}",
                level="error",
                stage_name=stage_name,
                payload={
                    "error": task.last_error,
                    "state_event_id": event.id,
                    **(
                        {
                            "failure_code": summary.get("failure_code"),
                            "failure_category": summary.get("failure_category"),
                            "failure_message": summary.get("failure_message"),
                        }
                        if summary.get("failure_code")
                        else {}
                    ),
                },
            )
            self._record_main_state_write_blocked(
                db,
                task,
                source="owner_fact_apply",
                attempted_stage_name=stage_name,
                attempted_status="failed",
                reason="stage_terminal_failure_requires_owner_worker",
            )
        if bool(payload.get("stage_retry_mode")) or bool(payload.get("task_retry_mode")):
            self._clear_retry_execution_context(db, task, stage_name=stage_name, payload={"status": status, "state_event_id": event.id})
        if self._ensure_task_remains_cancelling(db, task) is not None:
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        if str(task.status or "").strip() not in TASK_TERMINAL_STATUSES:
            self._request_task_layer_reconcile(
                db,
                task,
                stage_name=stage_name,
                source_event_type=event.event_type,
                state_event_id=event.id,
                reconcile_reason="stage_worker_terminal_observed",
                message="阶段终态事实已落库，等待 owner worker 统一收口任务主状态",
                event_payload={
                    "stage_status": status,
                    "terminal_status": observed_terminal_status,
                    "failure_message": summary.get("failure_message") or summary.get("error"),
                },
            )
        await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
    async def _apply_task_execution_failed_payload_locked(
        self: TaskManager,
        db: Session,
        task,
        *,
        error_message: str,
        dispatcher_instance_id: str | None = None,
        execution_token: str | None = None,
        state_event_id: str | None = None,
        source_event_type: str = "task_execution_failed",
    ) -> None:
        expected_dispatcher = str(dispatcher_instance_id or "").strip()
        expected_execution_token = str(execution_token or "").strip()
        current_execution_token = str(self._dispatch_token_for_task(db, task) or "").strip()
        runtime_lease = self._runtime_lease_for_task(db, getattr(task, "id", None))
        current_dispatcher = (
            str(getattr(runtime_lease, "owner_instance_id", "") or "").strip()
            if runtime_lease is not None and self._runtime_lease_is_active(runtime_lease)
            else ""
        )
        if expected_dispatcher and current_dispatcher and current_dispatcher != expected_dispatcher:
            self._record_event(
                db,
                task,
                "task_execution_failed_ignored",
                "执行失败事件已过期，当前 runtime lease owner 已变化",
                level="warning",
                stage_name=task.current_stage,
                payload={"state_event_id": state_event_id, "runtime_lease_owner": expected_dispatcher},
            )
            return
        if expected_execution_token and current_execution_token and expected_execution_token != current_execution_token:
            self._record_event(
                db,
                task,
                "task_execution_failed_ignored",
                "执行失败事件已过期，当前执行 token 已变化",
                level="warning",
                stage_name=task.current_stage,
                payload={"state_event_id": state_event_id, "execution_token": expected_execution_token},
            )
            return
        if task.status not in {"dispatching", "running"}:
            self._record_event(
                db,
                task,
                "task_execution_failed_ignored",
                "执行失败事件已过期，当前任务不在运行态",
                level="warning",
                stage_name=task.current_stage,
                payload={"state_event_id": state_event_id, "status": task.status},
            )
            return
        self._record_main_state_write_blocked(
            db,
            task,
            source="owner_fact_apply",
            attempted_stage_name=str(task.current_stage or "").strip() or None,
            attempted_status="failed",
            reason="task_execution_failed_requires_owner_worker",
        )
        self._record_event(
            db,
            task,
            "task_failed",
            f"任务执行失败: {error_message}",
            level="error",
            stage_name=task.current_stage,
            payload={"state_event_id": state_event_id, "error": error_message},
        )
        self._request_task_layer_reconcile(
            db,
            task,
            stage_name=str(task.current_stage or "").strip() or None,
            source_event_type=source_event_type,
            state_event_id=state_event_id,
            reconcile_reason="task_execution_failed",
            message="任务执行失败事实已落库，等待 owner worker 统一收口任务主状态",
            event_payload={"error": error_message},
        )
        await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)

    async def _apply_task_execution_failed_locked(self: TaskManager, db: Session, event: BinarySecurityStateEvent) -> None:
        from app.service import task_manager as task_manager_module

        payload = dict(event.payload or {})
        task = db.query(task_manager_module.BinarySecurityTask).filter(task_manager_module.BinarySecurityTask.id == event.task_id).first()
        if task is None:
            return
        await self._apply_task_execution_failed_payload_locked(
            db,
            task,
            error_message=str(payload.get("error") or "任务执行失败"),
            dispatcher_instance_id=str(payload.get("runtime_lease_owner") or payload.get("dispatcher_instance_id") or "").strip() or None,
            execution_token=str(payload.get("execution_token") or "").strip() or None,
            state_event_id=event.id,
            source_event_type=event.event_type,
        )

    def _apply_manual_policy_update_payload_locked(
        self: TaskManager,
        db: Session,
        task,
        *,
        payload: dict[str, object],
        state_event_id: str | None = None,
        applied_by: str = "owner_fact_apply",
    ) -> None:
        before = dict(payload.get("before") or {})
        after = dict(payload.get("after") or {})
        if not after:
            raise ValidationError("策略更新事件缺少目标策略")
        mode = str(payload.get("mode") or "policy").strip()
        event_payload = {
            "before": before,
            "after": after,
            "effective_scope": payload.get("effective_scope"),
            "state_event_id": state_event_id,
            "applied_by": applied_by,
        }
        if mode == "runtime_override":
            task.runtime_override = after
            task.runtime_override_version = int(getattr(task, "runtime_override_version", 0) or 0) + 1
            task.runtime_override_updated_at = task_shared._now()
            task.runtime_override_updated_by = str(payload.get("updated_by") or "").strip() or None
            self._record_event(
                db,
                task,
                "task_runtime_policy_updated",
                "任务运行时策略已更新",
                payload={
                    **event_payload,
                    "effective_scope": payload.get("effective_scope") or "tail_claim_immediate",
                },
            )
            return
        task.policy = after
        if mode == "concurrency":
            self._record_event(
                db,
                task,
                "task_concurrency_updated",
                "任务阶段并发配置已更新",
                payload={
                    "before": payload.get("concurrency_before") or before.get("stage_parallelism") or {},
                    "after": payload.get("concurrency_after") or after.get("stage_parallelism") or {},
                    "state_event_id": state_event_id,
                    "applied_by": applied_by,
                },
            )
        else:
            self._record_event(
                db,
                task,
                "task_policy_updated",
                "任务策略已更新",
                payload={
                    **event_payload,
                    "effective_scope": payload.get("effective_scope") or "future_stages_only",
                },
            )

    def _apply_manual_policy_update_requested_locked(self: TaskManager, db: Session, event: BinarySecurityStateEvent) -> None:
        from app.service import task_manager as task_manager_module

        payload = dict(event.payload or {})
        task = db.query(task_manager_module.BinarySecurityTask).filter(task_manager_module.BinarySecurityTask.id == event.task_id).first()
        if task is None:
            return
        self._apply_manual_policy_update_payload_locked(
            db,
            task,
            payload=payload,
            state_event_id=event.id,
            applied_by="owner_fact_apply",
        )

    def _apply_archive_job_copy_failed_payload_locked(
        self: TaskManager,
        db: Session,
        task,
        job,
        item,
        *,
        error_message: str,
        state_event_id: str | None = None,
        source_event_type: str = "archive_job_copy_failed",
    ) -> None:
        job.archive_status = "failed"
        job.error_message = error_message or job.error_message or "下游产物归档失败"
        job.completed_at = job.completed_at or task_shared._now()
        job.updated_at = task_shared._now()
        if task.status not in TASK_TERMINAL_STATUSES:
            self._record_main_state_write_blocked(
                db,
                task,
                source="owner_fact_apply",
                attempted_stage_name=job.stage_name,
                attempted_status="failed",
                reason="archive_job_copy_failed_requires_owner_worker",
            )
        self._record_event(
            db,
            task,
            "downstream_archive_job_copy_failed",
            "下游产物归档复制失败，失败事实已由 owner/compat apply 落库",
            level="warning",
            stage_name=job.stage_name,
            item=item,
            payload={"state_event_id": state_event_id, "archive_job_id": job.id, "archive_status": job.archive_status, "error": job.error_message},
        )
        if task.status not in TASK_TERMINAL_STATUSES:
            self._request_task_layer_reconcile(
                db,
                task,
                stage_name=job.stage_name,
                source_event_type=source_event_type,
                state_event_id=state_event_id,
                reconcile_reason="archive_job_copy_failed",
                message="下游产物归档失败事实已落库，等待 owner worker 统一收口任务主状态",
                event_payload={
                    "archive_job_id": job.id,
                    "error": job.error_message,
                },
            )
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)

    def _apply_archive_job_copy_failed_locked(self: TaskManager, db: Session, event: BinarySecurityStateEvent) -> None:
        from app.service import task_manager as task_manager_module

        job = db.query(task_manager_module.BinarySecurityArchiveJob).filter(task_manager_module.BinarySecurityArchiveJob.id == event.archive_job_id).first()
        if job is None:
            return
        task = db.query(task_manager_module.BinarySecurityTask).filter(task_manager_module.BinarySecurityTask.id == job.task_id).first()
        item = db.query(task_manager_module.BinarySecurityStageItem).filter(task_manager_module.BinarySecurityStageItem.id == job.item_id).first()
        if task is None:
            return
        payload = dict(event.payload or {})
        self._apply_archive_job_copy_failed_payload_locked(
            db,
            task,
            job,
            item,
            error_message=str(payload.get("error") or ""),
            state_event_id=event.id,
            source_event_type=event.event_type,
        )
