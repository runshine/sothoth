from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.exception import ValidationError
from app.model import BinarySecurityStateEvent
from app.model import TASK_RUNTIME_PHASE_OWNED_EXECUTION

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class TaskArchiveServiceMixin:
    _ARCHIVE_JOB_REUSABLE_STATUSES = frozenset({"pending", "running", "archived", "applying", "success", "ignored", "skipped"})

    def _collapse_duplicate_archive_jobs_for_dedupe(
        self: TaskManager,
        db: Session,
        task: Any,
        item: Any,
        *,
        job_dedupe_key: str,
    ):
        from app.service import task_manager as task_manager_module

        jobs = (
            db.query(task_manager_module.BinarySecurityArchiveJob)
            .filter(
                task_manager_module.BinarySecurityArchiveJob.task_id == task.id,
                task_manager_module.BinarySecurityArchiveJob.stage_name == item.stage_name,
                task_manager_module.BinarySecurityArchiveJob.job_dedupe_key == job_dedupe_key,
            )
            .order_by(task_manager_module.BinarySecurityArchiveJob.created_at.desc())
            .all()
        )
        if not jobs:
            return None
        canonical = next(
            (
                job
                for job in jobs
                if str(getattr(job, "archive_status", "") or "").strip().lower() in self._ARCHIVE_JOB_REUSABLE_STATUSES
            ),
            None,
        )
        if canonical is None:
            canonical = next(
                (
                    job
                    for job in jobs
                    if str(getattr(job, "archive_status", "") or "").strip().lower() == "failed"
                ),
                jobs[0],
            )
        collapsed_job_ids: list[str] = []
        now = task_manager_module._now()
        for job in jobs:
            if job is canonical:
                continue
            status = str(getattr(job, "archive_status", "") or "").strip().lower()
            if status not in self._ARCHIVE_JOB_REUSABLE_STATUSES:
                continue
            payload = dict(getattr(job, "payload", None) or {})
            payload["superseded"] = True
            payload["superseded_reason"] = "duplicate_archive_job_dedupe_key"
            payload["superseded_by_archive_job_id"] = canonical.id
            job.payload = payload
            job.archive_status = "superseded"
            job.owner_id = None
            job.completed_at = job.completed_at or now
            job.updated_at = now
            if not str(getattr(job, "error_message", "") or "").strip():
                job.error_message = f"superseded by canonical archive job {canonical.id}"
            collapsed_job_ids.append(str(getattr(job, "id", "") or ""))
        if collapsed_job_ids:
            self._record_event(
                db,
                task,
                "archive_job_duplicate_dedupe_collapsed",
                "归档重复 dedupe key 已收敛到单一 canonical job",
                stage_name=item.stage_name,
                item=item,
                level="warning",
                payload={
                    "job_dedupe_key": job_dedupe_key,
                    "canonical_archive_job_id": canonical.id,
                    "collapsed_archive_job_ids": collapsed_job_ids,
                    "downstream_task_id": str(getattr(item, "downstream_task_id", "") or "").strip() or None,
                },
            )
        return canonical

    def _archive_pending_full_retry_stage(
        self: TaskManager,
        db: Session,
        task: Any,
        stage_name: str | None = None,
    ) -> tuple[str | None, str | None]:
        from app.service import task_manager as task_manager_module

        stage_sequence = self._stage_sequence_for_task(task)
        if not stage_sequence:
            return None, None

        candidate_stages = (
            [str(stage_name or "").strip()]
            if str(stage_name or "").strip()
            else list(stage_sequence)
        )
        for candidate in candidate_stages:
            normalized_stage = task_manager_module.normalize_stage_name(candidate)
            if normalized_stage not in stage_sequence:
                continue
            jobs = self._archive_jobs_for_stages(db, task.id, [normalized_stage])
            if not jobs:
                continue
            has_pending_like_job = any(
                str(getattr(job, "archive_status", "") or "").strip() in {"pending", "running", "archived", "applying"}
                for job in jobs
            )
            has_retryable_failed_job = any(
                str(getattr(job, "archive_status", "") or "").strip() == "failed"
                and str((getattr(job, "payload", None) or {}).get("mapped_status") or "").strip().lower()
                in task_manager_module.ARCHIVE_SUCCESS_MAPPED_STATUSES
                for job in jobs
            )
            if not has_pending_like_job and not has_retryable_failed_job:
                continue
            supported, reason, _, _ = self._archive_full_retry_support(
                db,
                task,
                normalized_stage,
                ignore_operation_lock=True,
            )
            if supported:
                return normalized_stage, None
            if reason:
                return normalized_stage, reason
        return None, None

    def _archive_stage_full_retry_failure_reason(self: TaskManager, stage_name: str) -> str:
        return f"{stage_name} has no authoritative successful result for archive rebuild"

    def _archive_stage_full_retry_reason_payload(self: TaskManager, stage_name: str) -> dict[str, Any]:
        normalized_stage = str(stage_name or "").strip() or "unknown_stage"
        return {
            "reason_code": f"{normalized_stage}_archive_authoritative_success_missing",
            "reason_category": "authoritative_state",
        }

    def _archive_stage_full_retry_success_candidates(
        self: TaskManager,
        db: Session,
        task: Any,
        stage_name: str,
    ) -> tuple[list[Any], list[Any]]:
        from app.service import task_manager as task_manager_module

        jobs = self._archive_jobs_for_stages(db, task.id, [stage_name])
        stage_items = list(self._stage_items(db, task.id, stage_name))
        if not stage_items and not jobs:
            return [], []

        authoritative_items = [
            item
            for item in stage_items
            if (self._normalize_downstream_status(getattr(item, "status", None)) or str(getattr(item, "status", "") or "").strip().lower())
            in task_manager_module.ARCHIVE_SUCCESS_MAPPED_STATUSES
        ]
        if authoritative_items:
            return jobs, authoritative_items

        authoritative_job_item_ids = {
            str(getattr(job, "item_id", "") or "").strip()
            for job in jobs
            if str((getattr(job, "payload", None) or {}).get("mapped_status") or "").strip().lower()
            in task_manager_module.ARCHIVE_SUCCESS_MAPPED_STATUSES
        }
        if authoritative_job_item_ids:
            filtered_items = [
                item for item in stage_items
                if str(getattr(item, "id", "") or "").strip() in authoritative_job_item_ids
            ]
            if filtered_items:
                return jobs, filtered_items

        if self._archive_apply_stage_has_authoritative_success_payload(db, task, stage_name):
            return jobs, stage_items
        return jobs, []

    def _rebuild_authoritative_archive_jobs_for_stage(
        self: TaskManager,
        db: Session,
        task: Any,
        stage_name: str,
        stage_items: list[Any],
        *,
        archive_jobs: list[Any] | None = None,
    ) -> int:
        from app.service import task_manager as task_manager_module

        archive_jobs = list(archive_jobs or [])
        jobs_by_item_id = {
            str(getattr(job, "item_id", "") or "").strip(): job
            for job in archive_jobs
            if str(getattr(job, "item_id", "") or "").strip()
        }
        rebuilt = 0
        for stage_item in list(stage_items or []):
            payload = dict(self._load_stage_item_result_payload(stage_item).get("downstream") or {})
            normalized_item_status = (
                self._normalize_downstream_status(getattr(stage_item, "status", None))
                or str(getattr(stage_item, "status", "") or "").strip().lower()
                or None
            )
            mapped_status = (
                normalized_item_status
                if normalized_item_status in task_manager_module.ARCHIVE_SUCCESS_MAPPED_STATUSES
                else None
            )
            if mapped_status is None:
                existing_job = jobs_by_item_id.get(str(getattr(stage_item, "id", "") or "").strip())
                existing_job_status = str((getattr(existing_job, "payload", None) or {}).get("mapped_status") or "").strip().lower()
                if existing_job_status in task_manager_module.ARCHIVE_SUCCESS_MAPPED_STATUSES:
                    mapped_status = existing_job_status
            if mapped_status is None:
                raise ValidationError(self._archive_stage_full_retry_failure_reason(stage_name))
            job = self._queue_downstream_archive_job(
                db,
                task,
                stage_item,
                payload=payload,
                mapped_status=mapped_status,
                before_status=str(getattr(stage_item, "status", "") or "").strip() or None,
            )
            if job is not None:
                rebuilt += 1
        return rebuilt

    async def _prepare_authoritative_archive_retry_full(
        self: TaskManager,
        db: Session,
        task: Any,
        target_stage: str,
        *,
        jobs: list[Any],
        stage_items: list[Any],
    ) -> list[str]:
        from app.service import task_manager as task_manager_module

        stage_sequence = self._stage_sequence_for_task(task)
        if target_stage not in stage_sequence:
            raise ValidationError(f"{target_stage} is not present in current stage sequence")
        target_index = stage_sequence.index(target_stage)
        descendant_stages = list(stage_sequence[target_index + 1 :])
        downstream_refs = self._retry_downstream_refs_for_stages(db, task, descendant_stages)

        if jobs:
            self._delete_archive_roots_for_jobs(task, jobs)
        self._clear_archive_jobs_for_stages(db, task.id, [target_stage])
        rebuilt = self._rebuild_authoritative_archive_jobs_for_stage(
            db,
            task,
            target_stage,
            stage_items,
            archive_jobs=jobs,
        )

        if downstream_refs:
            await self._cleanup_downstream_refs(db, task, downstream_refs, self._service_token())
        if descendant_stages:
            self._clear_stage_outputs_from(task, descendant_stages[0], mark_stale=False)
            self._delete_archive_children_for_stages(db, task, descendant_stages)
            self._delete_stage_items_for_stages(db, task.id, descendant_stages)
            self._delete_state_event_rows_for_stages(db, task.id, descendant_stages)
            # Preserve task timeline history when descendant stages are rebuilt.
            for stage_name in descendant_stages:
                stage_run = db.query(task_manager_module.BinarySecurityStageRun).filter(
                    task_manager_module.BinarySecurityStageRun.task_id == task.id,
                    task_manager_module.BinarySecurityStageRun.stage_name == stage_name,
                ).first()
                if stage_run is not None:
                    self._reset_stage_run_for_retry(task, stage_run, increment_retry=False)

        self._mark_task_waiting_for_archive_retry(db, task, target_stage, preserve_active_state=True)
        self._record_event(
            db,
            task,
            "archive_stage_full_retry_requested",
            "阶段归档任务已清空并重建",
            stage_name=target_stage,
            payload={
                "stage_name": target_stage,
                "rebuild_count": rebuilt,
                "retry_semantics": "archive_full",
                "archive_rebuild_mode": "authoritative_stage_only",
                "cleared_business_stages": list(descendant_stages),
                "cleared_archive_stages": [target_stage, *descendant_stages],
            },
        )
        return [target_stage]

    async def _prepare_archive_retry_full_preserve_target_authority(
        self: TaskManager,
        db: Session,
        task: Any,
        target_stage: str,
        *,
        jobs: list[Any],
        stage_items: list[Any],
    ) -> list[str]:
        from app.service import task_manager as task_manager_module

        stage_sequence = self._stage_sequence_for_task(task)
        if target_stage not in stage_sequence:
            raise ValidationError(f"{target_stage} is not present in current stage sequence")

        target_index = stage_sequence.index(target_stage)
        descendant_stages = list(stage_sequence[target_index + 1 :])
        downstream_refs = self._retry_downstream_refs_for_stages(db, task, descendant_stages)

        if downstream_refs:
            await self._cleanup_downstream_refs(db, task, downstream_refs, self._service_token())

        if descendant_stages:
            self._clear_stage_outputs_from(task, descendant_stages[0], mark_stale=False)
            self._delete_archive_children_for_stages(db, task, descendant_stages)
            self._delete_stage_items_for_stages(db, task.id, descendant_stages)
            self._delete_state_event_rows_for_stages(db, task.id, descendant_stages)
            # Preserve task timeline history when descendant stages are rebuilt.
            for stage_name in descendant_stages:
                stage_run = db.query(task_manager_module.BinarySecurityStageRun).filter(
                    task_manager_module.BinarySecurityStageRun.task_id == task.id,
                    task_manager_module.BinarySecurityStageRun.stage_name == stage_name,
                ).first()
                if stage_run is not None:
                    self._reset_stage_run_for_retry(task, stage_run, increment_retry=False)

        if jobs:
            self._delete_archive_roots_for_jobs(task, jobs)
        self._clear_archive_jobs_for_stages(db, task.id, [target_stage])
        rebuilt = self._rebuild_authoritative_archive_jobs_for_stage(
            db,
            task,
            target_stage,
            stage_items,
            archive_jobs=jobs,
        )

        self._mark_task_waiting_for_archive_retry(db, task, target_stage, preserve_active_state=True)
        self._record_event(
            db,
            task,
            "archive_stage_full_retry_requested",
            "阶段归档任务已重建，并清空下游阶段等待重新物化",
            stage_name=target_stage,
            payload={
                "stage_name": target_stage,
                "rebuild_count": rebuilt,
                "retry_semantics": "archive_full",
                "archive_rebuild_mode": "target_stage_archive_only",
                "preserve_target_authoritative_child": True,
                "cleared_business_stages": list(descendant_stages),
                "cleared_archive_stages": [target_stage, *descendant_stages],
            },
        )
        return [target_stage]

    def _expand_stage_name_aliases(self: TaskManager, stage_names: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for stage_name in stage_names:
            raw_name = str(stage_name or "").strip()
            candidate = task_shared_name = None
            try:
                from app.service import task_manager as task_manager_module

                candidate = task_manager_module.normalize_stage_name(stage_name)
            except Exception:
                candidate = str(stage_name or "").strip() or None
            for alias in (raw_name, str(candidate or "").strip()):
                if alias and alias not in seen:
                    seen.add(alias)
                    normalized.append(alias)
            task_shared_name = str(candidate or "").strip()
            if task_shared_name == "dataflow_vuln_scan":
                for alias in ("dataflow_analysis", "vuln_scan"):
                    if alias not in seen:
                        seen.add(alias)
                        normalized.append(alias)
        return normalized

    def _clear_archive_jobs_for_stages(
        self: TaskManager,
        db: Session,
        task_id: str,
        stage_names: list[str],
        *,
        batch_size: int = 100,
        max_retries: int = 3,
    ) -> int:
        from app.service import task_manager as task_manager_module

        normalized = [str(stage_name or "").strip() for stage_name in stage_names if str(stage_name or "").strip()]
        if not normalized:
            return 0
        deleted = 0
        while True:
            job_ids = [
                row[0]
                for row in db.query(task_manager_module.BinarySecurityArchiveJob.id)
                .filter(
                    task_manager_module.BinarySecurityArchiveJob.task_id == task_id,
                    task_manager_module.BinarySecurityArchiveJob.stage_name.in_(normalized),
                )
                .order_by(task_manager_module.BinarySecurityArchiveJob.created_at.asc(), task_manager_module.BinarySecurityArchiveJob.id.asc())
                .limit(max(1, int(batch_size)))
                .all()
            ]
            if not job_ids:
                if hasattr(db, "archive_jobs") and isinstance(getattr(db, "archive_jobs"), list):
                    allowed_stage_names = set(normalized)
                    db.archive_jobs = [
                        row for row in db.archive_jobs
                        if not (
                            str(getattr(row, "task_id", "") or "").strip() == task_id
                            and str(getattr(row, "stage_name", "") or "").strip() in allowed_stage_names
                        )
                    ]
                return deleted
            for attempt in range(max(1, int(max_retries))):
                try:
                    with self._savepoint(db):
                        deleted += int(
                            db.query(task_manager_module.BinarySecurityArchiveJob)
                            .filter(
                                task_manager_module.BinarySecurityArchiveJob.task_id == task_id,
                                task_manager_module.BinarySecurityArchiveJob.id.in_(job_ids),
                            )
                            .delete(synchronize_session=False)
                            or 0
                        )
                    break
                except Exception as exc:
                    if attempt >= max(1, int(max_retries)) - 1 or not self._is_retryable_lock_error(exc):
                        raise
                    db.rollback()

    def _clear_archive_jobs_for_stage_items(
        self: TaskManager,
        db: Session,
        task_id: str,
        stage_name: str,
        item_ids: list[str],
    ) -> int:
        from app.service import task_manager as task_manager_module

        normalized_stage = str(stage_name or "").strip()
        normalized_item_ids = [str(item_id or "").strip() for item_id in item_ids if str(item_id or "").strip()]
        if not normalized_stage or not normalized_item_ids:
            return 0
        deleted = int(
            db.query(task_manager_module.BinarySecurityArchiveJob)
            .filter(
                task_manager_module.BinarySecurityArchiveJob.task_id == task_id,
                task_manager_module.BinarySecurityArchiveJob.stage_name == normalized_stage,
                task_manager_module.BinarySecurityArchiveJob.item_id.in_(normalized_item_ids),
            )
            .delete(synchronize_session=False)
            or 0
        )
        if hasattr(db, "archive_jobs") and isinstance(getattr(db, "archive_jobs"), list):
            allowed_item_ids = set(normalized_item_ids)
            db.archive_jobs = [
                row
                for row in db.archive_jobs
                if not (
                    str(getattr(row, "task_id", "") or "").strip() == task_id
                    and str(getattr(row, "stage_name", "") or "").strip() == normalized_stage
                    and str(getattr(row, "item_id", "") or "").strip() in allowed_item_ids
                )
            ]
        return deleted

    def _delete_archive_children_for_stages(
        self: TaskManager,
        db: Session,
        task,
        stage_names: list[str],
    ) -> int:
        normalized = [str(stage_name or "").strip() for stage_name in stage_names if str(stage_name or "").strip()]
        if not normalized:
            return 0
        self._clear_stage_output_artifacts(task, normalized)
        if hasattr(db, "archive_jobs") and isinstance(getattr(db, "archive_jobs"), list):
            allowed_stage_names = set(normalized)
            matching = [
                row
                for row in db.archive_jobs
                if str(getattr(row, "task_id", "") or "").strip() == task.id
                and str(getattr(row, "stage_name", "") or "").strip() in allowed_stage_names
            ]
            if matching:
                db.archive_jobs = [row for row in db.archive_jobs if row not in matching]
                return len(matching)
        return self._clear_archive_jobs_for_stages(db, task.id, normalized)

    def _archive_retry_blocked_reason(self: TaskManager, db: Session, task: Any) -> str | None:
        active_operation = self._active_operation(db, task.id)
        if active_operation is not None:
            return f"当前任务正在执行 {active_operation.operation_type}，请稍后重试"
        if task.status in {"dispatching", "running"}:
            return f"当前任务正在执行中，当前状态 {task.status} 下不可手工重试归档"
        if task.status in {"pending_upload", "uploading", "pending"}:
            return f"当前任务状态不允许重试归档: {task.status}"
        return None

    def _archive_job_retry_support(
        self: TaskManager,
        db: Session,
        task: Any,
        job: Any,
        *,
        ignore_operation_lock: bool = False,
    ) -> tuple[bool, str | None]:
        if not ignore_operation_lock:
            blocked_reason = self._archive_retry_blocked_reason(db, task)
            if blocked_reason:
                return False, blocked_reason
        if str(getattr(job, "task_id", "") or "").strip() != str(task.id):
            return False, "归档任务不属于当前任务"
        if str(getattr(job, "archive_status", "") or "").strip() != "failed":
            return False, f"当前归档任务状态不允许重试: {getattr(job, 'archive_status', None) or '-'}"
        mapped_status = str((getattr(job, "payload", None) or {}).get("mapped_status") or "").strip()
        if mapped_status not in {"success", "partial_success"}:
            return False, f"当前归档任务目标状态不允许重试: {mapped_status or '-'}"
        return True, None

    def _archive_retry_support(
        self: TaskManager,
        db: Session,
        task: Any,
        stage_name: str,
        *,
        ignore_operation_lock: bool = False,
    ):
        from app.service import task_manager as task_manager_module

        normalized_stage = task_manager_module.normalize_stage_name(stage_name)
        allowed_stage_names = set(self._expand_stage_name_aliases([normalized_stage or stage_name]))
        if not ignore_operation_lock:
            blocked_reason = self._archive_retry_blocked_reason(db, task)
            if blocked_reason:
                return False, blocked_reason, []
        jobs = (
            db.query(task_manager_module.BinarySecurityArchiveJob)
            .filter(task_manager_module.BinarySecurityArchiveJob.task_id == task.id)
            .order_by(task_manager_module.BinarySecurityArchiveJob.created_at.asc())
            .all()
        )
        jobs = [
            job
            for job in jobs
            if str(getattr(job, "task_id", "") or "").strip() == str(task.id)
            and str(getattr(job, "stage_name", "") or "").strip() in allowed_stage_names
        ]
        if not jobs:
            return False, "当前阶段暂无归档任务", []
        retryable_jobs = []
        for job in jobs:
            supported, _ = self._archive_job_retry_support(db, task, job, ignore_operation_lock=ignore_operation_lock)
            if supported:
                retryable_jobs.append(job)
        if not retryable_jobs:
            return False, "当前阶段暂无可重试的失败归档任务", []
        return True, None, retryable_jobs

    def _archive_full_retry_support(
        self: TaskManager,
        db: Session,
        task: Any,
        stage_name: str,
        *,
        ignore_operation_lock: bool = False,
    ):
        from app.service import task_manager as task_manager_module

        normalized_stage = task_manager_module.normalize_stage_name(stage_name)
        allowed_stage_names = set(self._expand_stage_name_aliases([normalized_stage or stage_name]))
        if not ignore_operation_lock:
            blocked_reason = self._archive_retry_blocked_reason(db, task)
            if blocked_reason:
                return False, blocked_reason, [], []
        stage_sequence = self._stage_sequence_for_task(task)
        if normalized_stage not in stage_sequence and str(stage_name or "").strip() not in stage_sequence:
            return False, f"无效阶段: {stage_name}", [], []
        jobs, retryable_items = self._archive_stage_full_retry_success_candidates(db, task, normalized_stage)
        if not jobs and not retryable_items:
            return False, "当前阶段暂无归档任务", [], []
        if not retryable_items:
            return False, self._archive_stage_full_retry_failure_reason(normalized_stage), jobs, []
        return True, None, jobs, retryable_items

    def _mark_task_waiting_for_archive_retry(
        self: TaskManager,
        db: Session,
        task: Any,
        stage_name: str,
        *,
        preserve_active_state: bool = False,
    ) -> None:
        next_status = "running" if preserve_active_state else "pending"
        self._apply_task_status_only_update(
            db,
            task,
            status=next_status,
            reason="归档重试后重新排队" if not preserve_active_state else "归档重试后保持当前阶段活跃执行",
            source="archive_worker",
            stage_name=stage_name,
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            finished_at=None,
            last_error=None,
            clear_runtime_owner=False,
        )
        task.execution_mode = None
        task.target_stage_name = None
        self._clear_task_abnormal_reason_snapshot(db, task)
        task.tail_reconcile_state = "idle"
        should_release_owner = not preserve_active_state
        clear_decision = None
        if not should_release_owner:
            clear_decision = self._can_reopen_parent_task_after_lease_loss(
                db,
                task,
                reason="archive_retry_requeue",
            )
            if clear_decision.allowed:
                reopen_event_type, reopen_message = self._parent_runtime_reopen_allowed_event(
                    clear_decision,
                    expired_message="父任务租约已过期，允许归档重试后重新排队",
                    missing_message="父任务租约已缺失，允许归档重试后重新排队",
                )
                self._record_parent_runtime_lease_decision(
                    db,
                    task,
                    event_type=reopen_event_type,
                    message=reopen_message,
                    decision=clear_decision,
                    reason="archive_retry_requeue",
                    stage_name=stage_name,
                    level="warning",
                )
                should_release_owner = True
            else:
                self._record_parent_runtime_lease_decision(
                    db,
                    task,
                    event_type="retry_takeover_suppressed_active_lease",
                    message="父任务租约仍有效，当前不允许归档重试时清理租约",
                    decision=clear_decision,
                    reason="archive_retry_requeue",
                    stage_name=stage_name,
                )
        task.finished_at = None
        if should_release_owner:
            observed_owner = str(getattr(clear_decision, "runtime_lease_owner", "") or "").strip() or None
            if observed_owner:
                self._clear_runtime_lease(db, task.id, owner_instance_id=observed_owner)
            self._enqueue_task(task.id)
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=next_status)
        self._record_event(
            db,
            task,
            "task_archive_retry_requeued",
            "失败任务的产物归档已重新排队，等待归档 worker 完成后继续推进",
            stage_name=stage_name,
            payload={
                "stage_name": stage_name,
                "retry_semantics": "archive_retry",
                "preserve_active_state": preserve_active_state,
            },
        )

    async def _prepare_archive_retry_failed_items(
        self: TaskManager,
        db: Session,
        task: Any,
        target_stage: str,
    ) -> list[str]:
        supported, reason, jobs = self._archive_retry_support(db, task, target_stage, ignore_operation_lock=True)
        if not supported:
            raise ValidationError(reason or f"阶段 {target_stage} 暂无可重试的归档任务")
        self._delete_archive_roots_for_jobs(task, jobs)
        self._requeue_archive_jobs(
            db,
            task,
            jobs,
            stage_name=target_stage,
            event_type="archive_stage_retry_requested",
            event_message="阶段归档任务已重新排队",
        )
        self._mark_task_waiting_for_archive_retry(db, task, target_stage)
        return [target_stage]

    async def _prepare_archive_retry_full(
        self: TaskManager,
        db: Session,
        task: Any,
        target_stage: str,
    ) -> list[str]:
        normalized_target_stage = str(target_stage or "").strip()
        supported, reason, jobs, stage_items = self._archive_full_retry_support(
            db,
            task,
            target_stage,
            ignore_operation_lock=True,
        )
        if not supported:
            raise ValidationError(reason or self._archive_stage_full_retry_failure_reason(normalized_target_stage))
        return await self._prepare_archive_retry_full_preserve_target_authority(
            db,
            task,
            normalized_target_stage,
            jobs=jobs,
            stage_items=stage_items,
        )

    def _requeue_archive_jobs(
        self: TaskManager,
        db: Session,
        task: Any,
        jobs: list[Any],
        *,
        stage_name: str,
        event_type: str,
        event_message: str,
    ) -> None:
        from app.service import task_manager as task_manager_module

        if not jobs:
            return
        now = task_manager_module._now()
        touched_stage_names: set[str] = set()
        for job in jobs:
            item = db.query(task_manager_module.BinarySecurityStageItem).filter(
                task_manager_module.BinarySecurityStageItem.id == job.item_id
            ).first()
            mapped_status = str((job.payload or {}).get("mapped_status") or "success").strip()
            if item is not None:
                item.status = mapped_status
                item.error_message = None
                item.started_at = item.started_at or now
                item.finished_at = item.finished_at or now
                if item.stage_name == "firmware_unpack":
                    self._refresh_firmware_unpack_item_result(
                        task,
                        item,
                        archived_dir=Path(job.archive_root) if job.archive_root else None,
                    )
                touched_stage_names.add(item.stage_name)
            job.payload = self._clear_archive_job_retry_metadata(job)
            job.archive_status = "pending"
            job.owner_id = None
            job.error_message = None
            job.archive_root = None
            job.started_at = None
            job.completed_at = None
            job.updated_at = now
            self._record_event(
                db,
                task,
                event_type,
                event_message,
                stage_name=stage_name,
                item=item,
                payload={
                    "archive_job_id": job.id,
                    "downstream_service": job.downstream_service,
                    "downstream_task_id": job.downstream_task_id,
                    "mapped_status": mapped_status,
                },
            )
        for current_stage in sorted(touched_stage_names):
            if current_stage == "system_analysis":
                self._refresh_system_analysis_stage_from_synced_items(db, task)
            else:
                self._refresh_stage_run_from_items(db, task, current_stage)
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)

    def _ensure_downstream_archive_job(
        self: TaskManager,
        db: Session,
        task,
        item,
        *,
        payload: dict[str, Any],
        mapped_status: str,
        before_status: str | None,
        force: bool = False,
        extra_paths: list[str | Path] | None = None,
    ):
        from app.service import task_manager as task_manager_module

        downstream_task_id = str(item.downstream_task_id or "").strip()
        job_dedupe_key = task_manager_module.build_archive_job_dedupe_key(item.id, downstream_task_id)
        lock_digest = hashlib.sha1(f"{item.id}:{downstream_task_id}".encode("utf-8")).hexdigest()
        lock_name = f"bs_archive:{lock_digest}"
        locked = False
        try:
            try:
                locked = bool(
                    db.execute(
                        task_manager_module.text("SELECT GET_LOCK(:name, :timeout)"),
                        {"name": lock_name, "timeout": 5},
                    ).scalar()
                )
            except Exception:
                locked = False
            if not locked:
                time.sleep(0.05)
            canonical = self._collapse_duplicate_archive_jobs_for_dedupe(
                db,
                task,
                item,
                job_dedupe_key=job_dedupe_key,
            )
            canonical_status = str(getattr(canonical, "archive_status", "") or "").strip().lower() if canonical is not None else ""
            if canonical is not None and canonical_status in self._ARCHIVE_JOB_REUSABLE_STATUSES:
                try:
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
                return canonical
            if canonical is not None and canonical_status == "failed":
                try:
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
                return canonical
            job = task_manager_module.BinarySecurityArchiveJob(
                id=f"aj_{uuid.uuid4().hex[:24]}",
                task_id=task.id,
                project_id=task.project_id,
                stage_name=item.stage_name,
                item_id=item.id,
                item_key=item.item_key,
                downstream_service=item.downstream_service,
                downstream_task_id=downstream_task_id,
                job_dedupe_key=job_dedupe_key,
            )
            job.archive_status = "pending"
            job.owner_id = None
            job.error_message = None
            job.archive_root = None
            job.started_at = None
            job.completed_at = None
            job.updated_at = task_manager_module._now()
            job.payload = self._build_archive_job_payload(
                mapped_status=mapped_status,
                before_status=before_status,
                force=force,
                payload=payload,
                bound_downstream_task_id=downstream_task_id,
                extra_paths=extra_paths,
            )
            db.add(job)
            max_attempts = self._retryable_write_attempts()
            for attempt in range(max_attempts):
                try:
                    with self._savepoint(db):
                        db.flush()
                    break
                except IntegrityError:
                    existing = (
                        db.query(task_manager_module.BinarySecurityArchiveJob)
                        .filter(
                            task_manager_module.BinarySecurityArchiveJob.task_id == task.id,
                            task_manager_module.BinarySecurityArchiveJob.stage_name == item.stage_name,
                            task_manager_module.BinarySecurityArchiveJob.job_dedupe_key == job_dedupe_key,
                        )
                        .order_by(task_manager_module.BinarySecurityArchiveJob.created_at.desc())
                        .first()
                    )
                    if existing is None:
                        raise
                    return existing
                except OperationalError as exc:
                    if not self._is_retryable_lock_error(exc) or attempt >= max_attempts - 1:
                        raise
                    self._sleep_after_retryable_lock_error(attempt + 1)
            for attempt in range(max_attempts):
                try:
                    db.commit()
                    break
                except OperationalError as exc:
                    db.rollback()
                    if not self._is_retryable_lock_error(exc) or attempt >= max_attempts - 1:
                        raise
                    self._sleep_after_retryable_lock_error(attempt + 1)
                except Exception:
                    db.rollback()
                    raise
            canonical = self._collapse_duplicate_archive_jobs_for_dedupe(
                db,
                task,
                item,
                job_dedupe_key=job_dedupe_key,
            )
            if canonical is not None:
                try:
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
                return canonical
            return job
        finally:
            if locked:
                try:
                    db.execute(task_manager_module.text("SELECT RELEASE_LOCK(:name)"), {"name": lock_name})
                except Exception:
                    pass

    def _queue_downstream_archive_job(
        self: TaskManager,
        db: Session,
        task,
        item,
        *,
        payload: dict[str, Any],
        mapped_status: str,
        before_status: str | None,
        extra_paths: list[str | Path] | None = None,
    ):
        from app.service import task_manager as task_manager_module

        if mapped_status not in task_manager_module.ARCHIVE_SUCCESS_MAPPED_STATUSES:
            raise ValidationError(f"当前状态不生成归档任务: {mapped_status}")
        allowed, ignored_reason = self._may_queue_archive_for_current_binding(
            item,
            payload=payload,
            mapped_status=mapped_status,
        )
        if not allowed:
            replacement_state = self._replacement_in_progress_state(item)
            mismatch_payload = self._binding_mismatch_payload(
                source="task_owner",
                expected_downstream_task_id=self._current_downstream_task_id(item),
                actual_downstream_task_id=self._payload_downstream_task_id(payload),
                current_downstream_task_id=self._current_downstream_task_id(item),
                payload_downstream_task_id=self._payload_downstream_task_id(payload),
                replacement_state=replacement_state,
            )
            if self._replacement_window_active_for_stale_ignore(item) and self._is_destructive_rebuild_transition(replacement_state):
                self._record_event(
                    db,
                    task,
                    "stale_archive_trigger_ignored",
                    "旧 child 的终态归档触发已忽略",
                    stage_name=item.stage_name,
                    item=item,
                    level="warning",
                    payload={
                        **mismatch_payload,
                        "downstream_service": item.downstream_service,
                        "mapped_status": mapped_status,
                        "ignored_reason": ignored_reason,
                        "superseded": True,
                    },
                )
            else:
                self._record_binding_mismatch_event(
                    db,
                    task,
                    item,
                    event_type="downstream_binding_mismatch_detected",
                    message="归档触发来自非 authoritative child，本次仅记录绑定不匹配观测",
                    payload={
                        **mismatch_payload,
                        "mapped_status": mapped_status,
                        "ignored_reason": ignored_reason,
                    },
                )
            return None
        job = self._ensure_downstream_archive_job(
            db,
            task,
            item,
            payload=payload,
            mapped_status=mapped_status,
            before_status=before_status,
            force=False,
            extra_paths=extra_paths,
        )
        self._record_event(
            db,
            task,
            "downstream_archive_job_queued" if job.archive_status in {"pending", "running"} else "downstream_archive_job_reused",
            "下游子任务已终态，产物归档已入队",
            stage_name=item.stage_name,
            item=item,
            payload={
                "archive_job_id": job.id,
                "archive_status": job.archive_status,
                "downstream_service": item.downstream_service,
                "downstream_task_id": item.downstream_task_id,
                "mapped_status": mapped_status,
            },
        )
        return job

    async def _queue_archive_and_wait(
        self: TaskManager,
        db: Session,
        task,
        item,
        *,
        payload: dict[str, Any],
        mapped_status: str,
        before_status: str | None,
        extra_paths: list[str | Path] | None = None,
    ) -> tuple[Path | None, Any]:
        from app.service import task_manager as task_manager_module

        if mapped_status not in task_manager_module.ARCHIVE_SUCCESS_MAPPED_STATUSES:
            return None, None
        job = self._queue_downstream_archive_job(
            db,
            task,
            item,
            payload=payload,
            mapped_status=mapped_status,
            before_status=before_status,
            extra_paths=extra_paths,
        )
        if job is None:
            return None, None
        db.commit()
        completed = await self._wait_archive_job_completion(job.id, task.id)
        try:
            db.refresh(item)
        except Exception:
            db.rollback()
        if completed is None or completed.archive_status != "success":
            error = completed.error_message if completed is not None else "归档任务不存在"
            self._record_event(
                db,
                task,
                "downstream_archive_blocking_failed",
                "总任务产物归档未完成，阶段结果不能用于后续推进",
                stage_name=item.stage_name,
                item=item,
                level="warning",
                payload={"archive_job_id": job.id, "error": error or "下游产物归档失败"},
            )
            db.commit()
            return None, completed
        return Path(completed.archive_root) if completed.archive_root else None, completed

    def _persist_downstream_sync_failure(self: TaskManager, db: Session, **kwargs):
        from app.service import task_manager as task_manager_module

        task = kwargs["task"]
        item = kwargs["item"]
        error = kwargs["error"]
        change_source = kwargs["change_source"]
        operation = kwargs["operation"]
        before_status = kwargs.get("before_status")
        error_type = self._classify_downstream_sync_error(error)
        observed_at = task_manager_module._now()
        http_status = self._extract_http_status_from_exception(error)
        is_http_429 = http_status == 429
        ownership_snapshot = self._parent_runtime_ownership_snapshot(db, task)
        error_message = str(error or "").strip() or repr(error).strip() or error.__class__.__name__
        error_detail = str(
            getattr(error, "error_type_detail", "") or getattr(error, "transport_error_kind", "")
        ).strip() or None
        runtime_lease_expires_at = getattr(ownership_snapshot, "runtime_lease_expires_at", None)
        failure_diagnostics = {
            "operation": operation,
            "stage_name": str(getattr(item, "stage_name", "") or "").strip() or None,
            "item_id": str(getattr(item, "id", "") or "").strip() or None,
            "item_key": str(getattr(item, "item_key", "") or "").strip() or None,
            "downstream_service": str(getattr(item, "downstream_service", "") or "").strip() or None,
            "downstream_task_id": str(getattr(item, "downstream_task_id", "") or "").strip() or None,
            "error_class": error.__class__.__name__,
            "error_message": error_message,
            "error_repr": repr(error),
            "error_type": error_type,
            "error_detail": error_detail,
            "http_status": http_status,
            "retryable_transport_error": bool(self._is_retryable_downstream_transport_error(error)),
            "runtime_phase": self._task_runtime_phase(task),
            "task_status": str(getattr(task, "status", "") or "").strip() or None,
            "current_stage": str(getattr(task, "current_stage", "") or "").strip() or None,
            "runtime_lease_active": bool(getattr(ownership_snapshot, "runtime_lease_active", False)),
            "runtime_lease_owner": getattr(ownership_snapshot, "runtime_lease_owner", None),
            "runtime_lease_expires_at": (
                runtime_lease_expires_at
                if isinstance(runtime_lease_expires_at, str)
                else task_manager_module._isoformat_or_none(runtime_lease_expires_at)
            ),
            "local_handle_alive": bool(getattr(ownership_snapshot, "local_handle_alive", False)),
        }
        state = (
            self._build_next_http_429_failure_state(item, observed_at=observed_at)
            if is_http_429
            else self._build_next_downstream_sync_failure_state(item, observed_at=observed_at)
        )
        sync_status = "rate_limited" if is_http_429 else "transport_error"
        persisted = self._persist_child_sync_observation(
            db,
            task=task,
            item=item,
            change_source=change_source,
            sync_status=sync_status,
            synced_at=observed_at,
            error_message=error_message,
            http_status=http_status,
            error_type=error_type,
            state_applied=False,
            extra_payload={
                **failure_diagnostics,
                **self._downstream_sync_failure_payload(
                    item,
                    error_type=error_type,
                    error_message=error_message,
                    state=state,
                ),
            },
            consecutive_error_count=state.consecutive_error_count,
            budget_exhausted=state.budget_exhausted,
            next_retry_at=state.next_retry_at,
            last_sync_result="error",
        )
        if not persisted:
            return False
        failure_payload = self._downstream_sync_failure_payload(
            item,
            error_type=error_type,
            error_message=error_message,
            state=state,
        )
        self._log_child_status_event(
            db,
            task=task,
            item=item,
            event_type="child_transport_failed",
            change_source=change_source,
            before_status=before_status or (str(item.status or "").strip().lower() or None),
            after_status=str(item.status or "").strip().lower() or before_status,
            sync_status=sync_status,
            downstream_status_raw=None,
            downstream_status_mapped=None,
            downstream_status=None,
            state_applied=False,
            error_message=error_message,
            error_type=error_type,
            http_status=http_status,
            extra_payload={
                **failure_diagnostics,
                **failure_payload,
            },
        )
        for event_type in (
            "downstream_http_429_retry_scheduled" if is_http_429 else "downstream_poll_retry_scheduled",
            (
                "downstream_http_429_retry_scheduled"
                if is_http_429
                else "downstream_sync_error_budget_exhausted" if state.budget_exhausted else "downstream_poll_retry_scheduled"
            ),
        ):
            self._log_child_status_event(
                db,
                task=task,
                item=item,
                event_type=event_type,
                change_source=change_source,
                before_status=before_status or (str(item.status or "").strip().lower() or None),
                after_status=str(item.status or "").strip().lower() or before_status,
                sync_status=sync_status,
                downstream_status_raw=None,
                downstream_status_mapped=None,
                downstream_status=None,
                state_applied=False,
                error_message=error_message,
                error_type=error_type,
                http_status=http_status,
                extra_payload={
                    **failure_diagnostics,
                    "retry_attempt_count": state.consecutive_error_count,
                    "retry_delay_seconds": (
                        self._next_http_429_retry_backoff_seconds(state.consecutive_error_count)
                        if is_http_429
                        else self._next_stage_sync_retry_backoff_seconds(state.consecutive_error_count)
                    ),
                    **failure_payload,
                },
            )
        return True

    def _run_archive_copy_job(self: TaskManager, job_id: str):
        from app.service import task_manager as task_manager_module

        session_factory = task_manager_module.get_session_factory()
        db = session_factory()
        try:
            job = db.query(task_manager_module.BinarySecurityArchiveJob).filter(
                task_manager_module.BinarySecurityArchiveJob.id == job_id
            ).first()
            if job is None or job.archive_status != "running":
                return None, "archive job is not running", False
            task = db.query(task_manager_module.BinarySecurityTask).filter(
                task_manager_module.BinarySecurityTask.id == job.task_id
            ).first()
            item = db.query(task_manager_module.BinarySecurityStageItem).filter(
                task_manager_module.BinarySecurityStageItem.id == job.item_id
            ).first()
            if task is None or item is None:
                job.archive_status = "failed"
                job.error_message = "任务或阶段子任务不存在"
                job.completed_at = task_manager_module._now()
                db.commit()
                return None, job.error_message, False
            if task.status == "cancelled":
                job.archive_status = "failed"
                job.error_message = "任务已取消，跳过归档复制"
                job.completed_at = task_manager_module._now()
                job.updated_at = task_manager_module._now()
                db.commit()
                return None, job.error_message, False
            payload = dict(job.payload or {})
            bound_downstream_task_id = self._archive_job_bound_downstream_task_id(job)
            archive_result = self._archive_downstream_output(
                db,
                task,
                item,
                semantic_key=item.item_key,
                bound_downstream_task_id=bound_downstream_task_id,
                payload=payload.get("downstream_payload") or {},
                extra_paths=payload.get("extra_paths") or None,
            )
            if archive_result.status == "source_not_ready":
                scheduled, retry_delay_seconds, next_retry_at = self._schedule_archive_job_missing_source_retry(
                    db,
                    task,
                    item,
                    job,
                    source_candidates=archive_result.source_candidates,
                )
                if scheduled:
                    db.commit()
                    return None, None, True
                exhausted_attempt = self._archive_job_retry_attempt(job)
                job.archive_status = "failed"
                job.error_message = "下游产物归档未完成"
                job.completed_at = task_manager_module._now()
                job.updated_at = task_manager_module._now()
                job.payload = {
                    **self._clear_archive_job_retry_metadata(job),
                    "archive_copy_stats": dict((item.output_ref or {}).get("archive_copy_stats") or {}),
                    "copy_retry_reason": task_manager_module.ARCHIVE_COPY_MISSING_SOURCE_RETRY_REASON,
                    "copy_retry_attempt": exhausted_attempt,
                    "copy_retry_schedule_seconds": self._archive_copy_missing_source_retry_schedule_seconds(),
                    "last_missing_source_observed_at": task_manager_module._now().isoformat(),
                    "last_source_candidate_count": len(archive_result.source_candidates),
                    "last_source_candidates_preview": list(
                        archive_result.source_candidates[:task_manager_module.DB_ARTIFACT_PREVIEW_LIMIT]
                    ),
                }
                self._record_event(
                    db,
                    task,
                    "downstream_archive_job_retry_exhausted",
                    "下游产物长时间未就绪，归档延迟重试已耗尽",
                    stage_name=job.stage_name,
                    item=item,
                    level="warning",
                    payload={
                        "archive_job_id": job.id,
                        "retry_attempt": exhausted_attempt,
                        "retry_delay_seconds": retry_delay_seconds,
                        "next_retry_at": next_retry_at.isoformat() if next_retry_at else None,
                        "source_candidate_count": len(archive_result.source_candidates),
                        "source_candidates_preview": list(
                            archive_result.source_candidates[:task_manager_module.DB_ARTIFACT_PREVIEW_LIMIT]
                        ),
                        "downstream_task_id": job.downstream_task_id,
                        "resolution_reason": "archive_source_retry_exhausted",
                    },
                )
                db.commit()
                return None, job.error_message, False
            archived_dir = archive_result.target_dir
            if not archived_dir:
                job.archive_status = "failed"
                job.error_message = "下游产物归档未完成"
                job.completed_at = task_manager_module._now()
                job.updated_at = task_manager_module._now()
                db.commit()
                return None, job.error_message, False
            copy_stats = dict((item.output_ref or {}).get("archive_copy_stats") or {})
            job.payload = {
                **self._clear_archive_job_retry_metadata(job),
                "bound_downstream_task_id": bound_downstream_task_id,
                "downstream_payload": payload.get("downstream_payload") or {},
                "extra_paths": payload.get("extra_paths") or None,
                "mapped_status": payload.get("mapped_status"),
                "archive_copy_stats": copy_stats,
            }
            task_manager_module.observe_archive_duration(
                action="copy",
                result="archived",
                duration_seconds=task_manager_module._elapsed_seconds_since(job.started_at),
            )
            job.archive_status = "archived"
            job.archive_root = str(archived_dir)
            job.error_message = None
            job.updated_at = task_manager_module._now()
            db.commit()
            return str(archived_dir), None, False
        except Exception as exc:
            db.rollback()
            try:
                job = db.query(task_manager_module.BinarySecurityArchiveJob).filter(
                    task_manager_module.BinarySecurityArchiveJob.id == job_id
                ).first()
                if job is not None:
                    job.archive_status = "failed"
                    job.error_message = str(exc)
                    job.completed_at = task_manager_module._now()
                    job.updated_at = task_manager_module._now()
                    task_manager_module.observe_archive_duration(
                        action="copy",
                        result="failed",
                        duration_seconds=task_manager_module._elapsed_seconds_since(job.started_at),
                    )
                    db.commit()
            except Exception:
                db.rollback()
            return None, str(exc), False
        finally:
            db.close()

    async def _apply_archive_job_status(self: TaskManager, job_id: str, archived_root: str | None) -> None:
        from app.service import task_manager as task_manager_module

        db = task_manager_module.get_session_factory()()
        try:
            await self._apply_archive_job_status_locked(
                db,
                job_id,
                archived_root,
                state_event_id=None,
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    async def _apply_archive_job_status_locked(
        self: TaskManager,
        db: Session,
        job_id: str,
        archived_root: str | None,
        *,
        state_event_id: str | None = None,
    ) -> None:
        from app.service import task_manager as task_manager_module

        job = db.query(task_manager_module.BinarySecurityArchiveJob).filter(
            task_manager_module.BinarySecurityArchiveJob.id == job_id
        ).first()
        if job is None or job.archive_status not in {"archived", "running", "applying", "success"}:
            return
        task = db.query(task_manager_module.BinarySecurityTask).filter(
            task_manager_module.BinarySecurityTask.id == job.task_id
        ).first()
        item = db.query(task_manager_module.BinarySecurityStageItem).filter(
            task_manager_module.BinarySecurityStageItem.id == job.item_id
        ).first()
        if task is None or item is None:
            return
        job_bound_downstream_task_id = self._archive_job_bound_downstream_task_id(job)
        current_downstream_task_id = self._current_downstream_task_id(item)
        if job_bound_downstream_task_id and current_downstream_task_id and job_bound_downstream_task_id != current_downstream_task_id:
            mismatch_payload = self._binding_mismatch_payload(
                source="archive_apply",
                expected_downstream_task_id=current_downstream_task_id,
                actual_downstream_task_id=job_bound_downstream_task_id,
                archive_job_id=job.id,
            )
            self._record_binding_mismatch_event(
                db,
                task,
                item,
                event_type="archive_job_superseded_late_result",
                message="旧 child 归档结果晚到，已忽略并废弃旧归档作业",
                payload=mismatch_payload,
            )
            job.archive_status = "superseded"
            job.error_message = None
            job.completed_at = task_manager_module._now()
            job.updated_at = task_manager_module._now()
            payload = dict(job.payload or {})
            payload["superseded"] = True
            payload["superseded_reason"] = "late_archive_apply_binding_mismatch"
            payload["superseded_downstream_task_id"] = job_bound_downstream_task_id or None
            job.payload = payload
            task_manager_module.observe_archive_action("apply", "superseded")
            task_manager_module.observe_archive_duration(
                action="apply",
                result="superseded",
                duration_seconds=task_manager_module._elapsed_seconds_since(job.started_at),
            )
            return
        if str(task.status or "").strip() in {task_manager_module.TASK_STATUS_CANCELLING, "cancelled"}:
            job.archive_status = "ignored"
            job.error_message = None
            job.completed_at = job.completed_at or task_manager_module._now()
            job.updated_at = task_manager_module._now()
            self._record_event(
                db,
                task,
                "downstream_archive_job_ignored",
                "归档完成事件到达时任务已进入取消链路，已忽略以避免恢复已取消阶段状态",
                level="warning",
                stage_name=item.stage_name,
                item=item,
                payload={
                    "archive_job_id": job.id,
                    "state_event_id": state_event_id,
                    "archive_root": archived_root or job.archive_root,
                    "task_status": task.status,
                    "archive_bound_downstream_task_id": job_bound_downstream_task_id or None,
                },
            )
            await self._write_task_metadata_async(
                task,
                Path(task.workspace_root) / "input" / "task-metadata.json",
                status=task.status,
            )
            return
        failure_ctx = self._current_stage_authoritative_failure_context(db, task)
        if (
            failure_ctx is not None
            and str(failure_ctx.get("failure_category") or "").strip() == "archive_blocked"
            and str(failure_ctx.get("stage_name") or "").strip() == str(item.stage_name or "").strip()
        ):
            job.archive_status = "ignored"
            job.error_message = None
            job.completed_at = job.completed_at or task_manager_module._now()
            job.updated_at = task_manager_module._now()
            self._record_event(
                db,
                task,
                "downstream_archive_apply_blocked_by_authoritative_failure",
                "归档结果到达时当前阶段已被归档失败阻断，已拒绝晚到回写推进",
                level="warning",
                stage_name=item.stage_name,
                item=item,
                payload={
                    "archive_job_id": job.id,
                    "state_event_id": state_event_id,
                    "archive_root": archived_root or job.archive_root,
                    "failure_code": self._string_or_none(failure_ctx.get("failure_code")),
                    "failure_message": self._string_or_none(failure_ctx.get("failure_message")),
                    "archive_bound_downstream_task_id": job_bound_downstream_task_id or None,
                },
            )
            await self._write_task_metadata_async(
                task,
                Path(task.workspace_root) / "input" / "task-metadata.json",
                status=task.status,
            )
            return
        try:
            payload = dict(job.payload or {})
            mapped_status = str(payload.get("mapped_status") or "").strip()
            downstream_payload = dict(payload.get("downstream_payload") or {})
            effective_archive_root = archived_root or job.archive_root
            archive_copy_stats = dict(payload.get("archive_copy_stats") or {})
            if not mapped_status:
                job.archive_status = "failed"
                job.error_message = "归档 job 缺少目标状态"
                job.completed_at = task_manager_module._now()
                return
            normalized_mapped_status = self._map_downstream_status(mapped_status) or mapped_status
            downstream_error_text = json.dumps(downstream_payload, ensure_ascii=False) if downstream_payload else ""
            if normalized_mapped_status == "failed" and any(
                marker in downstream_error_text.lower()
                for marker in ("task not found", "not found", "不存在", "downstream_missing")
            ):
                normalized_mapped_status = "downstream_missing"
            if str(item.status or "").strip().lower() == "downstream_missing" and normalized_mapped_status == "failed":
                normalized_mapped_status = "downstream_missing"
            self._apply_child_task_status_change(
                db,
                task=task,
                item=item,
                change_source="archive_apply",
                after_status=normalized_mapped_status,
                downstream_payload=downstream_payload,
                sync_status="synced",
                downstream_status_raw=self._string_or_none(downstream_payload.get("status")),
                downstream_status_mapped=normalized_mapped_status,
                downstream_status=self._string_or_none(downstream_payload.get("status")) or normalized_mapped_status,
                state_applied=True,
                error_message=(
                    downstream_payload.get("error")
                    or downstream_payload.get("error_message")
                    or downstream_payload.get("message")
                    or item.error_message
                ),
                archive_job_id=job.id,
                state_event_id=state_event_id,
                event_type="child_archive_status_changed",
                extra_payload={
                    "archive_root": effective_archive_root,
                    "downstream_payload": self._lightweight_downstream_payload(downstream_payload),
                },
            )
            self._merge_stage_item_output_ref(
                item,
                archive_root=effective_archive_root,
                **({"archive_copy_stats": archive_copy_stats} if archive_copy_stats else {}),
            )
            if item.stage_name == "firmware_unpack" and normalized_mapped_status == "success":
                self._refresh_firmware_unpack_item_result(
                    task,
                    item,
                    archived_dir=Path(effective_archive_root) if effective_archive_root else None,
                    bound_downstream_task_id=job_bound_downstream_task_id or None,
                    downstream_payload=downstream_payload,
                )
            if normalized_mapped_status in {"success", "partial_success"}:
                await self._refresh_terminal_item_result_from_downstream(
                    task,
                    item,
                    downstream_payload,
                    mapped_status=normalized_mapped_status,
                    archived_dir=Path(effective_archive_root) if effective_archive_root else None,
                )
            stage_run, _snapshot = self._reconcile_item_layer_facts_in_session(
                db,
                task,
                stage_name=item.stage_name,
            )
            if str(task.status or "").strip() not in task_manager_module.TASK_TERMINAL_STATUSES:
                self._request_task_layer_reconcile(
                    db,
                    task,
                    stage_name=item.stage_name,
                    source_event_type="archive_job_copied",
                    state_event_id=state_event_id,
                    reconcile_reason="archive_apply",
                    message="归档事实已更新，等待 owner worker 串行收口任务层决策",
                    event_payload={
                        "item_id": item.id,
                        "archive_job_id": job.id,
                        "downstream_task_id": item.downstream_task_id,
                        "stage_status": str(getattr(stage_run, "status", "") or "").strip() or None,
                    },
                )
            if effective_archive_root:
                job.archive_root = effective_archive_root
            job.archive_status = "success"
            job.error_message = None
            job.completed_at = task_manager_module._now()
            job.updated_at = task_manager_module._now()
            self._record_event(
                db,
                task,
                "downstream_archive_job_completed",
                "下游产物归档完成，状态已同步",
                stage_name=item.stage_name,
                item=item,
                payload={
                    "archive_job_id": job.id,
                    "archive_root": effective_archive_root,
                    "mapped_status": mapped_status,
                    "downstream_service": item.downstream_service,
                    "downstream_task_id": item.downstream_task_id,
                    "archive_bound_downstream_task_id": job_bound_downstream_task_id or None,
                },
            )
            await self._write_task_metadata_async(
                task,
                Path(task.workspace_root) / "input" / "task-metadata.json",
                status=task.status,
            )
            task_manager_module.observe_archive_action("apply", "success")
            task_manager_module.observe_archive_duration(
                action="apply",
                result="success",
                duration_seconds=task_manager_module._elapsed_seconds_since(job.started_at),
            )
        except Exception as exc:
            if job is not None:
                job.archive_status = "failed"
                job.error_message = str(exc)
                job.completed_at = task_manager_module._now()
                job.updated_at = task_manager_module._now()
            task_manager_module.observe_archive_action("apply", "failed")
            task_manager_module.observe_archive_duration(
                action="apply",
                result="failed",
                duration_seconds=task_manager_module._elapsed_seconds_since(job.started_at) if job is not None else None,
            )
            raise
