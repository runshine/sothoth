from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, or_
from sqlalchemy.orm import Session, load_only

from app.exception import NotFoundError
from app.model import (
    PIPELINE_PROFILE_DEFAULT,
    PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN,
    TASK_TYPE_SOURCE,
    BinarySecurityArchiveJob,
    BinarySecurityEvent,
    BinarySecurityStageRun,
    BinarySecuritySyncEvent,
    BinarySecurityStageItem,
    BinarySecurityTask,
    normalize_stage_name,
)
from app.observability import observe_task_list_query, observe_task_list_query_stage
from app.service.project import get_project_service
from app.schemas import (
    BinarySecurityActionResponse,
    BinarySecurityArchiveJobPageResponse,
    BinarySecurityArtifactsResponse,
    BinarySecurityDeleteQueueItem,
    BinarySecurityDeleteQueueResponse,
    BinarySecurityOverviewResponse,
    BinarySecurityProjectStats,
    BinarySecurityStageItemSummaryResponse,
    BinarySecurityStageItemDetailResponse,
    BinarySecurityStageSummary,
    BinarySecurityStageItemPageResponse,
    BinarySecurityTaskDetailResponse,
    BinarySecurityTaskEventResponse,
    BinarySecurityTaskListResponse,
    BinarySecurityTaskResponse,
    BinarySecurityTaskOperationPageResponse,
    BinarySecuritySyncEventPageResponse,
    BinarySecuritySyncEventResponse,
    BinarySecurityTimelineResponse,
)
from . import shared as task_shared

from . import read_model

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


logger = logging.getLogger(__name__)


class TaskQueryServiceMixin:
    def _stage_item_summary_response(
        self: TaskManager,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        archive_jobs: list[BinarySecurityArchiveJob] | None = None,
    ) -> BinarySecurityStageItemSummaryResponse:
        detail = self._stage_item_response(task, item, archive_jobs=archive_jobs)
        payload = detail.model_dump(exclude={"input_ref", "output_ref", "result"})
        return BinarySecurityStageItemSummaryResponse(**payload)

    def _task_summary_for_lite_detail_response(self: TaskManager, task) -> dict[str, Any]:
        summary_payload = dict(self._task_summary_for_detail_response(task) or {})
        heavy_keys = {
            "entry_results",
            "dataflow_results",
            "vuln_results",
            "input_files",
            "candidate_modules",
            "selected_modules",
            "system_analysis_modules",
            "b2s_results",
        }
        for key in heavy_keys:
            summary_payload.pop(key, None)
        entry_selection = summary_payload.get("entry_selection")
        if isinstance(entry_selection, dict):
            trimmed_entry_selection = dict(entry_selection)
            trimmed_entry_selection.pop("selected_entries", None)
            trimmed_entry_selection.pop("candidate_entries", None)
            summary_payload["entry_selection"] = trimmed_entry_selection
        return summary_payload

    def _task_list_latest_stage_runs_by_task(
        self: TaskManager,
        db: Session,
        tasks: list[BinarySecurityTask],
    ) -> dict[str, dict[str, BinarySecurityStageRun]]:
        task_ids = [
            str(getattr(task, "id", "") or "").strip()
            for task in tasks
            if str(getattr(task, "id", "") or "").strip()
        ]
        if not task_ids:
            return {}
        stage_runs = (
            db.query(BinarySecurityStageRun)
            .filter(BinarySecurityStageRun.task_id.in_(task_ids))
            .options(
                load_only(
                    BinarySecurityStageRun.id,
                    BinarySecurityStageRun.task_id,
                    BinarySecurityStageRun.stage_name,
                    BinarySecurityStageRun.sequence_no,
                    BinarySecurityStageRun.status,
                    BinarySecurityStageRun.retry_count,
                    BinarySecurityStageRun.started_at,
                    BinarySecurityStageRun.finished_at,
                    BinarySecurityStageRun.last_error,
                    BinarySecurityStageRun.created_at,
                )
            )
            .order_by(
                BinarySecurityStageRun.task_id.asc(),
                BinarySecurityStageRun.stage_name.asc(),
                BinarySecurityStageRun.sequence_no.desc(),
                BinarySecurityStageRun.created_at.desc(),
                BinarySecurityStageRun.id.desc(),
            )
            .all()
        )
        latest_by_task: dict[str, dict[str, BinarySecurityStageRun]] = {}
        for run in stage_runs:
            task_id = str(getattr(run, "task_id", "") or "").strip()
            stage_name = normalize_stage_name(getattr(run, "stage_name", None))
            if not task_id or not stage_name:
                continue
            task_bucket = latest_by_task.setdefault(task_id, {})
            current = task_bucket.get(stage_name)
            if current is None:
                task_bucket[stage_name] = run
                continue
            current_key = (
                int(getattr(current, "sequence_no", 0) or 0),
                str(getattr(current, "created_at", None) or ""),
                str(getattr(current, "id", "") or ""),
            )
            candidate_key = (
                int(getattr(run, "sequence_no", 0) or 0),
                str(getattr(run, "created_at", None) or ""),
                str(getattr(run, "id", "") or ""),
            )
            if candidate_key > current_key:
                task_bucket[stage_name] = run
        return latest_by_task

    def _build_task_list_light_stage_summaries(
        self: TaskManager,
        task: BinarySecurityTask,
        latest_stage_runs: dict[str, BinarySecurityStageRun] | None = None,
    ) -> list[BinarySecurityStageSummary]:
        latest_stage_runs = latest_stage_runs or {}
        snapshot = task.stage_summary if isinstance(task.stage_summary, dict) else {}
        stage_sequence = self._stage_sequence_for_task(task)
        summaries: list[BinarySecurityStageSummary] = []
        for index, stage_name in enumerate(stage_sequence, start=1):
            payload = snapshot.get(stage_name) if isinstance(snapshot.get(stage_name), dict) else {}
            latest_run = latest_stage_runs.get(stage_name)
            status_value = (
                str(getattr(latest_run, "status", "") or "").strip()
                or str(payload.get("status") or "").strip()
                or ("pending" if stage_name != task.current_stage else str(task.status or "pending"))
            )
            summaries.append(
                BinarySecurityStageSummary(
                    stage_name=stage_name,
                    sequence_no=int(getattr(latest_run, "sequence_no", 0) or payload.get("sequence_no") or index),
                    status=status_value,
                    retry_count=int(getattr(latest_run, "retry_count", 0) or payload.get("retry_count") or 0),
                    retry_supported=False,
                    retry_reason=None,
                    retry_failed_supported=False,
                    retry_failed_reason=None,
                    retry_full_supported=False,
                    retry_full_reason=None,
                    total_items=0,
                    success_items=0,
                    failed_items=0,
                    orchestration_failed_items=0,
                    downstream_missing_items=0,
                    skipped_items=0,
                    running_items=0,
                    cancelled_items=0,
                    downstream_status_counts={},
                    started_at=getattr(latest_run, "started_at", None) or payload.get("started_at"),
                    finished_at=getattr(latest_run, "finished_at", None) or payload.get("finished_at"),
                    last_error=(
                        getattr(latest_run, "last_error", None)
                        if latest_run is not None and getattr(latest_run, "last_error", None) is not None
                        else payload.get("last_error")
                    ),
                )
            )
        return summaries

    def _build_task_list_light_manual_operation_state(
        self: TaskManager,
        task: BinarySecurityTask,
        *,
        stage_summaries: list[BinarySecurityStageSummary],
    ) -> dict[str, Any]:
        task_status = str(getattr(task, "status", "") or "").strip().lower()
        running = task_status in {"pending", "dispatching", "running"}
        has_failed_stage = any(
            str(getattr(summary, "status", "") or "").strip().lower()
            in {"failed", "downstream_missing", "cancelled", "partial_success"}
            for summary in stage_summaries
        )
        if running:
            overall = "blocked"
            summary_text = "当前任务正在运行，详细手工操作能力请进入详情页查看"
            blocking_code = "task_running"
            blocking_reason = "当前任务正在运行，列表页不做实时操作态推导"
        elif has_failed_stage:
            overall = "ready"
            summary_text = "当前任务存在异常阶段，可进入详情页执行继续或重试"
            blocking_code = None
            blocking_reason = None
        else:
            overall = "ready"
            summary_text = "可进入详情页查看详细操作"
            blocking_code = None
            blocking_reason = None
        return {
            "overall": overall,
            "summary": summary_text,
            "blocking_code": blocking_code,
            "blocking_reason": blocking_reason,
            "operation_in_progress": False,
            "operation_type": None,
            "operation_status": None,
            "operation_owner": None,
            "operation_started_at": None,
            "operation_heartbeat_at": None,
            "operation_expires_at": None,
            "current_step": None,
            "target_stage": None,
            "error_code": None,
            "error_message": None,
            "cleanup_partial_failed": False,
            "downstream_cleanup_result_count": 0,
            "downstream_cleanup_blocking_count": 0,
            "downstream_cleanup_blocking_refs": [],
            "downstream_cleanup_deferred_count": 0,
            "downstream_cleanup_deferred_refs": [],
            "downstream_cleanup_warning_summary": None,
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
            "can_confirm_modules": False,
        }

    def _build_task_list_light_response(
        self: TaskManager,
        task: BinarySecurityTask,
        *,
        latest_stage_runs: dict[str, BinarySecurityStageRun] | None = None,
    ) -> BinarySecurityTaskResponse:
        from app.service import task_manager as task_manager_module

        metrics = task.metrics or {}
        abnormal_reason = None
        if isinstance(task.latest_abnormal_reason, dict):
            try:
                abnormal_reason = task_manager_module.BinarySecurityAbnormalReason(**task.latest_abnormal_reason)
            except Exception:
                abnormal_reason = None
        stage_sequence = self._stage_sequence_for_task(task)
        stage_summaries = self._build_task_list_light_stage_summaries(
            task,
            latest_stage_runs=latest_stage_runs,
        )
        manual_operation_state = self._build_task_list_light_manual_operation_state(
            task,
            stage_summaries=stage_summaries,
        )
        delete_state = self._task_delete_queue_state(task)
        task_status = str(getattr(task, "status", "") or "").strip().lower()
        queue_state = "dispatching" if task_status in {"pending", "dispatching"} else "idle"
        return BinarySecurityTaskResponse(
            id=task.id,
            project_id=task.project_id,
            task_type=self._task_type(task),
            pipeline_profile=self._pipeline_profile(task),
            name=task.name,
            schedule_user_task_id=str(getattr(task, "schedule_user_task_id", "") or "").strip() or None,
            status=task.status,
            runtime_phase=self._task_runtime_phase(task),
            tail_reconcile_state="idle",
            task_control_mode=self._task_control_mode(task),
            current_operation_id=task.current_operation_id,
            delete_queued=bool(delete_state.get("delete_queued")),
            delete_in_progress=bool(delete_state.get("delete_in_progress")),
            delete_mode=self._string_or_none(delete_state.get("delete_mode")),
            delete_operation_id=self._string_or_none(delete_state.get("delete_operation_id")),
            delete_requested_at=self._string_or_none(delete_state.get("delete_requested_at")),
            delete_last_error=self._string_or_none(delete_state.get("delete_last_error")),
            execution_epoch=int(getattr(task, "execution_epoch", 0) or 0),
            current_stage=task.current_stage,
            workflow_terminalization_ready=False,
            workflow_blocked_by_stage=None,
            last_error=task.last_error,
            terminal_failure=False,
            requeue_suppressed=False,
            failure_code=None,
            failure_category=None,
            failure_message=None,
            firmware_path=task.firmware_path,
            stage_sequence=stage_sequence,
            is_queued=task_status == "pending",
            queue_position=None,
            queue_state=queue_state,
            recoverable_reason=None,
            last_reconcile_at=None,
            dispatcher_instance_id=None,
            task_lease_owner_instance_id=None,
            task_lease_expires_at=None,
            task_lease_source=None,
            row_mirror_drift=False,
            tail_control_mode="idle",
            tail_has_runnable_unbound_items=False,
            tail_unbound_runnable_item_count=0,
            tail_bound_active_item_count=0,
            tail_has_downstream_refs=False,
            tail_takeover_required=False,
            tail_takeover_reason=None,
            runtime_override_version=0,
            runtime_override_updated_at=None,
            runtime_override_updated_by=None,
            runtime_policy_effect_scope={},
            base_policy={},
            runtime_override={},
            effective_runtime_policy={},
            last_successful_downstream_sync_at=None,
            last_sync_attempt_at=None,
            last_sync_error_at=None,
            last_sync_error_type=None,
            last_sync_error_message=None,
            active_sync_error_item_count=0,
            never_synced_item_count=0,
            stale_synced_item_count=0,
            created_by=task.created_by,
            created_at=task.created_at,
            updated_at=task.updated_at,
            started_at=task.started_at,
            finished_at=task.finished_at,
            high_risk_module_count=int(metrics.get("high_risk_module_count", 0) or 0),
            medium_risk_module_count=int(metrics.get("medium_risk_module_count", 0) or 0),
            low_risk_module_count=int(metrics.get("low_risk_module_count", 0) or 0),
            candidate_module_count=int(metrics.get("candidate_module_count", 0) or 0),
            selected_module_count=int(metrics.get("selected_module_count", 0) or 0),
            selected_risk_levels=[],
            module_selection_mode="auto",
            entry_selection_mode="auto",
            entry_auto_selection_strategy="all",
            entry_auto_selection_top_n=int(metrics.get("entry_auto_selection_top_n", 0) or 0),
            candidate_entry_count=int(metrics.get("candidate_entry_count", 0) or 0),
            selected_entry_count=int(metrics.get("selected_entry_count", 0) or 0),
            entry_count=int(metrics.get("entry_count", 0) or 0),
            knowledge_graph_raw_entry_count=int(metrics.get("knowledge_graph_raw_entry_count", 0) or 0),
            knowledge_graph_selected_entry_count=int(metrics.get("knowledge_graph_selected_entry_count", 0) or 0),
            knowledge_graph_filtered_out_count=int(metrics.get("knowledge_graph_filtered_out_count", 0) or 0),
            knowledge_graph_graph_status=None,
            knowledge_graph_identification_state=None,
            knowledge_graph_attack_status=None,
            knowledge_graph_analysis_total=int(metrics.get("knowledge_graph_analysis_total", 0) or 0),
            knowledge_graph_analysis_identified=int(metrics.get("knowledge_graph_analysis_identified", 0) or 0),
            knowledge_graph_analysis_pending=int(metrics.get("knowledge_graph_analysis_pending", 0) or 0),
            knowledge_graph_analysis_confirmed=int(metrics.get("knowledge_graph_analysis_confirmed", 0) or 0),
            knowledge_graph_analysis_rejected=int(metrics.get("knowledge_graph_analysis_rejected", 0) or 0),
            vuln_result_count=int(metrics.get("vuln_result_count", 0) or 0),
            firmware_item_count=int(metrics.get("firmware_item_count", 0) or 0),
            unpacked_firmware_count=int(metrics.get("unpacked_firmware_count", 0) or 0),
            failed_firmware_count=int(metrics.get("failed_firmware_count", 0) or 0),
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
            cancel_state={},
            cleanup_state={
                "status": None,
                "partial_failed": False,
                "deferred_ref_count": 0,
                "blocking_ref_count": 0,
                "last_error": None,
                "last_attempt_at": None,
                "next_retry_at": None,
            },
        )

    def _task_list_project_names(
        self: TaskManager,
        db: Session,
        tasks: list[BinarySecurityTask],
        *,
        token: str | None = None,
    ) -> dict[str, str | None]:
        del db
        project_ids = {
            str(getattr(task, "project_id", "") or "").strip()
            for task in (tasks or [])
            if str(getattr(task, "project_id", "") or "").strip()
        }
        if not project_ids:
            return {}
        project_names: dict[str, str | None] = {project_id: None for project_id in project_ids}
        if not token:
            return project_names
        project_service = get_project_service()
        for project_id in sorted(project_ids):
            try:
                payload = project_service.get_project(token, project_id)
            except Exception as exc:
                logger.warning(
                    "binary-security delete queue project name lookup failed: project_id=%s error_type=%s error=%s",
                    project_id,
                    type(exc).__name__,
                    exc,
                )
                continue
            project_name = str(
                payload.get("name")
                or payload.get("project_name")
                or payload.get("display_name")
                or ""
            ).strip() or None
            project_names[project_id] = project_name
        return project_names

    def list_delete_queue(
        self: TaskManager,
        db: Session,
        *,
        token: str | None = None,
        project_id: str | None = None,
        task_type: str | None = None,
        delete_status: str | None = None,
        search: str | None = None,
        sort_by: str = "delete_requested_at",
        sort_direction: str = "desc",
        page: int = 1,
        page_size: int = 20,
    ) -> BinarySecurityDeleteQueueResponse:
        normalized_project_id = str(project_id or "").strip() or None
        normalized_task_type = str(task_type or "").strip()
        normalized_delete_status = str(delete_status or "").strip().lower()
        normalized_search = str(search or "").strip()
        base_query = db.query(BinarySecurityTask).filter(
            or_(
                BinarySecurityTask.cleanup_snapshot_json.like('%"delete_queued": true%'),
                BinarySecurityTask.cleanup_snapshot_json.like('%"delete_in_progress": true%'),
                BinarySecurityTask.status.in_(["delete_failed", "force_delete_failed"]),
            )
        )
        if normalized_project_id:
            base_query = base_query.filter(BinarySecurityTask.project_id == normalized_project_id)
        if normalized_search:
            base_query = base_query.filter(
                or_(
                    BinarySecurityTask.id.like(f"%{normalized_search}%"),
                    BinarySecurityTask.name.like(f"%{normalized_search}%"),
                    BinarySecurityTask.project_id.like(f"%{normalized_search}%"),
                )
            )

        tasks = base_query.options(
            load_only(
                BinarySecurityTask.id,
                BinarySecurityTask.project_id,
                BinarySecurityTask.task_type,
                BinarySecurityTask.name,
                BinarySecurityTask.status,
                BinarySecurityTask.policy_json,
                BinarySecurityTask.cleanup_snapshot_json,
                BinarySecurityTask.current_operation_id,
                BinarySecurityTask.last_error,
                BinarySecurityTask.updated_at,
                BinarySecurityTask.started_at,
                BinarySecurityTask.finished_at,
            )
        ).all()
        project_names = self._task_list_project_names(db, tasks, token=token)

        def parse_datetime(value: Any):
            text = str(value or "").strip()
            if not text:
                return None
            try:
                return task_shared.parse_datetime(text)
            except Exception:
                return None

        def map_queue_task_type(task: BinarySecurityTask) -> str:
            task_kind = str(task.task_type or "binary").strip().lower() or "binary"
            if task_kind == "source":
                try:
                    policy = json.loads(str(task.policy_json or "").strip() or "{}")
                except Exception:
                    policy = {}
                if str(policy.get("pipeline_profile") or "").strip() == PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN:
                    return "kg_source_vuln_scan_e2e"
                return "source_scan_e2e"
            if task_kind == "binary_module":
                return "binary_module_e2e"
            return "binary_firmware_e2e"

        rows: list[BinarySecurityDeleteQueueItem] = []
        stats = {"queued_total": 0, "running_total": 0, "blocked_total": 0, "failed_total": 0}
        for task in tasks:
            delete_state = self._task_delete_queue_state(task)
            task_status = str(task.status or "").strip().lower()
            delete_error = str(delete_state.get("delete_last_error") or task.last_error or "").strip() or None
            mapped_task_type = map_queue_task_type(task)
            if normalized_task_type and normalized_task_type != mapped_task_type:
                continue
            if delete_state.get("delete_in_progress"):
                mapped_delete_status = "running"
            elif task_status in {"delete_failed", "force_delete_failed"} or delete_error:
                mapped_delete_status = "failed"
            elif delete_state.get("delete_queued"):
                mapped_delete_status = "queued"
            else:
                continue
            if normalized_delete_status and normalized_delete_status != mapped_delete_status:
                continue
            stats_key = f"{mapped_delete_status}_total"
            if stats_key in stats:
                stats[stats_key] += 1
            rows.append(
                BinarySecurityDeleteQueueItem(
                    id=str(task.id),
                    project_id=str(task.project_id),
                    project_name=project_names.get(str(task.project_id)),
                    name=str(task.name or task.id),
                    task_type=mapped_task_type,
                    task_status=str(task.status or ""),
                    display_status=str(task.status or ""),
                    delete_status=mapped_delete_status,
                    delete_mode=str(delete_state.get("delete_mode") or "").strip() or None,
                    delete_error=delete_error,
                    last_error=str(task.last_error or "").strip() or None,
                    delete_operation_id=str(delete_state.get("delete_operation_id") or task.current_operation_id or "").strip() or None,
                    delete_requested_at=parse_datetime(delete_state.get("delete_requested_at")),
                    delete_started_at=parse_datetime(delete_state.get("delete_started_at")),
                    delete_finished_at=parse_datetime(delete_state.get("delete_finished_at")),
                    updated_at=task.updated_at,
                )
            )

        sort_key = str(sort_by or "").strip().lower()
        reverse = str(sort_direction or "").strip().lower() != "asc"
        sort_getters = {
            "delete_requested_at": lambda item: item.delete_requested_at or item.updated_at,
            "updated_at": lambda item: item.updated_at,
            "name": lambda item: item.name.lower(),
        }
        rows.sort(
            key=lambda item: (sort_getters.get(sort_key, sort_getters["delete_requested_at"])(item) or ""),
            reverse=reverse,
        )
        total = len(rows)
        offset = max(0, (page - 1) * page_size)
        return BinarySecurityDeleteQueueResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=rows[offset: offset + page_size],
            stats=stats,
        )

    def list_tasks(
        self: TaskManager,
        db: Session,
        *,
        project_id: str | None,
        status: str | None = None,
        task_type: str | None = None,
        pipeline_profile: str | None = None,
        search: str | None = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        page: int = 1,
        page_size: int = 50,
    ) -> BinarySecurityTaskListResponse:
        started = time.perf_counter()
        normalized_project_id = str(project_id or "").strip() or None
        normalized_task_type = self._validate_task_type(task_type) if task_type else None
        normalized_pipeline_profile = (
            self._validate_pipeline_profile(normalized_task_type or TASK_TYPE_SOURCE, pipeline_profile)
            if pipeline_profile
            else None
        )
        metrics_task_type = normalized_task_type or "all"
        result = "success"
        stage_durations: dict[str, float] = {}
        try:
            stage_started = time.perf_counter()
            base_query = db.query(BinarySecurityTask)
            if normalized_project_id:
                base_query = base_query.filter(BinarySecurityTask.project_id == normalized_project_id)
            if normalized_task_type:
                if normalized_task_type == "binary":
                    base_query = base_query.filter(
                        or_(
                            BinarySecurityTask.task_type == normalized_task_type,
                            BinarySecurityTask.task_type.is_(None),
                        )
                    )
                else:
                    base_query = base_query.filter(BinarySecurityTask.task_type == normalized_task_type)
            if normalized_pipeline_profile and normalized_task_type == TASK_TYPE_SOURCE:
                base_query = self._apply_pipeline_profile_filter(base_query, normalized_pipeline_profile)
            base_query = base_query.filter(
                or_(
                    BinarySecurityTask.cleanup_snapshot_json.is_(None),
                    ~BinarySecurityTask.cleanup_snapshot_json.like('%"delete_queued": true%'),
                )
            ).filter(
                or_(
                    BinarySecurityTask.cleanup_snapshot_json.is_(None),
                    ~BinarySecurityTask.cleanup_snapshot_json.like('%"delete_in_progress": true%'),
                )
            )
            observe_task_list_query_stage(
                stage="build_base_query",
                task_type=metrics_task_type,
                duration_seconds=time.perf_counter() - stage_started,
            )
            stage_durations["build_base_query"] = time.perf_counter() - stage_started

            query = base_query
            if status:
                query = query.filter(BinarySecurityTask.status == status)
            normalized_search = str(search or "").strip()
            if normalized_search:
                query = query.filter(
                    or_(
                        BinarySecurityTask.id.like(f"%{normalized_search}%"),
                        BinarySecurityTask.name.like(f"%{normalized_search}%"),
                        BinarySecurityTask.firmware_path.like(f"%{normalized_search}%"),
                    )
                )

            offset = max(0, (page - 1) * page_size)
            sort_field_map = {
                "created_at": BinarySecurityTask.created_at,
                "updated_at": BinarySecurityTask.updated_at,
                "started_at": BinarySecurityTask.started_at,
                "finished_at": BinarySecurityTask.finished_at,
                "status": BinarySecurityTask.status,
                "name": BinarySecurityTask.name,
                "task_name": BinarySecurityTask.name,
            }
            sort_column = sort_field_map.get(str(sort_by or "").strip(), BinarySecurityTask.created_at)
            order_expr = sort_column.asc() if str(sort_order or "").lower() == "asc" else sort_column.desc()
            stage_started = time.perf_counter()
            page_rows = query.add_columns(func.count(BinarySecurityTask.id).over().label("_total_count")).options(
                load_only(
                    BinarySecurityTask.id,
                    BinarySecurityTask.project_id,
                    BinarySecurityTask.task_type,
                    BinarySecurityTask.name,
                    BinarySecurityTask.status,
                    BinarySecurityTask.current_stage,
                    BinarySecurityTask.firmware_path,
                    BinarySecurityTask.policy_json,
                    BinarySecurityTask.metrics_json,
                    BinarySecurityTask.stage_summary_json,
                    BinarySecurityTask.dispatcher_instance_id,
                    BinarySecurityTask.created_by,
                    BinarySecurityTask.created_at,
                    BinarySecurityTask.updated_at,
                    BinarySecurityTask.started_at,
                    BinarySecurityTask.finished_at,
                    BinarySecurityTask.execution_mode,
                    BinarySecurityTask.target_stage_name,
                    BinarySecurityTask.latest_abnormal_reason_json,
                    BinarySecurityTask.last_error,
                    BinarySecurityTask.current_operation_id,
                    BinarySecurityTask.cleanup_snapshot_json,
                    BinarySecurityTask.runtime_phase,
                    BinarySecurityTask.execution_epoch,
                    BinarySecurityTask.schedule_user_task_id,
                )
            ).order_by(order_expr, BinarySecurityTask.id.desc()).offset(offset).limit(page_size).all()
            tasks = [row[0] for row in page_rows]
            total = int(page_rows[0][1] or 0) if page_rows else 0
            observe_task_list_query_stage(
                stage="page_items",
                task_type=metrics_task_type,
                duration_seconds=time.perf_counter() - stage_started,
            )
            stage_durations["page_items"] = time.perf_counter() - stage_started

            stage_started = time.perf_counter()
            latest_stage_runs_by_task = self._task_list_latest_stage_runs_by_task(db, tasks)
            observe_task_list_query_stage(
                stage="stage_summaries",
                task_type=metrics_task_type,
                duration_seconds=time.perf_counter() - stage_started,
            )
            stage_durations["stage_summaries"] = time.perf_counter() - stage_started

            stage_started = time.perf_counter()
            items = [
                self._build_task_list_light_response(
                    task,
                    latest_stage_runs=latest_stage_runs_by_task.get(str(task.id), {}),
                )
                for task in tasks
            ]
            observe_task_list_query_stage(
                stage="light_serialize",
                task_type=metrics_task_type,
                duration_seconds=time.perf_counter() - stage_started,
            )
            stage_durations["light_serialize"] = time.perf_counter() - stage_started
            self._log_task_list_query(
                project_id=project_id,
                task_type=metrics_task_type,
                page=page,
                page_size=page_size,
                total=total,
                item_count=len(tasks),
                duration_seconds=time.perf_counter() - started,
                stage_durations=stage_durations,
            )
            return BinarySecurityTaskListResponse(
                total=total,
                page=page,
                page_size=page_size,
                total_pages=max(1, (total + page_size - 1) // page_size),
                scope="current" if normalized_project_id else "all",
                running_count=0,
                queued_count=0,
                max_concurrent_tasks=0,
                project_stats=BinarySecurityProjectStats(total=0),
                project_stage_aggregates=[],
                queue_runtime={"last_reconcile_at": None},
                items=items,
            )
        except Exception:
            result = "error"
            raise
        finally:
            total_duration = time.perf_counter() - started
            if result != "success":
                self._log_task_list_query(
                project_id=normalized_project_id or "__all__",
                task_type=metrics_task_type,
                    page=page,
                    page_size=page_size,
                    total=None,
                    item_count=None,
                    duration_seconds=total_duration,
                    stage_durations=stage_durations,
                    result=result,
                )
            observe_task_list_query(
                result=result,
                task_type=metrics_task_type,
                duration_seconds=total_duration,
            )

    def _apply_pipeline_profile_filter(self: TaskManager, query, pipeline_profile: str):
        compact_like = f'%"pipeline_profile":"{pipeline_profile}"%'
        spaced_like = f'%"pipeline_profile": "{pipeline_profile}"%'
        if pipeline_profile == PIPELINE_PROFILE_DEFAULT:
            return query.filter(
                or_(
                    BinarySecurityTask.policy_json.is_(None),
                    BinarySecurityTask.policy_json == "",
                    ~BinarySecurityTask.policy_json.like('%"pipeline_profile"%'),
                    BinarySecurityTask.policy_json.like(compact_like),
                    BinarySecurityTask.policy_json.like(spaced_like),
                )
            )
        if pipeline_profile == PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN:
            return query.filter(
                or_(
                    BinarySecurityTask.policy_json.like(compact_like),
                    BinarySecurityTask.policy_json.like(spaced_like),
                )
            )
        return query

    def get_task_detail(self: TaskManager, db: Session, *, project_id: str, task_id: str) -> BinarySecurityTaskDetailResponse:
        def _build() -> BinarySecurityTaskDetailResponse:
            ctx = self._build_light_task_detail_context(db, project_id=project_id, task_id=task_id)
            base = self._task_response(
                db,
                ctx.task,
                queue_info=ctx.queue_info,
                detail_ctx=ctx,
                projection_only=True,
            ).model_dump()
            base.pop("execution_epoch", None)
            response = BinarySecurityTaskDetailResponse(
                **base,
                execution_epoch=int(getattr(ctx.task, "execution_epoch", 0) or 0),
                description=ctx.task.description,
                output_root=ctx.task.output_root,
                workspace_root=ctx.task.workspace_root,
                fileserver_subproject_name=ctx.task.fileserver_subproject_name,
                task_key_source=str(getattr(ctx.task, "task_key_source", "") or "").strip() or None,
                root_task_key_id=str(getattr(ctx.task, "root_task_key_id", "") or "").strip() or None,
                root_task_key_name=str(getattr(ctx.task, "root_task_key_name", "") or "").strip() or None,
                root_task_key_prefix=str(getattr(ctx.task, "root_task_key_prefix", "") or "").strip() or None,
                has_root_task_key=bool(self._root_task_key_secret(ctx.task)),
                task_key_snapshot=self._build_task_key_snapshot(db, ctx.task),
                policy=self._effective_runtime_policy(ctx.task),
                policy_snapshot=self._build_task_policy_snapshot(
                    ctx.task,
                    stage_sequence=ctx.stage_sequence,
                ),
                summary=self._task_summary_for_lite_detail_response(ctx.task),
                metrics=ctx.task.metrics,
                item_stats=ctx.item_stats,
                stage_items_total=ctx.stage_items_total,
                stage_items_truncated=ctx.stage_items_total > 0,
                stage_items=[],
                archive_jobs=[],
                abnormal_reason_history=[],
                overview_nodes=[],
                orchestration_observability={},
                cleanup_snapshot=dict(ctx.task.cleanup_snapshot or {}),
                runtime_health=self._build_task_runtime_health(db, ctx.task, ctx=ctx),
            )
            self._log_task_read_projection_built(
                projection_kind="task_detail_read_projection_built",
                task=ctx.task,
                stage_items_count=ctx.stage_items_total,
                active_stage_name=self._active_reconcile_stage_name(ctx.task),
                used_cached_projection=False,
            )
            return response

        response, used_cached = self._load_readonly_projection_cached_value(
            cache_group="task_detail",
            project_id=project_id,
            task_id=task_id,
            ttl_seconds=self._readonly_projection_cache_ttl_seconds(),
            loader=_build,
        )
        if used_cached:
            self._log_task_read_projection_built(
                projection_kind="task_detail_read_projection_built",
                task=response,
                stage_items_count=len(getattr(response, "stage_items", []) or []),
                active_stage_name=getattr(response, "current_stage", None),
                used_cached_projection=True,
            )
        return response

    def get_task_stage_items_page(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        stage_name: str,
        status: str | None = None,
        downstream_status: str | None = None,
        sync_status: str | None = None,
        sort_by: str | None = None,
        sort_direction: str = "desc",
        page: int = 1,
        per_page: int = 50,
    ) -> BinarySecurityStageItemPageResponse:
        task = self._task_or_404(db, project_id, task_id)
        normalized_stage_name = normalize_stage_name(stage_name)
        query = db.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.task_id == task.id,
            BinarySecurityStageItem.stage_name == normalized_stage_name,
        )
        normalized_status = self._string_or_none(status)
        if normalized_status:
            query = query.filter(BinarySecurityStageItem.status == normalized_status)
        rows = query.order_by(BinarySecurityStageItem.created_at.asc(), BinarySecurityStageItem.id.asc()).all()
        archive_jobs_by_item = self._stage_archive_jobs_by_item(db, task.id, normalized_stage_name)
        item_responses = [
            self._stage_item_summary_response(task, item, archive_jobs=archive_jobs_by_item.get(str(item.id or ""), []))
            for item in rows
        ]
        item_responses = self._filter_stage_item_responses(
            item_responses,
            downstream_status=downstream_status,
            sync_status=sync_status,
        )
        item_responses = self._sort_stage_item_responses(
            item_responses,
            sort_by=sort_by,
            sort_direction=sort_direction,
        )
        total = len(item_responses)
        start = max(0, (page - 1) * per_page)
        end = start + per_page
        return BinarySecurityStageItemPageResponse(
            task_id=task.id,
            stage_name=normalized_stage_name,
            total=total,
            page=page,
            per_page=per_page,
            items=item_responses[start:end],
        )

    def get_task_stage_item_detail(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        item_id: str,
    ) -> BinarySecurityStageItemDetailResponse:
        task = self._task_or_404(db, project_id, task_id)
        item = (
            db.query(BinarySecurityStageItem)
            .filter(
                BinarySecurityStageItem.task_id == task.id,
                BinarySecurityStageItem.id == item_id,
            )
            .first()
        )
        if item is None:
            raise NotFoundError("阶段子任务不存在")
        archive_jobs_by_item = self._stage_archive_jobs_by_item(db, task.id, normalize_stage_name(item.stage_name))
        detail = self._stage_item_response(task, item, archive_jobs=archive_jobs_by_item.get(str(item.id or ""), []))
        return BinarySecurityStageItemDetailResponse(**detail.model_dump())

    def get_task_overview(self: TaskManager, db: Session, *, project_id: str, task_id: str) -> BinarySecurityOverviewResponse:
        def _build() -> BinarySecurityOverviewResponse:
            ctx = self._build_task_detail_context(db, project_id=project_id, task_id=task_id)
            archive_job_responses = self._archive_job_responses(db, ctx.task, ctx.archive_jobs)
            response = BinarySecurityOverviewResponse(
                task_id=ctx.task.id,
                nodes=self._build_stage_overview_nodes(
                    db,
                    ctx.task,
                    ctx.stage_summaries,
                    archive_job_responses,
                    ctx.stage_items,
                ),
            )
            self._log_task_read_projection_built(
                projection_kind="task_overview_read_projection_built",
                task=ctx.task,
                stage_items_count=ctx.stage_items_total,
                active_stage_name=self._active_reconcile_stage_name(ctx.task),
                used_cached_projection=False,
            )
            return response

        response, used_cached = self._load_readonly_projection_cached_value(
            cache_group="task_overview",
            project_id=project_id,
            task_id=task_id,
            ttl_seconds=self._readonly_projection_cache_ttl_seconds(),
            loader=_build,
        )
        if used_cached:
            logger.info(
                "binary-security task_overview_read_projection_built projection_only=true task_id=%s used_cached_projection=true",
                task_id,
            )
        return response

    def get_task_archive_jobs_page(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        stage_name: str | None = None,
        page: int = 1,
        per_page: int = 50,
    ) -> BinarySecurityArchiveJobPageResponse:
        task = self._task_or_404(db, project_id, task_id)
        normalized_stage_name = normalize_stage_name(stage_name) or None
        query = db.query(BinarySecurityArchiveJob).filter(BinarySecurityArchiveJob.task_id == task.id)
        if normalized_stage_name:
            query = query.filter(BinarySecurityArchiveJob.stage_name == normalized_stage_name)
        raw_rows = query.order_by(BinarySecurityArchiveJob.created_at.asc(), BinarySecurityArchiveJob.id.asc()).all()
        stage_items_query = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id)
        if normalized_stage_name:
            stage_items_query = stage_items_query.filter(BinarySecurityStageItem.stage_name == normalized_stage_name)
        scope_items = stage_items_query.order_by(BinarySecurityStageItem.created_at.asc(), BinarySecurityStageItem.id.asc()).all()
        canonical_rows = self._canonicalize_read_model_archive_jobs(db, task, scope_items, raw_rows)
        total = len(canonical_rows)
        start = (page - 1) * per_page
        rows = canonical_rows[start : start + per_page]
        return BinarySecurityArchiveJobPageResponse(
            task_id=task.id,
            stage_name=normalized_stage_name,
            total=total,
            page=page,
            per_page=per_page,
            items=self._archive_job_responses(db, task, rows),
        )

    def get_timeline(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        page: int = 1,
        page_size: int = 200,
    ) -> BinarySecurityTimelineResponse:
        task = self._task_or_404(db, project_id, task_id)
        query = db.query(BinarySecurityEvent).filter(BinarySecurityEvent.task_id == task.id)
        total = query.count()
        page = max(1, int(page or 1))
        page_size = min(1000, max(10, int(page_size or 200)))
        offset = (page - 1) * page_size
        events = query.order_by(BinarySecurityEvent.created_at.asc()).offset(offset).limit(page_size).all()
        timeline_events = self._compress_timeline_events(events)
        return BinarySecurityTimelineResponse(
            task_id=task.id,
            total=total,
            page=page,
            page_size=page_size,
            has_more=offset + len(events) < total,
            events=[
                BinarySecurityTaskEventResponse(
                    id=event.id,
                    stage_name=event.stage_name,
                    item_id=event.item_id,
                    item_key=event.item_key,
                    level=event.level,
                    event_type=event.event_type,
                    message=self._timeline_event_display_message(event),
                    payload=self._timeline_response_payload(event),
                    recorder_instance_id=self._timeline_recorder_value(event, "instance_id"),
                    recorder_hostname=self._timeline_recorder_value(event, "hostname"),
                    recorder_pod_name=self._timeline_recorder_value(event, "pod_name"),
                    recorder_node_name=self._timeline_recorder_value(event, "node_name"),
                    recorder_role=self._timeline_recorder_value(event, "role"),
                    origin_instance_id=self._timeline_origin_value(event, "emitted_by_instance_id"),
                    origin_hostname=self._timeline_origin_value(event, "emitted_by_hostname"),
                    origin_pod_name=self._timeline_origin_value(event, "emitted_by_pod_name"),
                    origin_node_name=self._timeline_origin_value(event, "emitted_by_node_name"),
                    origin_role=self._timeline_origin_value(event, "emitted_by_role"),
                    compressed=bool(getattr(event, "_timeline_compressed", False)),
                    repeat_count=int(getattr(event, "_timeline_repeat_count", 1) or 1),
                    created_at=event.created_at,
                )
                for event in timeline_events
            ],
        )

    def get_sync_events(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        stage_name: str | None = None,
        downstream_service: str | None = None,
        operation: str | None = None,
        event_type: str | None = None,
        sync_status: str | None = None,
        outcome: str | None = None,
        has_error: bool | None = None,
        state_applied: bool | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 100,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> BinarySecuritySyncEventPageResponse:
        task = self._task_or_404(db, project_id, task_id)
        query = db.query(BinarySecuritySyncEvent).filter(BinarySecuritySyncEvent.task_id == task.id)
        normalized_stage_name = str(stage_name or "").strip()
        if normalized_stage_name:
            query = query.filter(BinarySecuritySyncEvent.stage_name == normalized_stage_name)
        normalized_service = str(downstream_service or "").strip()
        if normalized_service:
            query = query.filter(BinarySecuritySyncEvent.downstream_service == normalized_service)
        normalized_operation = str(operation or "").strip()
        if normalized_operation:
            query = query.filter(BinarySecuritySyncEvent.operation == normalized_operation)
        normalized_event_type = str(event_type or "").strip()
        if normalized_event_type:
            query = query.filter(BinarySecuritySyncEvent.event_type == normalized_event_type)
        normalized_sync_status = str(sync_status or "").strip()
        if normalized_sync_status:
            query = query.filter(BinarySecuritySyncEvent.sync_status == normalized_sync_status)
        normalized_outcome = str(outcome or "").strip()
        if normalized_outcome:
            query = query.filter(BinarySecuritySyncEvent.outcome == normalized_outcome)
        page = max(1, int(page or 1))
        page_size = min(1000, max(10, int(page_size or 100)))
        sort_map = {
            "created_at": BinarySecuritySyncEvent.created_at,
            "stage_name": BinarySecuritySyncEvent.stage_name,
            "item_key": BinarySecuritySyncEvent.item_key,
            "downstream_service": BinarySecuritySyncEvent.downstream_service,
        }
        sort_column = sort_map.get(str(sort_by or "").strip(), BinarySecuritySyncEvent.created_at)
        order_expr = sort_column.asc() if str(sort_order or "").strip().lower() == "asc" else sort_column.desc()
        rows = query.order_by(order_expr, BinarySecuritySyncEvent.id.desc()).all()
        if has_error is not None:
            rows = [
                row for row in rows
                if (bool(getattr(row, "error_type", None) or getattr(row, "error_message", None)) == bool(has_error))
            ]
        if state_applied is not None:
            rows = [row for row in rows if bool(getattr(row, "state_applied", None)) == bool(state_applied)]
        normalized_search = str(search or "").strip().lower()
        if normalized_search:
            rows = [
                row for row in rows
                if normalized_search in " ".join([
                    str(getattr(row, "item_id", "") or ""),
                    str(getattr(row, "item_key", "") or ""),
                    str(getattr(row, "item_name", "") or ""),
                    str(getattr(row, "downstream_task_id", "") or ""),
                ]).lower()
            ]
        total = len(rows)
        rows = rows[(page - 1) * page_size : (page - 1) * page_size + page_size]
        return BinarySecuritySyncEventPageResponse(
            task_id=task.id,
            total=total,
            page=page,
            page_size=page_size,
            items=[self._sync_event_response(row) for row in rows],
        )

    def _sync_event_response(self: TaskManager, event: BinarySecuritySyncEvent) -> BinarySecuritySyncEventResponse:
        payload = dict(event.payload or {})
        return BinarySecuritySyncEventResponse(
            id=event.id,
            stage_name=event.stage_name,
            item_id=event.item_id,
            item_key=event.item_key,
            item_name=event.item_name,
            downstream_service=event.downstream_service,
            downstream_task_id=event.downstream_task_id,
            operation=event.operation,
            event_type=event.event_type,
            sync_status=event.sync_status,
            outcome=event.outcome,
            state_applied=event.state_applied,
            error_type=event.error_type,
            error_message=event.error_message,
            http_status=event.http_status,
            payload=payload,
            recorder_instance_id=event.recorder_instance_id,
            recorder_hostname=event.recorder_hostname,
            recorder_pod_name=event.recorder_pod_name,
            recorder_node_name=event.recorder_node_name,
            recorder_role=event.recorder_role,
            origin_instance_id=event.origin_instance_id,
            origin_hostname=event.origin_hostname,
            origin_pod_name=event.origin_pod_name,
            origin_node_name=event.origin_node_name,
            origin_role=event.origin_role,
            created_at=event.created_at,
        )

    def _timeline_response_payload(self: TaskManager, event: BinarySecurityEvent) -> dict[str, Any]:
        return getattr(event, "_timeline_payload", event.payload)

    def _timeline_recorder_value(self: TaskManager, event: BinarySecurityEvent, key: str) -> str | None:
        payload = dict(self._timeline_response_payload(event) or {})
        recorder = dict(payload.get("recorder") or {})
        value = str(recorder.get(key) or "").strip()
        return value or None

    def _timeline_origin_value(self: TaskManager, event: BinarySecurityEvent, key: str) -> str | None:
        payload = dict(self._timeline_response_payload(event) or {})
        origin = dict(payload.get("event_origin") or {})
        value = str(origin.get(key) or "").strip()
        return value or None

    def _compress_timeline_events(self: TaskManager, events: list[BinarySecurityEvent]) -> list[BinarySecurityEvent]:
        compressed: list[BinarySecurityEvent] = []
        index = 0
        total = len(events)
        while index < total:
            event = events[index]
            if not self._should_compress_timeline_event(event):
                compressed.append(event)
                index += 1
                continue
            grouped = [event]
            next_index = index + 1
            while next_index < total and self._same_timeline_compression_bucket(grouped[-1], events[next_index]):
                grouped.append(events[next_index])
                next_index += 1
            if len(grouped) == 1:
                compressed.append(event)
            else:
                first_event = grouped[0]
                last_event = grouped[-1]
                payload = dict(first_event.payload or {})
                payload["compressed_event_ids"] = [item.id for item in grouped]
                payload["compressed_repeat_count"] = len(grouped)
                payload["compressed_first_created_at"] = task_shared._isoformat_or_none(first_event.created_at)
                payload["compressed_last_created_at"] = task_shared._isoformat_or_none(last_event.created_at)
                payload["compressed_event_type"] = first_event.event_type
                first_event._timeline_payload = payload
                first_event._timeline_compressed = True
                first_event._timeline_repeat_count = len(grouped)
                compressed.append(first_event)
            index = next_index
        return compressed

    def _timeline_event_display_message(self: TaskManager, event: BinarySecurityEvent) -> str:
        message = str(getattr(event, "message", "") or "系统事件")
        repeat_count = int(getattr(event, "_timeline_repeat_count", 1) or 1)
        compressed = bool(getattr(event, "_timeline_compressed", False))
        if compressed and repeat_count > 1:
            return f"{message} · 已压缩 {repeat_count} 次"
        return message

    def _should_compress_timeline_event(self: TaskManager, event: BinarySecurityEvent) -> bool:
        return str(getattr(event, "event_type", "") or "").strip() in {
            "owned_execution_owner_lost",
            "downstream_http_429_retry_scheduled",
            "downstream_http_429_retry_attempted",
            "downstream_http_429_retry_recovered",
            "owned_execution_takeover_requeued",
            "streaming_stage_item_observation_gap_detected",
        }

    def _same_timeline_compression_bucket(
        self: TaskManager,
        left: BinarySecurityEvent,
        right: BinarySecurityEvent,
    ) -> bool:
        if not self._should_compress_timeline_event(left) or not self._should_compress_timeline_event(right):
            return False
        left_payload = left.payload or {}
        right_payload = right.payload or {}
        left_recorder = dict(left_payload.get("recorder") or {})
        right_recorder = dict(right_payload.get("recorder") or {})
        return (
            str(left.stage_name or "") == str(right.stage_name or "")
            and str(left.item_id or "") == str(right.item_id or "")
            and str(left.item_key or "") == str(right.item_key or "")
            and str(left.message or "") == str(right.message or "")
            and str(left_payload.get("downstream_service") or "") == str(right_payload.get("downstream_service") or "")
            and str(left_payload.get("downstream_task_id") or "") == str(right_payload.get("downstream_task_id") or "")
            and str(left_payload.get("http_status") or "") == str(right_payload.get("http_status") or "")
            and str(left_payload.get("error_type") or "") == str(right_payload.get("error_type") or "")
            and str(left_payload.get("error_message") or "") == str(right_payload.get("error_message") or "")
            and str(left_payload.get("takeover_action") or "") == str(right_payload.get("takeover_action") or "")
            and str(left_payload.get("takeover_reason") or "") == str(right_payload.get("takeover_reason") or "")
            and str(left_payload.get("recovery_action") or "") == str(right_payload.get("recovery_action") or "")
            and str(left_payload.get("task_execution_token") or "") == str(right_payload.get("task_execution_token") or "")
            and str(left_payload.get("dispatcher_instance_id") or "") == str(right_payload.get("dispatcher_instance_id") or "")
            and str(left_recorder.get("instance_id") or "") == str(right_recorder.get("instance_id") or "")
            and str(left_recorder.get("pod_name") or left_recorder.get("hostname") or "") == str(right_recorder.get("pod_name") or right_recorder.get("hostname") or "")
            and str(left_recorder.get("role") or "") == str(right_recorder.get("role") or "")
        )

    def get_operations(self: TaskManager, db: Session, *, project_id: str, task_id: str) -> BinarySecurityTaskOperationPageResponse:
        task = self._task_or_404(db, project_id, task_id)
        return BinarySecurityTaskOperationPageResponse(
            task_id=task.id,
            items=[self._operation_response(operation) for operation in self._list_task_operations(db, task.id)],
        )

    def _list_task_operations(self: TaskManager, db: Session, task_id: str):
        from app.service import task_manager as task_manager_module

        return (
            db.query(task_manager_module.BinarySecurityTaskOperation)
            .filter(task_manager_module.BinarySecurityTaskOperation.task_id == task_id)
            .order_by(
                task_manager_module.BinarySecurityTaskOperation.created_at.desc(),
                task_manager_module.BinarySecurityTaskOperation.id.desc(),
            )
            .all()
        )

    def clear_timeline(self: TaskManager, db: Session, *, project_id: str, task_id: str) -> BinarySecurityActionResponse:
        task = self._task_or_404(db, project_id, task_id)
        deleted_count = (
            db.query(BinarySecurityEvent)
            .filter(BinarySecurityEvent.task_id == task.id)
            .delete(synchronize_session=False)
        )
        db.commit()
        return BinarySecurityActionResponse(
            task_id=task.id,
            message=f"事件时间线已清空，共删除 {deleted_count} 条事件",
            deleted_event_count=int(deleted_count or 0),
        )

    def clear_sync_events(self: TaskManager, db: Session, *, project_id: str, task_id: str) -> BinarySecurityActionResponse:
        task = self._task_or_404(db, project_id, task_id)
        deleted_count = (
            db.query(BinarySecuritySyncEvent)
            .filter(BinarySecuritySyncEvent.task_id == task.id)
            .delete(synchronize_session=False)
        )
        db.commit()
        return BinarySecurityActionResponse(
            task_id=task.id,
            message=f"同步记录已清空，共删除 {deleted_count} 条记录",
            deleted_event_count=int(deleted_count or 0),
        )

    def delete_timeline_event(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        event_id: str,
    ) -> BinarySecurityActionResponse:
        task = self._task_or_404(db, project_id, task_id)
        deleted_count = (
            db.query(BinarySecurityEvent)
            .filter(
                BinarySecurityEvent.task_id == task.id,
                BinarySecurityEvent.id == event_id,
            )
            .delete(synchronize_session=False)
        )
        db.commit()
        if not deleted_count:
            raise NotFoundError("事件不存在或已删除")
        return BinarySecurityActionResponse(
            task_id=task.id,
            message=f"事件 {event_id} 已删除",
            deleted_event_count=int(deleted_count or 0),
        )

    def get_artifacts(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        limit: int = 200,
        offset: int = 0,
    ) -> BinarySecurityArtifactsResponse:
        task = self._task_or_404(db, project_id, task_id)
        page = self._list_artifact_page(Path(task.workspace_root), limit=max(1, limit), offset=max(0, offset))
        artifact_groups = self._artifact_groups_from_b2s_results(task)
        return BinarySecurityArtifactsResponse(
            task_id=task.id,
            workspace_root=task.workspace_root,
            output_root=task.output_root,
            fileserver_path=(task.summary or {}).get("fileserver_project_path"),
            total=page["total"],
            limit=page["limit"],
            offset=page["offset"],
            has_more=page["has_more"],
            files=page["files"],
            grouped_by_index=bool(artifact_groups),
            artifact_groups=artifact_groups,
        )

    def _artifact_groups_from_b2s_results(self: TaskManager, task: BinarySecurityTask) -> list[dict[str, Any]]:
        summary = task.summary if isinstance(task.summary, dict) else {}
        rows = summary.get("b2s_results") if isinstance(summary.get("b2s_results"), list) else []
        groups: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            artifact_index_path = str(row.get("artifact_index_path") or "").strip()
            if not artifact_index_path:
                continue
            try:
                payload = json.loads(Path(artifact_index_path).read_text(encoding="utf-8"))
            except Exception:
                continue
            raw_artifacts = payload.get("artifacts") if isinstance(payload.get("artifacts"), list) else []
            artifacts = [
                {
                    "relative_path": str(entry.get("relative_path") or "").strip(),
                    "kind": str(entry.get("kind") or "other").strip() or "other",
                    "size": int(entry.get("size") or 0),
                    "stage": entry.get("stage"),
                    "section": entry.get("section"),
                    "batch_no": entry.get("batch_no"),
                    "attempt_no": entry.get("attempt_no"),
                }
                for entry in raw_artifacts
                if isinstance(entry, dict) and str(entry.get("relative_path") or "").strip()
            ]
            groups.append(
                {
                    "module_key": str(row.get("module_key") or "").strip() or str(row.get("module_name") or "").strip() or "module",
                    "module_name": row.get("module_name"),
                    "source_root": row.get("source_root") or row.get("source_dir"),
                    "primary_result_kind": row.get("primary_result_kind"),
                    "result_kinds": [str(kind).strip() for kind in (row.get("result_kinds") or []) if str(kind).strip()],
                    "artifact_kind_summary": dict(row.get("artifact_kind_summary") or {}),
                    "result_kind_summary": dict(row.get("result_kind_summary") or {}),
                    "artifact_index_path": artifact_index_path,
                    "result_summary_version": int(row.get("result_summary_version") or payload.get("version") or 1),
                    "artifacts": artifacts,
                }
            )
        return groups

    def _detail_stage_items_limit(self: TaskManager) -> int:
        from app.service import task_manager as task_manager_module

        return task_manager_module.DETAIL_STAGE_ITEMS_LIMIT

    def _readonly_projection_cache_ttl_seconds(self: TaskManager) -> float:
        from app.service import task_manager as task_manager_module

        return task_manager_module.READONLY_TASK_PROJECTION_CACHE_TTL_SECONDS
