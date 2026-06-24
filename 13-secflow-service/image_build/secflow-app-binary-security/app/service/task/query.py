from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy import or_
from sqlalchemy.orm import Session, load_only

from app.exception import NotFoundError
from app.model import (
    PIPELINE_PROFILE_DEFAULT,
    PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN,
    TASK_TYPE_SOURCE,
    BinarySecurityArchiveJob,
    BinarySecurityEvent,
    BinarySecuritySyncEvent,
    BinarySecurityStageItem,
    BinarySecurityTask,
    normalize_stage_name,
)
from app.observability import observe_task_list_query, observe_task_list_query_stage
from app.schemas import (
    BinarySecurityActionResponse,
    BinarySecurityArchiveJobPageResponse,
    BinarySecurityArtifactsResponse,
    BinarySecurityOverviewResponse,
    BinarySecurityProjectStats,
    BinarySecurityStageItemPageResponse,
    BinarySecurityTaskDetailResponse,
    BinarySecurityTaskEventResponse,
    BinarySecurityTaskListResponse,
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
    def list_tasks(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
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
            base_query = db.query(BinarySecurityTask).filter(BinarySecurityTask.project_id == project_id)
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

            stage_started = time.perf_counter()
            total = int(query.count() or 0)
            observe_task_list_query_stage(
                stage="count",
                task_type=metrics_task_type,
                duration_seconds=time.perf_counter() - stage_started,
            )
            stage_durations["count"] = time.perf_counter() - stage_started

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
            tasks = query.options(
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
                )
            ).order_by(order_expr, BinarySecurityTask.id.desc()).offset(offset).limit(page_size).all()
            observe_task_list_query_stage(
                stage="page_items",
                task_type=metrics_task_type,
                duration_seconds=time.perf_counter() - stage_started,
            )
            stage_durations["page_items"] = time.perf_counter() - stage_started

            stage_started = time.perf_counter()
            queue_info = self._load_task_list_cached_value(
                cache_group="queue_info",
                project_id=project_id,
                task_type=normalized_task_type,
                pipeline_profile=normalized_pipeline_profile,
                ttl_seconds=3.0,
                loader=lambda: self._build_queue_info(db, project_id=project_id),
                fallback={"running_count": 0, "queued_count": 0, "pending_positions": {}, "last_reconcile_at": None},
            )
            observe_task_list_query_stage(
                stage="queue_info",
                task_type=metrics_task_type,
                duration_seconds=time.perf_counter() - stage_started,
            )
            stage_durations["queue_info"] = time.perf_counter() - stage_started

            stage_started = time.perf_counter()
            service_config = self._load_service_config(db)
            observe_task_list_query_stage(
                stage="service_config",
                task_type=metrics_task_type,
                duration_seconds=time.perf_counter() - stage_started,
            )
            stage_durations["service_config"] = time.perf_counter() - stage_started

            stage_started = time.perf_counter()
            project_stats = self._load_task_list_cached_value(
                cache_group="project_stats",
                project_id=project_id,
                task_type=normalized_task_type,
                pipeline_profile=normalized_pipeline_profile,
                ttl_seconds=5.0,
                loader=lambda: self._build_project_stats_sql(
                    db,
                    project_id=project_id,
                    task_type=normalized_task_type,
                    pipeline_profile=normalized_pipeline_profile,
                ),
                fallback=BinarySecurityProjectStats(total=0),
            )
            observe_task_list_query_stage(
                stage="project_stats",
                task_type=metrics_task_type,
                duration_seconds=time.perf_counter() - stage_started,
            )
            stage_durations["project_stats"] = time.perf_counter() - stage_started

            stage_started = time.perf_counter()
            project_stage_aggregates = self._load_task_list_cached_value(
                cache_group="project_stage_aggregates",
                project_id=project_id,
                task_type=normalized_task_type,
                pipeline_profile=normalized_pipeline_profile,
                ttl_seconds=5.0,
                loader=lambda: self._build_project_stage_aggregates_sql(
                    db,
                    project_id=project_id,
                    task_type=normalized_task_type,
                    pipeline_profile=normalized_pipeline_profile,
                ),
                fallback=[],
            )
            observe_task_list_query_stage(
                stage="project_stage_aggregates",
                task_type=metrics_task_type,
                duration_seconds=time.perf_counter() - stage_started,
            )
            stage_durations["project_stage_aggregates"] = time.perf_counter() - stage_started

            stage_started = time.perf_counter()
            stage_runs_by_task, stage_items_by_task = self._task_list_stage_state_by_task(db, tasks)
            active_operations_by_task, cancel_operations_by_task = self._task_list_operation_maps(db, tasks)
            items = [
                self._task_list_response(
                    db,
                    task,
                    queue_info=queue_info,
                    stage_runs=stage_runs_by_task.get(str(task.id), []),
                    stage_items=stage_items_by_task.get(str(task.id), []),
                    active_operation=active_operations_by_task.get(str(task.id)),
                    cancel_operation=cancel_operations_by_task.get(str(task.id)),
                )
                for task in tasks
            ]
            observe_task_list_query_stage(
                stage="serialize_items",
                task_type=metrics_task_type,
                duration_seconds=time.perf_counter() - stage_started,
            )
            stage_durations["serialize_items"] = time.perf_counter() - stage_started
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
                running_count=queue_info["running_count"],
                queued_count=queue_info["queued_count"],
                max_concurrent_tasks=service_config.max_concurrent_tasks,
                project_stats=project_stats,
                project_stage_aggregates=project_stage_aggregates,
                queue_runtime={"last_reconcile_at": queue_info.get("last_reconcile_at")},
                items=items,
            )
        except Exception:
            result = "error"
            raise
        finally:
            total_duration = time.perf_counter() - started
            if result != "success":
                self._log_task_list_query(
                    project_id=project_id,
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
            archive_jobs_by_item = self._archive_jobs_by_item_id(ctx.archive_jobs)
            archive_job_responses = self._archive_job_responses(db, ctx.task, ctx.archive_jobs)
            stage_item_responses = [
                self._stage_item_response(ctx.task, item, archive_jobs=archive_jobs_by_item.get(str(item.id or ""), []))
                for item in ctx.stage_items[: self._detail_stage_items_limit()]
            ]
            overview_nodes = self._build_stage_overview_nodes(
                db,
                ctx.task,
                ctx.stage_summaries,
                archive_job_responses,
                ctx.stage_items[: self._detail_stage_items_limit()],
            )
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
                summary=self._task_summary_for_detail_response(ctx.task),
                metrics=ctx.task.metrics,
                item_stats=ctx.item_stats,
                stage_items_total=ctx.stage_items_total,
                stage_items_truncated=ctx.stage_items_total > self._detail_stage_items_limit(),
                stage_items=stage_item_responses,
                archive_jobs=archive_job_responses,
                abnormal_reason_history=[],
                overview_nodes=overview_nodes,
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
            self._stage_item_response(task, item, archive_jobs=archive_jobs_by_item.get(str(item.id or ""), []))
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
        query = db.query(BinarySecurityArchiveJob).filter(BinarySecurityArchiveJob.task_id == task.id)
        normalized_stage_name = normalize_stage_name(stage_name) or None
        if normalized_stage_name:
            query = query.filter(BinarySecurityArchiveJob.stage_name == normalized_stage_name)
        query = query.order_by(BinarySecurityArchiveJob.created_at.asc(), BinarySecurityArchiveJob.id.asc())
        total = query.count()
        rows = query.offset((page - 1) * per_page).limit(per_page).all()
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
            "streaming_stage_item_requeued_after_downstream_missing",
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
