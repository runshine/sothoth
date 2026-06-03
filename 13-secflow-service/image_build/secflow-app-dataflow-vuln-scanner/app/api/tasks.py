from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import ensure_project_access, get_current_or_machine_subject, get_current_subject, get_db
from app.config import get_config
from app.models.database import WorkflowExecution
from app.schemas import (
    ActiveTaskReconcileRequest,
    ActiveTaskReconcileResponse,
    CreateEvolutionTaskRequest,
    DataflowTaskTimelineActionResponse,
    DataflowTaskTimelineResponse,
    ProjectFilesystemChildrenResponse,
    ProjectFilesystemRootResponse,
    ReplayReadyResponse,
    RunCycleResponse,
    RunDetailResponse,
    RunOverviewResponse,
    RunFileContentResponse,
    RunFileResponse,
    RunLogResponse,
    RunMutationResponse,
    RunResolveResponse,
    RunResumePreviewResponse,
    RunRetryRequest,
    RunSessionResponse,
    RunSummaryResponse,
    RunVulnReportRequest,
    RunVulnReportResponse,
    ScanTaskCreateRequest,
    ScanTaskProjectionRepairResponse,
    ScanTaskStatsResponse,
    WorkerClusterCapacityResponse,
    WorkerClusterCapacitySummaryResponse,
    ScanTaskDetailResponse,
    ScanTaskListResponse,
    ScanTaskPriorityUpdateRequest,
    ScanTaskResponse,
    SuccessResponse,
)
from app.services.execution_service import get_execution_service
from app.services.scheduler import get_scheduler_service

router = APIRouter(prefix="/api/dataflow-vuln-scanner", tags=["Dataflow Vuln Scanner"])


@router.get("/capabilities", response_model=Dict[str, Any])
async def get_capabilities(subject=Depends(get_current_subject)):
    task_input_modes = ["project_filesystem", "upload_to_project_filesystem", "fileserver_storage"]
    if get_config().service.allow_absolute_input_refs:
        task_input_modes.append("absolute_path")
    return {
        "service": "secflow-app-dataflow-vuln-scanner",
        "task_input_modes": task_input_modes,
        "required_inputs": ["data_flow", "source_dir"],
        "data_flow_input_kind": "directory",
        "data_flow_directory_file_types": [".md", ".txt"],
        "source_file_types": [".c", ".h", ".cpp", ".hpp", ".cc", ".asm", ".S", ".s"],
        "models": [
            "icsl/zai-org/GLM-5",
            "openai/gpt-5.4",
            "openai/gpt-5.4-mini",
            "anthropic/claude-sonnet-4-20250514",
            "anthropic/claude-opus-4-1-20250805",
        ],
        "thinking_policy": "profile_model_capability",
        "review_profiles": [
            {"value": "fast", "label": "快速筛选"},
            {"value": "balanced", "label": "平衡挖掘"},
            {"value": "audit", "label": "深度审计"},
        ],
        "process_views": ["runs", "cycles", "reviews", "results", "sessions", "files", "logs"],
    }


@router.get("/project-filesystem/root", response_model=ProjectFilesystemRootResponse)
async def get_project_filesystem_root(
    project_id: str = Query(...),
    subject=Depends(get_current_subject),
):
    principal, token = subject
    await ensure_project_access(project_id, token)
    return get_execution_service().get_project_filesystem_root(principal, project_id)


@router.get("/project-filesystem/children", response_model=ProjectFilesystemChildrenResponse)
async def get_project_filesystem_children(
    project_id: str = Query(...),
    path: str = Query(...),
    subject=Depends(get_current_subject),
):
    principal, token = subject
    await ensure_project_access(project_id, token)
    return get_execution_service().get_project_filesystem_children(principal, project_id, path)


@router.post("/tasks", response_model=ScanTaskResponse, status_code=status.HTTP_201_CREATED)
async def create_task(
    payload: ScanTaskCreateRequest,
    subject=Depends(get_current_or_machine_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    await ensure_project_access(payload.project_id, token)
    created = get_execution_service().create_scan_task(db, payload, principal, authorization_token=token)
    get_scheduler_service().start_execution_now(created.latest_execution_id)
    db.expire_all()
    return get_execution_service().get_scan_task_summary(db, created.task_id, principal)


@router.get("/tasks", response_model=ScanTaskListResponse)
async def list_tasks(
    project_id: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    profile_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    slot_binding_state: Optional[str] = Query(None),
    report_status: Optional[str] = Query(None),
    model: Optional[str] = Query(None),
    limit: int = Query(50, ge=10, le=1000),
    offset: int = Query(0, ge=0),
    page: Optional[int] = Query(None, ge=1),
    per_page: Optional[int] = Query(None, ge=10, le=1000),
    mode: Optional[str] = Query(None),
    parent_task_id: Optional[str] = Query(None),
    sort_by: Optional[str] = Query(None),
    sort_order: Optional[str] = Query(None),
    subject=Depends(get_current_or_machine_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    if project_id:
        await ensure_project_access(project_id, token)
    if page is None and per_page is None:
        if limit is not None:
            safe_limit = max(10, min(int(limit), 1000))
            safe_offset = max(0, int(offset or 0))
            per_page = safe_limit
            page = (safe_offset // safe_limit) + 1
        else:
            page = 1
            per_page = 50
    return get_execution_service().list_scan_tasks(
        db,
        principal,
        project_id=project_id,
        status_filter=status_filter,
        profile_id=profile_id,
        search=search,
        slot_binding_state=slot_binding_state,
        report_status=report_status,
        model=model,
        page=page,
        per_page=per_page,
        mode=mode,
        parent_task_id=parent_task_id,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@router.get("/tasks/stats", response_model=ScanTaskStatsResponse)
async def get_task_stats(
    project_id: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    profile_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    slot_binding_state: Optional[str] = Query(None),
    report_status: Optional[str] = Query(None),
    model: Optional[str] = Query(None),
    mode: Optional[str] = Query(None),
    parent_task_id: Optional[str] = Query(None),
    subject=Depends(get_current_or_machine_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    if project_id:
        await ensure_project_access(project_id, token)
    return get_execution_service().get_scan_task_stats(
        db,
        principal,
        project_id=project_id,
        status_filter=status_filter,
        profile_id=profile_id,
        search=search,
        slot_binding_state=slot_binding_state,
        report_status=report_status,
        model=model,
        mode=mode,
        parent_task_id=parent_task_id,
    )


@router.post("/tasks/projection/rebuild", response_model=ScanTaskProjectionRepairResponse)
async def rebuild_task_projection_batch(
    project_id: Optional[str] = Query(None),
    subject=Depends(get_current_or_machine_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    if project_id:
        await ensure_project_access(project_id, token)
    return get_execution_service().rebuild_scan_task_projections(
        db,
        principal,
        project_id=project_id,
    )


@router.get("/workers/cluster-capacity/summary", response_model=WorkerClusterCapacitySummaryResponse)
def get_worker_cluster_capacity_summary(
    subject=Depends(get_current_or_machine_subject),
    db: Session = Depends(get_db),
):
    return get_scheduler_service().get_cluster_capacity_summary(db)


@router.get("/workers/cluster-capacity", response_model=WorkerClusterCapacityResponse)
def get_worker_cluster_capacity(
    subject=Depends(get_current_or_machine_subject),
    db: Session = Depends(get_db),
):
    return get_scheduler_service().get_cluster_capacity(db)


@router.get("/tasks/{task_id}", response_model=ScanTaskDetailResponse)
def get_task(task_id: str, subject=Depends(get_current_or_machine_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().get_scan_task(db, task_id, principal)


@router.post("/tasks/{task_id}/projection/rebuild", response_model=ScanTaskProjectionRepairResponse)
async def rebuild_task_projection(task_id: str, subject=Depends(get_current_or_machine_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().rebuild_single_scan_task_projection(db, task_id, principal)


@router.post("/tasks/runtime/reconcile-active", response_model=ActiveTaskReconcileResponse)
async def reconcile_active_tasks(
    payload: ActiveTaskReconcileRequest,
    subject=Depends(get_current_or_machine_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    if payload.project_id:
        await ensure_project_access(payload.project_id, token)
    return get_execution_service().reconcile_active_tasks(
        db,
        principal=principal,
        project_id=payload.project_id,
        statuses=payload.statuses,
        limit=payload.limit,
        dry_run=payload.dry_run,
    )


@router.get("/tasks/{task_id}/timeline", response_model=DataflowTaskTimelineResponse)
async def get_task_timeline(task_id: str, subject=Depends(get_current_or_machine_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().get_scan_task_timeline(db, task_id, principal)


@router.delete("/tasks/{task_id}/timeline", response_model=DataflowTaskTimelineActionResponse)
async def clear_task_timeline(task_id: str, subject=Depends(get_current_or_machine_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().clear_scan_task_timeline(db, task_id, principal)


@router.delete("/tasks/{task_id}/timeline/{event_id}", response_model=DataflowTaskTimelineActionResponse)
async def delete_task_timeline_event(
    task_id: str,
    event_id: str,
    subject=Depends(get_current_or_machine_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().delete_scan_task_timeline_event(db, task_id, event_id, principal)


@router.get("/tasks/{task_id}/replay-ready", response_model=ReplayReadyResponse)
def get_task_replay_ready(task_id: str, subject=Depends(get_current_or_machine_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().get_task_replay_ready(db, task_id, principal)


@router.post("/tasks/{task_id}/create-evolution", response_model=ScanTaskResponse, status_code=status.HTTP_201_CREATED)
async def create_evolution_task(
    task_id: str,
    payload: CreateEvolutionTaskRequest,
    subject=Depends(get_current_or_machine_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    created = get_execution_service().create_evolution_task(
        db,
        source_task_id=task_id,
        payload=payload,
        principal=principal,
        authorization_token=token,
    )
    get_scheduler_service().start_execution_now(created.latest_execution_id)
    db.expire_all()
    return get_execution_service().get_scan_task_summary(db, created.task_id, principal)


@router.get("/tasks/{task_id}/artifacts", response_model=Dict[str, Any])
def get_task_artifacts(task_id: str, subject=Depends(get_current_or_machine_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().get_scan_task_artifacts(db, task_id, principal)


@router.post(
    "/tasks/{task_id}/retry",
    response_model=ScanTaskResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def retry_task(
    task_id: str,
    payload: RunRetryRequest | None = Body(default=None),
    subject=Depends(get_current_or_machine_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    result = get_execution_service().retry_scan_task(db, task_id, principal, payload)
    if get_scheduler_service().start_execution_now(result.get("linked_execution_id")):
        db.expire_all()
    return get_execution_service().get_scan_task_summary(db, task_id, principal)


@router.get("/runs", response_model=List[RunSummaryResponse])
async def list_runs(
    project_id: str = Query(...),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    await ensure_project_access(project_id, token)
    return get_execution_service().list_runs(db, principal, project_id=project_id)


@router.get("/runs/resolve", response_model=RunResolveResponse)
async def resolve_run(
    project_id: str = Query(...),
    run_name: str = Query(...),
    root_path: str = Query(...),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    await ensure_project_access(project_id, token)
    return get_execution_service().resolve_run(db, principal, project_id=project_id, run_name=run_name, root_path=root_path)


@router.get("/runs/by-task", response_model=RunResolveResponse)
async def resolve_run_by_task(
    project_id: str = Query(...),
    task_id: str = Query(...),
    execution_id: Optional[str] = Query(None),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    await ensure_project_access(project_id, token)
    return get_execution_service().resolve_run_by_task(
        db,
        principal,
        project_id=project_id,
        task_id=task_id,
        execution_id=execution_id,
    )


@router.get("/runs/{run_id}", response_model=RunOverviewResponse)
async def get_run(run_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().get_run(db, run_id, principal)


@router.get("/runs/{run_id}/overview", response_model=RunOverviewResponse)
async def get_run_overview(run_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().get_run_overview(db, run_id, principal)


@router.get("/runs/{run_id}/detail", response_model=RunDetailResponse)
async def get_run_detail(run_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().get_run_detail_full(db, run_id, principal)


@router.post("/runs/{run_id}/report-vulnerabilities", response_model=RunVulnReportResponse)
async def report_run_vulnerabilities(
    run_id: str,
    payload: RunVulnReportRequest,
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().report_run_vulnerabilities(db, run_id, principal, payload.result_files)


@router.get("/runs/{run_id}/cycles/{cycle}", response_model=RunCycleResponse)
async def get_run_cycle(
    run_id: str,
    cycle: int,
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().get_run_cycle(db, run_id, cycle, principal)


@router.get("/runs/{run_id}/sessions", response_model=List[RunSessionResponse])
async def list_run_sessions(run_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().list_run_sessions(db, run_id, principal)


@router.get("/runs/{run_id}/files", response_model=List[RunFileResponse])
async def list_run_files(
    run_id: str,
    limit: int = Query(default=1200, ge=1, le=5000),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().list_run_files(db, run_id, principal, limit=limit)


@router.get("/runs/{run_id}/file", response_model=RunFileContentResponse)
async def get_run_file(
    run_id: str,
    path: str = Query(...),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().get_run_file(db, run_id, principal, path)


@router.get("/runs/{run_id}/session-file", response_model=Dict[str, Any])
async def get_run_session_file(
    run_id: str,
    path: str = Query(...),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().get_run_session_file(db, run_id, principal, path)


@router.get("/runs/{run_id}/log", response_model=RunLogResponse)
async def get_run_log(
    run_id: str,
    lines: int = Query(default=300, ge=1, le=2000),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().get_run_log(db, run_id, principal, lines=lines)


@router.delete("/runs/{run_id}", response_model=RunMutationResponse)
async def delete_run(run_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().delete_run(db, run_id, principal)


@router.post("/runs/{run_id}/cancel", response_model=RunMutationResponse)
async def cancel_run(run_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().cancel_run(db, run_id, principal)


@router.post("/runs/{run_id}/adopt", response_model=RunMutationResponse)
async def adopt_run(run_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().adopt_run(db, run_id, principal)


@router.post("/runs/{run_id}/retry/preview", response_model=RunResumePreviewResponse)
async def preview_retry_run(
    run_id: str,
    payload: RunRetryRequest | None = Body(default=None),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().preview_run_retry(db, run_id, principal, payload or RunRetryRequest())


@router.post(
    "/runs/{run_id}/retry",
    response_model=RunMutationResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def retry_run(
    run_id: str,
    payload: RunRetryRequest,
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    result = get_execution_service().retry_run(db, run_id, principal, payload)
    if get_scheduler_service().start_execution_now(result.get("linked_execution_id")):
        db.expire_all()
        execution = db.get(WorkflowExecution, result.get("linked_execution_id"))
        if execution is not None and execution.status == "running":
            result["status"] = "running"
            result["message"] = "Run resume started"
        elif execution is not None and execution.dispatch_status in {"queued", "dispatching"}:
            result["status"] = "queued"
            result["message"] = "Run resume queued"
    return result


@router.post("/tasks/{task_id}/cancel", response_model=ScanTaskResponse)
def cancel_task(task_id: str, subject=Depends(get_current_or_machine_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().cancel_scan_task(db, task_id, principal)


@router.delete("/tasks/{task_id}", response_model=SuccessResponse)
def delete_task(task_id: str, subject=Depends(get_current_or_machine_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().delete_scan_task(db, task_id, principal)


@router.post("/tasks/{task_id}/priority", response_model=ScanTaskResponse)
async def update_task_priority(
    task_id: str,
    payload: ScanTaskPriorityUpdateRequest,
    subject=Depends(get_current_or_machine_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().update_scan_task_priority(db, task_id, principal, payload.priority)
