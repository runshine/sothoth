from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import ensure_project_access, get_current_subject, get_db
from app.config import get_config
from app.schemas import (
    CreateEvolutionTaskRequest,
    ProjectFilesystemChildrenResponse,
    ProjectFilesystemRootResponse,
    ReplayReadyResponse,
    RunCycleResponse,
    RunDetailResponse,
    RunFileContentResponse,
    RunFileResponse,
    RunLogResponse,
    RunMutationResponse,
    RunResolveResponse,
    RunRetryRequest,
    RunSessionResponse,
    RunSummaryResponse,
    RunVulnReportRequest,
    RunVulnReportResponse,
    ScanTaskCreateRequest,
    ScanTaskDetailResponse,
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
        "data_flow_file_types": [".md", ".txt"],
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
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    await ensure_project_access(payload.project_id, token)
    created = get_execution_service().create_scan_task(db, payload, principal, authorization_token=token)
    get_scheduler_service().start_execution_now(created.latest_execution_id)
    db.expire_all()
    return get_execution_service().get_scan_task_summary(db, created.task_id, principal)


@router.get("/tasks", response_model=List[ScanTaskResponse])
async def list_tasks(
    project_id: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    profile_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    if project_id:
        await ensure_project_access(project_id, token)
    return get_execution_service().list_scan_tasks(
        db,
        principal,
        project_id=project_id,
        status_filter=status_filter,
        profile_id=profile_id,
        limit=limit,
        offset=offset,
    )


@router.get("/tasks/{task_id}", response_model=ScanTaskDetailResponse)
async def get_task(task_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().get_scan_task(db, task_id, principal)


@router.get("/tasks/{task_id}/replay-ready", response_model=ReplayReadyResponse)
async def get_task_replay_ready(task_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().get_task_replay_ready(db, task_id, principal)


@router.post("/tasks/{task_id}/create-evolution", response_model=ScanTaskResponse, status_code=status.HTTP_201_CREATED)
async def create_evolution_task(
    task_id: str,
    payload: CreateEvolutionTaskRequest,
    subject=Depends(get_current_subject),
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


@router.get("/runs/{run_id}", response_model=RunDetailResponse)
async def get_run(run_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().get_run(db, run_id, principal)


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
        result["status"] = "running"
        result["message"] = "Run resume started"
    return result


@router.post("/tasks/{task_id}/cancel", response_model=ScanTaskResponse)
async def cancel_task(task_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().cancel_scan_task(db, task_id, principal)


@router.delete("/tasks/{task_id}", response_model=SuccessResponse)
async def delete_task(task_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().delete_scan_task(db, task_id, principal)


@router.post("/tasks/{task_id}/priority", response_model=ScanTaskResponse)
async def update_task_priority(
    task_id: str,
    payload: ScanTaskPriorityUpdateRequest,
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().update_scan_task_priority(db, task_id, principal, payload.priority)
