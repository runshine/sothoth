from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import ensure_project_access, get_current_subject, get_db
from app.schemas import (
    HistoryRunCycleResponse,
    HistoryRunDetailResponse,
    HistoryRunFileContentResponse,
    HistoryRunFileResponse,
    HistoryRunLogResponse,
    HistoryRunResolveResponse,
    HistoryRunSessionResponse,
    HistoryRunSummaryResponse,
    ProjectFilesystemChildrenResponse,
    ProjectFilesystemRootResponse,
    ScanTaskArtifactsResponse,
    ScanTaskAttemptResponse,
    ScanTaskCreateRequest,
    ScanTaskDetailResponse,
    ScanTaskEventResponse,
    ScanTaskPriorityUpdateRequest,
    ScanTaskResponse,
)
from app.services.execution_service import get_execution_service

router = APIRouter(prefix="/api/dataflow-vuln-scanner", tags=["Dataflow Vuln Scanner"])


@router.get("/capabilities", response_model=Dict[str, Any])
async def get_capabilities(subject=Depends(get_current_subject)):
    return {
        "service": "secflow-app-dataflow-vuln-scanner",
        "task_input_modes": ["project_filesystem", "upload_to_project_filesystem", "fileserver_storage", "absolute_path"],
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
        "thinking_levels": ["low", "medium", "high", "xhigh"],
        "review_profiles": [
            {"value": "fast", "label": "快速筛选"},
            {"value": "balanced", "label": "平衡默认"},
            {"value": "strict", "label": "正式报告"},
            {"value": "audit", "label": "审计闭环"},
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
    return get_execution_service().create_scan_task(db, payload, principal, authorization_token=token)


@router.get("/tasks", response_model=List[ScanTaskResponse])
async def list_tasks(
    project_id: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    profile_id: Optional[str] = Query(None),
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
    )


@router.get("/tasks/{task_id}", response_model=ScanTaskDetailResponse)
async def get_task(task_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().get_scan_task(db, task_id, principal)


@router.get("/tasks/{task_id}/attempts", response_model=List[ScanTaskAttemptResponse])
async def list_task_attempts(task_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().list_scan_task_attempts(db, task_id, principal)


@router.get("/tasks/{task_id}/events", response_model=List[ScanTaskEventResponse])
async def list_task_events(task_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().list_scan_task_events(db, task_id, principal)


@router.get("/tasks/{task_id}/artifacts", response_model=ScanTaskArtifactsResponse)
async def get_task_artifacts(task_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().get_scan_task_artifacts(db, task_id, principal)


@router.get("/tasks/{task_id}/runs", response_model=List[Dict[str, Any]])
async def list_task_runs(task_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().list_scan_task_runs(db, task_id, principal)


@router.get("/tasks/{task_id}/runs/{execution_id}", response_model=Dict[str, Any])
async def get_task_run(task_id: str, execution_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().get_scan_task_run(db, task_id, execution_id, principal)


@router.get("/tasks/{task_id}/runs/{execution_id}/cycles/{cycle}", response_model=Dict[str, Any])
async def get_task_run_cycle(
    task_id: str,
    execution_id: str,
    cycle: int,
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().get_scan_task_run_cycle(db, task_id, execution_id, cycle, principal)


@router.get("/tasks/{task_id}/runs/{execution_id}/sessions", response_model=List[Dict[str, Any]])
async def list_task_run_sessions(task_id: str, execution_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().list_scan_task_run_sessions(db, task_id, execution_id, principal)


@router.get("/tasks/{task_id}/runs/{execution_id}/files", response_model=List[Dict[str, Any]])
async def list_task_run_files(
    task_id: str,
    execution_id: str,
    limit: int = Query(default=1200, ge=1, le=5000),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().list_scan_task_run_files(db, task_id, execution_id, principal, limit=limit)


@router.get("/tasks/{task_id}/runs/{execution_id}/file", response_model=Dict[str, Any])
async def get_task_run_file(
    task_id: str,
    execution_id: str,
    path: str = Query(...),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().get_scan_task_run_file(db, task_id, execution_id, principal, path)


@router.get("/tasks/{task_id}/runs/{execution_id}/session-file", response_model=Dict[str, Any])
async def get_task_run_session_file(
    task_id: str,
    execution_id: str,
    path: str = Query(...),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().get_scan_task_run_session_file(db, task_id, execution_id, principal, path)


@router.get("/tasks/{task_id}/runs/{execution_id}/log", response_model=Dict[str, Any])
async def get_task_run_log(
    task_id: str,
    execution_id: str,
    lines: int = Query(default=300, ge=1, le=2000),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().get_scan_task_run_log(db, task_id, execution_id, principal, lines=lines)


@router.get("/history-runs", response_model=List[HistoryRunSummaryResponse])
async def list_history_runs(
    project_id: str = Query(...),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    await ensure_project_access(project_id, token)
    return get_execution_service().list_history_runs(db, principal, project_id=project_id)


@router.get("/history-runs/resolve", response_model=HistoryRunResolveResponse)
async def resolve_history_run(
    project_id: str = Query(...),
    run_name: str = Query(...),
    root_path: str = Query(...),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    await ensure_project_access(project_id, token)
    return get_execution_service().resolve_history_run(db, principal, project_id=project_id, run_name=run_name, root_path=root_path)


@router.get("/history-runs/{history_run_id}", response_model=HistoryRunDetailResponse)
async def get_history_run(history_run_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().get_history_run(db, history_run_id, principal)


@router.get("/history-runs/{history_run_id}/cycles/{cycle}", response_model=HistoryRunCycleResponse)
async def get_history_run_cycle(
    history_run_id: str,
    cycle: int,
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().get_history_run_cycle(db, history_run_id, cycle, principal)


@router.get("/history-runs/{history_run_id}/sessions", response_model=List[HistoryRunSessionResponse])
async def list_history_run_sessions(history_run_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().list_history_run_sessions(db, history_run_id, principal)


@router.get("/history-runs/{history_run_id}/files", response_model=List[HistoryRunFileResponse])
async def list_history_run_files(
    history_run_id: str,
    limit: int = Query(default=1200, ge=1, le=5000),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().list_history_run_files(db, history_run_id, principal, limit=limit)


@router.get("/history-runs/{history_run_id}/file", response_model=HistoryRunFileContentResponse)
async def get_history_run_file(
    history_run_id: str,
    path: str = Query(...),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().get_history_run_file(db, history_run_id, principal, path)


@router.get("/history-runs/{history_run_id}/session-file", response_model=Dict[str, Any])
async def get_history_run_session_file(
    history_run_id: str,
    path: str = Query(...),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().get_history_run_session_file(db, history_run_id, principal, path)


@router.get("/history-runs/{history_run_id}/log", response_model=HistoryRunLogResponse)
async def get_history_run_log(
    history_run_id: str,
    lines: int = Query(default=300, ge=1, le=2000),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().get_history_run_log(db, history_run_id, principal, lines=lines)


@router.post("/tasks/{task_id}/cancel", response_model=ScanTaskResponse)
async def cancel_task(task_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_execution_service().cancel_scan_task(db, task_id, principal)


@router.post("/tasks/{task_id}/retry", response_model=ScanTaskResponse)
async def retry_task(task_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    return get_execution_service().retry_scan_task(db, task_id, principal, authorization_token=token)


@router.post("/tasks/{task_id}/requeue", response_model=ScanTaskResponse)
async def requeue_task(task_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    return get_execution_service().requeue_scan_task(db, task_id, principal, authorization_token=token)


@router.post("/tasks/{task_id}/priority", response_model=ScanTaskResponse)
async def update_task_priority(
    task_id: str,
    payload: ScanTaskPriorityUpdateRequest,
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_execution_service().update_scan_task_priority(db, task_id, principal, payload.priority)
