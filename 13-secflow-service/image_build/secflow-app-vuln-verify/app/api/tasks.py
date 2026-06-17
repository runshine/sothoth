"""vuln-verify frontend API routes."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header, Query
from sqlalchemy.orm import Session

from app.build_info import build_service_meta
from app.exception import UnauthorizedError
from app.model import VulnVerifyTask, get_db
from app.schemas import (
    ActionResponse,
    ArtifactContentResponse,
    ArtifactEntry,
    ArtifactListResponse,
    ProjectStatsResponse,
    ServiceConfigResponse,
    ServiceConfigUpsertRequest,
    TaskCreate,
    ReportDataResponse,
    TaskDetailResponse,
    TaskListResponse,
    TaskResponse,
    TaskResultResponse,
    TokenUser,
)
from app.service.auth import get_auth_service
from app.service.project import get_project_service
from app.service.config_service import get_service_config, resolve_effective_default_model, save_service_config
from app.service.security import validate_project_id
from app.service.task_service import (
    build_project_stats,
    build_detail,
    build_report_data,
    build_response,
    create_task,
    get_task_or_404,
    list_artifacts,
    load_results,
    read_artifact,
    request_terminate,
    rerun_task,
    summarize_results,
    task_matches_result_verdict,
)

router = APIRouter(prefix="/api/app/vuln-verify", tags=["vuln-verify"])


@router.get("/health")
async def health_check():
    return {
        "status": "ok",
        "service": "secflow-app-vuln-verify",
        **build_service_meta(),
    }


@router.get("/ready")
async def ready_check():
    return {"status": "ready"}


async def get_current_context(project_id: str, authorization: Optional[str] = Header(None)) -> TokenUser:
    validate_project_id(project_id)
    if not authorization:
        raise UnauthorizedError("缺少Authorization头")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedError("Authorization格式错误，应为 Bearer <token>")
    token = parts[1]
    user = await get_auth_service().validate_token(token)
    await get_project_service().require_access(token, project_id)
    return TokenUser(**user)


@router.get("/projects/{project_id}/tasks", response_model=TaskListResponse)
def list_tasks(
    project_id: str,
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    result_verdict: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    query = db.query(VulnVerifyTask).filter(VulnVerifyTask.project_id == project_id)
    if status:
        query = query.filter(VulnVerifyTask.status == status)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(VulnVerifyTask.name.ilike(pattern))
    normalized_result_verdict = (result_verdict or "").strip().lower()
    ordered_query = query.order_by(VulnVerifyTask.created_at.desc())
    if not normalized_result_verdict:
        total = ordered_query.count()
        tasks = ordered_query.offset(offset).limit(limit).all()
        return TaskListResponse(total=total, items=[build_response(task) for task in tasks])

    filtered_tasks = [
        task
        for task in ordered_query.all()
        if task_matches_result_verdict(task, normalized_result_verdict)
    ]
    total = len(filtered_tasks)
    page_items = filtered_tasks[offset:offset + limit]
    return TaskListResponse(total=total, items=[build_response(task) for task in page_items])


@router.get("/projects/{project_id}/service-config", response_model=ServiceConfigResponse)
def get_vuln_verify_service_config(
    project_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    del project_id
    config, row = get_service_config(db)
    effective_default_model, source = resolve_effective_default_model(db)
    return ServiceConfigResponse(
        config=config,
        effective_default_model=effective_default_model,
        source=source,
        updated_by=row.updated_by if row else None,
        updated_at=row.updated_at if row else None,
    )


@router.put("/projects/{project_id}/service-config", response_model=ServiceConfigResponse)
async def update_vuln_verify_service_config(
    project_id: str,
    payload: ServiceConfigUpsertRequest,
    user: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    del project_id
    config, row = save_service_config(db, payload.config.model_dump(), user)
    effective_default_model, source = resolve_effective_default_model(db)
    return ServiceConfigResponse(
        config=config,
        effective_default_model=effective_default_model,
        source=source,
        updated_by=row.updated_by,
        updated_at=row.updated_at,
    )


@router.get("/projects/{project_id}/stats", response_model=ProjectStatsResponse)
def get_project_stats(
    project_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    tasks = (
        db.query(VulnVerifyTask)
        .filter(VulnVerifyTask.project_id == project_id)
        .order_by(VulnVerifyTask.created_at.desc())
        .all()
    )
    return ProjectStatsResponse(**build_project_stats(tasks))


@router.post("/projects/{project_id}/tasks", response_model=TaskResponse)
async def create_vuln_verify_task(
    project_id: str,
    payload: TaskCreate,
    user: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return await create_task(db, project_id, payload, user)


@router.get("/projects/{project_id}/tasks/{task_id}", response_model=TaskDetailResponse)
def get_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    return build_detail(db, task)


@router.post("/projects/{project_id}/tasks/{task_id}/terminate", response_model=ActionResponse)
async def terminate_task(
    project_id: str,
    task_id: str,
    user: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    await request_terminate(db, task, user)
    return ActionResponse(status="ok", task_id=task_id, message="任务已请求取消")


@router.post("/projects/{project_id}/tasks/{task_id}/rerun", response_model=ActionResponse)
async def rerun(
    project_id: str,
    task_id: str,
    user: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    await rerun_task(db, task, user)
    return ActionResponse(status="ok", task_id=task_id, message="任务已重新排队")


@router.get("/projects/{project_id}/tasks/{task_id}/result", response_model=TaskResultResponse)
def get_result(
    project_id: str,
    task_id: str,
    limit: int = Query(500, ge=1, le=5000),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    summary = summarize_results(task)
    return TaskResultResponse(
        task_id=task.id,
        status=task.status,
        result_count=int(summary.get("result_count") or 0),
        results=load_results(task, limit=limit),
        summary=summary,
    )


@router.get("/projects/{project_id}/tasks/{task_id}/report-data", response_model=ReportDataResponse)
def get_report_data(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    return ReportDataResponse(**build_report_data(task))


@router.get("/projects/{project_id}/tasks/{task_id}/artifacts", response_model=ArtifactListResponse)
def get_artifacts(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    return ArtifactListResponse(
        task_id=task.id,
        output_dir=task.output_dir,
        items=[ArtifactEntry(**item) for item in list_artifacts(task)],
    )


@router.get("/projects/{project_id}/tasks/{task_id}/artifacts/content", response_model=ArtifactContentResponse)
def get_artifact_content(
    project_id: str,
    task_id: str,
    path: str = Query(...),
    offset: int = Query(0, ge=0),
    limit: int = Query(512 * 1024, ge=1, le=512 * 1024),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    payload = read_artifact(task, path, offset=offset, limit=limit)
    return ArtifactContentResponse(task_id=task.id, **payload)
