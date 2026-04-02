"""Task API routes."""

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import ensure_project_access, get_current_subject
from app.celery_app import celery_app
from app.model import ItemTaskStatus, get_db
from app.schemas import (
    ActionResponse,
    BinaryToSourceTaskCreateRequest,
    BinaryToSourceTaskPatchRequest,
    RetryRequest,
    SuccessResponse,
    TaskCreatedResponse,
    TaskDetailResponse,
    TaskListResponse,
)
from app.services.task_service import (
    create_task,
    delete_task,
    get_task,
    list_tasks,
    manual_retry,
    mark_task_cancelling,
    patch_task,
)


router = APIRouter(prefix="/api/app/binary-to-source", tags=["BinaryToSource"])


def _task_to_response(task) -> dict:
    return task.to_dict()


def _task_detail_to_response(task) -> dict:
    payload = task.to_dict()
    payload["items"] = [item.to_dict() for item in sorted(task.items, key=lambda x: x.sequence_no)]
    return payload


@router.get("/health")
async def health_check():
    return {"status": "ok", "service": "secflow-app-binary-to-source-manager"}


@router.get("/ready")
async def ready_check():
    return {"status": "ready", "service": "secflow-app-binary-to-source-manager"}


@router.post(
    "/projects/{project_id}/tasks",
    response_model=TaskCreatedResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_task_api(
    project_id: str,
    request: BinaryToSourceTaskCreateRequest,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    subject, token = subject_and_token
    await ensure_project_access(project_id, token)

    task = create_task(
        db,
        project_id=project_id,
        name=request.name,
        description=request.description,
        priority=request.priority,
        tags=request.tags,
        created_by=str(subject.get("id") or subject.get("username") or "unknown"),
        elf_tasks=[item.model_dump() for item in request.elf_tasks],
    )
    return TaskCreatedResponse(message="任务创建成功", task_id=task.id)


@router.get("/projects/{project_id}/tasks", response_model=TaskListResponse)
async def list_tasks_api(
    project_id: str,
    status_filter: str | None = Query(None, alias="status"),
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=200),
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    total, items = list_tasks(db, project_id, status_filter, offset, limit)
    return TaskListResponse(total=total, items=[_task_to_response(item) for item in items])


@router.get("/projects/{project_id}/tasks/{task_id}", response_model=TaskDetailResponse)
async def get_task_api(
    project_id: str,
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    task = get_task(db, project_id, task_id)
    return TaskDetailResponse(**_task_detail_to_response(task))


@router.patch("/projects/{project_id}/tasks/{task_id}", response_model=TaskDetailResponse)
async def patch_task_api(
    project_id: str,
    task_id: str,
    request: BinaryToSourceTaskPatchRequest,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    task = patch_task(db, project_id, task_id, request.model_dump(exclude_unset=True))
    return TaskDetailResponse(**_task_detail_to_response(task))


@router.delete("/projects/{project_id}/tasks/{task_id}", response_model=SuccessResponse)
async def delete_task_api(
    project_id: str,
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    delete_task(db, project_id, task_id)
    return SuccessResponse(message="任务删除成功")


@router.post("/projects/{project_id}/tasks/{task_id}/terminate", response_model=ActionResponse)
async def terminate_task_api(
    project_id: str,
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    task = mark_task_cancelling(db, project_id, task_id)

    for item in task.items:
        if item.status == ItemTaskStatus.QUEUED and item.celery_task_id:
            celery_app.control.revoke(item.celery_task_id, terminate=False)
        elif item.status == ItemTaskStatus.RUNNING and item.celery_task_id:
            celery_app.control.revoke(item.celery_task_id, terminate=True, signal="SIGTERM")

    return ActionResponse(message="任务终止请求已提交", task_id=task.id)


@router.post("/projects/{project_id}/tasks/{task_id}/retry", response_model=ActionResponse)
async def retry_task_api(
    project_id: str,
    task_id: str,
    request: RetryRequest,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    task, _ = manual_retry(db, project_id, task_id, request.item_ids)
    return ActionResponse(message="任务已加入重试队列", task_id=task.id)
