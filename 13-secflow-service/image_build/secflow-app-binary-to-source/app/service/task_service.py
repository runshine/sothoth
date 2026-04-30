"""B2S task orchestration and pi-re-agent status mapping."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import ConflictError, NotFoundError, ValidationError
from app.model import B2STask, B2STaskItem
from app.schemas import TaskCreate, TaskDetailResponse, TaskItemResponse, TaskResponse
from app.service.llm_provider import resolve_job_model
from app.service.pi_re_agent import get_pi_client
from app.service.security import ensure_path_in_project, safe_output_dir

TERMINAL = {"success", "failed", "cancelled"}
PI_STATUS_MAP = {
    "queued": "queued",
    "running": "running",
    "completed": "success",
    "failed": "failed",
    "cancelled": "cancelled",
}


async def create_task(db: Session, project_id: str, req: TaskCreate, created_by: str | None) -> TaskResponse:
    if not req.elf_tasks:
        raise ValidationError("elf_tasks不能为空")

    task = B2STask(
        id=uuid4().hex[:16],
        project_id=project_id,
        name=req.name,
        description=req.description,
        priority=req.priority,
        status="pending",
        created_by=created_by,
    )
    task.tags = req.tags
    db.add(task)
    db.flush()

    pi_cfg = get_config().pi_re_agent
    job_model = await resolve_job_model()
    client = get_pi_client()
    for idx, elf in enumerate(req.elf_tasks, start=1):
        item = B2STaskItem(
            id=uuid4().hex[:16],
            task_id=task.id,
            project_id=project_id,
            sequence_no=idx,
            elf_path=str(ensure_path_in_project(project_id, elf.elf_path, must_be_file=True)),
            output_dir=str(safe_output_dir(project_id, task.id, idx, elf.output_subdir)),
            status="pending",
        )
        item.extra_metadata = {**(elf.metadata or {}), "file_list": elf.file_list or []}
        db.add(item)
        db.flush()

        try:
            job = await client.create_job({
                "target": item.elf_path,
                "output_dir": item.output_dir,
                "batch_size": pi_cfg.batch_size,
                "max_retries": pi_cfg.max_retries,
                "model": job_model,
                "functions": elf.file_list or None,
                "clean": False,
                "engine": pi_cfg.engine,
                "concurrency": pi_cfg.concurrency,
            })
            item.pi_job_id = job.get("id")
            item.status = map_pi_status(job.get("status"))
        except Exception as exc:
            item.status = "failed"
            item.failure_type = "pi-re-agent"
            item.error_reason = str(exc)
            item.finished_at = datetime.utcnow()
    recompute_task_status(db, task)
    db.commit()
    db.refresh(task)
    return build_task_response(db, task)


async def sync_task(db: Session, task: B2STask) -> None:
    client = get_pi_client()
    changed = False
    items = query_items(db, task.id)
    for item in items:
        if not item.pi_job_id or item.status in TERMINAL:
            continue
        job = await client.get_job(item.pi_job_id)
        if job is None:
            item.status = "failed"
            item.failure_type = "pi-re-agent"
            item.error_reason = "pi-re-agent job not found"
            item.finished_at = datetime.utcnow()
            changed = True
            continue
        new_status = map_pi_status(job.get("status"))
        if item.status != new_status:
            item.status = new_status
            changed = True
        if new_status == "running" and item.started_at is None:
            item.started_at = datetime.utcnow()
        if new_status in TERMINAL and item.finished_at is None:
            item.finished_at = datetime.utcnow()
        if new_status == "success":
            output = job.get("output") or {}
            item.generated_files = [p for p in [output.get("c"), output.get("h"), output.get("asm")] if p]
        if new_status == "failed":
            item.failure_type = "pi-re-agent"
            item.error_reason = job.get("error")
        changed = True
    if changed:
        recompute_task_status(db, task)
        db.commit()
        db.refresh(task)


async def terminate_task(db: Session, task: B2STask) -> None:
    client = get_pi_client()
    for item in query_items(db, task.id):
        if item.status in TERMINAL:
            continue
        if item.pi_job_id:
            await client.cancel_job(item.pi_job_id)
        item.status = "cancelled"
        item.finished_at = datetime.utcnow()
    recompute_task_status(db, task)
    db.commit()


async def retry_task(db: Session, task: B2STask, item_ids: list[str] | None = None) -> None:
    pi_cfg = get_config().pi_re_agent
    job_model = await resolve_job_model()
    client = get_pi_client()
    items = query_items(db, task.id)
    selected = [i for i in items if item_ids is None or i.id in item_ids]
    if not selected:
        raise NotFoundError("未找到可重试的任务项")
    for item in selected:
        if item.status not in {"failed", "cancelled"}:
            continue
        job = await client.create_job({
            "target": item.elf_path,
            "output_dir": item.output_dir,
            "batch_size": pi_cfg.batch_size,
            "max_retries": pi_cfg.max_retries,
            "model": job_model,
            "functions": (item.extra_metadata or {}).get("file_list") or None,
            "clean": True,
            "engine": pi_cfg.engine,
            "concurrency": pi_cfg.concurrency,
        })
        item.pi_job_id = job.get("id")
        item.status = map_pi_status(job.get("status"))
        item.failure_type = None
        item.error_reason = None
        item.generated_files = []
        item.started_at = None
        item.finished_at = None
    recompute_task_status(db, task)
    db.commit()


def get_task_or_404(db: Session, project_id: str, task_id: str) -> B2STask:
    task = db.query(B2STask).filter(B2STask.project_id == project_id, B2STask.id == task_id).first()
    if not task:
        raise NotFoundError("B2S任务不存在")
    return task


def query_items(db: Session, task_id: str) -> list[B2STaskItem]:
    return db.query(B2STaskItem).filter(B2STaskItem.task_id == task_id).order_by(B2STaskItem.sequence_no.asc()).all()


def map_pi_status(status: str | None) -> str:
    return PI_STATUS_MAP.get(status or "queued", status or "queued")


def recompute_task_status(db: Session, task: B2STask) -> None:
    items = query_items(db, task.id)
    counts = count_status(items)
    total = len(items)
    if total == 0:
        task.status = "pending"
    elif counts["running_items"] > 0:
        task.status = "running"
    elif counts["queued_items"] > 0 or counts["pending_items"] > 0:
        # 前端执行队列页面按 task.status=pending 查询等待/排队任务；
        # item 级别仍保留 queued_items 统计。
        task.status = "pending"
    elif counts["success_items"] == total:
        task.status = "completed"
    elif counts["cancelled_items"] == total:
        task.status = "cancelled"
    elif counts["failed_items"] == total:
        task.status = "failed"
    elif counts["success_items"] > 0 and counts["failed_items"] + counts["cancelled_items"] > 0:
        task.status = "partial"
    else:
        task.status = "pending"
    task.updated_at = datetime.utcnow()


def count_status(items: list[B2STaskItem]) -> dict[str, int]:
    return {
        "pending_items": sum(1 for i in items if i.status == "pending"),
        "queued_items": sum(1 for i in items if i.status == "queued"),
        "running_items": sum(1 for i in items if i.status == "running"),
        "success_items": sum(1 for i in items if i.status == "success"),
        "partial_items": sum(1 for i in items if i.status == "partial"),
        "failed_items": sum(1 for i in items if i.status == "failed"),
        "cancelled_items": sum(1 for i in items if i.status == "cancelled"),
    }


def build_task_response(db: Session, task: B2STask) -> TaskResponse:
    items = query_items(db, task.id)
    counts = count_status(items)
    return TaskResponse(
        id=task.id,
        project_id=task.project_id,
        name=task.name,
        status=task.status,
        total_items=len(items),
        created_at=task.created_at,
        updated_at=task.updated_at,
        **counts,
    )


def build_task_detail(db: Session, task: B2STask) -> TaskDetailResponse:
    base = build_task_response(db, task).model_dump()
    items = [
        TaskItemResponse(
            id=i.id,
            sequence_no=i.sequence_no,
            elf_path=i.elf_path,
            output_dir=i.output_dir,
            status=i.status,
            failure_type=i.failure_type,
            error_reason=i.error_reason,
            generated_files=i.generated_files,
            started_at=i.started_at,
            finished_at=i.finished_at,
        )
        for i in query_items(db, task.id)
    ]
    return TaskDetailResponse(**base, items=items)
