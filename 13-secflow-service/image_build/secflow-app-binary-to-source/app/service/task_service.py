"""B2S task orchestration and pi-re-agent status mapping."""

from __future__ import annotations

import hashlib
import os
import shutil
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import ConflictError, NotFoundError, ValidationError
from app.model import B2STask, B2STaskItem
from app.schemas import B2SOverallProgress, TaskCreate, TaskDetailResponse, TaskItemResponse, TaskResponse
from app.service.llm_provider import resolve_job_model
from app.service.pi_re_agent import get_pi_client
from app.service.security import app_task_item_root, app_task_root, ensure_path_in_project, project_root, safe_input_dir, safe_output_dir, validate_task_id

TERMINAL = {"success", "failed", "cancelled"}
PI_STATUS_MAP = {
    "queued": "queued",
    "running": "running",
    "completed": "success",
    "failed": "failed",
    "cancelled": "cancelled",
}

PI_PHASE_MAP = {
    "analyzing": "ida",
    "batching": "batching",
    "processing": "body",
    "merging": "merge",
}

PHASE_LABELS = {
    "queued": "排队中",
    "ida": "IDA 分析",
    "batching": "函数分批",
    "header": "头文件恢复",
    "body": "函数体恢复",
    "merge": "结果合并",
    "completed": "已完成",
    "failed": "失败",
    "cancelled": "已取消",
}


def generate_task_id(db: Session, project_id: str) -> str:
    for _ in range(10):
        task_id = uuid4().hex[:16]
        exists = db.query(B2STask.id).filter(B2STask.project_id == project_id, B2STask.id == task_id).first()
        if not exists:
            return task_id
    raise ConflictError("无法生成唯一B2S任务ID，请重试")


def configured_pi_workers() -> list[str]:
    cfg = get_config().pi_re_agent
    workers = [url.rstrip("/") for url in (cfg.worker_urls or []) if url and url.strip()]
    return workers or [cfg.base_url.rstrip("/")]


async def choose_pi_worker(db: Session, task_id: str, sequence_no: int) -> str:
    """Pick a pi-re-agent worker with simple worker affinity.

    The primary signal is the worker's own queued/running job count, which also
    covers jobs created before this B2S release.  The DB count is a cheap local
    supplement, and the stable hash is only a deterministic tie breaker.
    """
    workers = configured_pi_workers()
    if len(workers) == 1:
        return workers[0]
    counts = {worker: 0 for worker in workers}

    for worker in workers:
        try:
            jobs = await get_pi_client(worker).list_jobs()
            counts[worker] += sum(1 for job in jobs if job.get("status") in {"queued", "running"})
        except Exception:
            # Avoid placing new work on an unreachable worker.
            counts[worker] += 1_000_000

    active_items = db.query(B2STaskItem).filter(B2STaskItem.status.in_(["queued", "running"])).all()
    for active_item in active_items:
        worker_url = str((active_item.extra_metadata or {}).get("pi_worker_url") or "").rstrip("/")
        if worker_url in counts:
            counts[worker_url] += 1
    salt = int(hashlib.sha256(f"{task_id}:{sequence_no}".encode("utf-8")).hexdigest(), 16)
    return min(enumerate(workers), key=lambda item: (counts[item[1]], (item[0] - salt) % len(workers)))[1]


def item_pi_worker_url(item: B2STaskItem) -> str | None:
    worker_url = str((item.extra_metadata or {}).get("pi_worker_url") or "").strip()
    return worker_url.rstrip("/") or None


def prepare_input_file(project_id: str, task_id: str, sequence_no: int, source_path: Path) -> Path:
    input_dir = safe_input_dir(project_id, task_id, sequence_no)
    target_path = input_dir.joinpath(source_path.name).resolve()
    if not target_path.is_relative_to(input_dir):
        raise ValidationError("输入文件路径不合法")
    if source_path.resolve() != target_path:
        shutil.copy2(source_path, target_path)
    return target_path


async def create_task(db: Session, project_id: str, req: TaskCreate, created_by: str | None) -> TaskResponse:
    if not req.elf_tasks:
        raise ValidationError("elf_tasks不能为空")

    task_id = validate_task_id(req.task_id) if req.task_id else generate_task_id(db, project_id)
    if db.query(B2STask).filter(B2STask.project_id == project_id, B2STask.id == task_id).first():
        raise ConflictError("B2S任务ID已存在")

    task = B2STask(
        id=task_id,
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
    llm_provider_key = (req.llm_provider_key or "").strip() or None
    job_model = await resolve_job_model(llm_provider_key)
    job_concurrency = req.concurrency if req.concurrency and req.concurrency > 0 else pi_cfg.concurrency
    for idx, elf in enumerate(req.elf_tasks, start=1):
        source_elf_path = ensure_path_in_project(project_id, elf.elf_path, must_be_file=True)
        input_elf_path = prepare_input_file(project_id, task.id, idx, source_elf_path)
        item = B2STaskItem(
            id=uuid4().hex[:16],
            task_id=task.id,
            project_id=project_id,
            sequence_no=idx,
            elf_path=str(input_elf_path),
            output_dir=str(safe_output_dir(project_id, task.id, idx, elf.output_subdir)),
            status="pending",
        )
        worker_url = await choose_pi_worker(db, task.id, idx)
        item.extra_metadata = {
            **(elf.metadata or {}),
            "file_list": elf.file_list or [],
            "source_elf_path": str(source_elf_path),
            "llm_provider_key": llm_provider_key,
            "concurrency": job_concurrency,
            "pi_worker_url": worker_url,
        }
        item.phase = "queued"
        item.progress = build_item_progress(item, {"status": "queued", "phase": "queued", "progress": {}})
        db.add(item)
        db.flush()

        try:
            job = await get_pi_client(worker_url).create_job({
                "target": item.elf_path,
                "output_dir": item.output_dir,
                "batch_size": pi_cfg.batch_size,
                "max_retries": pi_cfg.max_retries,
                "model": job_model,
                "functions": elf.file_list or None,
                "clean": False,
                "engine": pi_cfg.engine,
                "concurrency": job_concurrency,
            })
            item.pi_job_id = job.get("id")
            item.status = map_pi_status(job.get("status"))
            item.phase = map_pi_phase(job.get("phase"), job.get("status"))
            item.progress = build_item_progress(item, job)
        except Exception as exc:
            item.status = "failed"
            item.phase = "failed"
            item.progress = build_item_progress(item, {"status": "failed", "phase": "failed", "progress": {}, "error": str(exc)})
            item.failure_type = "pi-re-agent"
            item.error_reason = str(exc)
            item.finished_at = datetime.utcnow()
    recompute_task_status(db, task)
    db.commit()
    db.refresh(task)
    return build_task_response(db, task)


async def sync_task(db: Session, task: B2STask) -> None:
    changed = False
    items = query_items(db, task.id)
    for item in items:
        if not item.pi_job_id or item.status in TERMINAL:
            continue
        job = await get_pi_client(item_pi_worker_url(item)).get_job(item.pi_job_id)
        if job is None:
            item.status = "failed"
            item.failure_type = "pi-re-agent"
            item.error_reason = "pi-re-agent job not found"
            item.finished_at = datetime.utcnow()
            changed = True
            continue
        new_status = map_pi_status(job.get("status"))
        new_phase = map_pi_phase(job.get("phase"), job.get("status"))
        new_progress = build_item_progress(item, job)
        if item.status != new_status:
            item.status = new_status
            changed = True
        if item.phase != new_phase:
            item.phase = new_phase
            changed = True
        if item.progress != new_progress:
            item.progress = new_progress
            changed = True
        if new_status == "running" and item.started_at is None:
            item.started_at = datetime.utcnow()
        if new_status in TERMINAL and item.finished_at is None:
            item.finished_at = datetime.utcnow()
        if new_status == "success":
            output = job.get("output") or {}
            item.generated_files = [p for p in [output.get("c"), output.get("h"), output.get("asm")] if p]
        if new_status == "failed":
            item.phase = "failed"
            item.failure_type = "pi-re-agent"
            item.error_reason = job.get("error")
        changed = True
    if changed:
        recompute_task_status(db, task)
        db.commit()
        db.refresh(task)


async def terminate_task(db: Session, task: B2STask) -> None:
    for item in query_items(db, task.id):
        if item.status in TERMINAL:
            continue
        if item.pi_job_id:
            await get_pi_client(item_pi_worker_url(item)).cancel_job(item.pi_job_id)
        item.status = "cancelled"
        item.phase = "cancelled"
        item.progress = build_item_progress(item, {"status": "cancelled", "phase": "cancelled", "progress": item.progress})
        item.finished_at = datetime.utcnow()
    recompute_task_status(db, task)
    db.commit()


def clean_item_output_dir(project_id: str, task_id: str, sequence_no: int, output_dir: str) -> Path:
    """Remove and recreate an item's output directory, preserving input files."""
    item_root = app_task_item_root(project_id, task_id, sequence_no)
    root = project_root(project_id)
    expected_output_root = item_root.joinpath("output").resolve()
    resolved_output = Path(output_dir).resolve()
    if not resolved_output.is_relative_to(root):
        raise ValidationError("输出目录不在项目目录内，拒绝清理")
    if not resolved_output.is_relative_to(item_root):
        raise ValidationError("输出目录不在任务项目录内，拒绝清理")
    if not resolved_output.is_relative_to(expected_output_root):
        raise ValidationError("仅允许清理output目录，拒绝清理input或其他目录")
    if resolved_output.exists():
        if not resolved_output.is_dir():
            raise ValidationError("输出路径不是目录，拒绝清理")
        shutil.rmtree(resolved_output)
    os.makedirs(resolved_output, exist_ok=True)
    return resolved_output


async def delete_task(db: Session, task: B2STask) -> None:
    """Delete a B2S task record and its complete task-id filesystem tree.

    Files are stored under ``<project_root>/<app_root_name>/<task_id>``.  Only
    that directory is removed; source files selected from elsewhere in the
    project are intentionally preserved.
    """
    items = query_items(db, task.id)
    for item in items:
        if item.pi_job_id and item.status not in TERMINAL:
            try:
                await get_pi_client(item_pi_worker_url(item)).cancel_job(item.pi_job_id)
            except Exception:
                # Deletion should not be blocked by a stale/unreachable upstream
                # job.  DB rows and the task workspace are still removed below.
                pass

    task_dir = app_task_root(task.project_id, task.id)
    root = project_root(task.project_id)
    if not task_dir.is_relative_to(root):
        raise ValidationError("B2S任务目录不合法")
    if task_dir.exists():
        if not task_dir.is_dir():
            raise ValidationError("B2S任务路径不是目录，拒绝删除")
        shutil.rmtree(task_dir)

    for item in items:
        db.delete(item)
    db.delete(task)
    db.commit()


async def rerun_task(db: Session, task: B2STask, *, clean_output: bool = True, cancel_running: bool = True) -> None:
    """Fully rerun all items of a task while keeping taskId and input files."""
    pi_cfg = get_config().pi_re_agent
    items = query_items(db, task.id)
    if not items:
        raise NotFoundError("任务没有可重跑的任务项")
    selected_provider_keys = [
        str((i.extra_metadata or {}).get("llm_provider_key") or "").strip()
        for i in items
        if str((i.extra_metadata or {}).get("llm_provider_key") or "").strip()
    ]
    job_model = await resolve_job_model(selected_provider_keys[0] if selected_provider_keys else None)

    for item in items:
        if cancel_running and item.pi_job_id and item.status not in TERMINAL:
            try:
                await get_pi_client(item_pi_worker_url(item)).cancel_job(item.pi_job_id)
            except Exception:
                pass

        if clean_output:
            item.output_dir = str(clean_item_output_dir(task.project_id, task.id, item.sequence_no, item.output_dir))

        item_concurrency = int((item.extra_metadata or {}).get("concurrency") or pi_cfg.concurrency)
        worker_url = await choose_pi_worker(db, task.id, item.sequence_no)
        metadata = item.extra_metadata or {}
        metadata["pi_worker_url"] = worker_url
        item.extra_metadata = metadata
        item.status = "queued"
        item.phase = "queued"
        item.progress = build_item_progress(item, {"status": "queued", "phase": "queued", "progress": {}})
        item.failure_type = None
        item.error_reason = None
        item.generated_files = []
        item.started_at = None
        item.finished_at = None
        db.flush()

        try:
            job = await get_pi_client(worker_url).create_job({
                "target": item.elf_path,
                "output_dir": item.output_dir,
                "batch_size": pi_cfg.batch_size,
                "max_retries": pi_cfg.max_retries,
                "model": job_model,
                "functions": (item.extra_metadata or {}).get("file_list") or None,
                "clean": True,
                "engine": pi_cfg.engine,
                "concurrency": item_concurrency,
            })
            item.pi_job_id = job.get("id")
            item.status = map_pi_status(job.get("status"))
            item.phase = map_pi_phase(job.get("phase"), job.get("status"))
            item.progress = build_item_progress(item, job)
        except Exception as exc:
            item.pi_job_id = None
            item.status = "failed"
            item.phase = "failed"
            item.progress = build_item_progress(item, {"status": "failed", "phase": "failed", "progress": {}, "error": str(exc)})
            item.failure_type = "pi-re-agent"
            item.error_reason = str(exc)
            item.finished_at = datetime.utcnow()
    recompute_task_status(db, task)
    db.commit()


async def retry_task(db: Session, task: B2STask, item_ids: list[str] | None = None) -> None:
    pi_cfg = get_config().pi_re_agent
    items = query_items(db, task.id)
    selected = [i for i in items if item_ids is None or i.id in item_ids]
    selected_provider_keys = [
        str((i.extra_metadata or {}).get("llm_provider_key") or "").strip()
        for i in selected
        if str((i.extra_metadata or {}).get("llm_provider_key") or "").strip()
    ]
    job_model = await resolve_job_model(selected_provider_keys[0] if selected_provider_keys else None)
    if not selected:
        raise NotFoundError("未找到可重试的任务项")
    for item in selected:
        if item.status not in {"failed", "cancelled"}:
            continue
        item_concurrency = int((item.extra_metadata or {}).get("concurrency") or pi_cfg.concurrency)
        worker_url = await choose_pi_worker(db, task.id, item.sequence_no)
        metadata = item.extra_metadata or {}
        metadata["pi_worker_url"] = worker_url
        item.extra_metadata = metadata
        job = await get_pi_client(worker_url).create_job({
            "target": item.elf_path,
            "output_dir": item.output_dir,
            "batch_size": pi_cfg.batch_size,
            "max_retries": pi_cfg.max_retries,
            "model": job_model,
            "functions": (item.extra_metadata or {}).get("file_list") or None,
            "clean": True,
            "engine": pi_cfg.engine,
            "concurrency": item_concurrency,
        })
        item.pi_job_id = job.get("id")
        item.status = map_pi_status(job.get("status"))
        item.phase = map_pi_phase(job.get("phase"), job.get("status"))
        item.progress = build_item_progress(item, job)
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


def map_pi_phase(raw_phase: str | None, status: str | None = None) -> str:
    mapped_status = map_pi_status(status)
    if mapped_status in {"success", "failed", "cancelled"}:
        return {"success": "completed", "failed": "failed", "cancelled": "cancelled"}[mapped_status]
    if mapped_status == "queued":
        return "queued"
    return PI_PHASE_MAP.get(raw_phase or "", "body" if mapped_status == "running" else "queued")


def phase_label(phase: str | None) -> str:
    return PHASE_LABELS.get(phase or "", phase or "-")


def _safe_percent(done: int | float | None, total: int | float | None) -> float | None:
    if total in (None, 0) or done is None:
        return None
    return round(max(0.0, min(100.0, float(done) * 100.0 / float(total))), 2)


def _file_size(path: str | None) -> int | None:
    try:
        if path and os.path.isfile(path):
            return os.path.getsize(path)
    except OSError:
        return None
    return None


def build_item_progress(item: B2STaskItem, job: dict) -> dict:
    raw_progress = job.get("progress") if isinstance(job.get("progress"), dict) else {}
    raw_phase = job.get("phase")
    status = map_pi_status(job.get("status"))
    phase = map_pi_phase(raw_phase, job.get("status"))
    total_batches = raw_progress.get("total_batches")
    completed_batches = raw_progress.get("completed_batches") or 0
    total_functions = raw_progress.get("total_functions")
    completed_functions = raw_progress.get("completed_functions")
    total_bytes = raw_progress.get("total_bytes") or raw_progress.get("total_binary_bytes") or _file_size(item.elf_path)

    if status == "success":
        if total_batches is not None:
            completed_batches = total_batches
        elif completed_batches == 0:
            completed_batches = 1
        if total_functions is not None:
            completed_functions = total_functions

    if completed_functions is None and total_functions and total_batches:
        completed_functions = int(float(total_functions) * float(completed_batches) / float(total_batches))
    completed_bytes = raw_progress.get("completed_bytes")
    batch_percent = _safe_percent(completed_batches, total_batches)
    if status == "success" and total_bytes is not None:
        completed_bytes = total_bytes
    elif completed_bytes is None and total_bytes and batch_percent is not None:
        completed_bytes = int(float(total_bytes) * batch_percent / 100.0)
    percent = _safe_percent(completed_functions, total_functions) or batch_percent or _safe_percent(completed_bytes, total_bytes)
    if status == "success":
        percent = 100.0
    message = raw_progress.get("message") or job.get("error") or phase_label(phase)
    return {
        "phase": phase,
        "raw_phase": raw_phase,
        "phase_label": phase_label(phase),
        "message": message,
        "total_functions": total_functions,
        "completed_functions": completed_functions,
        "total_bytes": total_bytes,
        "completed_bytes": completed_bytes,
        "total_batches": total_batches,
        "completed_batches": completed_batches,
        "current_batch": raw_progress.get("current_batch"),
        "current_attempt": raw_progress.get("current_attempt"),
        "current_function": raw_progress.get("current_function"),
        "percent": percent,
        "bytes_percent": _safe_percent(completed_bytes, total_bytes),
        "batches_percent": batch_percent,
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }


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
    raw_items = query_items(db, task.id)
    items = [
        TaskItemResponse(
            id=i.id,
            sequence_no=i.sequence_no,
            elf_path=i.elf_path,
            output_dir=i.output_dir,
            status=i.status,
            phase=i.phase,
            phase_label=phase_label(i.phase),
            phase_message=(i.progress or {}).get("message"),
            progress=i.progress or None,
            failure_type=i.failure_type,
            error_reason=i.error_reason,
            generated_files=i.generated_files,
            started_at=i.started_at,
            finished_at=i.finished_at,
        )
        for i in raw_items
    ]
    return TaskDetailResponse(**base, overall_progress=build_overall_progress(raw_items), items=items)


def build_overall_progress(items: list[B2STaskItem]) -> B2SOverallProgress:
    total_items = len(items)
    completed_items = sum(1 for item in items if item.status in TERMINAL)
    phase_summary: dict[str, int] = {}
    total_functions = 0
    completed_functions = 0
    total_bytes = 0
    completed_bytes = 0
    total_batches = 0
    completed_batches = 0
    has_functions = has_bytes = has_batches = False
    for item in items:
        phase = item.phase or (item.progress or {}).get("phase") or item.status
        phase_summary[phase] = phase_summary.get(phase, 0) + 1
        progress = item.progress or {}
        if progress.get("total_functions") is not None:
            has_functions = True
            total_functions += int(progress.get("total_functions") or 0)
            completed_functions += int(progress.get("completed_functions") or 0)
        if progress.get("total_bytes") is not None:
            has_bytes = True
            total_bytes += int(progress.get("total_bytes") or 0)
            completed_bytes += int(progress.get("completed_bytes") or 0)
        if progress.get("total_batches") is not None:
            has_batches = True
            total_batches += int(progress.get("total_batches") or 0)
            completed_batches += int(progress.get("completed_batches") or 0)
    percent = _safe_percent(completed_functions, total_functions) if has_functions else None
    if percent is None and has_batches:
        percent = _safe_percent(completed_batches, total_batches)
    if percent is None and has_bytes:
        percent = _safe_percent(completed_bytes, total_bytes)
    if percent is None:
        percent = _safe_percent(completed_items, total_items)
    return B2SOverallProgress(
        total_items=total_items,
        completed_items=completed_items,
        total_functions=total_functions if has_functions else None,
        completed_functions=completed_functions if has_functions else None,
        total_bytes=total_bytes if has_bytes else None,
        completed_bytes=completed_bytes if has_bytes else None,
        total_batches=total_batches if has_batches else None,
        completed_batches=completed_batches if has_batches else None,
        percent=percent,
        phase_summary=phase_summary,
    )
