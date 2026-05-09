"""B2S task orchestration and pi-re-agent status mapping."""

from __future__ import annotations

import hashlib
import os
import shutil
from datetime import datetime
import re
from pathlib import Path
from uuid import uuid4

from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import ConflictError, NotFoundError, UpstreamError, ValidationError
from app.model import B2STask, B2STaskItem
from app.schemas import AdvancedBatch, AdvancedFile, AdvancedRun, B2SOverallProgress, ReviewAnalyticsAttempt, ReviewAnalyticsFunction, ReviewAnalyticsFunctionAttempt, ReviewAnalyticsIssue, ReviewAnalyticsRadar, ReviewAnalyticsResponse, ReviewAnalyticsSummary, TaskCreate, TaskDetailResponse, TaskItemAdvancedResponse, TaskItemResponse, TaskResponse
from app.service.llm_provider import resolve_job_model
from app.service.pi_re_agent import get_pi_client
from app.service.security import app_task_item_root, app_task_root, ensure_path_in_project, project_root, safe_input_dir, safe_output_dir, validate_task_id
from app.time_utils import isoformat_local, now_local

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
    "header_synthesis": "header",
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


def _task_origin_payload(task: B2STask) -> dict:
    task_origin_type = str(task.task_origin_type or "").strip() or "manual"
    parent_task_type = str(task.parent_task_type or "").strip() or None
    origin_label = (
        "二进制安全-源码扫描"
        if task_origin_type == "binary_security" and parent_task_type == "source"
        else "二进制安全-二进制类扫描"
        if task_origin_type == "binary_security"
        else "手动任务"
    )
    return {
        "task_origin_type": task_origin_type,
        "parent_project_id": task.parent_project_id,
        "parent_task_id": task.parent_task_id,
        "parent_task_type": parent_task_type,
        "parent_stage_name": task.parent_stage_name,
        "parent_stage_item_id": task.parent_stage_item_id,
        "parent_stage_item_key": task.parent_stage_item_key,
        "origin_label": origin_label,
        "parent_task_display": task.parent_task_id,
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
        task_origin_type=str(req.task_origin_type or "").strip() or "manual",
        parent_project_id=req.parent_project_id,
        parent_task_id=req.parent_task_id,
        parent_task_type=req.parent_task_type,
        parent_stage_name=req.parent_stage_name,
        parent_stage_item_id=req.parent_stage_item_id,
        parent_stage_item_key=req.parent_stage_item_key,
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
    mode_engine_map = {"fast": "hybrid", "deep": "agent"}
    job_mode = req.mode or ({"hybrid": "fast", "agent": "deep"}.get(req.engine or "") if req.engine else None)
    job_engine = mode_engine_map.get(job_mode or "") or req.engine or pi_cfg.engine
    job_mode = job_mode or {"hybrid": "fast", "agent": "deep"}.get(job_engine)
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
            "task_origin_type": str(req.task_origin_type or "").strip() or "manual",
            "parent_project_id": req.parent_project_id,
            "parent_task_id": req.parent_task_id,
            "parent_task_type": req.parent_task_type,
            "parent_stage_name": req.parent_stage_name,
            "parent_stage_item_id": req.parent_stage_item_id,
            "parent_stage_item_key": req.parent_stage_item_key,
            "file_list": elf.file_list or [],
            "source_elf_path": str(source_elf_path),
            "llm_provider_key": llm_provider_key,
            "concurrency": job_concurrency,
            "mode": job_mode,
            "engine": job_engine,
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
                "engine": job_engine,
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
            item.finished_at = now_local()
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
        try:
            job = await get_pi_client(item_pi_worker_url(item)).get_job(item.pi_job_id)
        except UpstreamError as exc:
            # Do not let one stale/unreachable worker make the whole task detail
            # API return 502. Keep the item visible and let users rerun/delete it.
            item.failure_type = "pi-re-agent"
            item.error_reason = str(exc)
            item.progress = build_item_progress(item, {
                "status": item.status,
                "phase": item.phase,
                "progress": item.progress or {},
                "error": str(exc),
            })
            changed = True
            continue
        if job is None:
            item.status = "failed"
            item.failure_type = "pi-re-agent"
            item.error_reason = "pi-re-agent job not found"
            item.finished_at = now_local()
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
            item.started_at = now_local()
        if new_status in TERMINAL and item.finished_at is None:
            item.finished_at = now_local()
        if new_status == "success":
            output = job.get("output") or {}
            item.generated_files = build_generated_files(item, output)
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
        item.finished_at = now_local()
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
        item_engine = str((item.extra_metadata or {}).get("engine") or pi_cfg.engine).strip() or pi_cfg.engine
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
                "engine": item_engine,
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
            item.finished_at = now_local()
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
        item_engine = str((item.extra_metadata or {}).get("engine") or pi_cfg.engine).strip() or pi_cfg.engine
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
            "engine": item_engine,
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


def _safe_existing_file(path: Path, root: Path) -> str | None:
    try:
        resolved = path.resolve()
        resolved_root = root.resolve()
    except Exception:
        return None
    if not resolved.is_relative_to(resolved_root):
        return None
    if not resolved.is_file():
        return None
    return str(resolved)


def ida_decompiled_c_path(item: B2STaskItem, reference_path: str | None = None) -> str | None:
    """Return IDA's direct decompiled C output for an item if present."""
    output_root = Path(item.output_dir)
    stems: list[str] = []
    if reference_path:
        stems.append(Path(reference_path).stem)
    if item.elf_path:
        stems.append(Path(item.elf_path).stem)
    seen: set[str] = set()
    for stem in stems:
        if not stem or stem in seen:
            continue
        seen.add(stem)
        candidate = output_root / f".re_work_{stem}" / "ida_cache" / "ida_export" / "decompiled.c"
        existing = _safe_existing_file(candidate, output_root)
        if existing:
            return existing
    return None


def build_generated_files(item: B2STaskItem, output: dict | None) -> list[str]:
    output = output or {}
    ida_c = output.get("ida_c") or ida_decompiled_c_path(item, output.get("c"))
    return [p for p in [output.get("c"), output.get("h"), ida_c] if p]


def normalize_generated_files(item: B2STaskItem) -> list[str]:
    """Replace legacy .asm entries with IDA's direct decompiled.c for responses."""
    normalized: list[str] = []
    for path in item.generated_files:
        if Path(path).suffix.lower() == ".asm":
            ida_c = ida_decompiled_c_path(item, path)
            if ida_c:
                normalized.append(ida_c)
            continue
        normalized.append(path)
    return normalized


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
        "updated_at": isoformat_local(now_local()),
    }


def recompute_task_status(db: Session, task: B2STask) -> None:
    items = query_items(db, task.id)
    counts = count_status(items)
    total = len(items)
    if total == 0:
        task.status = "pending"
    elif counts["failed_items"] > 0 and counts["failed_items"] + counts["cancelled_items"] + counts["success_items"] == total:
        task.status = "partial" if counts["success_items"] > 0 else "failed"
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
    task.updated_at = now_local()


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


def task_mode_summary(items: list[B2STaskItem]) -> tuple[str | None, str | None]:
    modes: list[str] = []
    engine_mode_map = {"hybrid": "fast", "agent": "deep"}
    for item in items:
        metadata = item.extra_metadata or {}
        mode = str(metadata.get("mode") or "").strip()
        if not mode:
            mode = engine_mode_map.get(str(metadata.get("engine") or "").strip(), "")
        if mode and mode not in modes:
            modes.append(mode)
    if not modes:
        return None, None
    if len(modes) == 1:
        mode = modes[0]
        if mode == "deep":
            return mode, "深度模式"
        if mode == "fast":
            return mode, "快速模式"
        return mode, mode
    return "mixed", "混合模式"


def build_task_response(db: Session, task: B2STask) -> TaskResponse:
    items = query_items(db, task.id)
    counts = count_status(items)
    mode, mode_label = task_mode_summary(items)
    return TaskResponse(
        id=task.id,
        project_id=task.project_id,
        **_task_origin_payload(task),
        mode=mode,
        mode_label=mode_label,
        name=task.name,
        status=task.status,
        total_items=len(items),
        created_at=task.created_at,
        updated_at=task.updated_at,
        **counts,
    )


def get_task_item_or_404(db: Session, task: B2STask, item_id: str) -> B2STaskItem:
    item = db.query(B2STaskItem).filter(B2STaskItem.task_id == task.id, B2STaskItem.id == item_id).first()
    if item:
        return item
    if item_id.isdigit():
        item = db.query(B2STaskItem).filter(B2STaskItem.task_id == task.id, B2STaskItem.sequence_no == int(item_id)).first()
        if item:
            return item
    raise NotFoundError("B2S任务项不存在")


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
            generated_files=normalize_generated_files(i),
            started_at=i.started_at,
            finished_at=i.finished_at,
        )
        for i in raw_items
    ]
    return TaskDetailResponse(**base, overall_progress=build_overall_progress(raw_items), items=items)


ADVANCED_TEXT_EXTENSIONS = {".c", ".h", ".json", ".jsonl", ".md", ".txt", ".log", ".yaml", ".yml"}
ADVANCED_MAX_BYTES = 512 * 1024


def _advanced_kind(path: Path) -> str:
    name = path.name.lower()
    if name.startswith("batch_") and name.endswith(".c"):
        return "batch_source"
    if name.startswith("disasm_batch_") and name.endswith(".c"):
        return "batch_disasm"
    if "verdict" in name or "review" in name:
        return "review"
    if "session" in str(path).lower() or "prompt" in name:
        return "agent_session"
    if name.endswith(".json"):
        return "json"
    return path.suffix.lstrip(".") or "file"


def _safe_read_advanced_file(path: Path, base: Path, include_content: bool, metadata: dict | None = None) -> AdvancedFile | None:
    try:
        resolved = path.resolve()
        resolved.relative_to(base.resolve())
        if not resolved.is_file():
            return None
        size = resolved.stat().st_size
        content = None
        truncated = False
        if include_content and resolved.suffix.lower() in ADVANCED_TEXT_EXTENSIONS:
            raw = resolved.read_bytes()[:ADVANCED_MAX_BYTES + 1]
            truncated = len(raw) > ADVANCED_MAX_BYTES
            content = raw[:ADVANCED_MAX_BYTES].decode("utf-8", errors="replace")
        return AdvancedFile(
            name=resolved.name,
            path=str(resolved),
            kind=_advanced_kind(resolved),
            size=size,
            content=content,
            truncated=truncated,
            **(metadata or {}),
        )
    except Exception:
        return None


def _batch_no(path: Path) -> int | None:
    match = re.search(r"batch_(\d+)", str(path))
    return int(match.group(1)) if match else None


def _attempt_no(path: Path | str) -> int | None:
    match = re.search(r"attempt[_-]?(\d+)", str(path), re.IGNORECASE)
    return int(match.group(1)) if match else None


def _batch_label(no: int | None) -> str:
    return f"Batch {no:03d}" if no else "Batch"


def _stage4_meta(batch_no: int | None, *, section: str, section_order: int, round_label: str, round_order: int = 0, agent: str | None = None, role: str | None = None, attempt_no: int | None = None) -> dict:
    if batch_no:
        stage = f"阶段 4 · {_batch_label(batch_no)} 函数"
        stage_order = 4000 + batch_no
    else:
        stage = "阶段 4 · 全局执行会话"
        stage_order = 4998
    return {
        "stage": stage,
        "stage_order": stage_order,
        "section": section,
        "section_order": section_order,
        "round": round_label,
        "round_order": round_order,
        "agent": agent,
        "role": role,
        "batch_no": batch_no,
        "attempt_no": attempt_no,
    }


def _session_meta(path: Path, run_dir: Path, default_batch_no: int | None) -> dict:
    rel = str(path.relative_to(run_dir)) if path.is_relative_to(run_dir) else str(path)
    lower = rel.lower()
    batch_no = _batch_no(rel) or default_batch_no
    attempt_no = _attempt_no(rel)
    is_prompt = "system-prompt" in lower or path.name.lower().endswith("system-prompt.md")
    role = "System Prompt" if is_prompt else "JSONL 会话"
    if "header" in lower or "synth" in lower:
        return {
            "stage": "阶段 3 · 共享头文件合成",
            "stage_order": 3000,
            "section": "Header Agent",
            "section_order": 0,
            "round": f"第 {attempt_no} 轮" if attempt_no else "Header 会话",
            "round_order": attempt_no or 0,
            "agent": "header agent",
            "role": role,
            "batch_no": None,
            "attempt_no": attempt_no,
        }
    if "validator" in lower:
        return _stage4_meta(batch_no, section="评审", section_order=20, round_label=f"第 {attempt_no} 次评审" if attempt_no else "评审会话", round_order=attempt_no or 0, agent="validator agent", role=role, attempt_no=attempt_no)
    if "executor" in lower:
        return _stage4_meta(batch_no, section="执行", section_order=10, round_label="执行会话", round_order=0, agent="executor agent", role=role)
    return _stage4_meta(batch_no, section="其他会话", section_order=90, round_label=f"第 {attempt_no} 轮" if attempt_no else "Agent 会话", round_order=attempt_no or 0, agent="agent", role=role, attempt_no=attempt_no)


def _run_file_meta(path: Path) -> dict:
    name = path.name.lower()
    if name == "run_manifest.json":
        return {"stage": "阶段 0 · 运行配置", "stage_order": 0, "section": "文件", "section_order": 0, "round": "产物", "round_order": 0, "role": "运行配置"}
    if name == "batch_manifest.json":
        return {"stage": "阶段 2 · Batch 划分清单", "stage_order": 2000, "section": "文件", "section_order": 0, "round": "产物", "round_order": 0, "role": "Batch 清单"}
    if name == "results.json":
        return {"stage": "结果汇总", "stage_order": 6000, "section": "文件", "section_order": 0, "round": "产物", "round_order": 0, "role": "结果汇总"}
    if name == "preamble.h":
        return {"stage": "阶段 3 · 共享头文件", "stage_order": 3000, "section": "文件", "section_order": 0, "round": "产物", "round_order": 0, "role": "共享头文件"}
    return {"stage": "运行文件", "stage_order": 500, "section": "文件", "section_order": 0, "round": "产物", "round_order": 0}


def _ida_file_meta(path: Path) -> dict:
    return {"stage": "阶段 1 · IDA 分析缓存", "stage_order": 1000, "section": "文件", "section_order": 0, "round": "产物", "round_order": 0, "role": "IDA 缓存"}


def _collect_advanced_files(paths: list[Path], base: Path, include_content: bool) -> list[AdvancedFile]:
    files: list[AdvancedFile] = []
    for path in paths:
        file = _safe_read_advanced_file(path, base, include_content)
        if file:
            files.append(file)
    return files


def _mock_review_analytics(task_id: str, item_id: str) -> ReviewAnalyticsResponse:
    attempts = [
        ReviewAnalyticsAttempt(attempt_no=1, verdict="FAIL", total_functions=10, verified_functions=8, blocking_issues=3, semantic_score=68, confidence=64),
        ReviewAnalyticsAttempt(attempt_no=2, verdict="PASS", total_functions=10, verified_functions=10, blocking_issues=0, semantic_score=94, confidence=89),
    ]
    issues = [
        ReviewAnalyticsIssue(id="I1", label="Length Logic", function="sub_880", category="Validation", severity="blocking", introduced_attempt=1, resolved_attempt=2, status="resolved"),
        ReviewAnalyticsIssue(id="I2", label="Return Code", function="sub_880", category="Return", severity="blocking", introduced_attempt=1, resolved_attempt=2, status="resolved"),
        ReviewAnalyticsIssue(id="I3", label="Extra Check", function="sub_880", category="Validation", severity="major", introduced_attempt=1, resolved_attempt=2, status="resolved"),
    ]
    names = [".init_proc", "sub_880", "start", "sub_E74", "sub_E90", "sub_EC0", "sub_F00", "sub_F50", "sub_F60", ".term_proc"]
    matrix = [ReviewAnalyticsFunction(function=name, attempts=[ReviewAnalyticsFunctionAttempt(attempt_no=1, risk="critical" if name == "sub_880" else "passed", score=45 if name == "sub_880" else 86), ReviewAnalyticsFunctionAttempt(attempt_no=2, risk="warning" if name == "sub_E74" else "passed", score=80 if name == "sub_E74" else 95)]) for name in names]
    radar = [
        ReviewAnalyticsRadar(attempt_no=1, completeness=100, control_flow=70, return_semantics=55, input_validation=45, call_fidelity=94, type_struct_fidelity=88),
        ReviewAnalyticsRadar(attempt_no=2, completeness=100, control_flow=95, return_semantics=96, input_validation=96, call_fidelity=95, type_struct_fidelity=95),
    ]
    return ReviewAnalyticsResponse(task_id=task_id, item_id=item_id, summary=ReviewAnalyticsSummary(attempts=2, final_verdict="PASS", final_confidence=89, issue_closure_rate=1.0, residual_risk="low-medium", mock=True), attempts=attempts, issues=issues, function_matrix=matrix, radar=radar)


def _parse_review_file(file: AdvancedFile) -> dict:
    try:
        data = json.loads(file.content or "{}")
    except Exception:
        data = {}
    verdict = str(data.get("verdict") or "UNKNOWN").upper()
    issues = [str(issue) for issue in data.get("issues") or [] if str(issue).strip()]
    total = int(data.get("total_functions") or 0)
    verified = int(data.get("verified_functions") or 0)
    attempt_no = file.attempt_no or _attempt_no(file.name) or 0
    ratio = verified / total if total else (1 if verdict == "PASS" else 0)
    score = max(0, min(100, round(ratio * 100) - len(issues) * 8 + (0 if verdict == "PASS" else -8)))
    return {"attempt_no": attempt_no, "verdict": verdict, "issues": issues, "total": total, "verified": verified, "score": score}


def _review_issue_key(issue: str) -> tuple[str, str, str]:
    function_match = re.search(r"\b([A-Za-z_.][\w.]*)\s*:", issue)
    function_name = function_match.group(1) if function_match else "global"
    lower = issue.lower()
    if "return" in lower:
        category, label = "Return", "Return Code"
    elif "length" in lower:
        category, label = "Validation", "Length Logic"
    elif "hex_len" in lower or "validation" in lower:
        category, label = "Validation", "Extra Check"
    elif "call" in lower:
        category, label = "Call", "Call"
    elif "struct" in lower or "type" in lower:
        category, label = "Type", "Type"
    else:
        category, label = "Semantic", "Semantic"
    return function_name, category, label


def build_task_item_review_analytics(item: B2STaskItem, mock: bool = False) -> ReviewAnalyticsResponse:
    if mock:
        return _mock_review_analytics(item.task_id, item.id)
    advanced = build_task_item_advanced(item, include_content=True)
    review_files = [review for run in advanced.runs for batch in run.batches for review in batch.reviews]
    parsed = [_parse_review_file(file) for file in review_files]
    parsed = [entry for entry in parsed if entry["attempt_no"]]
    parsed.sort(key=lambda entry: entry["attempt_no"])
    if not parsed:
        return _mock_review_analytics(item.task_id, item.id)
    attempts = [ReviewAnalyticsAttempt(attempt_no=entry["attempt_no"], verdict=entry["verdict"], total_functions=entry["total"], verified_functions=entry["verified"], blocking_issues=len(entry["issues"]), semantic_score=entry["score"], confidence=max(0, min(100, entry["score"] + (10 if entry["verdict"] == "PASS" else -4)))) for entry in parsed]
    final = parsed[-1]
    final_keys = {_review_issue_key(issue) for issue in final["issues"]}
    first_seen: dict[tuple[str, str, str], tuple[str, int]] = {}
    for entry in parsed:
        for issue in entry["issues"]:
            first_seen.setdefault(_review_issue_key(issue), (issue, entry["attempt_no"]))
    issues: list[ReviewAnalyticsIssue] = []
    for idx, (key, (_, first_attempt)) in enumerate(first_seen.items(), start=1):
        function_name, category, label = key
        remaining = key in final_keys
        resolved_attempt = None if remaining else next((entry["attempt_no"] for entry in parsed if entry["attempt_no"] > first_attempt and key not in {_review_issue_key(candidate) for candidate in entry["issues"]}), None)
        issues.append(ReviewAnalyticsIssue(id=f"I{idx}", label=label, function=function_name, category=category, severity="blocking", introduced_attempt=first_attempt, resolved_attempt=resolved_attempt, status="remaining" if remaining else "resolved"))
    function_names = {issue.function for issue in issues}
    for run in advanced.runs:
        for batch in run.batches:
            source = (batch.source.content if batch.source else None) or (batch.review_snapshots[-1].content if batch.review_snapshots else "") or ""
            for match in re.finditer(r"(?:^|\n)(?:[\w\s_*]+\s+)?([A-Za-z_.][\w.]*)\s*\([^;{}]*\)\s*\{", source):
                function_names.add(match.group(1))
    matrix = []
    for name in list(function_names)[:24]:
        cells = []
        for entry in parsed:
            hits = sum(1 for issue in entry["issues"] if _review_issue_key(issue)[0] == name)
            cells.append(ReviewAnalyticsFunctionAttempt(attempt_no=entry["attempt_no"], risk="critical" if hits else ("passed" if entry["verdict"] == "PASS" else "unknown"), score=max(0, 42 - hits * 8) if hits else (95 if entry["verdict"] == "PASS" else 82)))
        matrix.append(ReviewAnalyticsFunction(function=name, attempts=cells))
    radar = []
    for entry in parsed:
        categories = {_review_issue_key(issue)[1] for issue in entry["issues"]}
        radar.append(ReviewAnalyticsRadar(attempt_no=entry["attempt_no"], completeness=round((entry["verified"] / entry["total"] * 100) if entry["total"] else (100 if entry["verdict"] == "PASS" else 0)), control_flow=94 if entry["verdict"] == "PASS" else 72, return_semantics=45 if "Return" in categories else 94, input_validation=42 if "Validation" in categories else 94, call_fidelity=92, type_struct_fidelity=88))
    resolved = sum(1 for issue in issues if issue.status == "resolved")
    closure = resolved / len(issues) if issues else (1.0 if final["verdict"] == "PASS" else 0.0)
    confidence = max(0, min(100, round(final["score"] * 0.42 + closure * 38 + (14 if final["verdict"] == "PASS" else 0) + min(len(parsed), 3) * 2)))
    residual = "high" if final["verdict"] != "PASS" or final["issues"] else ("low" if confidence >= 92 else "low-medium" if confidence >= 82 else "medium")
    return ReviewAnalyticsResponse(task_id=item.task_id, item_id=item.id, summary=ReviewAnalyticsSummary(attempts=len(parsed), final_verdict=final["verdict"], final_confidence=confidence, issue_closure_rate=closure, residual_risk=residual, mock=False), attempts=attempts, issues=issues, function_matrix=matrix, radar=radar)


def build_task_item_advanced(item: B2STaskItem, include_content: bool = True) -> TaskItemAdvancedResponse:
    output_dir = Path(item.output_dir)
    base = output_dir.resolve()
    work_dirs = sorted([p for p in output_dir.glob(".re_work_*") if p.is_dir()], key=lambda p: p.name)
    work_dir = work_dirs[-1] if work_dirs else None
    runs: list[AdvancedRun] = []
    ida_files: list[AdvancedFile] = []
    if work_dir:
        ida_root = work_dir / "ida_cache"
        if ida_root.exists():
            ida_paths = [p for p in ida_root.rglob("*") if p.is_file() and p.suffix.lower() in ADVANCED_TEXT_EXTENSIONS]
            ida_files = [file for path in sorted(ida_paths) if (file := _safe_read_advanced_file(path, base, include_content, _ida_file_meta(path)))]
        runs_root = work_dir / "runs"
        run_dirs = sorted([p for p in runs_root.iterdir() if p.is_dir()], key=lambda p: p.name) if runs_root.exists() else []
        for run_dir in run_dirs:
            batch_map: dict[int, AdvancedBatch] = {}
            for batch_path in sorted(run_dir.glob("batch_*.c")):
                no = _batch_no(batch_path) or 0
                batch_map.setdefault(no, AdvancedBatch(name=f"batch_{no:03d}", batch_no=no)).source = _safe_read_advanced_file(batch_path, base, include_content, _stage4_meta(no or None, section="执行", section_order=10, round_label="执行输出", round_order=0, agent="executor agent", role="batch 输出"))
            for disasm_path in sorted(run_dir.glob("disasm_batch_*.c")):
                no = _batch_no(disasm_path) or 0
                batch_map.setdefault(no, AdvancedBatch(name=f"batch_{no:03d}", batch_no=no)).disasm = _safe_read_advanced_file(disasm_path, base, include_content, {"stage": "阶段 2 · Batch 上下文切片", "stage_order": 2000, "section": "文件", "section_order": 0, "round": _batch_label(no or None), "round_order": no, "role": "反编译上下文", "batch_no": no or None})
            review_dir = run_dir / "review_snapshots"
            if review_dir.exists():
                for review_path in sorted(review_dir.iterdir()):
                    if not review_path.is_file():
                        continue
                    no = _batch_no(review_path) or 0
                    attempt_no = _attempt_no(review_path) or 0
                    role = "评审输出" if review_path.name.endswith(".verdict.json") else "评审输入"
                    file = _safe_read_advanced_file(review_path, base, include_content, _stage4_meta(no or None, section="评审", section_order=20, round_label=f"第 {attempt_no} 次评审" if attempt_no else "评审轮次", round_order=attempt_no, agent="validator agent", role=role, attempt_no=attempt_no or None))
                    if not file:
                        continue
                    batch = batch_map.setdefault(no, AdvancedBatch(name=f"batch_{no:03d}", batch_no=no))
                    if review_path.name.endswith(".verdict.json"):
                        batch.reviews.append(file)
                    else:
                        batch.review_snapshots.append(file)
            session_dir = run_dir / "agent_sessions"
            session_paths = sorted([p for p in session_dir.rglob("*") if p.is_file()]) if session_dir.exists() else []
            single_batch_no = next(iter(batch_map.keys())) if len(batch_map) == 1 else None
            session_files = [file for path in session_paths if (file := _safe_read_advanced_file(path, base, include_content, _session_meta(path, run_dir, single_batch_no)))]
            misc_paths = [p for p in run_dir.iterdir() if p.is_file() and p.name not in {"preamble.h"} and not p.name.startswith("batch_") and not p.name.startswith("disasm_batch_")]
            preamble = run_dir / "preamble.h"
            if preamble.exists():
                misc_paths.insert(0, preamble)
            runs.append(AdvancedRun(
                name=run_dir.name,
                path=str(run_dir),
                batches=[batch_map[key] for key in sorted(batch_map)],
                agent_sessions=session_files,
                files=[file for path in misc_paths if (file := _safe_read_advanced_file(path, base, include_content, _run_file_meta(path)))],
            ))
    mode, mode_label = task_mode_summary([item])
    return TaskItemAdvancedResponse(
        task_id=item.task_id,
        item_id=item.id,
        sequence_no=item.sequence_no,
        mode=mode,
        mode_label=mode_label,
        output_dir=item.output_dir,
        work_dir=str(work_dir) if work_dir else None,
        runs=runs,
        ida_files=ida_files,
    )


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
