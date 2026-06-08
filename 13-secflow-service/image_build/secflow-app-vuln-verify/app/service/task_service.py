"""Task orchestration for the vuln-verify CLI wrapper."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from uuid import uuid4

from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import ConflictError, NotFoundError, ValidationError
from app.model import VulnVerifyTask, VulnVerifyTaskEvent
from app.schemas import TaskCreate, TaskResponse, TaskDetailResponse, TaskEventResponse, TokenUser
from app.service.security import app_task_root, ensure_path_in_project, safe_output_dir, validate_task_id
from app.time_utils import now_local

TERMINAL = {"success", "failed", "cancelled"}


def generate_task_id(db: Session, project_id: str) -> str:
    del project_id
    for _ in range(10):
        task_id = uuid4().hex[:16]
        if not db.query(VulnVerifyTask).filter(VulnVerifyTask.id == task_id).first():
            return task_id
    raise ConflictError("无法生成唯一任务ID，请重试")


def create_event(
    db: Session,
    task: VulnVerifyTask,
    event_type: str,
    message: str,
    *,
    level: str = "info",
    payload: dict | None = None,
    status: str | None = None,
) -> None:
    event = VulnVerifyTaskEvent(
        id=uuid4().hex[:16],
        task_id=task.id,
        project_id=task.project_id,
        event_type=event_type,
        level=level,
        status=status or task.status,
        message=message,
        created_at=now_local(),
    )
    event.payload = payload or {}
    db.add(event)


def build_response(task: VulnVerifyTask) -> TaskResponse:
    return TaskResponse(
        id=task.id,
        project_id=task.project_id,
        name=task.name,
        description=task.description,
        status=task.status,
        reports_dir=task.reports_dir,
        source_root=task.source_root,
        binary_root=task.binary_root,
        threat_path=task.threat_path,
        output_dir=task.output_dir,
        model=task.model,
        concurrency=int(task.concurrency or 1),
        resume=bool(task.resume),
        pid=task.pid,
        return_code=task.return_code,
        worker_id=task.worker_id,
        error_reason=task.error_reason,
        progress=task.progress,
        result_summary=task.result_summary,
        created_by=task.created_by,
        created_at=task.created_at,
        updated_at=task.updated_at,
        started_at=task.started_at,
        finished_at=task.finished_at,
    )


def build_detail(db: Session, task: VulnVerifyTask) -> TaskDetailResponse:
    events = db.query(VulnVerifyTaskEvent).filter(VulnVerifyTaskEvent.task_id == task.id).order_by(VulnVerifyTaskEvent.created_at.desc()).limit(200).all()
    base = build_response(task).model_dump()
    base["events"] = [
        TaskEventResponse(
            id=e.id,
            task_id=e.task_id,
            project_id=e.project_id,
            event_type=e.event_type,
            level=e.level,
            status=e.status,
            message=e.message,
            payload=e.payload,
            created_at=e.created_at,
        )
        for e in events
    ]
    return TaskDetailResponse(**base)


def get_task_or_404(db: Session, project_id: str, task_id: str) -> VulnVerifyTask:
    task = db.query(VulnVerifyTask).filter(VulnVerifyTask.project_id == project_id, VulnVerifyTask.id == task_id).first()
    if not task:
        raise NotFoundError("漏洞验证任务不存在")
    return task


def _operator_name(operator: TokenUser | str | None) -> str | None:
    if isinstance(operator, TokenUser):
        return operator.username or operator.user_id
    return str(operator or "").strip() or None


def _normalize_concurrency(value: int | None) -> int:
    cfg = get_config().worker
    raw = int(value or cfg.default_concurrency or 1)
    return max(1, min(raw, int(cfg.max_concurrency or 16)))


async def create_task(db: Session, project_id: str, req: TaskCreate, operator: TokenUser | str | None) -> TaskResponse:
    task_id = validate_task_id(req.task_id) if req.task_id else generate_task_id(db, project_id)
    if db.query(VulnVerifyTask).filter(VulnVerifyTask.project_id == project_id, VulnVerifyTask.id == task_id).first():
        raise ConflictError("漏洞验证任务ID已存在")

    reports_dir = ensure_path_in_project(project_id, req.reports_dir, must_be_dir=True)
    source_root = ensure_path_in_project(project_id, req.source_root, must_be_dir=True)
    binary_root = ensure_path_in_project(project_id, req.binary_root, must_be_dir=True)
    threat_path = ensure_path_in_project(project_id, req.threat_path, must_be_file=True)
    output_dir = safe_output_dir(project_id, task_id)

    task = VulnVerifyTask(
        id=task_id,
        project_id=project_id,
        name=req.name,
        description=req.description,
        status="pending",
        reports_dir=str(reports_dir),
        source_root=str(source_root),
        binary_root=str(binary_root),
        threat_path=str(threat_path),
        output_dir=str(output_dir),
        model=(str(req.model).strip() if req.model else (get_config().worker.default_model or None)),
        concurrency=_normalize_concurrency(req.concurrency),
        resume=1 if req.resume else 0,
        created_by=_operator_name(operator),
        created_at=now_local(),
        updated_at=now_local(),
    )
    task.progress = {"message": "等待后台执行", "percent": 0}
    db.add(task)
    db.flush()
    create_event(db, task, "task_created", f"任务 {task.name} 已创建", payload={"output_dir": task.output_dir})
    db.commit()
    db.refresh(task)
    return build_response(task)


def summarize_results(task: VulnVerifyTask) -> dict:
    output = Path(task.output_dir)
    verifier_output = output / "verifier_output"
    result_files = sorted(verifier_output.glob("result_*.json")) if verifier_output.is_dir() else []
    group_done_files = sorted(verifier_output.glob("group_*.done")) if verifier_output.is_dir() else []
    stdout_files = sorted(verifier_output.glob("*.stdout")) if verifier_output.is_dir() else []
    stderr_files = sorted(verifier_output.glob("*.stderr")) if verifier_output.is_dir() else []
    groups_dir = output / "groups"
    group_count = len([p for p in groups_dir.iterdir() if p.is_dir() and p.name.startswith("group_")]) if groups_dir.is_dir() else 0
    return {
        "result_count": len(result_files),
        "group_count": group_count,
        "done_group_count": len(group_done_files),
        "stdout_count": len(stdout_files),
        "stderr_count": len(stderr_files),
        "verify_log_exists": (output / "verify.log").is_file(),
    }


def load_results(task: VulnVerifyTask, *, limit: int = 500) -> list[dict]:
    verifier_output = Path(task.output_dir) / "verifier_output"
    result_files = sorted(verifier_output.glob("result_*.json")) if verifier_output.is_dir() else []
    results: list[dict] = []
    for path in result_files[:limit]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                payload.setdefault("_file", str(path))
                results.append(payload)
            else:
                results.append({"_file": str(path), "value": payload})
        except Exception as exc:
            results.append({"_file": str(path), "_error": str(exc)})
    return results


def list_artifacts(task: VulnVerifyTask) -> list[dict]:
    root = Path(task.output_dir).resolve()
    if not root.exists():
        return []
    items: list[dict] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        try:
            rel = str(path.resolve().relative_to(root))
            stat = path.stat()
            items.append({"path": rel, "size": stat.st_size, "modified_at": now_local().fromtimestamp(stat.st_mtime), "kind": "file"})
        except Exception:
            continue
    return items


def read_artifact(task: VulnVerifyTask, rel_path: str, *, offset: int, limit: int) -> dict:
    root = Path(task.output_dir).resolve()
    target = (root / rel_path).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        raise NotFoundError("产物文件不存在")
    size = target.stat().st_size
    with target.open("rb") as handle:
        handle.seek(offset)
        raw = handle.read(limit)
    return {
        "path": rel_path,
        "offset": offset,
        "limit": limit,
        "size": size,
        "content": raw.decode("utf-8", errors="replace"),
        "truncated": offset + len(raw) < size,
    }


async def request_terminate(db: Session, task: VulnVerifyTask, operator: TokenUser | str | None = None) -> None:
    if task.status in TERMINAL:
        return
    task.status = "cancelling"
    task.error_reason = "用户请求取消"
    task.updated_at = now_local()
    create_event(db, task, "task_cancel_requested", "任务收到取消请求", level="warning", payload={"operator": _operator_name(operator), "pid": task.pid})
    db.commit()


async def rerun_task(db: Session, task: VulnVerifyTask, operator: TokenUser | str | None = None) -> None:
    if task.status not in TERMINAL:
        raise ValidationError("仅允许重跑已结束任务")
    output = Path(task.output_dir).resolve()
    task_root = app_task_root(task.project_id, task.id).resolve()
    if not output.is_relative_to(task_root):
        raise ValidationError("输出目录不在任务目录内，拒绝清理")
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    task.status = "pending"
    task.pid = None
    task.return_code = None
    task.worker_id = None
    task.lease_until = None
    task.heartbeat_at = None
    task.error_reason = None
    task.started_at = None
    task.finished_at = None
    task.progress = {"message": "等待后台重跑", "percent": 0}
    task.result_summary = {}
    task.updated_at = now_local()
    create_event(db, task, "task_rerun_requested", "任务已清空输出并重新排队", payload={"operator": _operator_name(operator)})
    db.commit()
