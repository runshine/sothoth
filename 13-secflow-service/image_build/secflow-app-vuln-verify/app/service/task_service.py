"""Task orchestration for the vuln-verify CLI wrapper."""

from __future__ import annotations

import json
import os
import re
import shutil
from collections import Counter
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
    result_summary = get_task_result_summary(task)
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
        result_summary=result_summary,
        created_by=task.created_by,
        created_at=task.created_at,
        updated_at=task.updated_at,
        started_at=task.started_at,
        finished_at=task.finished_at,
    )


def get_task_result_summary(task: VulnVerifyTask) -> dict:
    result_summary = dict(task.result_summary or {})
    if (result_summary.get("result_count") or 0) and "confirmed_count" not in result_summary:
        result_summary = summarize_results(task)
    return result_summary


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
    verdict_counter: Counter[str] = Counter()
    for path in result_files:
        payload = _safe_read_json(path)
        if not payload:
            continue
        verdict = str(payload.get("verdict") or "unverified").strip() or "unverified"
        verdict_counter[verdict] += 1
    return {
        "result_count": len(result_files),
        "group_count": group_count,
        "done_group_count": len(group_done_files),
        "stdout_count": len(stdout_files),
        "stderr_count": len(stderr_files),
        "verify_log_exists": (output / "verify.log").is_file(),
        "verified_count": int(sum(verdict_counter.values())),
        "confirmed_count": int(verdict_counter.get("confirmed", 0)),
        "ruled_out_count": int(verdict_counter.get("ruled_out", 0)),
        "unresolved_count": int(verdict_counter.get("unresolved", 0)),
        "unverified_count": int(verdict_counter.get("unverified", 0)),
        "verdicts": dict(verdict_counter),
    }


def build_project_stats(tasks: list[VulnVerifyTask]) -> dict:
    totals = {
        "total_tasks": len(tasks),
        "verified_tasks": 0,
        "total_results": 0,
        "confirmed_count": 0,
        "ruled_out_count": 0,
        "unresolved_count": 0,
        "unverified_count": 0,
    }
    for task in tasks:
        summary = get_task_result_summary(task)
        result_count = int(summary.get("result_count") or 0)
        if result_count > 0:
            totals["verified_tasks"] += 1
        totals["total_results"] += result_count
        totals["confirmed_count"] += int(summary.get("confirmed_count") or 0)
        totals["ruled_out_count"] += int(summary.get("ruled_out_count") or 0)
        totals["unresolved_count"] += int(summary.get("unresolved_count") or 0)
        totals["unverified_count"] += int(summary.get("unverified_count") or 0)
    return totals


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




_VERDICT_PRIORITY = {"confirmed": 4, "unresolved": 3, "ruled_out": 2, "unverified": 1}


def _safe_read_json(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


def _load_result_map(output_dir: Path) -> dict[str, dict]:
    verifier_output = output_dir / "verifier_output"
    result_map: dict[str, dict] = {}
    if not verifier_output.is_dir():
        return result_map
    result_files = sorted(verifier_output.glob("result_*.json")) + sorted(verifier_output.glob("*/result_*.json"))
    for path in result_files:
        payload = _safe_read_json(path)
        if not payload:
            continue
        report_id = str(payload.get("report_id") or path.name.removeprefix("result_").removesuffix(".json"))
        payload.setdefault("_file", str(path))
        result_map[report_id] = payload
    return result_map


def _parse_markdown_report(path: Path) -> tuple[str, str, str]:
    report_id = path.stem
    title = ""
    severity = "unknown"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return report_id, title, severity
    id_match = re.search(r"\*\*report_id\*\*\s*:\s*(.+)", text, flags=re.IGNORECASE)
    if id_match:
        report_id = id_match.group(1).strip() or report_id
    for line in text.splitlines():
        stripped = line.strip()
        if not title and stripped.startswith("#"):
            title = stripped.lstrip("#").strip()
        if severity == "unknown":
            match = re.match(r"\*\*severity\*\*\s*:\s*(.+)", stripped, flags=re.IGNORECASE)
            if match:
                severity = match.group(1).strip().lower() or "unknown"
        if title and severity != "unknown":
            break
    return report_id[:240], title[:240], severity[:40]


def _load_report_meta(reports_dir: str | None) -> tuple[dict[str, str], dict[str, str]]:
    titles: dict[str, str] = {}
    severities: dict[str, str] = {}
    if not reports_dir:
        return titles, severities
    root = Path(reports_dir)
    if not root.is_dir():
        return titles, severities
    for path in sorted(root.glob("*.json")):
        payload = _safe_read_json(path)
        if not payload:
            continue
        report_id = str(payload.get("finding_id") or payload.get("report_id") or path.stem)
        titles[report_id] = str(payload.get("title") or payload.get("summary") or report_id)[:240]
        severities[report_id] = str(payload.get("severity") or "unknown").lower()[:40]
    for path in sorted(root.glob("*.md")):
        report_id, title, severity = _parse_markdown_report(path)
        titles.setdefault(report_id, title or report_id)
        severities.setdefault(report_id, severity or "unknown")
    return titles, severities


def _load_groups(output_dir: Path) -> list[dict]:
    routing_path = output_dir / "routing_log.json"
    routing = _safe_read_json(routing_path)
    if routing and isinstance(routing.get("groups"), list):
        return [g for g in routing["groups"] if isinstance(g, dict)]

    groups_dir = output_dir / "groups"
    groups: list[dict] = []
    if not groups_dir.is_dir():
        return groups
    for group_dir in sorted(p for p in groups_dir.iterdir() if p.is_dir() and p.name.startswith("group_")):
        manifest = _safe_read_json(group_dir / "manifest.json") or {}
        report_ids = manifest.get("report_ids") if isinstance(manifest.get("report_ids"), list) else []
        groups.append({
            "group_id": str(manifest.get("group_id") or group_dir.name),
            "file": str(manifest.get("file") or ""),
            "function": str(manifest.get("function") or ""),
            "report_ids": [str(item) for item in report_ids],
        })
    return groups


def _dimension_payload(payload: dict) -> dict:
    dimensions = payload.get("dimensions") if isinstance(payload.get("dimensions"), dict) else {}
    normalized: dict[str, dict] = {}
    for key, value in dimensions.items():
        if isinstance(value, dict):
            normalized[str(key)] = {"status": value.get("status"), "detail": str(value.get("detail") or "")}
        else:
            normalized[str(key)] = {"status": bool(value), "detail": ""}
    return normalized


def _exploit_payload(payload: dict) -> dict | None:
    exploit = payload.get("exploitability") if isinstance(payload.get("exploitability"), dict) else None
    if not exploit:
        return None
    return {
        "preconditions": str(exploit.get("preconditions") or ""),
        "complexity": str(exploit.get("trigger_complexity") or ""),
        "impact": str(exploit.get("worst_case_impact") or ""),
    }


def _evidence_payload(payload: dict) -> list[dict]:
    evidence = payload.get("evidence") if isinstance(payload.get("evidence"), list) else []
    items: list[dict] = []
    for item in evidence:
        if not isinstance(item, dict):
            continue
        items.append({
            "type": str(item.get("type") or ""),
            "claim": str(item.get("claim") or ""),
            "finding": str(item.get("finding") or ""),
        })
    return items


def build_report_data(task: VulnVerifyTask) -> dict:
    output_dir = Path(task.output_dir)
    result_map = _load_result_map(output_dir)
    groups_raw = _load_groups(output_dir)
    titles, severities = _load_report_meta(task.reports_dir)

    verdict_counter: Counter[str] = Counter()
    severity_counter: Counter[str] = Counter()
    groups: list[dict] = []

    for group in groups_raw:
        report_items: list[dict] = []
        group_verdicts: Counter[str] = Counter()
        report_ids = [str(item) for item in group.get("report_ids", [])]
        for report_id in report_ids:
            result = result_map.get(report_id)
            verdict = str(result.get("verdict") or "unverified") if result else "unverified"
            severity = severities.get(report_id, "unknown") or "unknown"
            report_items.append({
                "id": report_id,
                "title": titles.get(report_id, report_id),
                "severity": severity,
                "verdict": verdict,
                "ruled_out_by": result.get("ruled_out_by") if result else None,
                "dimensions": _dimension_payload(result) if result else {},
                "root_cause": str(result.get("root_cause_summary") or "") if result else "",
                "exploit": _exploit_payload(result) if result else None,
                "evidence": _evidence_payload(result) if result else [],
                "raw_result": result,
            })
            group_verdicts[verdict] += 1
            if result:
                verdict_counter[verdict] += 1
                severity_counter[severity] += 1

        if group_verdicts:
            dominant = sorted(
                group_verdicts.items(),
                key=lambda kv: (kv[1], _VERDICT_PRIORITY.get(kv[0], 0)),
                reverse=True,
            )[0][0]
        else:
            dominant = "unverified"
        groups.append({
            "id": str(group.get("group_id") or ""),
            "file": str(group.get("file") or ""),
            "function": str(group.get("function") or ""),
            "report_count": len(report_items),
            "verdicts": dict(group_verdicts),
            "dominant": dominant,
            "reports": report_items,
        })

    return {
        "task_id": task.id,
        "status": task.status,
        "title": "漏洞验证报告",
        "target": task.name or task.id,
        "total_verified": len(result_map),
        "total_reports": sum(len(group.get("report_ids", [])) for group in groups_raw),
        "total_groups": len(groups),
        "verdicts": dict(verdict_counter),
        "severities": dict(severity_counter),
        "groups": groups,
    }

def _is_hidden_artifact(rel_path: str) -> bool:
    """Hide legacy/self-contained HTML reports from task artifacts.

    The SecFlow detail page renders vulnerability verification reports natively in
    React via the report-data API, so HTML report files must not be exposed as
    downloadable or previewable artifacts.
    """
    normalized = rel_path.replace("\\", "/").lower()
    return normalized.endswith(".html") or normalized.endswith(".htm") or normalized.endswith("vuln-verify-report.html")


def list_artifacts(task: VulnVerifyTask) -> list[dict]:
    root = Path(task.output_dir).resolve()
    if not root.exists():
        return []
    items: list[dict] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        try:
            rel = str(path.resolve().relative_to(root))
            if _is_hidden_artifact(rel):
                continue
            stat = path.stat()
            items.append({"path": rel, "size": stat.st_size, "modified_at": now_local().fromtimestamp(stat.st_mtime), "kind": "file"})
        except Exception:
            continue
    return items


def read_artifact(task: VulnVerifyTask, rel_path: str, *, offset: int, limit: int) -> dict:
    if _is_hidden_artifact(rel_path):
        raise NotFoundError("产物文件不存在")
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
