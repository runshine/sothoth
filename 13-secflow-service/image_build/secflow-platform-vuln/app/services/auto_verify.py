"""Auto verification task materialization for vulnerability cases."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.config import get_config
from app.models.database import Case, CaseEvent
from app.services.lifecycle_engine import (
    MAIN_STAGE_RECEIVE,
    MAIN_STAGE_TRIAGE,
    MAIN_STAGE_VALIDATION,
    VALIDATION_STATUS_COMPLETED,
    VALIDATION_STATUS_EVIDENCE_COLLECTING,
    VALIDATION_STATUS_EXP_GENERATING,
    VALIDATION_STATUS_POC_GENERATING,
    VALIDATION_STATUS_QUEUED,
    VALIDATION_STATUS_REPRODUCING,
    advance_case_stage,
    get_lifecycle_state,
    set_lifecycle_state,
)
from app.services.reporting import ensure_case_raw_report


_VALIDATION_STAGE_STATUSES = {
    VALIDATION_STATUS_QUEUED,
    VALIDATION_STATUS_POC_GENERATING,
    VALIDATION_STATUS_EXP_GENERATING,
    VALIDATION_STATUS_REPRODUCING,
    VALIDATION_STATUS_EVIDENCE_COLLECTING,
    VALIDATION_STATUS_COMPLETED,
}


def _safe_json(value: str | None, default: Any) -> Any:
    try:
        return json.loads(value or "")
    except Exception:
        return default


def _get_nested(data: dict[str, Any], path: str) -> Any:
    cur: Any = data
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _artifact_path(artifacts: Any, artifact_type: str) -> str | None:
    if not isinstance(artifacts, list):
        return None
    wanted = {artifact_type, artifact_type.replace("_root", ""), artifact_type.replace("_", "-")}
    for item in artifacts:
        if not isinstance(item, dict):
            continue
        candidates = {
            str(item.get("type") or "").strip(),
            str(item.get("kind") or "").strip(),
            str((item.get("metadata") or {}).get("type") or "").strip() if isinstance(item.get("metadata"), dict) else "",
        }
        if candidates & wanted:
            return _string_or_none(item.get("path") or item.get("content_ref"))
    return None


def _resolve_path(payload: dict[str, Any], key: str) -> tuple[str | None, str | None]:
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    fileserver_root = payload.get("fileserver_root") if isinstance(payload.get("fileserver_root"), dict) else {}
    artifacts = payload.get("artifacts") or []
    candidates = [
        (f"metadata.verification_context.{key}", _get_nested(metadata, f"verification_context.{key}")),
        (f"metadata.source.{key}", _get_nested(metadata, f"source.{key}")),
        (f"metadata.dataflow_vuln_scan.{key}", _get_nested(metadata, f"dataflow_vuln_scan.{key}")),
        (f"fileserver_root.{key}", fileserver_root.get(key)),
        (f"artifacts[type={key}].path", _artifact_path(artifacts, key)),
    ]
    for source, value in candidates:
        text = _string_or_none(value)
        if text:
            return text, source
    return None, None


def _derive_binary_root_from_source_root(project_id: str, source_root: str | None) -> tuple[str | None, str | None]:
    """Derive a conservative binary_root for binary-security task workspaces.

    Some binary-security intake records only carry source_root, typically pointing to
    /data/files/{project}/app/secflow-app-binary-security/{task_id}/input.  The
    verifier needs an existing binary_root as task context, so only return paths that
    are inside the same project data root and already exist on disk.
    """
    source_text = _string_or_none(source_root)
    if not source_text:
        return None, None

    project_root = _data_root(project_id)
    try:
        source_path = Path(source_text).expanduser().resolve()
        relative_parts = source_path.relative_to(project_root).parts
    except (OSError, RuntimeError, ValueError):
        return None, None

    if len(relative_parts) < 4:
        return None, None
    if relative_parts[0] != "app" or relative_parts[1] != "secflow-app-binary-security":
        return None, None

    task_root = (project_root / relative_parts[0] / relative_parts[1] / relative_parts[2]).resolve()
    try:
        task_root.relative_to(project_root)
    except ValueError:
        return None, None

    candidates = [
        ("derived.source_root.binary_security_task_root", task_root),
        ("derived.source_root.binary_security_output_entry_analyse", task_root / "output" / "entry-analyse"),
        ("derived.source_root.binary_security_output_system_analyse", task_root / "output" / "system-analyse"),
        ("derived.source_root.binary_security_output_dataflow_vuln_scan", task_root / "output" / "dataflow-vuln-scan"),
        ("derived.source_root.binary_security_output", task_root / "output"),
        ("derived.source_root.binary_security_input", task_root / "input"),
    ]
    for source, candidate in candidates:
        try:
            resolved = candidate.resolve()
            resolved.relative_to(project_root)
        except (OSError, RuntimeError, ValueError):
            continue
        if resolved.is_dir():
            return str(resolved), source
    return None, None


def build_case_report_markdown(case: Case, payload: dict[str, Any]) -> tuple[str, str]:
    raw_report = ensure_case_raw_report(case)
    if raw_report and raw_report.get("markdown"):
        return str(raw_report["markdown"]), str(raw_report.get("report_id") or payload.get("report_id") or case.id)

    display_summary = payload.get("display_summary") if isinstance(payload.get("display_summary"), dict) else {}
    evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
    subject = payload.get("subject") if isinstance(payload.get("subject"), dict) else {}
    report_id = str(payload.get("report_id") or payload.get("finding_id") or case.id)
    markdown = f"""# {payload.get('title') or case.title}

## Summary
{payload.get('summary') or display_summary.get('subtitle') or 'No summary provided.'}

## Severity
{payload.get('severity') or case.severity}

## Subject
- Type: {subject.get('type') or 'unknown'}
- Locator: {subject.get('locator') or subject.get('name') or 'unknown'}

## Evidence
{evidence.get('summary') or evidence.get('reproduction_hint') or 'No evidence summary provided.'}

## Source
- Case ID: {case.id}
- Finding ID: {payload.get('finding_id') or ''}
- Rule: {payload.get('rule_name') or payload.get('rule_id') or ''}
""".strip()
    return markdown, report_id


def build_auto_verify_context(case: Case, payload: dict[str, Any]) -> dict[str, Any]:
    source_root, source_from = _resolve_path(payload, "source_root")
    binary_root, binary_from = _resolve_path(payload, "binary_root")
    if not binary_root:
        binary_root, binary_from = _derive_binary_root_from_source_root(case.project_id, source_root)
    report_md, report_id = build_case_report_markdown(case, payload)
    path_status = {
        "source_root": {"ok": bool(source_root), "source": source_from, "message": None if source_root else "source_root missing"},
        "binary_root": {"ok": bool(binary_root), "source": binary_from, "message": None if binary_root else "binary_root missing"},
    }
    return {
        "case_id": case.id,
        "project_id": case.project_id,
        "case_title": case.title,
        "source_root": source_root,
        "binary_root": binary_root,
        "report_id": report_id,
        "report_preview": report_md[:4000],
        "path_status": path_status,
        "default_task_name": f"自动化验证-{case.title[:48]}",
        "default_model": os.environ.get("SECFLOW_VULN_VERIFY_MODEL", "local_minimax/MiniMax/MiniMax-M2.5"),
        "default_concurrency": int(os.environ.get("SECFLOW_VULN_VERIFY_CONCURRENCY", "1")),
    }


def _data_root(project_id: str) -> Path:
    root = os.environ.get("SECFLOW_FILE_DATA_ROOT") or "/data/files"
    return (Path(root).resolve() / project_id).resolve()


def _ensure_inside(path: Path, base: Path) -> None:
    try:
        path.resolve().relative_to(base.resolve())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="unsafe materialization path") from exc


def _vuln_verify_base_url() -> str:
    env = os.environ.get("SECFLOW_VULN_VERIFY_ENDPOINT")
    if env:
        return env.rstrip("/")
    try:
        cfg = get_config()
        extra = getattr(cfg, "vuln_verify_endpoint", None)
        if extra:
            return str(extra).rstrip("/")
    except Exception:
        pass
    return "http://secflow-app-vuln-verify/api/app/vuln-verify"


def _normalize_task_status(value: Any) -> str:
    return str(value or "").strip().lower() or "unknown"


def _latest_auto_verify_task_event(db: Session, case: Case, task_id: str | None = None) -> tuple[str, str | None, dict[str, Any]]:
    query = db.query(CaseEvent).filter(
        CaseEvent.case_id == case.id,
        CaseEvent.event_type == "auto_verify_task_created",
    )
    events = query.order_by(CaseEvent.created_at.desc()).all()
    wanted = str(task_id or "").strip()
    for event in events:
        payload = _safe_json(event.payload_json, {})
        if not isinstance(payload, dict):
            continue
        event_task_id = str(payload.get("vuln_verify_task_id") or payload.get("task_id") or "").strip()
        if not event_task_id:
            continue
        if wanted and event_task_id != wanted:
            continue
        report_data_url = _string_or_none(payload.get("report_data_url"))
        return event_task_id, report_data_url, payload
    if wanted:
        report_data_url = f"/api/app/vuln-verify/projects/{case.project_id}/tasks/{wanted}/report-data"
        return wanted, report_data_url, {"vuln_verify_task_id": wanted, "report_data_url": report_data_url}
    raise HTTPException(status_code=404, detail="auto verify task event not found")


def _compact_report_data(report_data: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(report_data, dict):
        return None
    return {
        "task_id": report_data.get("task_id"),
        "status": report_data.get("status"),
        "title": report_data.get("title"),
        "target": report_data.get("target"),
        "total_verified": report_data.get("total_verified"),
        "total_reports": report_data.get("total_reports"),
        "total_groups": report_data.get("total_groups"),
        "verdicts": report_data.get("verdicts") if isinstance(report_data.get("verdicts"), dict) else {},
        "severities": report_data.get("severities") if isinstance(report_data.get("severities"), dict) else {},
    }


def _normalize_verdict_counts(report_data: dict[str, Any] | None) -> tuple[dict[str, int], int]:
    if not isinstance(report_data, dict):
        return {}, 0
    counts: dict[str, int] = {}

    def add_verdict(value: Any, amount: Any = 1) -> None:
        key = str(value or "").strip().lower()
        if not key:
            return
        try:
            count = int(amount or 0)
        except Exception:
            count = 0
        if count <= 0:
            return
        counts[key] = counts.get(key, 0) + count

    verdicts = report_data.get("verdicts")
    if isinstance(verdicts, dict):
        for key, value in verdicts.items():
            add_verdict(key, value)

    if not counts:
        groups = report_data.get("groups")
        if isinstance(groups, list):
            for group in groups:
                if not isinstance(group, dict):
                    continue
                group_verdicts = group.get("verdicts")
                if isinstance(group_verdicts, dict):
                    for key, value in group_verdicts.items():
                        add_verdict(key, value)
                reports = group.get("reports")
                if isinstance(reports, list):
                    for report in reports:
                        if isinstance(report, dict):
                            add_verdict(report.get("verdict"), 1)

    total_reports = 0
    for key in ("total_reports", "total_verified"):
        try:
            total_reports = max(total_reports, int(report_data.get(key) or 0))
        except Exception:
            pass
    total_reports = max(total_reports, sum(counts.values()))
    return counts, total_reports


def _derive_validation_result(report_data: dict[str, Any] | None) -> str:
    verdicts, total_reports = _normalize_verdict_counts(report_data)
    confirmed = {
        "confirmed",
        "exploitable",
        "vulnerable",
        "verified",
        "true_positive",
        "true-positive",
        "tp",
        "confirmed_vulnerable",
    }
    ruled_out = {
        "ruled_out",
        "ruled-out",
        "rejected",
        "not_vulnerable",
        "not-vulnerable",
        "false_positive",
        "false-positive",
        "fp",
        "non_vulnerable",
        "non-vulnerable",
    }
    if any(verdicts.get(item, 0) > 0 for item in confirmed):
        return "vulnerable"
    if total_reports > 0:
        known = sum(verdicts.values())
        ruled_out_count = sum(count for verdict, count in verdicts.items() if verdict in ruled_out)
        if known > 0 and ruled_out_count == known:
            return "not_vulnerable"
    return "inconclusive"


def _ensure_validation_stage(db: Session, case: Case) -> None:
    if case.current_stage == MAIN_STAGE_VALIDATION:
        return
    if case.current_stage in {MAIN_STAGE_RECEIVE, MAIN_STAGE_TRIAGE}:
        advance_case_stage(db, case, MAIN_STAGE_VALIDATION, "auto verify task synced", source_type="system")
    elif case.current_stage != MAIN_STAGE_VALIDATION:
        advance_case_stage(db, case, MAIN_STAGE_VALIDATION, "auto verify task synced", source_type="system")


def _sync_case_validation_state(db: Session, case: Case, task_status: str, validation_result: str) -> str:
    _ensure_validation_stage(db, case)
    lifecycle = get_lifecycle_state(case)
    if task_status in {"pending", "queued", "created"}:
        stage_status = VALIDATION_STATUS_QUEUED
        lifecycle["validation_result"] = "inconclusive"
    elif task_status in {"running", "cancelling", "terminating"}:
        stage_status = VALIDATION_STATUS_EVIDENCE_COLLECTING
        lifecycle["validation_result"] = "inconclusive"
    elif task_status == "success":
        stage_status = VALIDATION_STATUS_COMPLETED
        lifecycle["validation_result"] = validation_result
    elif task_status in {"failed", "terminated", "cancelled", "canceled"}:
        stage_status = VALIDATION_STATUS_COMPLETED
        lifecycle["validation_result"] = "inconclusive"
    else:
        stage_status = VALIDATION_STATUS_EVIDENCE_COLLECTING
        lifecycle["validation_result"] = "inconclusive"
    lifecycle["stage_status"] = stage_status
    set_lifecycle_state(case, lifecycle)
    case.current_status = stage_status
    return str(lifecycle.get("validation_result") or "inconclusive")


async def sync_auto_verify_task(
    db: Session,
    case: Case,
    request: Any,
    token: str,
    actor: str | None = None,
) -> dict[str, Any]:
    requested_task_id = _string_or_none(getattr(request, "vuln_verify_task_id", None))
    vuln_verify_task_id, report_data_url, event_payload = _latest_auto_verify_task_event(db, case, requested_task_id)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    base_url = _vuln_verify_base_url()
    detail_url = f"{base_url}/projects/{case.project_id}/tasks/{vuln_verify_task_id}"
    report_url = f"{base_url}/projects/{case.project_id}/tasks/{vuln_verify_task_id}/report-data"

    task: dict[str, Any]
    report_data: dict[str, Any] | None = None
    report_error: str | None = None
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            detail_resp = await client.get(detail_url, headers=headers)
            if detail_resp.status_code >= 400:
                raise HTTPException(status_code=502, detail=f"vuln-verify task detail failed: {detail_resp.text[:500]}")
            task = detail_resp.json()
            task_status = _normalize_task_status(task.get("status"))
            if task_status in {"success", "failed", "terminated", "cancelled", "canceled"}:
                try:
                    report_resp = await client.get(report_url, headers=headers)
                    if report_resp.status_code < 400:
                        report_payload = report_resp.json()
                        if isinstance(report_payload, dict):
                            report_data = report_payload
                    else:
                        report_error = report_resp.text[:500]
                except Exception as exc:
                    report_error = str(exc)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"vuln-verify service unavailable: {exc}") from exc

    task_status = _normalize_task_status(task.get("status"))
    derived_validation_result = _derive_validation_result(report_data) if task_status == "success" else "inconclusive"
    validation_result = _sync_case_validation_state(db, case, task_status, derived_validation_result)
    verdicts, total_reports = _normalize_verdict_counts(report_data)
    synced_at = datetime.utcnow().isoformat()
    effective_report_data_url = report_data_url or f"/api/app/vuln-verify/projects/{case.project_id}/tasks/{vuln_verify_task_id}/report-data"

    event_type = "auto_verify_task_completed" if task_status in {"success", "failed", "terminated", "cancelled", "canceled"} else "auto_verify_task_synced"
    db.add(CaseEvent(
        id=uuid4().hex,
        case_id=case.id,
        event_type=event_type,
        summary=f"自动化验证任务同步：{task_status} / {validation_result}",
        payload_json=json.dumps(
            {
                "task_id": vuln_verify_task_id,
                "vuln_verify_task_id": vuln_verify_task_id,
                "task_status": task_status,
                "report_data_url": effective_report_data_url,
                "verdicts": verdicts,
                "total_reports": total_reports,
                "validation_result": validation_result,
                "synced_at": synced_at,
                "actor": actor,
                "report_error": report_error,
            },
            ensure_ascii=False,
        ),
    ))

    db.add(case)
    db.commit()
    db.refresh(case)
    return {
        "case_id": case.id,
        "project_id": case.project_id,
        "vuln_verify_task_id": vuln_verify_task_id,
        "task_status": task_status,
        "case_stage": case.current_stage,
        "case_status": case.current_status,
        "validation_result": validation_result,
        "report_data_url": effective_report_data_url,
        "verdicts": verdicts,
        "total_reports": total_reports,
        "task": task,
        "report_data": _compact_report_data(report_data),
        "report_error": report_error,
        "event_payload": event_payload,
    }


async def create_auto_verify_task(
    db: Session,
    case: Case,
    payload: dict[str, Any],
    request: Any,
    token: str,
    actor: str | None = None,
) -> dict[str, Any]:
    context = build_auto_verify_context(case, payload)
    missing = [key for key, item in context["path_status"].items() if not item["ok"]]
    if missing:
        raise HTTPException(status_code=400, detail=f"missing required paths: {', '.join(missing)}")

    task_id = uuid4().hex
    project_root = _data_root(case.project_id)
    materialized_root = project_root / "app" / "secflow-app-vuln-verify" / "case-verification" / case.id / task_id
    _ensure_inside(materialized_root, project_root)
    reports_dir = materialized_root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    report_md, report_id = build_case_report_markdown(case, payload)
    report_filename = f"{str(report_id).replace('/', '_') or case.id}.md"
    report_path = reports_dir / report_filename
    threat_path = materialized_root / "threat_model.md"
    manifest_path = materialized_root / "manifest.json"

    threat_model = str(request.threat_model_markdown or "").strip()
    if not threat_model:
        raise HTTPException(status_code=400, detail="threat_model_markdown cannot be empty")

    report_path.write_text(report_md, encoding="utf-8")
    threat_path.write_text(threat_model, encoding="utf-8")
    manifest = {
        "case_id": case.id,
        "project_id": case.project_id,
        "source_root": context["source_root"],
        "binary_root": context["binary_root"],
        "reports_dir": str(reports_dir),
        "threat_path": str(threat_path),
        "report_id": report_id,
        "template_id": getattr(request, "template_id", None),
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    create_payload = {
        "name": request.name,
        "reports_dir": str(reports_dir),
        "source_root": context["source_root"],
        "binary_root": context["binary_root"],
        "threat_path": str(threat_path),
        "model": request.model,
        "concurrency": request.concurrency,
    }
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = f"{_vuln_verify_base_url()}/projects/{case.project_id}/tasks"
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(url, json=create_payload, headers=headers)
        if resp.status_code >= 400:
            raise HTTPException(status_code=502, detail=f"vuln-verify task creation failed: {resp.text[:500]}")
        task = resp.json()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"vuln-verify service unavailable: {exc}") from exc

    vuln_verify_task_id = str(task.get("id") or task.get("task_id") or "")
    report_data_url = f"/api/app/vuln-verify/projects/{case.project_id}/tasks/{vuln_verify_task_id}/report-data" if vuln_verify_task_id else None
    db.add(CaseEvent(
        id=uuid4().hex,
        case_id=case.id,
        event_type="auto_verify_task_created",
        summary=f"创建自动化验证任务：{request.name}",
        payload_json=json.dumps({
            "vuln_verify_task_id": vuln_verify_task_id,
            "report_data_url": report_data_url,
            "materialized_root": str(materialized_root),
            "actor": actor,
        }, ensure_ascii=False),
    ))
    should_advance_to_validation = getattr(request, "advance_to_validation", True)
    was_validation_stage = case.current_stage == MAIN_STAGE_VALIDATION
    if should_advance_to_validation and case.current_stage != MAIN_STAGE_VALIDATION:
        if case.current_stage in {MAIN_STAGE_RECEIVE, MAIN_STAGE_TRIAGE}:
            advance_case_stage(db, case, MAIN_STAGE_VALIDATION, "auto verify task created", source_type="system")
        elif case.current_stage != MAIN_STAGE_VALIDATION:
            advance_case_stage(db, case, MAIN_STAGE_VALIDATION, "auto verify task created", source_type="system")

    if case.current_stage == MAIN_STAGE_VALIDATION:
        lifecycle = get_lifecycle_state(case)
        lifecycle_status = lifecycle.get("stage_status")
        case_status = case.current_status
        should_sync_validation_status = should_advance_to_validation and not was_validation_stage
        if should_sync_validation_status:
            validation_status = VALIDATION_STATUS_QUEUED
        elif lifecycle_status in _VALIDATION_STAGE_STATUSES:
            validation_status = lifecycle_status
        elif case_status in _VALIDATION_STAGE_STATUSES:
            validation_status = case_status
        else:
            validation_status = VALIDATION_STATUS_QUEUED

        if (
            should_sync_validation_status
            or lifecycle_status != validation_status
            or case_status != validation_status
        ):
            lifecycle["stage_status"] = validation_status
            set_lifecycle_state(case, lifecycle)
            case.current_status = validation_status
    db.commit()
    return {
        "case_id": case.id,
        "project_id": case.project_id,
        "vuln_verify_task_id": vuln_verify_task_id,
        "report_data_url": report_data_url,
        "materialized_root": str(materialized_root),
        "reports_dir": str(reports_dir),
        "threat_path": str(threat_path),
        "task": task,
    }
