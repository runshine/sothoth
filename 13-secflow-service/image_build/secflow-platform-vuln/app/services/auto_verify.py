"""Auto verification task materialization for vulnerability cases."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.config import get_config
from app.models.database import Case, CaseEvent
from app.services.lifecycle_engine import MAIN_STAGE_VALIDATION, advance_case_stage
from app.services.reporting import ensure_case_raw_report


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
    if getattr(request, "advance_to_validation", True) and case.current_stage != MAIN_STAGE_VALIDATION:
        advance_case_stage(db, case, MAIN_STAGE_VALIDATION, "auto verify task created", source_type="system")
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
