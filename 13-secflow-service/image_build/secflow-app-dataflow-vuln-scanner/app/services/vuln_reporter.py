from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_config
from app.models.database import (
    RunIndex,
    RunIndexResult,
    TriggerTask,
    VulnReportSubmission,
    WorkflowExecution,
)
from app.pi_vuln_core.utils.result_docs import list_final_result_report_files
from app.services.run_index_service import _load_externalized_json_payload
from app.time_utils import now_local

SERVICE_NAME = "secflow-app-dataflow-vuln-scanner"
SERVICE_ID = "secflow-app-dataflow-vuln-scanner"


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def _json_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def _read_text(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _first_markdown_heading(text: str, fallback: str) -> str:
    for line in text.splitlines():
        match = re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*$", line)
        if match:
            return match.group(1).strip()[:256] or fallback
    return fallback


def _frontmatter_value(text: str, key: str) -> str:
    patterns = [
        rf"(?im)^\s*[-*]?\s*\*\*{re.escape(key)}\*\*\s*[:：]\s*(.+?)\s*$",
        rf"(?im)^\s*[-*]?\s*{re.escape(key)}\s*[:：]\s*(.+?)\s*$",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1).strip().strip("` ")
    return ""


def _normalize_severity(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"critical", "high", "medium", "low"}:
        return text
    if text in {"严重", "致命"}:
        return "critical"
    if text in {"高", "高危"}:
        return "high"
    if text in {"中", "中危"}:
        return "medium"
    if text in {"低", "低危"}:
        return "low"
    return "medium"


def _normalize_state(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"suspected", "confirmed", "rejected"}:
        return text
    if text in {"已确认", "确认", "confirmed"}:
        return "confirmed"
    if text in {"误报", "已拒绝", "rejected"}:
        return "rejected"
    return "suspected"


def _int_confidence(value: Any) -> int:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    if number <= 1:
        number *= 100
    return max(0, min(100, int(round(number))))


def _float_or_zero(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _task_metadata(trigger: TriggerTask) -> dict[str, Any]:
    payload = trigger.input_tasks_json or {}
    tasks = payload.get("tasks") if isinstance(payload, dict) else []
    if tasks and isinstance(tasks[0], dict):
        return dict(tasks[0].get("metadata") or {})
    return {}


def _auto_report_enabled(trigger: TriggerTask) -> bool:
    metadata = _task_metadata(trigger)
    return bool(metadata.get("auto_report_vulnerabilities", True))


def _report_status(db: Session, task_id: str, execution_id: str | None = None) -> dict[str, Any]:
    query = db.query(VulnReportSubmission).filter(VulnReportSubmission.task_id == task_id)
    if execution_id:
        query = query.filter(VulnReportSubmission.execution_id == execution_id)
    rows = query.all()
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.status] = counts.get(row.status, 0) + 1
    if not rows:
        status = "not_started"
    elif counts.get("failed") and counts.get("reported"):
        status = "partial_failed"
    elif counts.get("failed"):
        status = "failed"
    elif counts.get("reported") == len(rows):
        status = "reported"
    else:
        status = "pending"
    return {
        "status": status,
        "total": len(rows),
        "reported": counts.get("reported", 0),
        "failed": counts.get("failed", 0),
        "pending": counts.get("pending", 0),
        "items": [
            {
                "result_file": row.result_file,
                "status": row.status,
                "case_id": row.case_id,
                "attempt_count": row.attempt_count,
                "last_error": row.last_error,
                "reported_at": row.reported_at,
            }
            for row in rows
        ],
    }


def get_task_vuln_report_status(db: Session, trigger: TriggerTask, execution_id: str | None = None) -> dict[str, Any]:
    if not _auto_report_enabled(trigger):
        return {"status": "disabled", "enabled": False, "total": 0, "reported": 0, "failed": 0, "pending": 0, "items": []}
    return {"enabled": True, **_report_status(db, trigger.id, execution_id)}


class VulnReportService:
    def _result_rows(self, db: Session, run_index: RunIndex) -> list[RunIndexResult]:
        rows = (
            db.query(RunIndexResult)
            .filter(
                RunIndexResult.run_index_id == run_index.id,
                RunIndexResult.active.is_(True),
                RunIndexResult.taskable.is_(True),
            )
            .order_by(RunIndexResult.filename.asc())
            .all()
        )
        if rows:
            return rows
        results_dir = Path(run_index.run_root_path) / "results"
        summary_file = Path(run_index.run_root_path) / "summary.md"
        filenames = list_final_result_report_files(results_dir, summary_file if summary_file.exists() else None)
        return [
            RunIndexResult(
                id="",
                run_index_id=run_index.id,
                filename=name,
                path=str(results_dir / name),
                title=Path(name).stem,
                active=True,
                taskable=True,
            )
            for name in filenames
        ]

    def _payload_for_result(
        self,
        *,
        trigger: TriggerTask,
        execution: WorkflowExecution,
        run_index: RunIndex,
        result: RunIndexResult,
    ) -> dict[str, Any]:
        raw_payload = _load_externalized_json_payload(run_index.run_root_path, result.raw_json or {})
        raw = raw_payload if isinstance(raw_payload, dict) else {}
        result_path = str(result.path or "")
        if result_path and not Path(result_path).is_absolute():
            result_path = str(Path(run_index.run_root_path) / result_path)
        content = _read_text(result_path)
        title = str(raw.get("title") or result.title or "").strip() or _first_markdown_heading(content, result.filename)
        summary = str(raw.get("summary") or raw.get("description") or _frontmatter_value(content, "summary") or "").strip()
        if not summary:
            summary = "\n".join(line.strip() for line in content.splitlines() if line.strip())[:500]
        severity = _normalize_severity(raw.get("severity") or _frontmatter_value(content, "severity") or _frontmatter_value(content, "严重程度"))
        confidence = _int_confidence(raw.get("confidence") or result.confidence)
        source = {
            "service_name": SERVICE_NAME,
            "service_id": SERVICE_ID,
            "task_id": trigger.id,
            "execution_id": execution.id,
            "run_id": run_index.id,
            "run_name": run_index.run_name,
            "run_root_path": run_index.run_root_path,
            "result_file": result.filename,
            "result_path": result_path,
            "project_id": trigger.project_id,
            "parent_task_id": trigger.parent_task_id,
            "parent_stage_name": trigger.parent_stage_name,
            "parent_stage_item_id": trigger.parent_stage_item_id,
        }
        report_id = f"dfvs:{trigger.id}:{execution.id}:{result.filename}"
        subject_locator = str(raw.get("subject_locator") or raw.get("locator") or result_path or result.filename)
        return {
            "project_id": trigger.project_id,
            "report_id": report_id,
            "title": title[:256],
            "summary": summary[:4000] if summary else None,
            "severity": severity,
            "cvss_score": _float_or_zero(raw.get("cvss_score") or _frontmatter_value(content, "cvss_score")),
            "confidence": confidence,
            "state": _normalize_state(raw.get("state") or _frontmatter_value(content, "state")),
            "category": str(raw.get("category") or _frontmatter_value(content, "category") or "dataflow").strip() or None,
            "rule_id": str(raw.get("rule_id") or _frontmatter_value(content, "rule_id") or "").strip() or None,
            "rule_name": str(raw.get("rule_name") or _frontmatter_value(content, "rule_name") or "").strip() or None,
            "fingerprint": str(raw.get("fingerprint") or hashlib.sha256(f"{report_id}:{title}".encode("utf-8")).hexdigest()).strip(),
            "reporter": {
                "name": SERVICE_NAME,
                "type": "service",
                "instance_id": execution.owner_pod_id or get_config().scheduler.pod_id,
            },
            "subject": {
                "type": str(raw.get("subject_type") or "dataflow_vulnerability"),
                "locator": subject_locator,
                "name": str(raw.get("subject_name") or title),
            },
            "evidence": {
                "summary": summary[:2000] if summary else title,
                "reproduction_hint": str(raw.get("reproduction_hint") or _frontmatter_value(content, "reproduction_hint") or ""),
                "references": [result_path] if result_path else [],
            },
            "artifacts": [
                {
                    "kind": "report",
                    "name": result.filename,
                    "path": result_path,
                    "size": int(result.size or 0),
                    "metadata": {"run_id": run_index.id, "result_file": result.filename},
                }
            ],
            "metadata": {
                "source": source,
                "dataflow_vuln_scanner": {
                    "run_status": run_index.status,
                    "review_verdict": result.verdict,
                    "review_cycle": result.review_cycle,
                    "lifecycle_status": result.lifecycle_status,
                },
            },
        }

    def report_execution_results(
        self,
        db: Session,
        *,
        trigger: TriggerTask,
        execution: WorkflowExecution,
        run_index: RunIndex | None,
    ) -> dict[str, Any]:
        if not _auto_report_enabled(trigger):
            return {"status": "disabled", "enabled": False}
        cfg = get_config()
        vuln_cfg = cfg.vuln_engine_service
        token = vuln_cfg.service_machine_token or cfg.auth_service.service_machine_token
        if not vuln_cfg.enabled:
            return {"status": "disabled", "enabled": False, "reason": "vuln engine integration disabled"}
        if not token:
            return {"status": "failed", "enabled": True, "error": "missing service machine token"}
        if run_index is None:
            return {"status": "failed", "enabled": True, "error": "run index missing"}

        rows = self._result_rows(db, run_index)
        if not rows:
            return {"status": "empty", "enabled": True, "total": 0}

        for result in rows:
            payload = self._payload_for_result(trigger=trigger, execution=execution, run_index=run_index, result=result)
            payload_hash = _json_hash(payload)
            record = (
                db.query(VulnReportSubmission)
                .filter(
                    VulnReportSubmission.task_id == trigger.id,
                    VulnReportSubmission.execution_id == execution.id,
                    VulnReportSubmission.result_file == result.filename,
                )
                .first()
            )
            if record and record.status == "reported" and record.payload_hash == payload_hash:
                continue
            if record is None:
                record = VulnReportSubmission(
                    id=_new_id("vrs"),
                    task_id=trigger.id,
                    execution_id=execution.id,
                    run_index_id=run_index.id,
                    result_file=result.filename,
                    result_path=str(result.path or ""),
                    report_id=str(payload.get("report_id") or ""),
                )
                db.add(record)
                try:
                    db.flush()
                except IntegrityError:
                    db.rollback()
                    record = (
                        db.query(VulnReportSubmission)
                        .filter(
                            VulnReportSubmission.task_id == trigger.id,
                            VulnReportSubmission.execution_id == execution.id,
                            VulnReportSubmission.result_file == result.filename,
                        )
                        .one()
                    )
            record.payload_hash = payload_hash
            record.payload_json = payload
            record.attempt_count = int(record.attempt_count or 0) + 1
            record.status = "pending"
            db.commit()
            try:
                with httpx.Client(timeout=vuln_cfg.timeout) as client:
                    response = client.post(
                        vuln_cfg.submit_url,
                        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                        json=payload,
                    )
                    response.raise_for_status()
                    response_payload = response.json()
                record.case_id = str(response_payload.get("id") or response_payload.get("case_id") or "")
                record.response_json = response_payload
                record.status = "reported"
                record.last_error = None
                record.reported_at = now_local()
            except Exception as exc:
                record.status = "failed"
                record.last_error = str(exc)
            db.add(record)
            db.commit()
        return get_task_vuln_report_status(db, trigger, execution.id)


_service: VulnReportService | None = None


def get_vuln_report_service() -> VulnReportService:
    global _service
    if _service is None:
        _service = VulnReportService()
    return _service
