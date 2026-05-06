from __future__ import annotations

import json
import posixpath
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.config import get_config
from app.models.database import (
    HistoryRun,
    HistoryRunCycle,
    HistoryRunFile,
    HistoryRunGlobalReview,
    HistoryRunRemovedResult,
    HistoryRunResult,
    HistoryRunResultReview,
    HistoryRunSession,
    TriggerTask,
    WorkflowExecution,
)
from app.services.run_inspector import (
    inspect_cycle_detail,
    inspect_file,
    inspect_files,
    inspect_log,
    inspect_run_detail,
    inspect_run_summary,
    inspect_session_file,
    inspect_sessions,
)


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def _parse_datetime(value: str | None) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _datetime_from_epoch(value: int | float | None) -> datetime | None:
    epoch = float(value or 0)
    if epoch <= 0:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).replace(tzinfo=None)


def _iso_or_empty(value: datetime | None) -> str:
    return value.isoformat() if value else ""


def _read_json_file(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _read_text_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _compute_source_mtime(path: Path) -> float:
    if not path.is_dir():
        return 0.0
    latest = 0.0
    try:
        latest = max(latest, path.stat().st_mtime)
    except OSError:
        return 0.0
    for item in path.rglob("*"):
        try:
            latest = max(latest, item.stat().st_mtime)
        except OSError:
            continue
    return latest


def _task_markdown_for_run(run_root: Path) -> str:
    input_manifest = run_root / "input" / "tasks.json"
    payload = _read_json_file(input_manifest)
    tasks = payload.get("tasks") if isinstance(payload, dict) else None
    if isinstance(tasks, list):
        for item in tasks:
            if not isinstance(item, dict):
                continue
            task_md_path = str(item.get("task_md_path") or "").strip()
            if task_md_path:
                content = _read_text_file(Path(task_md_path))
                if content:
                    return content
    for candidate in run_root.glob("trigger_inputs/*/input/task.md"):
        content = _read_text_file(candidate)
        if content:
            return content
    return ""


def _summary_markdown_for_run(run_root: Path, atomic_work_path: str | None) -> str:
    candidates = []
    if atomic_work_path:
        atomic = Path(atomic_work_path)
        candidates.extend([
            atomic / "summary.md",
            atomic / "final_output" / "summary.md",
        ])
    candidates.extend([
        run_root / "summary.md",
        run_root / "final_output" / "summary.md",
    ])
    for candidate in candidates:
        content = _read_text_file(candidate)
        if content:
            return content
    return ""


def _parent_root(path: str) -> str:
    try:
        return str(Path(path).resolve().parent)
    except Exception:
        return str(Path(path).parent)


def _effective_legacy_project_id(project_id: str) -> str:
    config = get_config()
    fixed_project_id = str(config.history_runs.fixed_project_id or "").strip()
    return fixed_project_id or str(project_id or "").strip()


def _project_files_root(project_id: str) -> Path:
    config = get_config()
    return Path(config.fileserver_service.data_mount_path) / config.fileserver_service.project_files_dirname / _effective_legacy_project_id(project_id)


def _normalize_legacy_request_root(project_id: str, root_path: str) -> Path:
    config = get_config()
    raw = str(root_path or "").strip()
    if not raw:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="root_path is required")
    data_root = Path(config.fileserver_service.data_mount_path).resolve()
    if raw.startswith(str(data_root)):
        target = Path(raw)
    else:
        normalized = posixpath.normpath(raw)
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        if normalized.startswith("/../") or normalized == "/..":
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="root_path escapes project root")
        target = _project_files_root(project_id) / normalized.lstrip("/")
    try:
        resolved = target.resolve()
    except FileNotFoundError:
        resolved = target
    project_root = _project_files_root(project_id).resolve()
    try:
        resolved.relative_to(project_root)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="root_path escapes project root") from exc
    return resolved


class HistoryRunService:
    def _history_run_or_404(self, db: Session, history_run_id: str) -> HistoryRun:
        record = db.get(HistoryRun, history_run_id)
        if record is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="history run not found")
        return record

    def _is_run_directory(self, entry: Path) -> bool:
        return entry.is_dir() and entry.name != "detached_logs" and not entry.name.startswith(".")

    def _legacy_root_candidates(self, project_id: str) -> list[Path]:
        config = get_config()
        effective_project_id = _effective_legacy_project_id(project_id)
        values = []
        for template in config.history_runs.legacy_root_candidates:
            rendered = template.format(
                data_mount_path=config.fileserver_service.data_mount_path.rstrip("/"),
                project_files_dirname=config.fileserver_service.project_files_dirname.strip("/"),
                project_id=effective_project_id,
            )
            values.append(Path(rendered))
        # Keep order but drop duplicates.
        unique: list[Path] = []
        seen = set()
        for path in values:
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            unique.append(path)
        return unique

    def _discover_legacy_runs(self, project_id: str) -> list[tuple[str, Path]]:
        runs: list[tuple[str, Path]] = []
        for root in self._legacy_root_candidates(project_id):
            if not root.is_dir():
                continue
            for entry in sorted(root.iterdir()):
                if self._is_run_directory(entry):
                    runs.append(("legacy_runs_root", entry))
        return runs

    def _discover_execution_runs(self, db: Session, project_id: str) -> list[tuple[WorkflowExecution, Path]]:
        items: list[tuple[WorkflowExecution, Path]] = []
        executions = (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.project_id == project_id)
            .order_by(WorkflowExecution.created_at.desc())
            .all()
        )
        for execution in executions:
            if not execution.workspace_root:
                continue
            path = Path(execution.workspace_root)
            if path.is_dir():
                items.append((execution, path))
        return items

    def _sync_children(self, db: Session, history_run_id: str, detail: dict[str, Any], sessions: list[dict[str, Any]], files: list[dict[str, Any]]) -> None:
        db.query(HistoryRunCycle).filter(HistoryRunCycle.history_run_id == history_run_id).delete(synchronize_session=False)
        db.query(HistoryRunGlobalReview).filter(HistoryRunGlobalReview.history_run_id == history_run_id).delete(synchronize_session=False)
        db.query(HistoryRunResult).filter(HistoryRunResult.history_run_id == history_run_id).delete(synchronize_session=False)
        db.query(HistoryRunResultReview).filter(HistoryRunResultReview.history_run_id == history_run_id).delete(synchronize_session=False)
        db.query(HistoryRunRemovedResult).filter(HistoryRunRemovedResult.history_run_id == history_run_id).delete(synchronize_session=False)
        db.query(HistoryRunSession).filter(HistoryRunSession.history_run_id == history_run_id).delete(synchronize_session=False)
        db.query(HistoryRunFile).filter(HistoryRunFile.history_run_id == history_run_id).delete(synchronize_session=False)

        for cycle in detail.get("cycles") or []:
            cycle_no = int(cycle.get("cycle") or 0)
            cycle_detail = inspect_cycle_detail(detail["path"], cycle_no) if detail.get("atomic_work_path") else {
                "cycle": cycle_no,
                "global_reviews": [],
                "result_reviews": [],
                "summary_snapshot": "",
                "metrics": {},
            }
            db.add(
                HistoryRunCycle(
                    id=_new_id("hrc"),
                    history_run_id=history_run_id,
                    cycle=cycle_no,
                    timestamp=str(cycle.get("timestamp") or ""),
                    outcome=str(cycle.get("outcome") or ""),
                    workflow_mode=str(cycle.get("workflow_mode") or ""),
                    global_passed=bool(cycle.get("global_passed")),
                    failed_advisor_id=str(cycle.get("failed_advisor_id") or ""),
                    failed_role_name=str(cycle.get("failed_role_name") or ""),
                    result_total=int(cycle.get("result_total") or 0),
                    result_passed=int(cycle.get("result_passed") or 0),
                    result_failed=int(cycle.get("result_failed") or 0),
                    scores_json=dict(cycle.get("scores") or {}),
                    metrics_json=dict(cycle_detail.get("metrics") or {}),
                    issues_json=list(cycle.get("issues") or []),
                    plateau_status_json=dict(cycle.get("plateau_status") or {}),
                    summary_snapshot_text=str(cycle_detail.get("summary_snapshot") or ""),
                    raw_json=dict(cycle),
                )
            )
            for review in cycle_detail.get("global_reviews") or []:
                db.add(
                    HistoryRunGlobalReview(
                        id=_new_id("hrgr"),
                        history_run_id=history_run_id,
                        cycle=cycle_no,
                        advisor_id=str(review.get("advisor_id") or ""),
                        path=str(review.get("path") or ""),
                        role_name=str(review.get("role_name") or ""),
                        passed=bool(review.get("passed")),
                        verdict=str(review.get("verdict") or ""),
                        confidence=float(review.get("confidence") or 0),
                        scores_json=dict(review.get("scores") or {}),
                        feedback=str(review.get("feedback") or ""),
                        feedback_detail=str(review.get("feedback_detail") or ""),
                        schema_valid=review.get("schema_valid"),
                        parser_mode=str(review.get("parser_mode") or ""),
                        repair_attempts=int(review.get("repair_attempts") or 0),
                        issues_json=list(review.get("issues") or []),
                        resolved_issue_ids_json=list(review.get("resolved_issue_ids") or []),
                        raw_json=dict(review),
                    )
                )
            for review in cycle_detail.get("result_reviews") or []:
                db.add(
                    HistoryRunResultReview(
                        id=_new_id("hrrr"),
                        history_run_id=history_run_id,
                        cycle=cycle_no,
                        result_file=str(review.get("result_file") or ""),
                        path=str(review.get("path") or ""),
                        advisor_id=str(review.get("advisor_id") or ""),
                        passed=bool(review.get("passed")),
                        verdict=str(review.get("verdict") or ""),
                        confidence=float(review.get("confidence") or 0),
                        feedback=str(review.get("feedback") or ""),
                        feedback_detail=str(review.get("feedback_detail") or ""),
                        schema_valid=review.get("schema_valid"),
                        parser_mode=str(review.get("parser_mode") or ""),
                        repair_attempts=int(review.get("repair_attempts") or 0),
                        raw_json=dict(review),
                    )
                )

        for result in detail.get("results") or []:
            db.add(
                HistoryRunResult(
                    id=_new_id("hrr"),
                    history_run_id=history_run_id,
                    filename=str(result.get("filename") or ""),
                    path=str(result.get("path") or ""),
                    title=str(result.get("title") or ""),
                    size=int(result.get("size") or 0),
                    passed=result.get("passed"),
                    verdict=str(result.get("verdict") or ""),
                    confidence=float(result.get("confidence") or 0),
                    review_cycle=int(result.get("review_cycle") or 0),
                    feedback=str(result.get("feedback") or ""),
                    feedback_detail=str(result.get("feedback_detail") or ""),
                    schema_valid=result.get("schema_valid"),
                    parser_mode=str(result.get("parser_mode") or ""),
                    review_path=str(result.get("review_path") or ""),
                    role=str(result.get("role") or ""),
                    lifecycle_status=str(result.get("lifecycle_status") or ""),
                    active=bool(result.get("active", True)),
                    taskable=bool(result.get("taskable", True)),
                    delivery_bucket=str(result.get("delivery_bucket") or ""),
                    multi_finding=bool(result.get("multi_finding")),
                    vulnerability_headings_json=list(result.get("vulnerability_headings") or []),
                    related_to=str(result.get("related_to") or ""),
                    raw_json=dict(result),
                )
            )

        for result in detail.get("removed_results") or []:
            db.add(
                HistoryRunRemovedResult(
                    id=_new_id("hrrm"),
                    history_run_id=history_run_id,
                    filename=str(result.get("filename") or ""),
                    path=str(result.get("path") or ""),
                    meta_path=str(result.get("meta_path") or ""),
                    cycle=int(result.get("cycle") or 0),
                    lifecycle_status=str(result.get("lifecycle_status") or ""),
                    reason=str(result.get("reason") or ""),
                    signals_json=list(result.get("signals") or []),
                    raw_json=dict(result),
                )
            )

        for session in sessions:
            db.add(
                HistoryRunSession(
                    id=_new_id("hrs"),
                    history_run_id=history_run_id,
                    session_id=str(session.get("session_id") or ""),
                    format=str(session.get("format") or ""),
                    worker_id=str(session.get("worker_id") or ""),
                    jsonl_path=str(session.get("jsonl_path") or ""),
                    size=int(session.get("size") or 0),
                    mtime=float(session.get("mtime") or 0),
                    calls_json=list(session.get("calls") or []),
                    raw_json=dict(session),
                )
            )

        for entry in files:
            db.add(
                HistoryRunFile(
                    id=_new_id("hrf"),
                    history_run_id=history_run_id,
                    category=str(entry.get("category") or ""),
                    path=str(entry.get("path") or ""),
                    name=str(entry.get("name") or ""),
                    size=int(entry.get("size") or 0),
                    mtime=float(entry.get("mtime") or 0),
                    type=str(entry.get("type") or ""),
                )
            )

    def sync_run_path(
        self,
        db: Session,
        *,
        project_id: str,
        run_root: Path,
        source_type: str,
        linked_execution: WorkflowExecution | None = None,
        linked_task: TriggerTask | None = None,
        profile_id: str | None = None,
    ) -> HistoryRun:
        run_root = run_root.resolve()
        if not run_root.is_dir():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"run root not found: {run_root}")

        source_key = str(run_root)
        source_mtime = _compute_source_mtime(run_root)
        record = db.query(HistoryRun).filter(HistoryRun.source_key == source_key).first()
        if record is not None and record.source_mtime >= source_mtime:
            return record

        summary = inspect_run_summary(run_root)
        detail = inspect_run_detail(run_root)
        sessions = inspect_sessions(run_root)
        files = inspect_files(run_root, limit=20000)
        run_log = inspect_log(run_root, lines=2000).get("content", "")
        run_timestamps = _read_json_file(run_root / "_meta" / "run_timestamps.json")
        started_at = _parse_datetime(str(run_timestamps.get("started_at") or "")) or _datetime_from_epoch(summary.get("start_epoch"))
        finished_at = _parse_datetime(str(run_timestamps.get("finished_at") or ""))
        last_activity_at = _parse_datetime(str(detail.get("last_activity") or "")) or finished_at
        if finished_at is None and summary.get("status") not in {"running", "pending", "queued", "cancel_requested"}:
            duration = int(summary.get("duration_seconds") or 0)
            if started_at and duration > 0:
                finished_at = started_at + timedelta(seconds=duration)
        log_path = run_root / "run.log"
        raw_summary = {
            "start_time": str(summary.get("start_time") or ""),
            "summary_markdown": _summary_markdown_for_run(run_root, detail.get("atomic_work_path")),
            "task_markdown": _task_markdown_for_run(run_root),
        }

        if record is None:
            record = HistoryRun(id=_new_id("hr"))

        record.project_id = project_id
        record.source_type = source_type
        record.source_key = source_key
        record.run_name = str(summary.get("name") or run_root.name)
        record.run_root_path = str(run_root)
        record.atomic_work_path = str(detail.get("atomic_work_path") or "")
        record.linked_task_id = linked_task.id if linked_task else (linked_execution.trigger_task_id if linked_execution else None)
        record.linked_execution_id = linked_execution.id if linked_execution else None
        record.profile_id = profile_id or (linked_task.profile_id if linked_task else None)
        record.status = str(summary.get("status") or "pending")
        record.started_at = started_at
        record.finished_at = finished_at
        record.duration_seconds = int(summary.get("duration_seconds") or 0)
        record.last_activity_at = last_activity_at
        record.model = str(summary.get("model") or "")
        record.provider = str(summary.get("provider") or "")
        record.thinking = str(summary.get("thinking") or "")
        record.max_cycles = int(summary.get("max_cycles") or 0)
        record.cycles_used = int(summary.get("cycles_used") or 0)
        record.result_count = int(summary.get("result_count") or 0)
        record.passed_count = int(summary.get("passed_count") or 0)
        record.failed_count = int(summary.get("failed_count") or 0)
        record.workflow_mode = str(summary.get("workflow_mode") or "")
        record.error = str(detail.get("error") or "")
        record.config_json = dict(detail.get("config") or {})
        record.manifests_json = dict(detail.get("manifests") or {})
        record.latest_issues_json = list(detail.get("latest_issues") or [])
        record.raw_summary_json = raw_summary
        record.log_tail_text = run_log
        record.log_size_bytes = log_path.stat().st_size if log_path.is_file() else 0
        record.source_mtime = source_mtime
        record.last_synced_at = datetime.utcnow()
        db.add(record)
        db.flush()
        detail["path"] = str(run_root)
        self._sync_children(db, record.id, detail, sessions, files)
        db.flush()
        return record

    def sync_execution_run(self, db: Session, execution: WorkflowExecution) -> HistoryRun | None:
        if not execution.workspace_root:
            return None
        run_root = Path(execution.workspace_root)
        if not run_root.is_dir():
            return None
        linked_task = db.get(TriggerTask, execution.trigger_task_id)
        return self.sync_run_path(
            db,
            project_id=execution.project_id,
            run_root=run_root,
            source_type="execution_workspace",
            linked_execution=execution,
            linked_task=linked_task,
            profile_id=linked_task.profile_id if linked_task else None,
        )

    def sync_project_history_runs(self, db: Session, project_id: str) -> None:
        if not get_config().history_runs.enabled:
            return
        for execution, run_root in self._discover_execution_runs(db, project_id):
            linked_task = db.get(TriggerTask, execution.trigger_task_id)
            self.sync_run_path(
                db,
                project_id=project_id,
                run_root=run_root,
                source_type="execution_workspace",
                linked_execution=execution,
                linked_task=linked_task,
                profile_id=linked_task.profile_id if linked_task else None,
            )
        for source_type, run_root in self._discover_legacy_runs(project_id):
            self.sync_run_path(
                db,
                project_id=project_id,
                run_root=run_root,
                source_type=source_type,
            )
        db.commit()

    def refresh_history_run(self, db: Session, history_run: HistoryRun) -> HistoryRun:
        run_root = Path(history_run.run_root_path)
        if not run_root.is_dir():
            return history_run
        current_mtime = _compute_source_mtime(run_root)
        if current_mtime <= float(history_run.source_mtime or 0):
            return history_run
        linked_execution = db.get(WorkflowExecution, history_run.linked_execution_id) if history_run.linked_execution_id else None
        linked_task = db.get(TriggerTask, history_run.linked_task_id) if history_run.linked_task_id else None
        history_run = self.sync_run_path(
            db,
            project_id=history_run.project_id,
            run_root=run_root,
            source_type=history_run.source_type,
            linked_execution=linked_execution,
            linked_task=linked_task,
            profile_id=history_run.profile_id,
        )
        db.commit()
        return history_run

    def resolve_history_run(self, db: Session, *, project_id: str, run_name: str, root_path: str) -> HistoryRun:
        normalized_root = _normalize_legacy_request_root(project_id, root_path)
        candidate = normalized_root / run_name
        record = db.query(HistoryRun).filter(HistoryRun.project_id == project_id, HistoryRun.run_root_path == str(candidate)).first()
        if record is not None:
            return self.refresh_history_run(db, record)
        self.sync_project_history_runs(db, project_id)
        record = db.query(HistoryRun).filter(HistoryRun.project_id == project_id, HistoryRun.run_root_path == str(candidate)).first()
        if record is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="history run not found")
        return record

    def _summary_payload(self, history_run: HistoryRun) -> dict[str, Any]:
        return {
            "history_run_id": history_run.id,
            "project_id": history_run.project_id,
            "source_type": history_run.source_type,
            "source_key": history_run.source_key,
            "linked_task_id": history_run.linked_task_id,
            "linked_execution_id": history_run.linked_execution_id,
            "profile_id": history_run.profile_id,
            "name": history_run.run_name,
            "path": history_run.run_root_path,
            "root_path": _parent_root(history_run.run_root_path),
            "status": history_run.status,
            "start_time": str((history_run.raw_summary_json or {}).get("start_time") or ""),
            "start_epoch": int(history_run.started_at.replace(tzinfo=timezone.utc).timestamp()) if history_run.started_at else 0,
            "duration_seconds": history_run.duration_seconds,
            "last_activity": _iso_or_empty(history_run.last_activity_at),
            "model": history_run.model,
            "provider": history_run.provider,
            "thinking": history_run.thinking,
            "max_cycles": history_run.max_cycles,
            "cycles_used": history_run.cycles_used,
            "result_count": history_run.result_count,
            "passed_count": history_run.passed_count,
            "failed_count": history_run.failed_count,
            "workflow_mode": history_run.workflow_mode,
            "updated_at": _iso_or_empty(history_run.last_synced_at),
        }

    def list_history_runs(self, db: Session, project_id: str) -> list[dict[str, Any]]:
        self.sync_project_history_runs(db, project_id)
        records = [
            item
            for item in db.query(HistoryRun).filter(HistoryRun.project_id == project_id).all()
            if Path(item.run_root_path).is_dir()
        ]
        records.sort(
            key=lambda item: (
                item.started_at or datetime.min,
                item.last_activity_at or datetime.min,
                item.created_at or datetime.min,
            ),
            reverse=True,
        )
        return [self._summary_payload(self.refresh_history_run(db, item)) for item in records]

    def get_history_run_summary(self, db: Session, history_run: HistoryRun) -> dict[str, Any]:
        history_run = self.refresh_history_run(db, history_run)
        return self._summary_payload(history_run)

    def _cycle_payloads(self, db: Session, history_run_id: str) -> list[dict[str, Any]]:
        cycles = (
            db.query(HistoryRunCycle)
            .filter(HistoryRunCycle.history_run_id == history_run_id)
            .order_by(HistoryRunCycle.cycle.asc())
            .all()
        )
        return [
            {
                "cycle": item.cycle,
                "timestamp": item.timestamp,
                "outcome": item.outcome,
                "workflow_mode": item.workflow_mode,
                "global_passed": item.global_passed,
                "failed_advisor_id": item.failed_advisor_id,
                "failed_role_name": item.failed_role_name,
                "result_total": item.result_total,
                "result_passed": item.result_passed,
                "result_failed": item.result_failed,
                "scores": dict(item.scores_json or {}),
                "global_failure_scope": dict(item.metrics_json or {}).get("global_failure_scope", ""),
                "failed_result_count": dict(item.metrics_json or {}).get("failed_result_count", item.result_failed),
                "current_failed_result_count": dict(item.metrics_json or {}).get("current_failed_result_count", item.result_failed),
                "historical_removed_result_count": dict(item.metrics_json or {}).get("historical_removed_result_count", 0),
                "unreviewed_new_result_count": dict(item.metrics_json or {}).get("unreviewed_new_result_count", 0),
                "unreviewed_new_result_files": dict(item.metrics_json or {}).get("unreviewed_new_result_files", []),
                "issue_count": len(item.issues_json or []),
                "issue_ids": dict(item.metrics_json or {}).get("issue_ids", []),
                "summary_size": dict(item.metrics_json or {}).get("summary_size", 0),
                "plateau_status": dict(item.plateau_status_json or {}),
                "issues": list(item.issues_json or []),
            }
            for item in cycles
        ]

    def _result_payloads(self, db: Session, history_run_id: str) -> list[dict[str, Any]]:
        results = (
            db.query(HistoryRunResult)
            .filter(HistoryRunResult.history_run_id == history_run_id)
            .order_by(HistoryRunResult.filename.asc())
            .all()
        )
        return [
            {
                "filename": item.filename,
                "path": item.path,
                "title": item.title,
                "size": item.size,
                "passed": item.passed,
                "verdict": item.verdict,
                "confidence": item.confidence,
                "review_cycle": item.review_cycle,
                "feedback": item.feedback or "",
                "feedback_detail": item.feedback_detail or "",
                "schema_valid": item.schema_valid,
                "parser_mode": item.parser_mode,
                "review_path": item.review_path,
                "role": item.role,
                "lifecycle_status": item.lifecycle_status,
                "active": item.active,
                "taskable": item.taskable,
                "delivery_bucket": item.delivery_bucket,
                "multi_finding": item.multi_finding,
                "vulnerability_headings": list(item.vulnerability_headings_json or []),
                "related_to": item.related_to,
            }
            for item in results
        ]

    def _removed_result_payloads(self, db: Session, history_run_id: str) -> list[dict[str, Any]]:
        results = (
            db.query(HistoryRunRemovedResult)
            .filter(HistoryRunRemovedResult.history_run_id == history_run_id)
            .order_by(HistoryRunRemovedResult.cycle.asc(), HistoryRunRemovedResult.filename.asc())
            .all()
        )
        return [
            {
                "filename": item.filename,
                "path": item.path,
                "meta_path": item.meta_path,
                "cycle": item.cycle,
                "lifecycle_status": item.lifecycle_status,
                "reason": item.reason or "",
                "signals": list(item.signals_json or []),
            }
            for item in results
        ]

    def list_history_run_sessions(self, db: Session, history_run: HistoryRun) -> list[dict[str, Any]]:
        history_run = self.refresh_history_run(db, history_run)
        sessions = (
            db.query(HistoryRunSession)
            .filter(HistoryRunSession.history_run_id == history_run.id)
            .order_by(HistoryRunSession.session_id.asc())
            .all()
        )
        return [
            {
                "session_id": item.session_id,
                "format": item.format,
                "worker_id": item.worker_id,
                "jsonl_path": item.jsonl_path,
                "size": item.size,
                "mtime": item.mtime,
                "calls": list(item.calls_json or []),
            }
            for item in sessions
        ]

    def list_history_run_files(self, db: Session, history_run: HistoryRun, limit: int = 1200) -> list[dict[str, Any]]:
        history_run = self.refresh_history_run(db, history_run)
        files = (
            db.query(HistoryRunFile)
            .filter(HistoryRunFile.history_run_id == history_run.id)
            .order_by(HistoryRunFile.category.asc(), HistoryRunFile.path.asc())
            .limit(limit)
            .all()
        )
        return [
            {
                "category": item.category,
                "path": item.path,
                "name": item.name,
                "size": item.size,
                "mtime": item.mtime,
                "type": item.type,
            }
            for item in files
        ]

    def get_history_run_detail(self, db: Session, history_run: HistoryRun) -> dict[str, Any]:
        history_run = self.refresh_history_run(db, history_run)
        payload = self._summary_payload(history_run)
        payload.update(
            {
                "config": dict(history_run.config_json or {}),
                "error": history_run.error or None,
                "cycles": self._cycle_payloads(db, history_run.id),
                "results": self._result_payloads(db, history_run.id),
                "removed_results": self._removed_result_payloads(db, history_run.id),
                "manifests": dict(history_run.manifests_json or {}),
                "latest_issues": list(history_run.latest_issues_json or []),
                "atomic_work_path": history_run.atomic_work_path or "",
                "files": self.list_history_run_files(db, history_run, limit=20000),
                "sessions": self.list_history_run_sessions(db, history_run),
                "run_log": history_run.log_tail_text or "",
                "raw": dict(history_run.raw_summary_json or {}),
            }
        )
        return payload

    def get_history_run_cycle(self, db: Session, history_run: HistoryRun, cycle: int) -> dict[str, Any]:
        history_run = self.refresh_history_run(db, history_run)
        cycle_row = (
            db.query(HistoryRunCycle)
            .filter(HistoryRunCycle.history_run_id == history_run.id, HistoryRunCycle.cycle == cycle)
            .first()
        )
        if cycle_row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="history run cycle not found")
        global_reviews = (
            db.query(HistoryRunGlobalReview)
            .filter(HistoryRunGlobalReview.history_run_id == history_run.id, HistoryRunGlobalReview.cycle == cycle)
            .order_by(HistoryRunGlobalReview.advisor_id.asc())
            .all()
        )
        result_reviews = (
            db.query(HistoryRunResultReview)
            .filter(HistoryRunResultReview.history_run_id == history_run.id, HistoryRunResultReview.cycle == cycle)
            .order_by(HistoryRunResultReview.result_file.asc(), HistoryRunResultReview.advisor_id.asc())
            .all()
        )
        return {
            "cycle": cycle,
            "global_reviews": [
                {
                    "advisor_id": item.advisor_id,
                    "path": item.path,
                    "role_name": item.role_name,
                    "passed": item.passed,
                    "verdict": item.verdict,
                    "scores": dict(item.scores_json or {}),
                    "confidence": item.confidence,
                    "feedback": item.feedback or "",
                    "feedback_detail": item.feedback_detail or "",
                    "schema_valid": item.schema_valid,
                    "parser_mode": item.parser_mode,
                    "repair_attempts": item.repair_attempts,
                    "issues": list(item.issues_json or []),
                    "resolved_issue_ids": list(item.resolved_issue_ids_json or []),
                }
                for item in global_reviews
            ],
            "result_reviews": [
                {
                    "result_file": item.result_file,
                    "path": item.path,
                    "advisor_id": item.advisor_id,
                    "passed": item.passed,
                    "verdict": item.verdict,
                    "confidence": item.confidence,
                    "feedback": item.feedback or "",
                    "feedback_detail": item.feedback_detail or "",
                    "schema_valid": item.schema_valid,
                    "parser_mode": item.parser_mode,
                    "repair_attempts": item.repair_attempts,
                }
                for item in result_reviews
            ],
            "summary_snapshot": cycle_row.summary_snapshot_text or "",
            "metrics": dict(cycle_row.metrics_json or {}),
        }

    def get_history_run_file(self, db: Session, history_run: HistoryRun, path: str) -> dict[str, Any]:
        history_run = self.refresh_history_run(db, history_run)
        return inspect_file(history_run.run_root_path, path)

    def get_history_run_session_file(self, db: Session, history_run: HistoryRun, path: str) -> dict[str, Any]:
        history_run = self.refresh_history_run(db, history_run)
        return inspect_session_file(history_run.run_root_path, path)

    def get_history_run_log(self, db: Session, history_run: HistoryRun, lines: int = 300) -> dict[str, Any]:
        history_run = self.refresh_history_run(db, history_run)
        return inspect_log(history_run.run_root_path, lines=lines)

    def get_history_run_by_execution(self, db: Session, execution: WorkflowExecution) -> HistoryRun | None:
        if not execution.workspace_root:
            return None
        record = db.query(HistoryRun).filter(HistoryRun.linked_execution_id == execution.id).first()
        if record is not None:
            return self.refresh_history_run(db, record)
        record = self.sync_execution_run(db, execution)
        if record is not None:
            db.commit()
        return record


_history_run_service: HistoryRunService | None = None


def get_history_run_service() -> HistoryRunService:
    global _history_run_service
    if _history_run_service is None:
        _history_run_service = HistoryRunService()
    return _history_run_service
