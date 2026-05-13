from __future__ import annotations

import json
import re
import shlex
import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_config
from app.models.database import (
    RunIndex,
    RunIndexCycle,
    RunIndexFile,
    RunIndexGlobalReview,
    RunIndexRemovedResult,
    RunIndexResult,
    RunIndexResultReview,
    RunIndexSession,
    TriggerTask,
    WorkflowExecution,
    WorkflowExecutionEvent,
    run_source_hash,
)
from app.services.run_inspector import (
    _session_runtime_metadata,
    collect_new_results_by_cycle,
    derive_profile_gate_summary,
    inspect_cycle_detail,
    inspect_file,
    inspect_files,
    inspect_log,
    inspect_run_detail,
    inspect_run_summary,
    inspect_session_file,
    inspect_sessions,
    load_active_issue_records_from_ledger,
)
from app.time_utils import UTC_PLUS_8, ensure_local, isoformat_local, now_local

RUN_INDEX_LOG_SUMMARY_MAX_CHARS = 32768
_ACTIVE_RUN_INDEX_STATUSES = {"running", "pending", "queued", "cancel_requested", "delete_requested"}
_SOURCE_MTIME_COMPARE_EPSILON = 1e-6


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def _safe_path_component(value: Any) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "").strip())
    return text[:160] or "unknown"


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


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
    return ensure_local(parsed)


def _datetime_from_epoch(value: int | float | None) -> datetime | None:
    epoch = float(value or 0)
    if epoch <= 0:
        return None
    return datetime.fromtimestamp(epoch, tz=UTC_PLUS_8).replace(tzinfo=None)


def _iso_or_empty(value: datetime | None) -> str:
    return isoformat_local(value) or ""


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


def _write_json_file(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _run_index_db_meta_dir(run_root: str | Path) -> Path:
    return Path(run_root) / "run" / "_meta" / "run_index_db"


def _relative_to_run_root(run_root: str | Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path(run_root).resolve()))
    except Exception:
        return str(path)


def _externalize_json_payload(
    run_root: str | Path,
    relative_name: str,
    payload: Any,
    *,
    summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    path = _run_index_db_meta_dir(run_root) / relative_name
    _write_json_file(path, payload)
    result = dict(summary or {})
    result["externalized"] = True
    result["raw_file"] = _relative_to_run_root(run_root, path)
    return result


def _load_externalized_json_payload(run_root: str | Path, stored: Any) -> Any:
    if not isinstance(stored, dict):
        return stored
    raw_file = str(stored.get("raw_file") or "").strip()
    if not raw_file:
        return stored
    path = Path(run_root) / raw_file
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return stored


def _load_externalized_mapping_payload(run_root: str | Path, stored: Any) -> dict[str, Any]:
    payload = _load_externalized_json_payload(run_root, stored)
    return dict(payload) if isinstance(payload, dict) else {}


def _load_externalized_list_payload(run_root: str | Path, stored: Any) -> list[Any]:
    payload = _load_externalized_json_payload(run_root, stored)
    return list(payload) if isinstance(payload, list) else []


def _externalized_list_summary(payload: list[Any], *, preview_limit: int = 20) -> dict[str, Any]:
    preview = payload[:preview_limit] if isinstance(payload, list) else []
    return {
        "count": len(payload) if isinstance(payload, list) else 0,
        "preview": preview,
    }


def _truncate_log_summary(content: str, max_chars: int = RUN_INDEX_LOG_SUMMARY_MAX_CHARS) -> str:
    text = str(content or "")
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    return text[-max_chars:]


def _raw_summary_db_view(payload: dict[str, Any]) -> dict[str, Any]:
    cli_payload = payload.get("dataflow_cli") if isinstance(payload.get("dataflow_cli"), dict) else {}
    current_step = payload.get("current_step") if isinstance(payload.get("current_step"), dict) else {}
    step_history = payload.get("step_history") if isinstance(payload.get("step_history"), list) else []
    cycle_timing = payload.get("cycle_timing") if isinstance(payload.get("cycle_timing"), dict) else {}
    return {
        "start_time": str(payload.get("start_time") or ""),
        "command": list(payload.get("command") or []) if isinstance(payload.get("command"), list) else [],
        "command_display": str(payload.get("command_display") or ""),
        "dataflow_cli": cli_payload,
        "current_step": {
            "cycle": current_step.get("cycle"),
            "phase": current_step.get("phase"),
            "step_key": current_step.get("step_key"),
            "status": current_step.get("status"),
            "started_at": current_step.get("started_at"),
            "started_epoch": current_step.get("started_epoch"),
            "finished_at": current_step.get("finished_at"),
            "finished_epoch": current_step.get("finished_epoch"),
            "duration_seconds": current_step.get("duration_seconds"),
            "duration_ms": current_step.get("duration_ms"),
            "elapsed_seconds": current_step.get("elapsed_seconds"),
        },
        "step_history_count": len(step_history),
        "cycle_timing": cycle_timing,
        "summary_markdown_length": len(str(payload.get("summary_markdown") or "")),
        "task_markdown_length": len(str(payload.get("task_markdown") or "")),
    }


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


def _compute_source_mtime_hint(run_root: Path, atomic_work_path: str | None = None) -> float:
    runtime_root = run_root / "run"
    candidates: list[Path] = [
        run_root,
        runtime_root,
        runtime_root / "_meta",
        runtime_root / "_meta" / "run_timestamps.json",
        runtime_root / "_meta" / "process.json",
        runtime_root / "input",
        runtime_root / "workspace",
        runtime_root / "ws",
        runtime_root / "config.json",
        runtime_root / "run.log",
        run_root / "_meta",
        run_root / "_meta" / "run_timestamps.json",
        run_root / "_meta" / "process.json",
        run_root / "input",
        run_root / "output",
        run_root / "workspace",
        run_root / "ws",
        run_root / "config.json",
        run_root / "run.log",
    ]
    glob_specs: list[tuple[Path, str]] = []
    atomic_text = str(atomic_work_path or "").strip()
    if atomic_text:
        atomic = Path(atomic_text)
        candidates.extend([
            atomic,
            atomic / "_meta",
            atomic / "_meta" / "state.json",
            atomic / "_meta" / "workflow_result.json",
            atomic / "_meta" / "results_manifest.json",
            atomic / "_meta" / "result_relations_manifest.json",
            atomic / "_meta" / "coverage_ledger.json",
            atomic / "_meta" / "review_summaries",
            atomic / "_meta" / "review_feedback",
            atomic / "_meta" / "cycle_metrics",
            atomic / "_meta" / "summary_snapshots",
            atomic / "results",
            atomic / "final_output",
            atomic / "final_output" / "results",
            atomic / "reviews",
            atomic / "sessions",
            atomic / "supporting_docs",
            atomic / "removed_results",
            atomic / "output",
            atomic / "working",
            atomic / "input",
        ])
        glob_specs.extend([
            (atomic / "_meta" / "review_summaries", "*.json"),
            (atomic / "_meta" / "cycle_metrics", "*.json"),
            (atomic / "_meta" / "summary_snapshots", "*"),
            (atomic / "reviews", "**/*.json"),
            (atomic / "results", "*.md"),
            (atomic / "final_output", "summary.md"),
            (atomic / "final_output" / "results", "*.md"),
            (atomic / "supporting_docs", "**/*"),
            (atomic / "removed_results", "**/*"),
            (atomic / "sessions", "*/calls/*/response.json"),
        ])
    latest = 0.0
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        try:
            if candidate.exists():
                latest = max(latest, candidate.stat().st_mtime)
        except OSError:
            continue
    for root, pattern in glob_specs:
        try:
            matches = root.glob(pattern)
        except OSError:
            continue
        for candidate in matches:
            key = str(candidate)
            if key in seen:
                continue
            seen.add(key)
            try:
                if candidate.exists():
                    latest = max(latest, candidate.stat().st_mtime)
            except OSError:
                continue
    return latest


def _stored_source_mtime(value: Any) -> float:
    try:
        return max(float(value or 0), 0.0)
    except (TypeError, ValueError):
        return 0.0


def _source_mtime_is_current(current_mtime: float, stored_mtime: Any) -> bool:
    return current_mtime <= (_stored_source_mtime(stored_mtime) + _SOURCE_MTIME_COMPARE_EPSILON)


def _find_run_by_source(db: Session, *, source_type: str, source_key: str, source_hash: str) -> RunIndex | None:
    record = db.query(RunIndex).filter(
        RunIndex.source_type == source_type,
        RunIndex.source_hash == source_hash,
    ).first()
    if record is not None:
        return record
    return db.query(RunIndex).filter(
        RunIndex.source_type == source_type,
        RunIndex.source_key == source_key,
    ).first()


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
    content = _read_text_file(run_root / "run" / "input" / "task.md")
    if content:
        return content
    for candidate in run_root.glob("trigger_inputs/*/input/task.md"):
        content = _read_text_file(candidate)
        if content:
            return content
    content = _read_text_file(run_root / "input" / "task.md")
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


def _command_display(args: list[Any]) -> str:
    return " ".join(shlex.quote(str(item)) for item in args)


def _normalize_command_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    command = payload.get("command")
    if not isinstance(command, list):
        command = payload.get("argv") if isinstance(payload.get("argv"), list) else []
    command = [str(item) for item in command]
    command_display = str(payload.get("command_display") or "").strip()
    if not command_display and command:
        command_display = _command_display(command)
    normalized: dict[str, Any] = {
        "command": command,
        "command_display": command_display,
    }
    for key in ("argv", "launcher", "launch_mode", "run_name", "runs_root"):
        if key in payload:
            normalized[key] = payload[key]
    return {key: value for key, value in normalized.items() if value not in ("", [], None)}


def _task_dataflow_cli_payload(linked_task: TriggerTask | None) -> dict[str, Any]:
    if linked_task is None or not isinstance(linked_task.input_tasks_json, dict):
        return {}
    tasks = linked_task.input_tasks_json.get("tasks")
    if not isinstance(tasks, list):
        return {}
    for item in tasks:
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        payload = _normalize_command_payload(metadata.get("dataflow_cli") if isinstance(metadata.get("dataflow_cli"), dict) else {})
        if payload:
            return payload
    return {}


def _execution_started_command_payload(db: Session, linked_execution: WorkflowExecution | None) -> dict[str, Any]:
    if linked_execution is None:
        return {}
    event = (
        db.query(WorkflowExecutionEvent)
        .filter(
            WorkflowExecutionEvent.execution_id == linked_execution.id,
            WorkflowExecutionEvent.event_type == "execution_started",
        )
        .order_by(WorkflowExecutionEvent.created_at.desc())
        .first()
    )
    return _normalize_command_payload(dict(event.payload_json or {}) if event else {})


def _process_file_command_payload(run_root: Path) -> dict[str, Any]:
    payload = _read_json_file(run_root / "run" / "_meta" / "process.json") or _read_json_file(run_root / "_meta" / "process.json")
    return _normalize_command_payload(payload)


def _run_command_payload(
    db: Session,
    *,
    run_root: Path,
    linked_execution: WorkflowExecution | None,
    linked_task: TriggerTask | None,
) -> dict[str, Any]:
    for candidate in (
        _execution_started_command_payload(db, linked_execution),
        _task_dataflow_cli_payload(linked_task),
        _process_file_command_payload(run_root),
    ):
        if candidate.get("command_display") or candidate.get("command"):
            return candidate
    return {}


def _parent_root(path: str) -> str:
    try:
        return str(Path(path).resolve().parent)
    except Exception:
        return str(Path(path).parent)


def _detail_atomic_work_path(detail: dict[str, Any]) -> str:
    return str(detail.get("atomic_work_path") or detail.get("atomic_work_dir") or "").strip()


def _run_index_needs_parser_resync(record: RunIndex) -> bool:
    atomic_work_path = str(record.atomic_work_path or "").strip()
    if not atomic_work_path:
        return True
    try:
        return not Path(atomic_work_path).is_dir()
    except Exception:
        return True


def _run_index_is_active(record: RunIndex) -> bool:
    return str(record.status or "").strip().lower() in _ACTIVE_RUN_INDEX_STATUSES


def _new_results_by_cycle_for_index(run_index: RunIndex) -> dict[int, list[dict[str, Any]]]:
    atomic_work_path = str(run_index.atomic_work_path or "").strip()
    if not atomic_work_path:
        return {}
    try:
        atomic = Path(atomic_work_path)
    except Exception:
        return {}
    if not atomic.is_dir():
        return {}
    return collect_new_results_by_cycle(atomic)


def _project_files_root(project_id: str) -> Path:
    config = get_config()
    return Path(config.fileserver_service.data_mount_path) / config.fileserver_service.project_files_dirname / str(project_id or "").strip()


def _project_watch_path(project_id: str, absolute_path: str | Path) -> str:
    try:
        project_root = _project_files_root(project_id).resolve()
        target = Path(absolute_path).resolve()
        rel = target.relative_to(project_root)
        return "/" + str(rel).replace("\\", "/")
    except Exception:
        return ""


def _normalize_execution_request_root(root_path: str) -> Path:
    raw = str(root_path or "").strip()
    if not raw:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="root_path is required")
    target = Path(raw)
    if not target.is_absolute():
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="root_path must be absolute")
    return target.resolve()


class RunIndexService:
    def _refresh_record_bindings(
        self,
        record: RunIndex,
        *,
        project_id: str,
        source_type: str,
        linked_execution: WorkflowExecution | None,
        linked_task: TriggerTask | None,
        profile_id: str | None,
    ) -> None:
        record.project_id = project_id
        record.source_type = source_type
        if linked_execution is not None:
            record.linked_execution_id = linked_execution.id
        if linked_task is not None:
            record.linked_task_id = linked_task.id
        elif linked_execution is not None and linked_execution.trigger_task_id:
            record.linked_task_id = linked_execution.trigger_task_id
        if profile_id:
            record.profile_id = profile_id
        elif linked_task is not None and linked_task.profile_id:
            record.profile_id = linked_task.profile_id

    def _run_index_or_404(self, db: Session, run_index_id: str) -> RunIndex:
        record = db.get(RunIndex, run_index_id)
        if record is None or record.source_type != "execution_workspace":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run not found")
        return record

    def _delete_children(
        self,
        db: Session,
        run_index_id: str,
        *,
        include_sessions: bool = True,
        include_files: bool = True,
    ) -> None:
        db.query(RunIndexCycle).filter(RunIndexCycle.run_index_id == run_index_id).delete(synchronize_session=False)
        db.query(RunIndexGlobalReview).filter(RunIndexGlobalReview.run_index_id == run_index_id).delete(synchronize_session=False)
        db.query(RunIndexResult).filter(RunIndexResult.run_index_id == run_index_id).delete(synchronize_session=False)
        db.query(RunIndexResultReview).filter(RunIndexResultReview.run_index_id == run_index_id).delete(synchronize_session=False)
        db.query(RunIndexRemovedResult).filter(RunIndexRemovedResult.run_index_id == run_index_id).delete(synchronize_session=False)
        if include_sessions:
            db.query(RunIndexSession).filter(RunIndexSession.run_index_id == run_index_id).delete(synchronize_session=False)
        if include_files:
            db.query(RunIndexFile).filter(RunIndexFile.run_index_id == run_index_id).delete(synchronize_session=False)

    def _managed_project_run_root(self, project_id: str, run_root: str | Path) -> Path:
        project_root = _project_files_root(project_id).resolve()
        candidate = Path(run_root).resolve()
        try:
            candidate.relative_to(project_root)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="run path escapes project root") from exc
        return candidate

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

    def _sync_children(
        self,
        db: Session,
        run_index_id: str,
        detail: dict[str, Any],
        sessions: list[dict[str, Any]],
        files: list[dict[str, Any]],
        *,
        include_sessions: bool = True,
        include_files: bool = True,
    ) -> None:
        self._delete_children(
            db,
            run_index_id,
            include_sessions=include_sessions,
            include_files=include_files,
        )
        run_root = Path(str(detail.get("path") or "")).resolve()

        for cycle in detail.get("cycles") or []:
            cycle_no = int(cycle.get("cycle") or 0)
            cycle_detail = inspect_cycle_detail(detail["path"], cycle_no) if _detail_atomic_work_path(detail) else {
                "cycle": cycle_no,
                "global_reviews": [],
                "result_reviews": [],
                "summary_snapshot": "",
                "metrics": {},
            }
            db.add(
                RunIndexCycle(
                    id=_new_id("ric"),
                    run_index_id=run_index_id,
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
                    scores_json=_externalize_json_payload(
                        run_root,
                        f"cycles/cycle_{cycle_no:03d}.scores.json",
                        dict(cycle.get("scores") or {}),
                    ),
                    metrics_json=_externalize_json_payload(
                        run_root,
                        f"cycles/cycle_{cycle_no:03d}.metrics.json",
                        dict(cycle_detail.get("metrics") or {}),
                    ),
                    issues_json=_externalize_json_payload(
                        run_root,
                        f"cycles/cycle_{cycle_no:03d}.issues.json",
                        list(cycle.get("issues") or []),
                        summary=_externalized_list_summary(list(cycle.get("issues") or [])),
                    ),
                    plateau_status_json=_externalize_json_payload(
                        run_root,
                        f"cycles/cycle_{cycle_no:03d}.plateau_status.json",
                        dict(cycle.get("plateau_status") or {}),
                    ),
                    summary_snapshot_text=str(cycle_detail.get("summary_snapshot") or ""),
                    raw_json=_externalize_json_payload(
                        run_root,
                        f"cycles/cycle_{cycle_no:03d}.json",
                        dict(cycle),
                        summary={
                            "cycle": cycle_no,
                            "outcome": str(cycle.get("outcome") or ""),
                            "result_total": int(cycle.get("result_total") or 0),
                            "new_result_count": _safe_int(cycle.get("new_result_count")),
                            "issue_count": len(list(cycle.get("issues") or [])),
                        },
                    ),
                )
            )
            for review in cycle_detail.get("global_reviews") or []:
                advisor_id = _safe_path_component(review.get("advisor_id") or "unknown")
                db.add(
                    RunIndexGlobalReview(
                        id=_new_id("rigr"),
                        run_index_id=run_index_id,
                        cycle=cycle_no,
                        advisor_id=str(review.get("advisor_id") or ""),
                        path=str(review.get("path") or ""),
                        role_name=str(review.get("role_name") or ""),
                        passed=bool(review.get("passed")),
                        verdict=str(review.get("verdict") or ""),
                        confidence=float(review.get("confidence") or 0),
                        scores_json=_externalize_json_payload(
                            run_root,
                            f"global_reviews/cycle_{cycle_no:03d}/{advisor_id}.scores.json",
                            dict(review.get("scores") or {}),
                        ),
                        feedback=str(review.get("feedback") or ""),
                        feedback_detail=str(review.get("feedback_detail") or ""),
                        schema_valid=review.get("schema_valid"),
                        parser_mode=str(review.get("parser_mode") or ""),
                        repair_attempts=int(review.get("repair_attempts") or 0),
                        issues_json=_externalize_json_payload(
                            run_root,
                            f"global_reviews/cycle_{cycle_no:03d}/{advisor_id}.issues.json",
                            list(review.get("issues") or []),
                            summary=_externalized_list_summary(list(review.get("issues") or [])),
                        ),
                        resolved_issue_ids_json=_externalize_json_payload(
                            run_root,
                            f"global_reviews/cycle_{cycle_no:03d}/{advisor_id}.resolved_issue_ids.json",
                            list(review.get("resolved_issue_ids") or []),
                            summary=_externalized_list_summary(list(review.get("resolved_issue_ids") or [])),
                        ),
                        raw_json=_externalize_json_payload(
                            run_root,
                            f"global_reviews/cycle_{cycle_no:03d}/{advisor_id}.json",
                            dict(review),
                            summary={
                                "advisor_id": advisor_id,
                                "passed": bool(review.get("passed")),
                                "verdict": str(review.get("verdict") or ""),
                            },
                        ),
                    )
                )
            for review in cycle_detail.get("result_reviews") or []:
                advisor_id = _safe_path_component(review.get("advisor_id") or "unknown")
                result_file = _safe_path_component(review.get("result_file") or "unknown")
                db.add(
                    RunIndexResultReview(
                        id=_new_id("rirr"),
                        run_index_id=run_index_id,
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
                        raw_json=_externalize_json_payload(
                            run_root,
                            f"result_reviews/cycle_{cycle_no:03d}/{result_file}__{advisor_id}.json",
                            dict(review),
                            summary={
                                "result_file": result_file,
                                "advisor_id": advisor_id,
                                "passed": bool(review.get("passed")),
                                "verdict": str(review.get("verdict") or ""),
                            },
                        ),
                    )
                )

        for result in detail.get("results") or []:
            filename = _safe_path_component(result.get("filename") or "unknown")
            db.add(
                RunIndexResult(
                    id=_new_id("rir"),
                    run_index_id=run_index_id,
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
                    vulnerability_headings_json=_externalize_json_payload(
                        run_root,
                        f"results/{filename}.vulnerability_headings.json",
                        list(result.get("vulnerability_headings") or []),
                        summary=_externalized_list_summary(list(result.get("vulnerability_headings") or [])),
                    ),
                    related_to=str(result.get("related_to") or ""),
                    raw_json=_externalize_json_payload(
                        run_root,
                        f"results/{filename}.json",
                        dict(result),
                        summary={
                            "filename": filename,
                            "passed": result.get("passed"),
                            "verdict": str(result.get("verdict") or ""),
                            "confidence": float(result.get("confidence") or 0),
                        },
                    ),
                )
            )

        for result in detail.get("removed_results") or []:
            filename = _safe_path_component(result.get("filename") or "unknown")
            db.add(
                RunIndexRemovedResult(
                    id=_new_id("rirm"),
                    run_index_id=run_index_id,
                    filename=str(result.get("filename") or ""),
                    path=str(result.get("path") or ""),
                    meta_path=str(result.get("meta_path") or ""),
                    cycle=int(result.get("cycle") or 0),
                    lifecycle_status=str(result.get("lifecycle_status") or ""),
                    reason=str(result.get("reason") or ""),
                    signals_json=_externalize_json_payload(
                        run_root,
                        f"removed_results/{filename}.signals.json",
                        list(result.get("signals") or []),
                        summary=_externalized_list_summary(list(result.get("signals") or [])),
                    ),
                    raw_json=_externalize_json_payload(
                        run_root,
                        f"removed_results/{filename}.json",
                        dict(result),
                        summary={
                            "filename": filename,
                            "cycle": int(result.get("cycle") or 0),
                            "lifecycle_status": str(result.get("lifecycle_status") or ""),
                        },
                    ),
                )
            )

        if include_sessions:
            for session in sessions:
                session_id = _safe_path_component(session.get("session_id") or "unknown")
                db.add(
                    RunIndexSession(
                        id=_new_id("ris"),
                        run_index_id=run_index_id,
                        session_id=str(session.get("session_id") or ""),
                        format=str(session.get("format") or ""),
                        worker_id=str(session.get("worker_id") or ""),
                        jsonl_path=str(session.get("jsonl_path") or ""),
                        size=int(session.get("size") or 0),
                        mtime=float(session.get("mtime") or 0),
                        calls_json=_externalize_json_payload(
                            run_root,
                            f"sessions/{session_id}.calls.json",
                            list(session.get("calls") or []),
                            summary=_externalized_list_summary(list(session.get("calls") or [])),
                        ),
                        raw_json=_externalize_json_payload(
                            run_root,
                            f"sessions/{session_id}.json",
                            dict(session),
                            summary={
                                "session_id": session_id,
                                "worker_id": str(session.get("worker_id") or ""),
                                "format": str(session.get("format") or ""),
                                "event_count": int(session.get("event_count") or 0),
                                "line_count": int(session.get("line_count") or 0),
                                "warnings": list(session.get("warnings") or []),
                                "display_name": str(session.get("display_name") or ""),
                                "stage_group": str(session.get("stage_group") or ""),
                                "role_name": str(session.get("role_name") or ""),
                                "watch_project_path": str(session.get("watch_project_path") or ""),
                                "model": str(session.get("model") or ""),
                                "raw_model": str(session.get("raw_model") or ""),
                                "provider": str(session.get("provider") or ""),
                                "thinking": str(session.get("thinking") or ""),
                            },
                        ),
                    )
                )

        if include_files:
            for entry in files:
                db.add(
                    RunIndexFile(
                        id=_new_id("rif"),
                        run_index_id=run_index_id,
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
        include_runtime_assets: bool = True,
    ) -> RunIndex:
        run_root = run_root.resolve()
        if not run_root.is_dir():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"run root not found: {run_root}")

        source_key = str(run_root)
        source_hash = run_source_hash(source_type, source_key)
        record = _find_run_by_source(
            db,
            source_type=source_type,
            source_key=source_key,
            source_hash=source_hash,
        )
        stored_source_mtime = _stored_source_mtime(record.source_mtime) if record is not None else 0.0
        if record is not None and not _run_index_is_active(record) and not _run_index_needs_parser_resync(record):
            hint_mtime = _compute_source_mtime_hint(run_root, record.atomic_work_path)
            if _source_mtime_is_current(hint_mtime, stored_source_mtime):
                self._refresh_record_bindings(
                    record,
                    project_id=project_id,
                    source_type=source_type,
                    linked_execution=linked_execution,
                    linked_task=linked_task,
                    profile_id=profile_id,
                )
                record.source_key = source_key
                record.source_hash = source_hash
                db.add(record)
                db.flush()
                return record
        source_mtime = (
            _compute_source_mtime(run_root)
            if include_runtime_assets
            else _compute_source_mtime_hint(run_root, record.atomic_work_path if record is not None else None)
        )
        if record is not None and _source_mtime_is_current(source_mtime, stored_source_mtime) and not _run_index_needs_parser_resync(record):
            self._refresh_record_bindings(
                record,
                project_id=project_id,
                source_type=source_type,
                linked_execution=linked_execution,
                linked_task=linked_task,
                profile_id=profile_id,
            )
            record.source_key = source_key
            record.source_hash = source_hash
            db.add(record)
            db.flush()
            return record

        summary = inspect_run_summary(run_root)
        detail = inspect_run_detail(run_root)
        sessions = inspect_sessions(run_root) if include_runtime_assets else []
        files = inspect_files(run_root, limit=20000) if include_runtime_assets else []
        run_log = inspect_log(run_root, lines=2000).get("content", "")
        run_timestamps = _read_json_file(run_root / "run" / "_meta" / "run_timestamps.json") or _read_json_file(run_root / "_meta" / "run_timestamps.json")
        started_at = _parse_datetime(str(run_timestamps.get("started_at") or "")) or _datetime_from_epoch(summary.get("start_epoch"))
        finished_at = _parse_datetime(str(run_timestamps.get("finished_at") or ""))
        last_activity_at = _parse_datetime(str(detail.get("last_activity") or "")) or finished_at
        if finished_at is None and summary.get("status") not in {"running", "pending", "queued", "cancel_requested", "delete_requested"}:
            duration = int(summary.get("duration_seconds") or 0)
            if started_at and duration > 0:
                finished_at = started_at + timedelta(seconds=duration)
        log_path = run_root / "run" / "run.log"
        if not log_path.is_file():
            log_path = run_root / "run.log"
        atomic_work_path = _detail_atomic_work_path(detail)
        raw_summary = {
            "start_time": str(summary.get("start_time") or ""),
            "summary_markdown": _summary_markdown_for_run(run_root, atomic_work_path),
            "task_markdown": _task_markdown_for_run(run_root),
            "current_step": dict(detail.get("current_step") or {}),
            "step_history": list(detail.get("step_history") or []),
            "cycle_timing": dict(detail.get("cycle_timing") or {}),
        }
        command_payload = _run_command_payload(
            db,
            run_root=run_root,
            linked_execution=linked_execution,
            linked_task=linked_task,
        )
        if command_payload:
            raw_summary["dataflow_cli"] = command_payload
            raw_summary["command"] = command_payload.get("command") or []
            raw_summary["command_display"] = command_payload.get("command_display") or ""

        if record is None:
            record = _find_run_by_source(
                db,
                source_type=source_type,
                source_key=source_key,
                source_hash=source_hash,
            )
        if record is None:
            record = RunIndex(id=_new_id("ri"))

        def apply_payload(target: RunIndex) -> None:
            self._refresh_record_bindings(
                target,
                project_id=project_id,
                source_type=source_type,
                linked_execution=linked_execution,
                linked_task=linked_task,
                profile_id=profile_id,
            )
            target.source_key = source_key
            target.source_hash = source_hash
            target.run_name = str(summary.get("name") or run_root.name)
            target.run_root_path = str(run_root)
            target.atomic_work_path = atomic_work_path
            target.status = str(summary.get("status") or "pending")
            target.started_at = started_at
            target.finished_at = finished_at
            target.duration_seconds = int(summary.get("duration_seconds") or 0)
            target.last_activity_at = last_activity_at
            target.model = str(summary.get("model") or "")
            target.provider = str(summary.get("provider") or "")
            target.thinking = str(summary.get("thinking") or "")
            target.max_cycles = int(summary.get("max_cycles") or 0)
            target.cycles_used = int(summary.get("cycles_used") or 0)
            target.result_count = int(summary.get("result_count") or 0)
            target.passed_count = int(summary.get("passed_count") or 0)
            target.failed_count = int(summary.get("failed_count") or 0)
            target.workflow_mode = str(summary.get("workflow_mode") or "")
            target.error = str(detail.get("error") or "")
            target.config_json = _externalize_json_payload(
                run_root,
                "config.json",
                dict(detail.get("config") or {}),
            )
            target.manifests_json = _externalize_json_payload(
                run_root,
                "manifests.json",
                dict(detail.get("manifests") or {}),
            )
            target.latest_issues_json = _externalize_json_payload(
                run_root,
                "latest_issues.json",
                list(detail.get("latest_issues") or []),
                summary=_externalized_list_summary(list(detail.get("latest_issues") or [])),
            )
            target.raw_summary_json = _externalize_json_payload(
                run_root,
                "run_summary.json",
                raw_summary,
                summary=_raw_summary_db_view(raw_summary),
            )
            target.log_tail_text = _truncate_log_summary(run_log)
            target.log_size_bytes = log_path.stat().st_size if log_path.is_file() else 0
            target.source_mtime = source_mtime
            target.last_synced_at = now_local()

        apply_payload(record)
        try:
            with db.begin_nested():
                db.add(record)
                db.flush()
        except IntegrityError:
            # Another manager/worker may have indexed this run concurrently while
            # the current session was preparing a new RunIndex object.  Expunge
            # the failed pending object before querying, otherwise SQLAlchemy can
            # return the same not-inserted instance from the identity map and the
            # final flush will try the duplicate INSERT again.
            try:
                db.expunge(record)
            except Exception:
                pass
            with db.no_autoflush:
                existing = _find_run_by_source(
                    db,
                    source_type=source_type,
                    source_key=source_key,
                    source_hash=source_hash,
                )
            if existing is None:
                raise
            record = existing
            apply_payload(record)
            db.add(record)
            db.flush()
        detail["path"] = str(run_root)
        self._sync_children(
            db,
            record.id,
            detail,
            sessions,
            files,
            include_sessions=include_runtime_assets,
            include_files=include_runtime_assets,
        )
        db.flush()
        return record

    def sync_execution_run(self, db: Session, execution: WorkflowExecution) -> RunIndex | None:
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

    def sync_project_runs(self, db: Session, project_id: str) -> None:
        if not get_config().runs.enabled:
            return
        execution_runs = self._discover_execution_runs(db, project_id)
        linked_tasks_by_id: dict[str, TriggerTask] = {}
        task_ids = sorted({execution.trigger_task_id for execution, _ in execution_runs if execution.trigger_task_id})
        if task_ids:
            linked_tasks_by_id = {
                item.id: item
                for item in db.query(TriggerTask).filter(TriggerTask.id.in_(task_ids)).all()
            }
        for execution, run_root in execution_runs:
            linked_task = linked_tasks_by_id.get(execution.trigger_task_id)
            try:
                with db.begin_nested():
                    self.sync_run_path(
                        db,
                        project_id=project_id,
                        run_root=run_root,
                        source_type="execution_workspace",
                        linked_execution=execution,
                        linked_task=linked_task,
                        profile_id=linked_task.profile_id if linked_task else None,
                    )
            except Exception:
                continue
        db.commit()

    def refresh_run_index(
        self,
        db: Session,
        run_index: RunIndex,
        *,
        include_runtime_assets: bool = True,
        force_runtime_assets: bool = False,
    ) -> RunIndex:
        run_root = Path(run_index.run_root_path)
        if not run_root.is_dir():
            return run_index
        stored_source_mtime = _stored_source_mtime(run_index.source_mtime)
        if (
            not force_runtime_assets
            and not _run_index_is_active(run_index)
            and not _run_index_needs_parser_resync(run_index)
        ):
            hint_mtime = _compute_source_mtime_hint(run_root, run_index.atomic_work_path)
            if _source_mtime_is_current(hint_mtime, stored_source_mtime):
                return run_index
        current_mtime = (
            _compute_source_mtime(run_root)
            if include_runtime_assets or force_runtime_assets
            else _compute_source_mtime_hint(run_root, run_index.atomic_work_path)
        )
        if (
            not force_runtime_assets
            and _source_mtime_is_current(current_mtime, stored_source_mtime)
            and not _run_index_needs_parser_resync(run_index)
        ):
            return run_index
        linked_execution = db.get(WorkflowExecution, run_index.linked_execution_id) if run_index.linked_execution_id else None
        linked_task = db.get(TriggerTask, run_index.linked_task_id) if run_index.linked_task_id else None
        run_index = self.sync_run_path(
            db,
            project_id=run_index.project_id,
            run_root=run_root,
            source_type=run_index.source_type,
            linked_execution=linked_execution,
            linked_task=linked_task,
            profile_id=run_index.profile_id,
            include_runtime_assets=include_runtime_assets,
        )
        db.commit()
        return run_index

    def resolve_run(self, db: Session, *, project_id: str, run_name: str, root_path: str) -> RunIndex:
        normalized_root = _normalize_execution_request_root(root_path)
        candidate = normalized_root / run_name
        record = db.query(RunIndex).filter(
            RunIndex.project_id == project_id,
            RunIndex.source_type == "execution_workspace",
            RunIndex.run_root_path == str(candidate.resolve()),
        ).first()
        if record is not None:
            return self.refresh_run_index(db, record, include_runtime_assets=False)
        self.sync_project_runs(db, project_id)
        record = db.query(RunIndex).filter(
            RunIndex.project_id == project_id,
            RunIndex.source_type == "execution_workspace",
            RunIndex.run_root_path == str(candidate.resolve()),
        ).first()
        if record is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run not found")
        return record

    def _summary_payload(self, run_index: RunIndex) -> dict[str, Any]:
        config = _load_externalized_mapping_payload(run_index.run_root_path, run_index.config_json)
        return {
            "run_id": run_index.id,
            "project_id": run_index.project_id,
            "source_type": run_index.source_type,
            "source_key": run_index.source_key,
            "linked_task_id": run_index.linked_task_id,
            "linked_execution_id": run_index.linked_execution_id,
            "profile_id": run_index.profile_id,
            "name": run_index.run_name,
            "path": run_index.run_root_path,
            "root_path": _parent_root(run_index.run_root_path),
            "status": run_index.status,
            "start_time": str((_load_externalized_json_payload(run_index.run_root_path, run_index.raw_summary_json) or {}).get("start_time") or ""),
            "start_epoch": int(run_index.started_at.replace(tzinfo=timezone.utc).timestamp()) if run_index.started_at else 0,
            "duration_seconds": run_index.duration_seconds,
            "last_activity": _iso_or_empty(run_index.last_activity_at),
            "model": run_index.model,
            "provider": run_index.provider,
            "thinking": run_index.thinking,
            "review_profile": str(config.get("review_profile") or ""),
            "max_cycles": run_index.max_cycles,
            "cycles_used": run_index.cycles_used,
            "result_count": run_index.result_count,
            "passed_count": run_index.passed_count,
            "failed_count": run_index.failed_count,
            "workflow_mode": run_index.workflow_mode,
            "updated_at": _iso_or_empty(run_index.last_synced_at),
        }

    def list_runs(self, db: Session, project_id: str) -> list[dict[str, Any]]:
        self.sync_project_runs(db, project_id)
        records = [
            item
            for item in db.query(RunIndex).filter(
                RunIndex.project_id == project_id,
                RunIndex.source_type == "execution_workspace",
            ).all()
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
        return [self._summary_payload(item) for item in records]

    def get_run_summary(self, db: Session, run_index: RunIndex) -> dict[str, Any]:
        run_index = self.refresh_run_index(db, run_index)
        return self._summary_payload(run_index)

    def _cycle_payloads(self, db: Session, run_index: RunIndex) -> list[dict[str, Any]]:
        cycles = (
            db.query(RunIndexCycle)
            .filter(RunIndexCycle.run_index_id == run_index.id)
            .order_by(RunIndexCycle.cycle.asc())
            .all()
        )
        rows: list[dict[str, Any]] = []
        derived_new_results_by_cycle: dict[int, list[dict[str, Any]]] | None = None
        for item in cycles:
            metrics = _load_externalized_mapping_payload(run_index.run_root_path, item.metrics_json)
            issues = _load_externalized_list_payload(run_index.run_root_path, item.issues_json)
            raw_cycle = _load_externalized_json_payload(run_index.run_root_path, item.raw_json) or {}
            new_results = raw_cycle.get("new_results") if isinstance(raw_cycle.get("new_results"), list) else None
            if new_results is None:
                if derived_new_results_by_cycle is None:
                    derived_new_results_by_cycle = _new_results_by_cycle_for_index(run_index)
                new_results = derived_new_results_by_cycle.get(item.cycle, [])
            raw_global_review = raw_cycle.get("global_review") if isinstance(raw_cycle.get("global_review"), dict) else {}
            if not raw_global_review:
                raw_global_review = {
                    "passed": item.global_passed,
                    "feedback_preview": metrics.get("global_feedback_preview", ""),
                    "issues": issues,
                    "total_advisor_count": raw_cycle.get("global_advisor_total", 0),
                    "passed_advisor_count": raw_cycle.get("global_advisor_passed", 0),
                    "failed_advisor_id": item.failed_advisor_id,
                    "failed_role_name": item.failed_role_name,
                }
            metrics_with_issues = dict(metrics)
            metrics_with_issues["issues"] = issues
            profile_gate = derive_profile_gate_summary(raw_global_review, metrics_with_issues)
            rows.append(
                {
                    "cycle": item.cycle,
                    "timestamp": item.timestamp,
                    "outcome": item.outcome,
                    "workflow_mode": item.workflow_mode,
                    "global_passed": item.global_passed,
                    "global_feedback_preview": str(raw_global_review.get("feedback_preview") or metrics.get("global_feedback_preview") or ""),
                    "global_advisor_total": int(profile_gate.get("total_advisor_count") or 0),
                    "global_advisor_passed": int(profile_gate.get("passed_advisor_count") or 0),
                    "global_aggregate_status": str(raw_global_review.get("aggregate_status") or ""),
                    "profile_gate": profile_gate,
                    "failed_advisor_id": item.failed_advisor_id,
                    "failed_role_name": item.failed_role_name,
                    "result_total": item.result_total,
                    "result_passed": item.result_passed,
                    "result_failed": item.result_failed,
                    "scores": _load_externalized_mapping_payload(run_index.run_root_path, item.scores_json),
                    "global_failure_scope": str(metrics.get("global_failure_scope") or ""),
                    "failed_result_count": metrics.get("failed_result_count", item.result_failed),
                    "current_failed_result_count": metrics.get("current_failed_result_count", item.result_failed),
                    "historical_removed_result_count": metrics.get("historical_removed_result_count", 0),
                    "unreviewed_new_result_count": metrics.get("unreviewed_new_result_count", 0),
                    "unreviewed_new_result_files": list(metrics.get("unreviewed_new_result_files") or []),
                    "issue_count": len(issues),
                    "issue_ids": list(metrics.get("issue_ids") or []),
                    "summary_size": metrics.get("summary_size", 0),
                    "plateau_status": _load_externalized_mapping_payload(run_index.run_root_path, item.plateau_status_json),
                    "issues": issues,
                    "new_result_count": _safe_int(raw_cycle.get("new_result_count"), len(new_results)),
                    "new_results": new_results,
                }
            )
        return rows

    def _result_payloads(self, db: Session, run_index: RunIndex) -> list[dict[str, Any]]:
        results = (
            db.query(RunIndexResult)
            .filter(RunIndexResult.run_index_id == run_index.id)
            .order_by(RunIndexResult.filename.asc())
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
                "vulnerability_headings": _load_externalized_list_payload(run_index.run_root_path, item.vulnerability_headings_json),
                "related_to": item.related_to,
            }
            for item in results
        ]

    def _removed_result_payloads(self, db: Session, run_index: RunIndex) -> list[dict[str, Any]]:
        results = (
            db.query(RunIndexRemovedResult)
            .filter(RunIndexRemovedResult.run_index_id == run_index.id)
            .order_by(RunIndexRemovedResult.cycle.asc(), RunIndexRemovedResult.filename.asc())
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
                "signals": _load_externalized_list_payload(run_index.run_root_path, item.signals_json),
            }
            for item in results
        ]

    def list_run_sessions(self, db: Session, run_index: RunIndex) -> list[dict[str, Any]]:
        run_index = self.refresh_run_index(
            db,
            run_index,
            include_runtime_assets=True,
            force_runtime_assets=True,
        )
        return self._list_run_sessions_rows(db, run_index)

    def _list_run_sessions_rows(self, db: Session, run_index: RunIndex) -> list[dict[str, Any]]:
        sessions = (
            db.query(RunIndexSession)
            .filter(RunIndexSession.run_index_id == run_index.id)
            .order_by(RunIndexSession.session_id.asc())
            .all()
        )
        rows: list[dict[str, Any]] = []
        atomic = Path(run_index.atomic_work_path) if run_index.atomic_work_path else None
        for item in sessions:
            raw = dict(_load_externalized_json_payload(run_index.run_root_path, item.raw_json) or {})
            if item.format in {"jsonl", "hybrid"} and item.jsonl_path and "line_count" not in raw:
                try:
                    parsed_session = inspect_session_file(run_index.run_root_path, item.jsonl_path)
                    raw["event_count"] = len(parsed_session.get("events") or [])
                    raw["line_count"] = int(parsed_session.get("line_count") or 0)
                    raw["warnings"] = list(parsed_session.get("warnings") or [])
                except Exception:
                    raw["event_count"] = 0
                    raw["line_count"] = 0
                    raw["warnings"] = ["会话文件解析失败"]
            watch_project_path = str(raw.get("watch_project_path") or "")
            if not watch_project_path and atomic and item.jsonl_path:
                watch_project_path = _project_watch_path(run_index.project_id, atomic / item.jsonl_path)
            runtime_meta: dict[str, Any] = {}
            if item.format in {"jsonl", "hybrid"} and item.jsonl_path and (not raw.get("model") or not raw.get("thinking")):
                try:
                    session_file = (atomic / item.jsonl_path) if atomic else Path(run_index.run_root_path) / item.jsonl_path
                    runtime_meta = _session_runtime_metadata(session_file.parent)
                except Exception:
                    runtime_meta = {}
            rows.append(
                {
                    "session_id": item.session_id,
                    "format": item.format,
                    "worker_id": item.worker_id,
                    "jsonl_path": item.jsonl_path,
                    "size": item.size,
                    "mtime": item.mtime,
                    "event_count": int(raw.get("event_count") or 0),
                    "line_count": int(raw.get("line_count") or 0),
                    "warnings": list(raw.get("warnings") or []),
                    "display_name": str(raw.get("display_name") or item.worker_id or item.session_id),
                    "stage_group": str(raw.get("stage_group") or item.worker_id or "root"),
                    "role_name": str(raw.get("role_name") or item.worker_id or ""),
                    "watch_project_path": watch_project_path,
                    "model": str(raw.get("model") or runtime_meta.get("model") or ""),
                    "raw_model": str(raw.get("raw_model") or runtime_meta.get("raw_model") or raw.get("model") or runtime_meta.get("model") or ""),
                    "provider": str(raw.get("provider") or runtime_meta.get("provider") or ""),
                    "thinking": str(raw.get("thinking") or runtime_meta.get("thinking") or ""),
                    "calls": _load_externalized_list_payload(run_index.run_root_path, item.calls_json),
                }
            )
        return rows

    def list_run_files(self, db: Session, run_index: RunIndex, limit: int = 1200) -> list[dict[str, Any]]:
        run_index = self.refresh_run_index(
            db,
            run_index,
            include_runtime_assets=True,
            force_runtime_assets=True,
        )
        return self._list_run_files_rows(db, run_index, limit=limit)

    def _list_run_files_rows(self, db: Session, run_index: RunIndex, limit: int = 1200) -> list[dict[str, Any]]:
        files = (
            db.query(RunIndexFile)
            .filter(RunIndexFile.run_index_id == run_index.id)
            .order_by(RunIndexFile.category.asc(), RunIndexFile.path.asc())
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

    def get_run_detail(self, db: Session, run_index: RunIndex) -> dict[str, Any]:
        run_index = self.refresh_run_index(db, run_index, include_runtime_assets=True)
        payload = self._summary_payload(run_index)
        raw_summary = dict(_load_externalized_json_payload(run_index.run_root_path, run_index.raw_summary_json) or {})
        cli_payload = raw_summary.get("dataflow_cli") if isinstance(raw_summary.get("dataflow_cli"), dict) else {}
        command = cli_payload.get("command") if isinstance(cli_payload.get("command"), list) else raw_summary.get("command")
        if not isinstance(command, list):
            command = []
        command_display = str(cli_payload.get("command_display") or raw_summary.get("command_display") or "")
        if not command and not command_display:
            linked_execution = db.get(WorkflowExecution, run_index.linked_execution_id) if run_index.linked_execution_id else None
            linked_task = db.get(TriggerTask, run_index.linked_task_id) if run_index.linked_task_id else None
            cli_payload = _run_command_payload(
                db,
                run_root=Path(run_index.run_root_path),
                linked_execution=linked_execution,
                linked_task=linked_task,
            )
            if cli_payload:
                raw_summary["dataflow_cli"] = cli_payload
                raw_summary["command"] = cli_payload.get("command") or []
                raw_summary["command_display"] = cli_payload.get("command_display") or ""
                run_index.raw_summary_json = _externalize_json_payload(
                    run_index.run_root_path,
                    "run_summary.json",
                    raw_summary,
                    summary=_raw_summary_db_view(raw_summary),
                )
                db.add(run_index)
                db.commit()
                command = cli_payload.get("command") if isinstance(cli_payload.get("command"), list) else []
                command_display = str(cli_payload.get("command_display") or "")
        latest_issues = _load_externalized_list_payload(run_index.run_root_path, run_index.latest_issues_json)
        if run_index.atomic_work_path and not _run_index_is_active(run_index):
            active_issues = load_active_issue_records_from_ledger(run_index.atomic_work_path)
            if active_issues is not None:
                latest_issues = active_issues
        try:
            file_payloads = inspect_files(run_index.run_root_path, limit=1200)
        except HTTPException:
            file_payloads = self._list_run_files_rows(db, run_index)

        payload.update(
            {
                "config": _load_externalized_mapping_payload(run_index.run_root_path, run_index.config_json),
                "error": run_index.error or None,
                "cycles": self._cycle_payloads(db, run_index),
                "results": self._result_payloads(db, run_index),
                "removed_results": self._removed_result_payloads(db, run_index),
                "manifests": _load_externalized_mapping_payload(run_index.run_root_path, run_index.manifests_json),
                "latest_issues": latest_issues,
                "atomic_work_path": run_index.atomic_work_path or "",
                "files": file_payloads,
                "sessions": self._list_run_sessions_rows(db, run_index),
                "run_log": run_index.log_tail_text or "",
                "command": [str(item) for item in command],
                "command_display": command_display,
                "current_step": dict(raw_summary.get("current_step") or {}),
                "step_history": list(raw_summary.get("step_history") or []),
                "cycle_timing": dict(raw_summary.get("cycle_timing") or {}),
                "raw": raw_summary,
            }
        )
        return payload

    def get_run_cycle(self, db: Session, run_index: RunIndex, cycle: int) -> dict[str, Any]:
        run_index = self.refresh_run_index(db, run_index, include_runtime_assets=False)
        cycle_row = (
            db.query(RunIndexCycle)
            .filter(RunIndexCycle.run_index_id == run_index.id, RunIndexCycle.cycle == cycle)
            .first()
        )
        if cycle_row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run cycle not found")
        global_reviews = (
            db.query(RunIndexGlobalReview)
            .filter(RunIndexGlobalReview.run_index_id == run_index.id, RunIndexGlobalReview.cycle == cycle)
            .order_by(RunIndexGlobalReview.advisor_id.asc())
            .all()
        )
        result_reviews = (
            db.query(RunIndexResultReview)
            .filter(RunIndexResultReview.run_index_id == run_index.id, RunIndexResultReview.cycle == cycle)
            .order_by(RunIndexResultReview.result_file.asc(), RunIndexResultReview.advisor_id.asc())
            .all()
        )
        metrics = _load_externalized_mapping_payload(run_index.run_root_path, cycle_row.metrics_json)
        issues = _load_externalized_list_payload(run_index.run_root_path, cycle_row.issues_json)
        raw_cycle = _load_externalized_json_payload(run_index.run_root_path, cycle_row.raw_json) or {}
        new_results = raw_cycle.get("new_results") if isinstance(raw_cycle.get("new_results"), list) else None
        if new_results is None:
            new_results = _new_results_by_cycle_for_index(run_index).get(cycle, [])
        raw_global_review = raw_cycle.get("global_review") if isinstance(raw_cycle.get("global_review"), dict) else {}
        if not raw_global_review:
            raw_global_review = {
                "passed": cycle_row.global_passed,
                "feedback_preview": metrics.get("global_feedback_preview", ""),
                "issues": issues,
                "total_advisor_count": raw_cycle.get("global_advisor_total", len(global_reviews)),
                "passed_advisor_count": raw_cycle.get("global_advisor_passed", len([item for item in global_reviews if item.passed])),
                "failed_advisor_id": cycle_row.failed_advisor_id,
                "failed_role_name": cycle_row.failed_role_name,
            }
        metrics_with_issues = dict(metrics)
        metrics_with_issues["issues"] = issues
        profile_gate = derive_profile_gate_summary(raw_global_review, metrics_with_issues)
        return {
            "cycle": cycle,
            "global_reviews": [
                {
                    "advisor_id": item.advisor_id,
                    "path": item.path,
                    "role_name": item.role_name,
                    "passed": item.passed,
                    "verdict": item.verdict,
                    "scores": _load_externalized_mapping_payload(run_index.run_root_path, item.scores_json),
                    "confidence": item.confidence,
                    "feedback": item.feedback or "",
                    "feedback_detail": item.feedback_detail or "",
                    "schema_valid": item.schema_valid,
                    "parser_mode": item.parser_mode,
                    "repair_attempts": item.repair_attempts,
                    "issues": _load_externalized_list_payload(run_index.run_root_path, item.issues_json),
                    "resolved_issue_ids": _load_externalized_list_payload(run_index.run_root_path, item.resolved_issue_ids_json),
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
            "metrics": metrics,
            "global_review_summary": raw_global_review,
            "profile_gate": profile_gate,
            "new_result_count": _safe_int(raw_cycle.get("new_result_count"), len(new_results)),
            "new_results": new_results,
        }

    def get_run_file(self, db: Session, run_index: RunIndex, path: str) -> dict[str, Any]:
        run_index = self.refresh_run_index(db, run_index, include_runtime_assets=False)
        return inspect_file(run_index.run_root_path, path)

    def get_run_session_file(self, db: Session, run_index: RunIndex, path: str) -> dict[str, Any]:
        run_index = self.refresh_run_index(db, run_index, include_runtime_assets=False)
        return inspect_session_file(run_index.run_root_path, path)

    def get_run_log(self, db: Session, run_index: RunIndex, lines: int = 300) -> dict[str, Any]:
        run_index = self.refresh_run_index(db, run_index, include_runtime_assets=False)
        return inspect_log(run_index.run_root_path, lines=lines)

    def get_run_index_by_execution(self, db: Session, execution: WorkflowExecution) -> RunIndex | None:
        if not execution.workspace_root:
            return None
        record = db.query(RunIndex).filter(
            RunIndex.linked_execution_id == execution.id,
            RunIndex.source_type == "execution_workspace",
        ).first()
        if record is not None:
            return self.refresh_run_index(db, record)
        source_key = str(Path(execution.workspace_root).resolve())
        record = _find_run_by_source(
            db,
            source_type="execution_workspace",
            source_key=source_key,
            source_hash=run_source_hash("execution_workspace", source_key),
        )
        if record is not None:
            return self.refresh_run_index(db, record)
        if str(execution.status or "").strip().lower() in _ACTIVE_RUN_INDEX_STATUSES:
            return None
        record = self.sync_execution_run(db, execution)
        if record is not None:
            db.commit()
        return record

    def bind_runtime_state(
        self,
        db: Session,
        run_index: RunIndex,
        *,
        linked_execution: WorkflowExecution | None = None,
        linked_task: TriggerTask | None = None,
        profile_id: str | None = None,
        status_text: str | None = None,
    ) -> RunIndex:
        self._refresh_record_bindings(
            run_index,
            project_id=run_index.project_id,
            source_type=run_index.source_type,
            linked_execution=linked_execution,
            linked_task=linked_task,
            profile_id=profile_id,
        )
        if status_text:
            run_index.status = status_text
        if run_index.source_key and not run_index.source_hash:
            run_index.source_hash = run_source_hash(run_index.source_type, run_index.source_key)
        run_root = Path(run_index.run_root_path)
        if run_root.is_dir():
            run_index.source_mtime = max(_stored_source_mtime(run_index.source_mtime), _compute_source_mtime(run_root))
        run_index.last_synced_at = now_local()
        db.add(run_index)
        db.flush()
        return run_index

    def delete_run_index(self, db: Session, run_index: RunIndex, *, allow_active: bool = False) -> None:
        run_root = self._managed_project_run_root(run_index.project_id, run_index.run_root_path)
        if _run_index_is_active(run_index) and not allow_active:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="run is active and cannot be deleted")
        self._delete_children(db, run_index.id)
        db.delete(run_index)
        db.flush()
        if run_root.exists():
            shutil.rmtree(run_root, ignore_errors=False)


_run_index_service: RunIndexService | None = None


def get_run_index_service() -> RunIndexService:
    global _run_index_service
    if _run_index_service is None:
        _run_index_service = RunIndexService()
    return _run_index_service
