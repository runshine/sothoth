#!/usr/bin/env python3
"""
漏洞扫描 Dashboard — 实时监控服务

启动: python3 dashboard/server.py [--port 8501] [--runs-dir runs/]
打开: http://localhost:8501
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any

from app.pi_vuln_core.utils.win_compat import from_msys_path
from fastapi import FastAPI, HTTPException, Query
import shutil
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RUNS_DIR = PROJECT_ROOT / "runs"
STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="Vuln Scan Dashboard")
RUNS_DIR: Path = DEFAULT_RUNS_DIR

_RUNNING_WORKFLOW_STATES = {
    "created",
    "start_plugins",
    "worker",
    "reflect",
    "summary",
    "global_review",
    "result_review",
    "end_plugins",
}

_TERMINAL_STATUSES = {
    "completed",
    "succeeded",
    "failed",
    "interrupted",
    "cancelled",
    "stopped",
    "review_error",
    "review_plateau",
    "summary_incomplete",
    "runtime_output_limit",
    "runtime_timeout",
    "blocked_context_window",
    "blocked_quota",
    "provider_rate_limited",
    "model_contract_violation",
    "no_workspace",
    "error",
}


# ═══════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════

def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _read_text(path: Path, max_bytes: int = 0) -> str:
    try:
        if max_bytes > 0:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read(max_bytes)
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _tail_lines(path: Path, n: int = 200) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            chunk = min(size, n * 500)
            f.seek(max(0, size - chunk))
            data = f.read().decode("utf-8", errors="replace")
            lines = data.splitlines()
            return "\n".join(lines[-n:])
    except Exception:
        return ""


def _atomic_candidate_search_roots(run_dir: Path, config: dict[str, Any]) -> list[Path]:
    workspace_candidates: list[Path] = []
    workspace_root = str((config.get("global") or {}).get("workspace_root") or "").strip()
    if workspace_root:
        workspace_candidates.append(Path(from_msys_path(workspace_root) or workspace_root))
        workspace_name = Path(workspace_root).name
        if workspace_name:
            workspace_candidates.append(run_dir / workspace_name)
    workspace_candidates.extend([run_dir / "workspace", run_dir / "ws", run_dir])

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in workspace_candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        if candidate.is_dir():
            unique.append(candidate)
    return unique


def _atomic_candidate_score(candidate: Path) -> tuple[int, int]:
    score = 0
    evidence = 0

    def mark(points: int, condition: bool) -> None:
        nonlocal score, evidence
        if condition:
            score += points
            evidence += 1

    mark(12, (candidate / "input" / "task.md").is_file())
    mark(10, (candidate / "results").is_dir() or (candidate / "final_output" / "results").is_dir())
    mark(8, (candidate / "reviews").is_dir())
    mark(7, (candidate / "sessions").is_dir())
    mark(6, (candidate / "removed_results").is_dir() or (candidate / "final_output" / "removed_results").is_dir())
    mark(5, (candidate / "supporting_docs").is_dir() or (candidate / "final_output" / "supporting_docs").is_dir())
    mark(4, (candidate / "output").is_dir() or (candidate / "working").is_dir() or (candidate / "summary.md").is_file())
    mark(4, (candidate / "_meta" / "workflow_result.json").is_file())
    mark(3, (candidate / "_meta" / "state.json").is_file())
    mark(3, (candidate / "_meta" / "review_summaries").is_dir())
    mark(2, (candidate / "_meta" / "cycle_metrics").is_dir())
    mark(2, (candidate / "_meta" / "issues").is_dir())

    return score, evidence


def _find_atomic_work_dir(run_dir: Path) -> Path | None:
    cfg = _read_json(run_dir / "config.json")
    candidates: list[tuple[int, int, int, Path]] = []
    fallback_candidates: list[tuple[int, Path]] = []
    seen: set[str] = set()

    for search_root in _atomic_candidate_search_roots(run_dir, cfg):
        meta_dirs: list[Path] = []
        if (search_root / "_meta").is_dir():
            meta_dirs.append(search_root / "_meta")
        meta_dirs.extend(path for path in search_root.rglob("_meta") if path.is_dir())
        for meta_dir in meta_dirs:
            candidate = meta_dir.parent
            key = str(candidate.resolve())
            if key in seen:
                continue
            seen.add(key)
            score, evidence = _atomic_candidate_score(candidate)
            try:
                depth = len(candidate.relative_to(run_dir).parts)
            except ValueError:
                depth = len(candidate.parts)
            if score > 0 and evidence >= 2:
                candidates.append((score, evidence, depth, candidate))
            fallback_candidates.append((depth, candidate))

    if candidates:
        candidates.sort(key=lambda item: (item[0], item[1], item[2], len(str(item[3]))), reverse=True)
        return candidates[0][3]
    if fallback_candidates:
        fallback_candidates.sort(key=lambda item: (item[0], len(str(item[1]))), reverse=True)
        return fallback_candidates[0][1]
    return None


def _parse_timestamp_from_name(name: str) -> str:
    m = re.search(r"(\d{8})_(\d{6})(?:$|\D)", name)
    if not m:
        m = re.search(r"(\d{8})_(\d{6})", name)
    if not m:
        return ""
    d, t = m.group(1), m.group(2)
    return f"{d[:4]}-{d[4:6]}-{d[6:8]} {t[:2]}:{t[2:4]}:{t[4:6]}"


def _derive_run_date_label(
    run_dir: Path,
    *,
    name: str,
    start_time: str = "",
    last_activity: str = "",
    run_meta: dict | None = None,
) -> str:
    run_meta = run_meta or {}
    started_at = _parse_iso_timestamp(str(run_meta.get("started_at") or ""))
    if started_at:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(started_at, tz=timezone.utc).strftime("%Y-%m-%d")

    if start_time:
        return start_time.split(" ")[0]

    ts_from_name = _parse_timestamp_from_name(name)
    if ts_from_name:
        return ts_from_name.split(" ")[0]

    m = re.search(r"(\d{4})[-_]?(\d{2})[-_]?(\d{2})", name)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"

    last_epoch = _parse_iso_timestamp(last_activity)
    if last_epoch:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(last_epoch, tz=timezone.utc).strftime("%Y-%m-%d")

    try:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(run_dir.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%d")
    except OSError:
        return ""


def _sorted_json_files(directory: Path, pattern: str = "cycle_*.json") -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(directory.glob(pattern))


def _rel_to_atomic(path: Path, atomic: Path) -> str:
    return str(path.relative_to(atomic))


def _file_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix == ".md":
        return "markdown"
    return "text"


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _file_entry(path: Path, base: Path, category: str) -> dict:
    stat = path.stat()
    return {
        "category": category,
        "path": str(path.relative_to(base)),
        "name": path.name,
        "size": stat.st_size,
        "mtime": stat.st_mtime,
        "type": _file_type(path),
    }


def _read_run_timestamps(run_dir: Path) -> dict:
    return _read_json(run_dir / "_meta" / "run_timestamps.json")


def _normalize_run_status(raw_status: str, run_meta: dict | None = None) -> str:
    run_meta = run_meta or {}
    text = str(raw_status or "").strip().lower()
    if run_meta.get("finished_at"):
        meta_status = str(run_meta.get("status") or "").strip().lower()
        if meta_status in _TERMINAL_STATUSES:
            return meta_status
    if text in {"", "unknown", "pending"}:
        return text or "pending"
    if text in _TERMINAL_STATUSES:
        return text
    if text in _RUNNING_WORKFLOW_STATES or text in {"running", "cancel_requested", "queued"}:
        return "running"
    return "running"


def _find_run_start_epoch(run_dir: Path, run_meta: dict | None = None) -> float:
    run_meta = run_meta or {}
    started_at = _parse_iso_timestamp(str(run_meta.get("started_at") or ""))
    if started_at:
        return started_at
    parsed = _parse_start_time_from_name(run_dir.name)
    if parsed:
        return parsed
    try:
        return run_dir.stat().st_mtime
    except OSError:
        return 0.0


def _extract_config_summary(config: dict) -> dict:
    agents = config.get("agents", [])
    worker = next((a for a in agents if a.get("id", "").endswith("worker")), agents[0] if agents else {})
    rt = worker.get("runtime_config", {})
    sdk = rt.get("sdk_specific", {})
    gbl = config.get("global", {})
    exe = config.get("execution", {})
    return {
        "model": rt.get("model", ""),
        "provider": sdk.get("provider", ""),
        "thinking": sdk.get("thinking", ""),
        "timeout_seconds": rt.get("timeout_seconds", 0),
        "max_review_cycles": gbl.get("max_review_cycles", 0),
        "parallel_result_review": gbl.get("parallel_result_review", False),
        "parallel_result_review_limit": gbl.get("parallel_result_review_limit", 0),
        "execution_id": exe.get("execution_id", ""),
        "task_file": exe.get("input_task", {}).get("task_file", ""),
        "global_review_advisors": _summarize_global_review_advisors(config),
    }


def _summarize_global_review_advisors(config: dict) -> list[dict[str, Any]]:
    advisors: list[dict[str, Any]] = []
    for workflow in ((config.get("workflows") or {}).get("atomic") or []):
        roles = workflow.get("roles") or {}
        group = ((roles.get("advisors") or {}).get("global_review") or [])
        for advisor in group:
            advisors.append({
                "instance_id": advisor.get("instance_id", ""),
                "role_name": advisor.get("role_name", ""),
                "score_fields": advisor.get("score_fields", []),
                "score_thresholds": advisor.get("score_thresholds", {}),
                "score_thresholds_start": advisor.get("score_thresholds_start", {}),
            })
    return advisors


def _manifest_path_summary(atomic: Path, path: Path) -> dict[str, Any]:
    return {
        "path": _rel_to_atomic(path, atomic),
        "exists": path.is_file(),
    }


def _load_manifest_summary(atomic: Path) -> dict[str, Any]:
    result_relations_path = atomic / "_meta" / "result_relations_manifest.json"
    results_manifest_path = atomic / "_meta" / "results_manifest.json"
    coverage_ledger_path = atomic / "_meta" / "coverage_ledger.json"

    relations = _read_json(result_relations_path)
    results_manifest = _read_json(results_manifest_path)
    coverage_ledger = _read_json(coverage_ledger_path)
    return {
        "result_relations_manifest": _manifest_path_summary(atomic, result_relations_path),
        "results_manifest": _manifest_path_summary(atomic, results_manifest_path),
        "coverage_ledger": _manifest_path_summary(atomic, coverage_ledger_path),
        "total_result_files": results_manifest.get("total_result_files", len(relations.get("all_results", []))),
        "active_result_count": results_manifest.get("active_result_count", 0),
        "inactive_result_count": results_manifest.get("inactive_result_count", len(relations.get("inactive_results", []))),
        "taskable_result_count": results_manifest.get("taskable_result_count", len(relations.get("taskable_results", []))),
        "supplemental_result_count": results_manifest.get("supplemental_result_count", len(relations.get("supplemental_results", []))),
        "excluded_result_count": len(results_manifest.get("excluded_results", relations.get("excluded_results", [])) or []),
        "missing_referenced_results": coverage_ledger.get("missing_referenced_results", []),
        "unreferenced_active_results": coverage_ledger.get("unreferenced_active_results", []),
    }


# ═══════════════════════════════════════════════════
# API: Runs list
# ═══════════════════════════════════════════════════

def _run_sort_tuple(run_dir: Path, info: dict[str, Any]) -> tuple[float, float, str]:
    start_epoch = float(info.get("start_epoch") or 0)
    try:
        fallback_mtime = run_dir.stat().st_mtime
    except OSError:
        fallback_mtime = 0.0
    return (start_epoch, fallback_mtime, run_dir.name)


@app.get("/api/runs")
def list_runs():
    if not RUNS_DIR.is_dir():
        return []
    runs: list[tuple[Path, dict[str, Any]]] = []
    for entry in RUNS_DIR.iterdir():
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        info = _build_run_summary(entry)
        if info:
            runs.append((entry, info))
    runs.sort(key=lambda item: _run_sort_tuple(item[0], item[1]), reverse=True)
    return [info for _, info in runs]


def _find_run_end_epoch(atomic: Path | None, run_dir: Path, status: str, run_meta: dict | None = None) -> float:
    """Find the best-known end timestamp for a run.

    Priority for finished runs:
    1. explicit terminal artifacts (`workflow_result.json`, `abnormal_exit.json`)
    2. durable state/review timestamps inside the workspace
    3. run.log mtime as a last resort
    """
    from datetime import datetime, timezone
    run_meta = run_meta or {}

    if status == "running":
        return datetime.now(tz=timezone.utc).timestamp()

    finished_at = _parse_iso_timestamp(str(run_meta.get("finished_at") or ""))
    if finished_at:
        return finished_at

    explicit_terminal: list[float] = []
    durable_activity: list[float] = []
    if atomic:
        for meta_name in ("workflow_result.json", "abnormal_exit.json"):
            payload = _read_json(atomic / "_meta" / meta_name)
            ts = _parse_iso_timestamp(str(payload.get("timestamp") or ""))
            if ts:
                explicit_terminal.append(ts)

        state_payload = _read_json(atomic / "_meta" / "state.json")
        ts = _parse_iso_timestamp(str(state_payload.get("timestamp") or ""))
        if ts:
            durable_activity.append(ts)

        summaries = _sorted_json_files(atomic / "_meta" / "review_summaries")
        if summaries:
            latest = _read_json(summaries[-1])
            ts = _parse_iso_timestamp(str(latest.get("timestamp") or ""))
            if ts:
                durable_activity.append(ts)

    if explicit_terminal:
        return max(explicit_terminal)
    if durable_activity:
        return max(durable_activity)

    last_activity = _find_last_activity(atomic, run_dir)
    ts = _parse_iso_timestamp(last_activity)
    if ts:
        return ts

    log_path = run_dir / "run.log"
    if log_path.is_file():
        try:
            return log_path.stat().st_mtime
        except OSError:
            pass

    return 0.0


def _compute_duration(run_dir: Path, atomic: Path | None, status: str, run_meta: dict | None = None) -> int:
    """Compute run duration in seconds.

    - running: start -> now
    - finished: start -> terminal/durable end timestamp
    - unknown without valid timestamps: 0
    """
    start_epoch = _find_run_start_epoch(run_dir, run_meta)
    if not start_epoch:
        return 0

    end_epoch = _find_run_end_epoch(atomic, run_dir, status, run_meta)
    if not end_epoch or end_epoch < start_epoch:
        return 0
    return int(end_epoch - start_epoch)


def _find_last_activity(atomic: Path | None, run_dir: Path) -> str:
    """Find the most recent timestamp from state.json, review_summaries, or session .jsonl files."""
    candidates: list[str] = []

    if atomic:
        # 1. state.json timestamp
        state = _read_json(atomic / "_meta" / "state.json")
        ts = state.get("timestamp", "")
        if ts:
            candidates.append(ts)

        # 2. Latest review_summary timestamp
        summaries = _sorted_json_files(atomic / "_meta" / "review_summaries")
        if summaries:
            latest = _read_json(summaries[-1])
            ts = latest.get("timestamp", "")
            if ts:
                candidates.append(ts)

        # 3. Latest session .jsonl last-line timestamp
        for jsonl in sorted(atomic.rglob("*.jsonl")):
            try:
                with open(jsonl, "rb") as f:
                    f.seek(0, 2)
                    size = f.tell()
                    # Read last ~4KB to find the last timestamp
                    f.seek(max(0, size - 4096))
                    tail = f.read().decode("utf-8", errors="replace")
                    for line in reversed(tail.splitlines()):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            ts = obj.get("timestamp", "")
                            if ts:
                                candidates.append(ts)
                                break
                        except json.JSONDecodeError:
                            continue
            except Exception:
                pass

    # 4. run.log modification time as fallback (always available)
    log_path = run_dir / "run.log"
    if log_path.is_file():
        try:
            from datetime import datetime, timezone
            mtime = log_path.stat().st_mtime
            dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
            candidates.append(dt.isoformat())
        except Exception:
            pass

    # Return the lexicographically latest timestamp
    if candidates:
        return max(candidates)
    return ""


def _parse_iso_timestamp(ts: str) -> float:
    """Parse various ISO timestamp formats to epoch seconds. Returns 0 on failure."""
    if not ts:
        return 0
    from datetime import datetime, timezone
    # Try common formats
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f+00:00",
        "%Y-%m-%dT%H:%M:%S+00:00",
    ):
        try:
            dt = datetime.strptime(ts, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    # Fallback: try fromisoformat
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return 0


def _parse_start_time_from_name(name: str) -> float:
    """Parse the start timestamp from run directory name to epoch seconds."""
    ts_str = _parse_timestamp_from_name(name)
    if not ts_str:
        return 0
    from datetime import datetime, timezone
    try:
        dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return 0


def _build_run_summary(run_dir: Path) -> dict | None:
    config_path = run_dir / "config.json"
    if not config_path.is_file():
        return None
    config = _read_json(config_path)
    cfg_summary = _extract_config_summary(config)
    atomic = _find_atomic_work_dir(run_dir)
    run_meta = _read_run_timestamps(run_dir)

    status = "unknown"
    cycles_used = 0
    result_count = 0
    passed_count = 0
    failed_count = 0
    workflow_mode = ""
    last_activity = ""

    if atomic:
        wf_result = _read_json(atomic / "_meta" / "workflow_result.json")
        status = wf_result.get("status", "")
        cycles_used = (wf_result.get("detail") or {}).get("cycles_used", 0)
        state = _read_json(atomic / "_meta" / "state.json")
        if not status:
            status = state.get("current_state", "unknown")

        # Get latest cycle info
        summaries = _sorted_json_files(atomic / "_meta" / "review_summaries")
        if summaries:
            latest = _read_json(summaries[-1])
            rr = latest.get("result_review", {})
            result_count = rr.get("total", 0)
            passed_count = rr.get("passed_count", 0)
            failed_count = rr.get("failed_count", 0)
            workflow_mode = latest.get("workflow_mode", "")
            if not cycles_used:
                cycles_used = latest.get("cycle", 0)

        # Check if still running (no workflow_result but state exists)
        if not wf_result and state.get("current_state") not in ("completed", "failed", ""):
            status = "running"

        last_activity = _find_last_activity(atomic, run_dir)
        results_manifest = _read_json(atomic / "_meta" / "results_manifest.json")
        if results_manifest:
            result_count = results_manifest.get("taskable_result_count", result_count)

    status = _normalize_run_status(status, run_meta)

    # Duration calculation (works even without atomic, uses explicit run markers and durable metadata)
    duration_seconds = _compute_duration(run_dir, atomic, status, run_meta)

    start_time = _parse_timestamp_from_name(run_dir.name)
    start_epoch = _find_run_start_epoch(run_dir, run_meta)
    start_date = _derive_run_date_label(
        run_dir,
        name=run_dir.name,
        start_time=start_time,
        last_activity=last_activity,
        run_meta=run_meta,
    )
    return {
        "name": run_dir.name,
        "status": status or "pending",
        "start_time": start_time,
        "start_epoch": int(start_epoch) if start_epoch else 0,
        "start_date": start_date,
        "duration_seconds": duration_seconds,
        "last_activity": last_activity,
        "model": cfg_summary["model"],
        "provider": cfg_summary["provider"],
        "thinking": cfg_summary["thinking"],
        "max_cycles": cfg_summary["max_review_cycles"],
        "cycles_used": cycles_used,
        "result_count": result_count,
        "passed_count": passed_count,
        "failed_count": failed_count,
        "workflow_mode": workflow_mode,
    }


# ═══════════════════════════════════════════════════
# API: Run detail
# ═══════════════════════════════════════════════════

@app.get("/api/runs/{name}")
def get_run_detail(name: str):
    run_dir = RUNS_DIR / name
    if not run_dir.is_dir():
        raise HTTPException(404, "run not found")

    config = _read_json(run_dir / "config.json")
    cfg_summary = _extract_config_summary(config)
    atomic = _find_atomic_work_dir(run_dir)
    run_meta = _read_run_timestamps(run_dir)
    if not atomic:
        start_time = _parse_timestamp_from_name(name)
        start_date = _derive_run_date_label(run_dir, name=name, start_time=start_time, last_activity="", run_meta=run_meta)
        status = _normalize_run_status("no_workspace", run_meta)
        return {"config": cfg_summary, "status": status, "start_time": start_time, "start_epoch": int(_find_run_start_epoch(run_dir, run_meta) or 0), "start_date": start_date, "duration_seconds": _compute_duration(run_dir, None, status, run_meta), "last_activity": "", "cycles": [], "results": [], "latest_issues": [], "atomic_work_path": "", "atomic_work_dir": ""}

    wf_result = _read_json(atomic / "_meta" / "workflow_result.json")
    state = _read_json(atomic / "_meta" / "state.json")
    status = _normalize_run_status(wf_result.get("status", state.get("current_state", "unknown")), run_meta)

    # Cycles
    cycles = []
    for f in _sorted_json_files(atomic / "_meta" / "review_summaries"):
        summary = _read_json(f)
        cycle_num = summary.get("cycle", 0)
        metrics_path = atomic / "_meta" / "cycle_metrics" / f"cycle_{cycle_num:03d}.json"
        metrics = _read_json(metrics_path) if metrics_path.is_file() else {}
        issue_path = atomic / "_meta" / "review_feedback" / f"cycle_{cycle_num:03d}.json"
        issue_data = _read_json(issue_path) if issue_path.is_file() else {}

        gr = summary.get("global_review", {})
        rr = summary.get("result_review", {})
        cycles.append({
            "cycle": cycle_num,
            "timestamp": summary.get("timestamp", ""),
            "outcome": summary.get("outcome", ""),
            "workflow_mode": summary.get("workflow_mode", ""),
            "global_passed": gr.get("passed", False),
            "global_advisors": gr.get("advisor_results", []),
            "failed_advisor_id": gr.get("failed_advisor_id", ""),
            "failed_role_name": gr.get("failed_role_name", ""),
            "result_total": rr.get("total", 0),
            "result_passed": rr.get("passed_count", 0),
            "result_failed": rr.get("failed_count", 0),
            "passed_files": rr.get("passed_files", []),
            "failed_files": rr.get("failed_files", []),
            "scores": metrics.get("scores", {}),
            "global_failure_scope": metrics.get("global_failure_scope", ""),
            "failed_result_count": metrics.get("failed_result_count", rr.get("failed_count", 0)),
            "current_failed_result_count": metrics.get("current_failed_result_count", rr.get("failed_count", 0)),
            "historical_removed_result_count": metrics.get("historical_removed_result_count", 0),
            "unreviewed_new_result_count": metrics.get("unreviewed_new_result_count", 0),
            "unreviewed_new_result_files": metrics.get("unreviewed_new_result_files", []),
            "issue_count": metrics.get("issue_count", len(issue_data.get("issues", []))),
            "issue_ids": metrics.get("issue_ids", []),
            "summary_size": metrics.get("summary_size", 0),
            "plateau_status": summary.get("plateau_status", {}),
            "issues": issue_data.get("issues", []),
        })

    # Results
    results = _collect_results(atomic)

    # Latest issues from review_feedback
    feedback_files = _sorted_json_files(atomic / "_meta" / "review_feedback")
    latest_issues = []
    if feedback_files:
        latest_data = _read_json(feedback_files[-1])
        latest_issues = latest_data.get("issues", [])

    last_activity = _find_last_activity(atomic, run_dir)
    start_time = _parse_timestamp_from_name(name)
    return {
        "name": name,
        "config": cfg_summary,
        "status": status,
        "start_time": start_time,
        "start_epoch": int(_find_run_start_epoch(run_dir, run_meta) or 0),
        "start_date": _derive_run_date_label(run_dir, name=name, start_time=start_time, last_activity=last_activity, run_meta=run_meta),
        "duration_seconds": _compute_duration(run_dir, atomic, status, run_meta),
        "last_activity": last_activity,
        "cycles_used": (wf_result.get("detail") or {}).get("cycles_used", len(cycles)),
        "error": (wf_result.get("detail") or {}).get("error", wf_result.get("error")),
        "cycles": cycles,
        "results": results,
        "removed_results": _collect_removed_results(atomic),
        "manifests": _load_manifest_summary(atomic),
        "latest_issues": latest_issues,
        "atomic_work_path": str(atomic),
        "atomic_work_dir": str(atomic),
    }


def _collect_results(atomic: Path) -> list[dict]:
    results_dir = atomic / "results"
    if not results_dir.is_dir():
        return []
    results_manifest = _read_json(atomic / "_meta" / "results_manifest.json")
    relations_manifest = _read_json(atomic / "_meta" / "result_relations_manifest.json")
    entries = results_manifest.get("entries") or relations_manifest.get("relationships") or []
    entry_by_name = {
        str(item.get("filename") or ""): item
        for item in entries
        if isinstance(item, dict)
    }
    results = []
    for f in sorted(results_dir.glob("result_*.md")):
        # Find latest review
        stem = f.stem
        review_dir = atomic / "reviews" / "results" / stem
        latest_review = {}
        if review_dir.is_dir():
            for cycle_dir in sorted(review_dir.glob("cycle_*"), reverse=True):
                for rfile in sorted(cycle_dir.glob("*.json")):
                    latest_review = _read_json(rfile)
                    break
                if latest_review:
                    break

        # Extract title from first heading
        content = _read_text(f, max_bytes=500)
        title = ""
        for line in content.splitlines():
            if line.startswith("#"):
                title = re.sub(r"^#+\s*", "", line).strip()
                break

        latest_review_path = None
        if review_dir.is_dir():
            for cycle_dir in sorted(review_dir.glob("cycle_*"), reverse=True):
                for rfile in sorted(cycle_dir.glob("*.json")):
                    latest_review_path = rfile
                    break
                if latest_review_path:
                    break

        manifest_entry = entry_by_name.get(f.name, {})
        results.append({
            "filename": f.name,
            "path": _rel_to_atomic(f, atomic),
            "title": title,
            "size": f.stat().st_size,
            "passed": latest_review.get("passed"),
            "verdict": latest_review.get("verdict", ""),
            "confidence": latest_review.get("confidence", 0),
            "review_cycle": latest_review.get("cycle", 0),
            "feedback": latest_review.get("feedback", ""),
            "feedback_detail": latest_review.get("feedback_detail", ""),
            "parser_mode": latest_review.get("parser_mode", ""),
            "schema_valid": latest_review.get("schema_valid"),
            "review_path": _rel_to_atomic(latest_review_path, atomic) if latest_review_path else "",
            "role": manifest_entry.get("role", ""),
            "lifecycle_status": manifest_entry.get("lifecycle_status", ""),
            "active": manifest_entry.get("active", True),
            "taskable": manifest_entry.get("taskable", True),
            "delivery_bucket": manifest_entry.get("delivery_bucket", "results"),
            "multi_finding": manifest_entry.get("multi_finding", False),
            "vulnerability_headings": manifest_entry.get("vulnerability_headings", []),
            "related_to": manifest_entry.get("related_to", ""),
        })
    return results


def _collect_removed_results(atomic: Path) -> list[dict]:
    removed_root = atomic / "removed_results"
    if not removed_root.is_dir():
        return []
    removed: list[dict] = []
    for meta_path in sorted(removed_root.glob("cycle_*/*.json")):
        data = _read_json(meta_path)
        md_path = meta_path.with_suffix(".md")
        backup_path = Path(str(data.get("backup_path") or ""))
        if backup_path.is_file() and _is_within(backup_path.resolve(), atomic.resolve()):
            md_path = backup_path
        cycle = data.get("removed_in_cycle")
        if not cycle:
            m = re.search(r"cycle_(\d+)", str(meta_path.parent.name))
            cycle = int(m.group(1)) if m else 0
        removed.append({
            "filename": data.get("original_filename") or md_path.name,
            "path": _rel_to_atomic(md_path, atomic) if md_path.is_file() else "",
            "meta_path": _rel_to_atomic(meta_path, atomic),
            "cycle": cycle,
            "lifecycle_status": data.get("lifecycle_status", "inactive"),
            "reason": data.get("reason", ""),
            "signals": data.get("signals", []),
        })
    return removed


# ═══════════════════════════════════════════════════
# API: Cycle detail (global + result reviews)
# ═══════════════════════════════════════════════════

@app.get("/api/runs/{name}/cycles/{cycle}")
def get_cycle_detail(name: str, cycle: int):
    run_dir = RUNS_DIR / name
    atomic = _find_atomic_work_dir(run_dir)
    if not atomic:
        raise HTTPException(404, "atomic work dir not found")

    # Global reviews
    global_reviews = []
    gr_dir = atomic / "reviews" / "global" / f"cycle_{cycle:03d}"
    if gr_dir.is_dir():
        for f in sorted(gr_dir.glob("*.json")):
            data = _read_json(f)
            global_reviews.append({
                "advisor_id": data.get("advisor_instance_id", f.stem),
                "path": _rel_to_atomic(f, atomic),
                "role_name": data.get("role_name", ""),
                "passed": data.get("passed", False),
                "verdict": data.get("verdict", ""),
                "scores": data.get("scores", {}),
                "confidence": data.get("confidence", 0),
                "feedback": data.get("feedback", ""),
                "feedback_detail": data.get("feedback_detail", ""),
                "schema_valid": data.get("schema_valid"),
                "parser_mode": data.get("parser_mode", ""),
                "repair_attempts": data.get("repair_attempts", 0),
                "issues": data.get("issues", []),
                "resolved_issue_ids": data.get("resolved_issue_ids", []),
            })

    # Result reviews for this cycle
    result_reviews = []
    rr_root = atomic / "reviews" / "results"
    if rr_root.is_dir():
        for result_dir in sorted(rr_root.iterdir()):
            cycle_dir = result_dir / f"cycle_{cycle:03d}"
            if not cycle_dir.is_dir():
                continue
            for f in sorted(cycle_dir.glob("*.json")):
                data = _read_json(f)
                result_reviews.append({
                    "result_file": data.get("result_file", f"{result_dir.name}.md"),
                    "path": _rel_to_atomic(f, atomic),
                    "advisor_id": data.get("advisor_instance_id", f.stem),
                    "passed": data.get("passed", False),
                    "verdict": data.get("verdict", ""),
                    "confidence": data.get("confidence", 0),
                    "feedback": data.get("feedback", ""),
                    "feedback_detail": data.get("feedback_detail", ""),
                    "schema_valid": data.get("schema_valid"),
                    "parser_mode": data.get("parser_mode", ""),
                    "repair_attempts": data.get("repair_attempts", 0),
                })

    # Summary snapshot
    snapshot_path = atomic / "_meta" / "summary_snapshots" / f"cycle_{cycle:03d}_after_summary.md"
    summary_snapshot = _read_text(snapshot_path, max_bytes=50000) if snapshot_path.is_file() else ""

    return {
        "cycle": cycle,
        "global_reviews": global_reviews,
        "result_reviews": result_reviews,
        "summary_snapshot": summary_snapshot,
        "metrics": _read_json(atomic / "_meta" / "cycle_metrics" / f"cycle_{cycle:03d}.json"),
    }


# ═══════════════════════════════════════════════════
# API: Sessions
# ═══════════════════════════════════════════════════

@app.get("/api/runs/{name}/sessions")
def get_sessions(name: str):
    run_dir = RUNS_DIR / name
    atomic = _find_atomic_work_dir(run_dir)
    if not atomic:
        raise HTTPException(404)

    sessions_root = atomic / "sessions"
    if not sessions_root.is_dir():
        return []

    sessions = []
    # Find .jsonl session files (new format)
    for jsonl_file in sorted(sessions_root.rglob("*.jsonl")):
        # Build a relative path from atomic for the API
        rel_path = str(jsonl_file.relative_to(atomic))
        # Extract worker id from path: sessions/<worker_id>/<filename>.jsonl
        parts = jsonl_file.relative_to(sessions_root).parts
        worker_id = parts[0] if len(parts) >= 2 else jsonl_file.stem
        stat = jsonl_file.stat()
        sessions.append({
            "session_id": jsonl_file.stem,
            "format": "jsonl",
            "worker_id": worker_id,
            "jsonl_path": rel_path,
            "size": stat.st_size,
            "mtime": stat.st_mtime,
            "calls": [],  # populated below or on-demand
        })

    # Also find call-based sessions (legacy / compat)
    for sess_dir in sorted(sessions_root.iterdir()):
        if not sess_dir.is_dir():
            continue
        # Skip if already covered by jsonl
        calls_dir = sess_dir / "calls"
        if not calls_dir.is_dir():
            continue
        calls = []
        for call_dir in sorted(calls_dir.iterdir()):
            if not call_dir.is_dir():
                continue
            req = _read_json(call_dir / "request.json")
            resp = _read_json(call_dir / "response.json")
            files = {}
            for key, filename in {
                "request": "request.json",
                "response": "response.json",
                "user_prompt": "user_prompt.md",
                "system_prompt": "system_prompt.md",
                "stdout": "stdout.txt",
                "stderr": "stderr.txt",
                "stdout_events": "stdout_events.json",
            }.items():
                file_path = call_dir / filename
                if file_path.is_file():
                    files[key] = _rel_to_atomic(file_path, atomic)

            calls.append({
                "call_id": call_dir.name,
                "turn": req.get("turn_number", 0),
                "agent_id": req.get("agent_id", ""),
                "is_continuation": req.get("is_continuation", False),
                "user_prompt_len": req.get("user_prompt_len", 0),
                "sys_prompt_len": req.get("sys_prompt_len", 0),
                "status": resp.get("status", ""),
                "duration_ms": resp.get("duration_ms"),
                "output_len": resp.get("output_len", 0),
                "error": resp.get("error"),
                "files": files,
            })
        if calls:
            sessions.append({"session_id": sess_dir.name, "format": "calls", "calls": calls})
    return sessions


# ═══════════════════════════════════════════════════
# API: File index
# ═══════════════════════════════════════════════════

@app.get("/api/runs/{name}/files")
def list_files(name: str, limit: int = Query(default=1200, le=5000)):
    run_dir = RUNS_DIR / name
    atomic = _find_atomic_work_dir(run_dir)
    if not run_dir.is_dir():
        raise HTTPException(404, "run not found")

    entries: list[dict] = []

    def add(path: Path, base: Path, category: str):
        if path.is_file() and len(entries) < limit:
            entries.append(_file_entry(path, base, category))

    def add_glob(base_dir: Path, pattern: str, base: Path, category: str):
        if not base_dir.is_dir():
            return
        for path in sorted(base_dir.glob(pattern)):
            add(path, base, category)
            if len(entries) >= limit:
                return

    add(run_dir / "config.json", run_dir, "Run Root")
    add(run_dir / "run.log", run_dir, "Run Root")
    add(run_dir / "input" / "task.md", run_dir, "Input")

    if atomic:
        add(atomic / "summary.md", atomic, "Outputs")
        add(atomic / "previous_limitations.md", atomic, "Outputs")
        add_glob(atomic / "results", "*.md", atomic, "Outputs / Results")
        add_glob(atomic / "supporting_docs", "*.md", atomic, "Outputs / Supporting Docs")
        add_glob(atomic / "removed_results", "cycle_*/*.md", atomic, "Outputs / Removed Results")
        add_glob(atomic / "removed_results", "cycle_*/*.json", atomic, "Outputs / Removed Results")

        add(atomic / "_meta" / "state.json", atomic, "Meta")
        add(atomic / "_meta" / "workflow_result.json", atomic, "Meta")
        add(atomic / "_meta" / "abnormal_exit.json", atomic, "Meta")
        add(atomic / "_meta" / "result_relations_manifest.json", atomic, "Meta / Result Manifests")
        add(atomic / "_meta" / "results_manifest.json", atomic, "Meta / Result Manifests")
        add(atomic / "_meta" / "coverage_ledger.json", atomic, "Meta / Result Manifests")
        add(atomic / "_meta" / "checkpoints" / "current_step.json", atomic, "Meta / Checkpoints")
        add_glob(atomic / "_meta" / "checkpoints" / "steps", "cycle_*/*/*.json", atomic, "Meta / Checkpoints")
        add_glob(atomic / "_meta" / "reflections", "*.json", atomic, "Meta / Reflections")
        add_glob(atomic / "_meta" / "review_summaries", "*.json", atomic, "Meta / Review Summaries")
        add_glob(atomic / "_meta" / "cycle_metrics", "*.json", atomic, "Meta / Cycle Metrics")
        add_glob(atomic / "_meta" / "review_feedback", "*.json", atomic, "Meta / Review Feedback")
        add_glob(atomic / "_meta" / "summary_snapshots", "*.md", atomic, "Meta / Summary Snapshots")

        add_glob(atomic / "plugins" / "start", "*.json", atomic, "Plugins")
        add_glob(atomic / "plugins" / "end", "*.json", atomic, "Plugins")
        add_glob(atomic / "reviews" / "global", "cycle_*/*.json", atomic, "Reviews / Global")
        add_glob(atomic / "reviews" / "results", "result_*/cycle_*/*.json", atomic, "Reviews / Results")
        add_glob(atomic / "sessions", "*/calls/*/request.json", atomic, "Sessions")
        add_glob(atomic / "sessions", "*/calls/*/response.json", atomic, "Sessions")
        add_glob(atomic / "sessions", "*/calls/*/user_prompt.md", atomic, "Sessions")
        add_glob(atomic / "sessions", "*/calls/*/system_prompt.md", atomic, "Sessions")
        add_glob(atomic / "sessions", "*/calls/*/stdout.txt", atomic, "Sessions")
        add_glob(atomic / "sessions", "*/calls/*/stderr.txt", atomic, "Sessions")
        add_glob(atomic / "sessions", "*/calls/*/stdout_events.json", atomic, "Sessions")
        add_glob(atomic / "sessions", "*/*.jsonl", atomic, "Sessions")

    return entries


# ═══════════════════════════════════════════════════
# API: File viewer
# ═══════════════════════════════════════════════════

@app.get("/api/runs/{name}/file")
def get_file(name: str, path: str = Query(...)):
    run_dir = RUNS_DIR / name
    atomic = _find_atomic_work_dir(run_dir)
    if not atomic:
        raise HTTPException(404)

    # Allow paths relative to atomic work dir or run dir
    candidates = [atomic / path, run_dir / path]
    target = None
    for c in candidates:
        resolved = c.resolve()
        if resolved.is_file() and _is_within(resolved, run_dir.resolve()):
            target = resolved
            break
    if not target:
        raise HTTPException(404, f"file not found: {path}")

    content = _read_text(target, max_bytes=500_000)
    suffix = target.suffix.lower()
    if suffix == ".json":
        file_type = "json"
    elif suffix == ".md":
        file_type = "markdown"
    elif suffix == ".jsonl":
        file_type = "jsonl"
    else:
        file_type = "text"
    return {"path": str(target.relative_to(run_dir)), "type": file_type, "content": content}


# ═══════════════════════════════════════════════════
# API: Delete run
# ═══════════════════════════════════════════════════

@app.delete("/api/runs/{name}")
def delete_run(name: str):
    run_dir = RUNS_DIR / name
    if not run_dir.is_dir():
        raise HTTPException(404, "run not found")
    # Safety: only allow deleting directories directly under RUNS_DIR
    if run_dir.resolve().parent != RUNS_DIR.resolve():
        raise HTTPException(403, "forbidden: directory not under runs dir")
    try:
        shutil.rmtree(run_dir)
        return {"ok": True, "deleted": name}
    except Exception as e:
        raise HTTPException(500, f"failed to delete: {e}")


# ═══════════════════════════════════════════════════
# API: Session JSONL viewer
# ═══════════════════════════════════════════════════

@app.get("/api/runs/{name}/session-file")
def get_session_file(name: str, path: str = Query(...)):
    run_dir = RUNS_DIR / name
    if not run_dir.is_dir():
        raise HTTPException(404, "run not found")

    # Allow paths relative to run_dir or atomic work dir
    atomic = _find_atomic_work_dir(run_dir)
    candidates = [run_dir / path]
    if atomic:
        candidates.append(atomic / path)
    target = None
    for c in candidates:
        resolved = c.resolve()
        if resolved.is_file() and _is_within(resolved, run_dir.resolve()):
            target = resolved
            break
    if not target:
        raise HTTPException(404, f"file not found: {path}")
    if not target.suffix.lower() == ".jsonl":
        raise HTTPException(400, "not a .jsonl file")

    events: list[dict] = []
    session_meta: dict = {}
    try:
        with open(target, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    events.append({"type": "raw", "line": line_no, "text": line[:200]})
                    continue

                etype = obj.get("type", "")

                if etype == "session":
                    session_meta = {
                        "id": obj.get("id", ""),
                        "version": obj.get("version", ""),
                        "timestamp": obj.get("timestamp", ""),
                        "cwd": obj.get("cwd", ""),
                    }
                    continue

                if etype == "model_change":
                    events.append({
                        "type": "model_change",
                        "line": line_no,
                        "timestamp": obj.get("timestamp", ""),
                        "provider": obj.get("provider", ""),
                        "modelId": obj.get("modelId", ""),
                    })
                    continue

                if etype == "thinking_level_change":
                    events.append({
                        "type": "thinking_level_change",
                        "line": line_no,
                        "timestamp": obj.get("timestamp", ""),
                        "thinkingLevel": obj.get("thinkingLevel", ""),
                    })
                    continue

                if etype == "message":
                    msg = obj.get("message", {})
                    role = msg.get("role", "")
                    ts = obj.get("timestamp", "")
                    content = msg.get("content", [])

                    # Extra fields for toolResult messages
                    extra = {}
                    if role == "toolResult":
                        extra["toolCallId"] = msg.get("toolCallId", msg.get("tool_call_id", ""))
                        extra["toolName"] = msg.get("toolName", msg.get("tool_name", ""))
                        extra["isError"] = msg.get("isError", msg.get("is_error", False))

                    # Parse content parts
                    parts: list[dict] = []
                    if isinstance(content, str):
                        parts.append({"type": "text", "text": content})
                    elif isinstance(content, list):
                        for c in content:
                            if not isinstance(c, dict):
                                continue
                            ct = c.get("type", "")
                            if ct == "text":
                                parts.append({"type": "text", "text": c.get("text", "")})
                            elif ct == "thinking":
                                parts.append({"type": "thinking", "text": c.get("thinking", "")})
                            elif ct == "toolCall":
                                parts.append({
                                    "type": "toolCall",
                                    "name": c.get("name", ""),
                                    "id": c.get("id", ""),
                                    "arguments": c.get("arguments", {}),
                                })
                            elif ct == "toolResult":
                                parts.append({
                                    "type": "toolResult",
                                    "text": c.get("text", ""),
                                })
                            else:
                                # Unknown content type – include summary
                                parts.append({"type": "unknown", "detail": str(c)[:200]})

                    event_data = {
                        "type": "message",
                        "line": line_no,
                        "timestamp": ts,
                        "role": role,
                        "parts": parts,
                    }
                    event_data.update(extra)
                    events.append(event_data)
                    continue

                # Fallback for unknown event types
                events.append({
                    "type": etype or "unknown_event",
                    "line": line_no,
                    "summary": str(obj)[:200],
                })
    except Exception as e:
        raise HTTPException(500, f"failed to parse session file: {e}")

    return {
        "path": str(target.relative_to(run_dir)),
        "session_meta": session_meta,
        "events": events,
    }


# ═══════════════════════════════════════════════════
# API: Log tail
# ═══════════════════════════════════════════════════

@app.get("/api/runs/{name}/log")
def get_log(name: str, lines: int = Query(default=300, le=2000)):
    run_dir = RUNS_DIR / name
    log_path = run_dir / "run.log"
    if not log_path.is_file():
        return {"content": "(no log file)"}
    return {"content": _tail_lines(log_path, lines)}


# ═══════════════════════════════════════════════════
# Static files & entry point
# ═══════════════════════════════════════════════════

@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def main():
    parser = argparse.ArgumentParser(description="Vuln Scan Dashboard")
    parser.add_argument("--port", type=int, default=8501)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--runs-dir", default=str(DEFAULT_RUNS_DIR))
    args = parser.parse_args()

    global RUNS_DIR
    RUNS_DIR = Path(args.runs_dir).resolve()
    print(f"Dashboard: http://localhost:{args.port}")
    print(f"Runs dir:  {RUNS_DIR}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
