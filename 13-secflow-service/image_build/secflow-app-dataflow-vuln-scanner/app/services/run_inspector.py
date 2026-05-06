from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from app.pi_vuln_core.utils.win_compat import from_msys_path


_RUNNING_WORKFLOW_STATES = {
    "created",
    "start_plugins",
    "worker",
    "reflect",
    "summary",
    "global_review",
    "result_review",
    "end_plugins",
    "running",
    "queued",
    "pending",
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


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _read_text(path: Path, max_bytes: int = 0) -> str:
    try:
        if max_bytes > 0:
            with path.open("r", encoding="utf-8", errors="replace") as file:
                return file.read(max_bytes)
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _tail_lines(path: Path, n: int = 300) -> str:
    try:
        with path.open("rb") as file:
            file.seek(0, 2)
            size = file.tell()
            chunk = min(size, max(n, 1) * 500)
            file.seek(max(0, size - chunk))
            data = file.read().decode("utf-8", errors="replace")
        return "\n".join(data.splitlines()[-n:])
    except Exception:
        return ""


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _file_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix == ".jsonl":
        return "jsonl"
    if suffix == ".md":
        return "markdown"
    return "text"


def _parse_iso_timestamp(value: str) -> float:
    if not value:
        return 0
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f+00:00",
        "%Y-%m-%dT%H:%M:%S+00:00",
    ):
        try:
            parsed = datetime.strptime(value, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except Exception:
        return 0


def _parse_timestamp_from_name(name: str) -> str:
    match = re.search(r"(\d{8})_(\d{6})(?:$|\D)", name) or re.search(r"(\d{8})_(\d{6})", name)
    if not match:
        return ""
    date, time = match.group(1), match.group(2)
    return f"{date[:4]}-{date[4:6]}-{date[6:8]} {time[:2]}:{time[2:4]}:{time[4:6]}"


def _parse_start_time_from_name(name: str) -> float:
    text = _parse_timestamp_from_name(name)
    if not text:
        return 0
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return 0


def _sorted_json_files(directory: Path, pattern: str = "cycle_*.json") -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(directory.glob(pattern))


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
    mark(2, (candidate / "_meta" / "review_feedback").is_dir())

    return score, evidence


def _find_atomic_work_dir(run_dir: Path) -> Path | None:
    config = _read_json(run_dir / "config.json")
    candidates: list[tuple[int, int, int, Path]] = []
    fallback_candidates: list[tuple[int, Path]] = []
    seen: set[str] = set()

    for search_root in _atomic_candidate_search_roots(run_dir, config):
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


def _summarize_global_review_advisors(config: dict[str, Any]) -> list[dict[str, Any]]:
    advisors: list[dict[str, Any]] = []
    for workflow in ((config.get("workflows") or {}).get("atomic") or []):
        group = (((workflow.get("roles") or {}).get("advisors") or {}).get("global_review") or [])
        for advisor in group:
            advisors.append(
                {
                    "instance_id": advisor.get("instance_id", ""),
                    "role_name": advisor.get("role_name", ""),
                    "score_fields": advisor.get("score_fields", []),
                    "score_thresholds": advisor.get("score_thresholds", {}),
                    "score_thresholds_start": advisor.get("score_thresholds_start", {}),
                }
            )
    return advisors


def _extract_config_summary(config: dict[str, Any]) -> dict[str, Any]:
    agents = config.get("agents", [])
    worker = next((item for item in agents if str(item.get("id", "")).endswith("worker")), agents[0] if agents else {})
    runtime = worker.get("runtime_config", {})
    sdk = runtime.get("sdk_specific", {})
    global_cfg = config.get("global", {})
    execution_cfg = config.get("execution", {})
    return {
        "model": runtime.get("model", ""),
        "provider": sdk.get("provider", ""),
        "thinking": sdk.get("thinking", ""),
        "timeout_seconds": runtime.get("timeout_seconds", 0),
        "max_review_cycles": global_cfg.get("max_review_cycles", 0),
        "parallel_result_review": global_cfg.get("parallel_result_review", False),
        "parallel_result_review_limit": global_cfg.get("parallel_result_review_limit", 0),
        "execution_id": execution_cfg.get("execution_id", ""),
        "task_file": (execution_cfg.get("input_task") or {}).get("task_file", ""),
        "global_review_advisors": _summarize_global_review_advisors(config),
    }


def _read_run_timestamps(run_dir: Path) -> dict[str, Any]:
    return _read_json(run_dir / "_meta" / "run_timestamps.json")


def _normalize_run_status(raw_status: str, run_meta: dict[str, Any] | None = None) -> str:
    run_meta = run_meta or {}
    text = str(raw_status or "").strip().lower()
    if run_meta.get("finished_at"):
        meta_status = str(run_meta.get("status") or "").strip().lower()
        if meta_status in _TERMINAL_STATUSES:
            return meta_status
    if text in _TERMINAL_STATUSES:
        return text
    if text in _RUNNING_WORKFLOW_STATES:
        return "running" if text not in {"pending", "queued"} else text
    return text or "pending"


def _find_last_activity(atomic: Path | None, run_dir: Path) -> str:
    candidates: list[str] = []
    if atomic:
        state = _read_json(atomic / "_meta" / "state.json")
        if state.get("timestamp"):
            candidates.append(str(state["timestamp"]))
        summaries = _sorted_json_files(atomic / "_meta" / "review_summaries")
        if summaries:
            latest = _read_json(summaries[-1])
            if latest.get("timestamp"):
                candidates.append(str(latest["timestamp"]))
        for jsonl in sorted(atomic.rglob("*.jsonl")):
            try:
                with jsonl.open("rb") as file:
                    file.seek(0, 2)
                    size = file.tell()
                    file.seek(max(0, size - 4096))
                    tail = file.read().decode("utf-8", errors="replace")
                for line in reversed(tail.splitlines()):
                    try:
                        event = json.loads(line.strip())
                    except json.JSONDecodeError:
                        continue
                    if event.get("timestamp"):
                        candidates.append(str(event["timestamp"]))
                        break
            except Exception:
                continue
    log_path = run_dir / "run.log"
    if log_path.is_file():
        try:
            candidates.append(datetime.fromtimestamp(log_path.stat().st_mtime, tz=timezone.utc).isoformat())
        except Exception:
            pass
    return max(candidates) if candidates else ""


def _find_run_start_epoch(run_dir: Path, run_meta: dict[str, Any] | None = None) -> float:
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
        return 0


def _find_run_end_epoch(atomic: Path | None, run_dir: Path, status: str, run_meta: dict[str, Any] | None = None) -> float:
    if status == "running":
        return datetime.now(tz=timezone.utc).timestamp()
    run_meta = run_meta or {}
    finished_at = _parse_iso_timestamp(str(run_meta.get("finished_at") or ""))
    if finished_at:
        return finished_at
    candidates: list[float] = []
    if atomic:
        for meta_name in ("workflow_result.json", "abnormal_exit.json"):
            timestamp = _parse_iso_timestamp(str(_read_json(atomic / "_meta" / meta_name).get("timestamp") or ""))
            if timestamp:
                candidates.append(timestamp)
        state_timestamp = _parse_iso_timestamp(str(_read_json(atomic / "_meta" / "state.json").get("timestamp") or ""))
        if state_timestamp:
            candidates.append(state_timestamp)
    last_activity = _parse_iso_timestamp(_find_last_activity(atomic, run_dir))
    if last_activity:
        candidates.append(last_activity)
    return max(candidates) if candidates else 0


def _compute_duration(run_dir: Path, atomic: Path | None, status: str, run_meta: dict[str, Any] | None = None) -> int:
    start = _find_run_start_epoch(run_dir, run_meta)
    end = _find_run_end_epoch(atomic, run_dir, status, run_meta)
    if not start or not end or end < start:
        return 0
    return int(end - start)


def _manifest_path_summary(atomic: Path, path: Path) -> dict[str, Any]:
    return {"path": str(path.relative_to(atomic)), "exists": path.is_file()}


def _load_manifest_summary(atomic: Path) -> dict[str, Any]:
    relations_path = atomic / "_meta" / "result_relations_manifest.json"
    results_path = atomic / "_meta" / "results_manifest.json"
    coverage_path = atomic / "_meta" / "coverage_ledger.json"
    relations = _read_json(relations_path)
    results = _read_json(results_path)
    coverage = _read_json(coverage_path)
    return {
        "result_relations_manifest": _manifest_path_summary(atomic, relations_path),
        "results_manifest": _manifest_path_summary(atomic, results_path),
        "coverage_ledger": _manifest_path_summary(atomic, coverage_path),
        "total_result_files": results.get("total_result_files", len(relations.get("all_results", []))),
        "active_result_count": results.get("active_result_count", 0),
        "inactive_result_count": results.get("inactive_result_count", len(relations.get("inactive_results", []))),
        "taskable_result_count": results.get("taskable_result_count", len(relations.get("taskable_results", []))),
        "supplemental_result_count": results.get("supplemental_result_count", len(relations.get("supplemental_results", []))),
        "excluded_result_count": len(results.get("excluded_results", relations.get("excluded_results", [])) or []),
        "missing_referenced_results": coverage.get("missing_referenced_results", []),
        "unreferenced_active_results": coverage.get("unreferenced_active_results", []),
    }


def _rel_to_atomic(path: Path, atomic: Path) -> str:
    return str(path.relative_to(atomic))


def _collect_results(atomic: Path) -> list[dict[str, Any]]:
    results_dir = atomic / "results"
    if not results_dir.is_dir():
        results_dir = atomic / "final_output" / "results"
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
    results: list[dict[str, Any]] = []
    for file_path in sorted(results_dir.glob("result_*.md")):
        review_dir = atomic / "reviews" / "results" / file_path.stem
        latest_review: dict[str, Any] = {}
        latest_review_path: Path | None = None
        if review_dir.is_dir():
            for cycle_dir in sorted(review_dir.glob("cycle_*"), reverse=True):
                for review_file in sorted(cycle_dir.glob("*.json")):
                    latest_review = _read_json(review_file)
                    latest_review_path = review_file
                    break
                if latest_review:
                    break
        title = ""
        for line in _read_text(file_path, max_bytes=600).splitlines():
            if line.startswith("#"):
                title = re.sub(r"^#+\s*", "", line).strip()
                break
        manifest_entry = entry_by_name.get(file_path.name, {})
        results.append(
            {
                "filename": file_path.name,
                "path": _rel_to_atomic(file_path, atomic),
                "title": title,
                "size": file_path.stat().st_size,
                "passed": latest_review.get("passed"),
                "verdict": latest_review.get("verdict", ""),
                "confidence": latest_review.get("confidence", 0),
                "review_cycle": latest_review.get("cycle", 0),
                "feedback": latest_review.get("feedback", ""),
                "feedback_detail": latest_review.get("feedback_detail", ""),
                "schema_valid": latest_review.get("schema_valid"),
                "parser_mode": latest_review.get("parser_mode", ""),
                "review_path": _rel_to_atomic(latest_review_path, atomic) if latest_review_path else "",
                "role": manifest_entry.get("role", ""),
                "lifecycle_status": manifest_entry.get("lifecycle_status", ""),
                "active": manifest_entry.get("active", True),
                "taskable": manifest_entry.get("taskable", True),
                "delivery_bucket": manifest_entry.get("delivery_bucket", "results"),
                "multi_finding": manifest_entry.get("multi_finding", False),
                "vulnerability_headings": manifest_entry.get("vulnerability_headings", []),
                "related_to": manifest_entry.get("related_to", ""),
            }
        )
    return results


def _collect_removed_results(atomic: Path) -> list[dict[str, Any]]:
    removed_root = atomic / "removed_results"
    if not removed_root.is_dir():
        return []
    removed: list[dict[str, Any]] = []
    for meta_path in sorted(removed_root.glob("cycle_*/*.json")):
        data = _read_json(meta_path)
        md_path = meta_path.with_suffix(".md")
        cycle = data.get("removed_in_cycle")
        if not cycle:
            match = re.search(r"cycle_(\d+)", str(meta_path.parent.name))
            cycle = int(match.group(1)) if match else 0
        removed.append(
            {
                "filename": data.get("original_filename") or md_path.name,
                "path": _rel_to_atomic(md_path, atomic) if md_path.is_file() else "",
                "meta_path": _rel_to_atomic(meta_path, atomic),
                "cycle": cycle,
                "lifecycle_status": data.get("lifecycle_status", "inactive"),
                "reason": data.get("reason", ""),
                "signals": data.get("signals", []),
            }
        )
    return removed


def inspect_run_summary(workspace_root: str | Path) -> dict[str, Any]:
    run_dir = Path(workspace_root)
    if not run_dir.is_dir():
        return {"status": "pending", "cycles_used": 0, "result_count": 0}
    config = _read_json(run_dir / "config.json")
    cfg_summary = _extract_config_summary(config)
    atomic = _find_atomic_work_dir(run_dir)
    run_meta = _read_run_timestamps(run_dir)
    status = "pending"
    cycles_used = 0
    result_count = 0
    passed_count = 0
    failed_count = 0
    workflow_mode = ""
    last_activity = ""
    if atomic:
        workflow_result = _read_json(atomic / "_meta" / "workflow_result.json")
        state = _read_json(atomic / "_meta" / "state.json")
        status = workflow_result.get("status", state.get("current_state", "running"))
        summaries = _sorted_json_files(atomic / "_meta" / "review_summaries")
        if summaries:
            latest = _read_json(summaries[-1])
            result_review = latest.get("result_review", {})
            result_count = result_review.get("total", 0)
            passed_count = result_review.get("passed_count", 0)
            failed_count = result_review.get("failed_count", 0)
            workflow_mode = latest.get("workflow_mode", "")
            cycles_used = latest.get("cycle", 0)
        result_manifest = _read_json(atomic / "_meta" / "results_manifest.json")
        if result_manifest:
            result_count = result_manifest.get("taskable_result_count", result_count)
        if workflow_result:
            cycles_used = (workflow_result.get("detail") or {}).get("cycles_used", cycles_used)
        last_activity = _find_last_activity(atomic, run_dir)
    status = _normalize_run_status(status, run_meta)
    return {
        "name": run_dir.name,
        "status": status,
        "start_time": _parse_timestamp_from_name(run_dir.name),
        "start_epoch": int(_find_run_start_epoch(run_dir, run_meta) or 0),
        "duration_seconds": _compute_duration(run_dir, atomic, status, run_meta),
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


def inspect_run_detail(workspace_root: str | Path) -> dict[str, Any]:
    run_dir = Path(workspace_root)
    if not run_dir.is_dir():
        raise HTTPException(404, "run workspace not found")
    config = _read_json(run_dir / "config.json")
    cfg_summary = _extract_config_summary(config)
    atomic = _find_atomic_work_dir(run_dir)
    run_meta = _read_run_timestamps(run_dir)
    if not atomic:
        status = _normalize_run_status("no_workspace", run_meta)
        return {
            "name": run_dir.name,
            "config": cfg_summary,
            "status": status,
            "start_time": _parse_timestamp_from_name(run_dir.name),
            "start_epoch": int(_find_run_start_epoch(run_dir, run_meta) or 0),
            "duration_seconds": _compute_duration(run_dir, None, status, run_meta),
            "last_activity": "",
            "cycles": [],
            "results": [],
            "removed_results": [],
            "latest_issues": [],
            "manifests": {},
            "atomic_work_path": "",
            "atomic_work_dir": "",
        }

    workflow_result = _read_json(atomic / "_meta" / "workflow_result.json")
    state = _read_json(atomic / "_meta" / "state.json")
    status = _normalize_run_status(workflow_result.get("status", state.get("current_state", "running")), run_meta)
    cycles: list[dict[str, Any]] = []
    for summary_file in _sorted_json_files(atomic / "_meta" / "review_summaries"):
        summary = _read_json(summary_file)
        cycle_num = int(summary.get("cycle", 0) or 0)
        metrics = _read_json(atomic / "_meta" / "cycle_metrics" / f"cycle_{cycle_num:03d}.json")
        issue_data = _read_json(atomic / "_meta" / "review_feedback" / f"cycle_{cycle_num:03d}.json")
        global_review = summary.get("global_review", {})
        result_review = summary.get("result_review", {})
        cycles.append(
            {
                "cycle": cycle_num,
                "timestamp": summary.get("timestamp", ""),
                "outcome": summary.get("outcome", ""),
                "workflow_mode": summary.get("workflow_mode", ""),
                "global_passed": global_review.get("passed", False),
                "global_advisors": global_review.get("advisor_results", []),
                "failed_advisor_id": global_review.get("failed_advisor_id", ""),
                "failed_role_name": global_review.get("failed_role_name", ""),
                "result_total": result_review.get("total", 0),
                "result_passed": result_review.get("passed_count", 0),
                "result_failed": result_review.get("failed_count", 0),
                "passed_files": result_review.get("passed_files", []),
                "failed_files": result_review.get("failed_files", []),
                "scores": metrics.get("scores", {}),
                "global_failure_scope": metrics.get("global_failure_scope", ""),
                "failed_result_count": metrics.get("failed_result_count", result_review.get("failed_count", 0)),
                "current_failed_result_count": metrics.get("current_failed_result_count", result_review.get("failed_count", 0)),
                "historical_removed_result_count": metrics.get("historical_removed_result_count", 0),
                "unreviewed_new_result_count": metrics.get("unreviewed_new_result_count", 0),
                "unreviewed_new_result_files": metrics.get("unreviewed_new_result_files", []),
                "issue_count": metrics.get("issue_count", len(issue_data.get("issues", []))),
                "issue_ids": metrics.get("issue_ids", []),
                "summary_size": metrics.get("summary_size", 0),
                "plateau_status": summary.get("plateau_status", {}),
                "issues": issue_data.get("issues", []),
            }
        )
    feedback_files = _sorted_json_files(atomic / "_meta" / "review_feedback")
    latest_issues = _read_json(feedback_files[-1]).get("issues", []) if feedback_files else []
    last_activity = _find_last_activity(atomic, run_dir)
    return {
        "name": run_dir.name,
        "config": cfg_summary,
        "status": status,
        "start_time": _parse_timestamp_from_name(run_dir.name),
        "start_epoch": int(_find_run_start_epoch(run_dir, run_meta) or 0),
        "duration_seconds": _compute_duration(run_dir, atomic, status, run_meta),
        "last_activity": last_activity,
        "cycles_used": (workflow_result.get("detail") or {}).get("cycles_used", len(cycles)),
        "error": (workflow_result.get("detail") or {}).get("error", workflow_result.get("error")),
        "cycles": cycles,
        "results": _collect_results(atomic),
        "removed_results": _collect_removed_results(atomic),
        "manifests": _load_manifest_summary(atomic),
        "latest_issues": latest_issues,
        "atomic_work_path": str(atomic),
        "atomic_work_dir": str(atomic),
    }


def inspect_cycle_detail(workspace_root: str | Path, cycle: int) -> dict[str, Any]:
    run_dir = Path(workspace_root)
    atomic = _find_atomic_work_dir(run_dir)
    if not atomic:
        raise HTTPException(404, "atomic work dir not found")
    global_reviews: list[dict[str, Any]] = []
    global_dir = atomic / "reviews" / "global" / f"cycle_{cycle:03d}"
    if global_dir.is_dir():
        for review_file in sorted(global_dir.glob("*.json")):
            data = _read_json(review_file)
            global_reviews.append(
                {
                    "advisor_id": data.get("advisor_instance_id", review_file.stem),
                    "path": _rel_to_atomic(review_file, atomic),
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
                }
            )
    result_reviews: list[dict[str, Any]] = []
    result_root = atomic / "reviews" / "results"
    if result_root.is_dir():
        for result_dir in sorted(item for item in result_root.iterdir() if item.is_dir()):
            cycle_dir = result_dir / f"cycle_{cycle:03d}"
            if not cycle_dir.is_dir():
                continue
            for review_file in sorted(cycle_dir.glob("*.json")):
                data = _read_json(review_file)
                result_reviews.append(
                    {
                        "result_file": data.get("result_file", f"{result_dir.name}.md"),
                        "path": _rel_to_atomic(review_file, atomic),
                        "advisor_id": data.get("advisor_instance_id", review_file.stem),
                        "passed": data.get("passed", False),
                        "verdict": data.get("verdict", ""),
                        "confidence": data.get("confidence", 0),
                        "feedback": data.get("feedback", ""),
                        "feedback_detail": data.get("feedback_detail", ""),
                        "schema_valid": data.get("schema_valid"),
                        "parser_mode": data.get("parser_mode", ""),
                        "repair_attempts": data.get("repair_attempts", 0),
                    }
                )
    snapshot_path = atomic / "_meta" / "summary_snapshots" / f"cycle_{cycle:03d}_after_summary.md"
    return {
        "cycle": cycle,
        "global_reviews": global_reviews,
        "result_reviews": result_reviews,
        "summary_snapshot": _read_text(snapshot_path, max_bytes=50_000) if snapshot_path.is_file() else "",
        "metrics": _read_json(atomic / "_meta" / "cycle_metrics" / f"cycle_{cycle:03d}.json"),
    }


def inspect_sessions(workspace_root: str | Path) -> list[dict[str, Any]]:
    run_dir = Path(workspace_root)
    atomic = _find_atomic_work_dir(run_dir)
    if not atomic:
        return []
    sessions_root = atomic / "sessions"
    if not sessions_root.is_dir():
        return []
    sessions: list[dict[str, Any]] = []
    for jsonl_file in sorted(sessions_root.rglob("*.jsonl")):
        rel_path = str(jsonl_file.relative_to(atomic))
        parts = jsonl_file.relative_to(sessions_root).parts
        worker_id = parts[0] if len(parts) >= 2 else jsonl_file.stem
        stat = jsonl_file.stat()
        sessions.append(
            {
                "session_id": jsonl_file.stem,
                "format": "jsonl",
                "worker_id": worker_id,
                "jsonl_path": rel_path,
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "calls": [],
            }
        )
    for session_dir in sorted(item for item in sessions_root.iterdir() if item.is_dir()):
        calls_dir = session_dir / "calls"
        if not calls_dir.is_dir():
            continue
        calls: list[dict[str, Any]] = []
        for call_dir in sorted(item for item in calls_dir.iterdir() if item.is_dir()):
            request = _read_json(call_dir / "request.json")
            response = _read_json(call_dir / "response.json")
            files: dict[str, str] = {}
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
            calls.append(
                {
                    "call_id": call_dir.name,
                    "turn": request.get("turn_number", 0),
                    "agent_id": request.get("agent_id", ""),
                    "is_continuation": request.get("is_continuation", False),
                    "user_prompt_len": request.get("user_prompt_len", 0),
                    "sys_prompt_len": request.get("sys_prompt_len", 0),
                    "status": response.get("status", ""),
                    "duration_ms": response.get("duration_ms"),
                    "output_len": response.get("output_len", 0),
                    "error": response.get("error"),
                    "files": files,
                }
            )
        if calls:
            sessions.append({"session_id": session_dir.name, "format": "calls", "calls": calls})
    return sessions


def inspect_files(workspace_root: str | Path, limit: int = 1200) -> list[dict[str, Any]]:
    run_dir = Path(workspace_root)
    if not run_dir.is_dir():
        raise HTTPException(404, "run workspace not found")
    atomic = _find_atomic_work_dir(run_dir)
    entries: list[dict[str, Any]] = []

    def add(path: Path, base: Path, category: str) -> None:
        if not path.is_file() or len(entries) >= limit:
            return
        stat = path.stat()
        entries.append(
            {
                "category": category,
                "path": str(path.relative_to(base)),
                "name": path.name,
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "type": _file_type(path),
            }
        )

    def add_glob(base_dir: Path, pattern: str, base: Path, category: str) -> None:
        if not base_dir.is_dir():
            return
        for path in sorted(base_dir.glob(pattern)):
            add(path, base, category)
            if len(entries) >= limit:
                return

    add(run_dir / "config.json", run_dir, "Run Root")
    add(run_dir / "run.log", run_dir, "Run Root")
    add(run_dir / "execution_meta.json", run_dir, "Run Root")
    add_glob(run_dir / "input", "**/*.md", run_dir, "Input")
    add_glob(run_dir / "trigger_inputs", "**/*.md", run_dir, "Input")
    if atomic:
        add(atomic / "summary.md", atomic, "Outputs")
        add(atomic / "final_output" / "summary.md", atomic, "Outputs")
        add_glob(atomic / "results", "*.md", atomic, "Outputs / Results")
        add_glob(atomic / "final_output" / "results", "*.md", atomic, "Outputs / Results")
        add_glob(atomic / "supporting_docs", "*.md", atomic, "Outputs / Supporting Docs")
        add(atomic / "_meta" / "state.json", atomic, "Meta")
        add(atomic / "_meta" / "workflow_result.json", atomic, "Meta")
        add(atomic / "_meta" / "abnormal_exit.json", atomic, "Meta")
        add(atomic / "_meta" / "result_relations_manifest.json", atomic, "Meta / Result Manifests")
        add(atomic / "_meta" / "results_manifest.json", atomic, "Meta / Result Manifests")
        add(atomic / "_meta" / "coverage_ledger.json", atomic, "Meta / Result Manifests")
        add_glob(atomic / "_meta" / "reflections", "*.json", atomic, "Meta / Reflections")
        add_glob(atomic / "_meta" / "review_summaries", "*.json", atomic, "Meta / Review Summaries")
        add_glob(atomic / "_meta" / "cycle_metrics", "*.json", atomic, "Meta / Cycle Metrics")
        add_glob(atomic / "_meta" / "review_feedback", "*.json", atomic, "Meta / Review Feedback")
        add_glob(atomic / "_meta" / "summary_snapshots", "*.md", atomic, "Meta / Summary Snapshots")
        add_glob(atomic / "reviews" / "global", "cycle_*/*.json", atomic, "Reviews / Global")
        add_glob(atomic / "reviews" / "results", "result_*/cycle_*/*.json", atomic, "Reviews / Results")
        add_glob(atomic / "sessions", "*/*.jsonl", atomic, "Sessions")
        add_glob(atomic / "sessions", "*/calls/*/*.json", atomic, "Sessions")
        add_glob(atomic / "sessions", "*/calls/*/*.md", atomic, "Sessions")
        add_glob(atomic / "sessions", "*/calls/*/*.txt", atomic, "Sessions")
    return entries


def inspect_file(workspace_root: str | Path, path: str) -> dict[str, Any]:
    run_dir = Path(workspace_root)
    if not run_dir.is_dir():
        raise HTTPException(404, "run workspace not found")
    atomic = _find_atomic_work_dir(run_dir)
    candidates = [run_dir / path]
    if atomic:
        candidates.append(atomic / path)
    target: Path | None = None
    root = run_dir.resolve()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved.is_file() and _is_within(resolved, root):
            target = resolved
            break
    if target is None:
        raise HTTPException(404, f"file not found: {path}")
    return {
        "path": str(target.relative_to(run_dir)),
        "type": _file_type(target),
        "content": _read_text(target, max_bytes=500_000),
    }


def inspect_session_file(workspace_root: str | Path, path: str) -> dict[str, Any]:
    file_payload = inspect_file(workspace_root, path)
    if file_payload["type"] != "jsonl":
        raise HTTPException(400, "not a .jsonl file")
    events: list[dict[str, Any]] = []
    session_meta: dict[str, Any] = {}
    for line_no, line in enumerate(str(file_payload["content"]).splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            events.append({"type": "raw", "line": line_no, "text": line[:200]})
            continue
        event_type = obj.get("type", "")
        if event_type == "session":
            session_meta = {
                "id": obj.get("id", ""),
                "version": obj.get("version", ""),
                "timestamp": obj.get("timestamp", ""),
                "cwd": obj.get("cwd", ""),
            }
            continue
        if event_type == "message":
            message = obj.get("message", {})
            content = message.get("content", [])
            parts: list[dict[str, Any]] = []
            if isinstance(content, str):
                parts.append({"type": "text", "text": content})
            elif isinstance(content, list):
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    part_type = part.get("type", "")
                    if part_type == "text":
                        parts.append({"type": "text", "text": part.get("text", "")})
                    elif part_type == "thinking":
                        parts.append({"type": "thinking", "text": part.get("thinking", "")})
                    elif part_type == "toolCall":
                        parts.append({"type": "toolCall", "name": part.get("name", ""), "id": part.get("id", ""), "arguments": part.get("arguments", {})})
                    elif part_type == "toolResult":
                        parts.append({"type": "toolResult", "text": part.get("text", "")})
                    else:
                        parts.append({"type": "unknown", "detail": str(part)[:200]})
            events.append(
                {
                    "type": "message",
                    "line": line_no,
                    "timestamp": obj.get("timestamp", ""),
                    "role": message.get("role", ""),
                    "parts": parts,
                }
            )
            continue
        events.append({"type": event_type or "unknown_event", "line": line_no, "summary": str(obj)[:200]})
    return {"path": file_payload["path"], "session_meta": session_meta, "events": events}


def inspect_log(workspace_root: str | Path, lines: int = 300) -> dict[str, str]:
    log_path = Path(workspace_root) / "run.log"
    if not log_path.is_file():
        return {"content": "(no log file)"}
    return {"content": _tail_lines(log_path, lines)}
