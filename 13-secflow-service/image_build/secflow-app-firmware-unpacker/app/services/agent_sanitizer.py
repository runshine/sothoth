"""Agent process cleanup utilities for firmware unpacker dispatchers."""

from __future__ import annotations

import json
import logging
import os
import signal
import time
from pathlib import Path
from typing import Any, Optional

from app.model import TaskCleanupScan, UnpackTask, WorkerInstance, generate_id, get_db_session
from app.time_utils import now_local


logger = logging.getLogger(__name__)

AGENT_MARKERS = ("pi", "codex", "claude", "opencode")


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _read_cmdline(path: Path) -> str:
    try:
        return path.read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _proc_matches(command: str, exe_name: str) -> bool:
    haystack = f"{command} {exe_name}".lower()
    return any(marker in haystack for marker in AGENT_MARKERS)


def _normalize_path(value: Optional[str]) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        return str(Path(raw).resolve())
    except Exception:
        return raw


def _path_matches(candidate: str, roots: list[str]) -> bool:
    normalized = _normalize_path(candidate)
    if not normalized:
        return False
    for root in roots:
        root_value = _normalize_path(root)
        if not root_value:
            continue
        if normalized == root_value or normalized.startswith(f"{root_value}/"):
            return True
    return False


def _collect_suspects(task: Optional[UnpackTask]) -> list[dict[str, Any]]:
    roots: list[str] = []
    if task is not None:
        for value in (
            getattr(task, "firmware_path", None),
            getattr(task, "output_path", None),
            getattr(task, "runtime_root", None),
        ):
            normalized = _normalize_path(value)
            if normalized:
                roots.append(normalized)
        output_path = str(getattr(task, "output_path", "") or "").strip()
        if output_path:
            roots.append(_normalize_path(str(Path(output_path).parent)))
            roots.append(_normalize_path(str(Path(output_path).parent / "run")))
            roots.append(_normalize_path(str(Path(output_path).parent / "run" / "sessions")))
    suspects: list[dict[str, Any]] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        proc_dir = entry
        try:
            comm = _read_text(proc_dir / "comm").strip()
            cmdline = _read_cmdline(proc_dir / "cmdline")
            exe_name = os.path.basename(os.readlink(proc_dir / "exe")) if (proc_dir / "exe").exists() else ""
            cwd = os.readlink(proc_dir / "cwd") if (proc_dir / "cwd").exists() else ""
            status_text = _read_text(proc_dir / "status")
        except Exception:
            continue
        if not _proc_matches(cmdline, exe_name or comm):
            continue
        ppid = None
        for line in status_text.splitlines():
            if line.startswith("PPid:"):
                try:
                    ppid = int(line.split(":", 1)[1].strip())
                except Exception:
                    ppid = None
                break
        if task is not None:
            bound = (
                _path_matches(cwd, roots)
                or any(root and root in cmdline for root in roots)
                or str(getattr(task, "id", "")) in cmdline
            )
            if not bound and ppid != 1:
                continue
        suspects.append(
            {
                "pid": pid,
                "ppid": ppid,
                "comm": comm,
                "exe_name": exe_name,
                "cmdline": cmdline,
                "cwd": cwd,
            }
        )
    return suspects


def _kill_process_tree(pid: int) -> tuple[bool, bool]:
    terminated = False
    killed = False
    try:
        pgid = os.getpgid(pid)
    except Exception:
        pgid = None
    try:
        if pgid:
            os.killpg(pgid, signal.SIGTERM)
        else:
            os.kill(pid, signal.SIGTERM)
        terminated = True
    except Exception:
        return False, False
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
            time.sleep(0.1)
        except ProcessLookupError:
            return terminated, killed
        except Exception:
            break
    try:
        if pgid:
            os.killpg(pgid, signal.SIGKILL)
        else:
            os.kill(pid, signal.SIGKILL)
        killed = True
    except Exception:
        pass
    return terminated, killed


def run_agent_cleanup(*, worker_id: str, phase: str, task_id: Optional[str] = None) -> dict[str, Any]:
    db = get_db_session()
    task: UnpackTask | None = None
    try:
        if task_id:
            task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
    finally:
        db.close()

    started_at = now_local()
    suspects = _collect_suspects(task)
    terminated_count = 0
    killed_count = 0
    errors: list[str] = []
    remaining: list[dict[str, Any]] = []
    for item in suspects:
        pid = int(item.get("pid") or 0)
        try:
            terminated, killed = _kill_process_tree(pid)
            terminated_count += 1 if terminated else 0
            killed_count += 1 if killed else 0
        except Exception as exc:
            errors.append(f"pid={pid}:{exc}")
    time.sleep(0.2)
    for item in _collect_suspects(task):
        remaining.append(item)

    payload = {
        "id": generate_id(),
        "task_id": task_id,
        "worker_id": worker_id,
        "phase": phase,
        "started_at": started_at,
        "completed_at": now_local(),
        "suspected_process_count": len(suspects),
        "terminated_count": terminated_count,
        "killed_count": killed_count,
        "remaining_count": len(remaining),
        "processes_json": json.dumps({"suspects": suspects, "remaining": remaining}, ensure_ascii=False),
        "errors_json": json.dumps(errors, ensure_ascii=False),
    }

    db = get_db_session()
    try:
        scan = TaskCleanupScan(**payload)
        db.add(scan)
        worker = db.query(WorkerInstance).filter(WorkerInstance.worker_id == worker_id).first()
        if worker is not None:
            worker.last_cleanup_scan_at = payload["completed_at"]
            worker.last_cleanup_summary_json = json.dumps(
                {
                    "phase": phase,
                    "remaining_count": len(remaining),
                    "terminated_count": terminated_count,
                    "killed_count": killed_count,
                },
                ensure_ascii=False,
            )
        if task_id:
            current_task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
            if current_task is not None:
                if phase == "pre-run":
                    current_task.pre_cleanup_scan_id = scan.id
                elif phase == "post-run":
                    current_task.post_cleanup_scan_id = scan.id
                current_task.last_cleanup_residual_count = len(remaining)
        db.commit()
    finally:
        db.close()
    logger.info(
        "agent cleanup finished worker_id=%s phase=%s task_id=%s suspected=%s remaining=%s",
        worker_id,
        phase,
        task_id,
        len(suspects),
        len(remaining),
    )
    return {
        "scan_id": payload["id"],
        "phase": phase,
        "suspected_process_count": len(suspects),
        "terminated_count": terminated_count,
        "killed_count": killed_count,
        "remaining_count": len(remaining),
        "errors": errors,
    }
