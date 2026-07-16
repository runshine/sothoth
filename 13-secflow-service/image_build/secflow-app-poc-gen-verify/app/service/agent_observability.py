"""Agent observability: live process snapshots on worker pods + orphan cleanup.

Provides:
- get_agent_process_snapshot(): list poc/claude/gdb/node processes on this pod
- kill_orphan_processes(): SIGKILL residual poc/claude/gdb processes

Runs on the API pod — calls are proxied to individual worker pods via Celery
broadcast (or direct HTTP to worker pod IP). For simplicity, the API endpoint
queries the local pod only (which is the API pod, not a worker) and returns
aggregate info from Celery inspect + DB.

The kill operations use Celery control broadcast to reach all workers.
"""
from __future__ import annotations

import logging
import os
import signal
import time
from dataclasses import dataclass, field
from typing import Any, List

logger = logging.getLogger("poc.agent_observability")


@dataclass
class AgentProcess:
    pid: int
    name: str = ""
    cmd: str = ""
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    status: str = ""
    create_time: float = 0.0


def get_local_process_snapshot() -> List[dict]:
    """Get processes on this pod matching poc/claude/gdb/node patterns.

    Uses psutil if available, falls back to /proc scanning.
    """
    try:
        import psutil
    except ImportError:
        return _get_procs_from_procfs()

    results: List[dict] = []
    my_pid = os.getpid()
    patterns = ("poc", "claude", "gdb", "tmux", "node")
    for proc in psutil.process_iter(["pid", "name", "cmdline", "cpu_percent", "memory_info", "status", "create_time"]):
        try:
            info = proc.info
            if info["pid"] == my_pid:
                continue
            cmdline = " ".join(info.get("cmdline") or [])
            name = info.get("name", "")
            if not any(p in name.lower() or p in cmdline.lower() for p in patterns):
                continue
            mem = info.get("memory_info")
            mem_mb = (mem.rss / (1024 * 1024)) if mem else 0.0
            results.append({
                "pid": info["pid"],
                "name": name,
                "cmd": cmdline[:500],
                "cpu_percent": info.get("cpu_percent", 0.0) or 0.0,
                "memory_mb": round(mem_mb, 1),
                "status": info.get("status", ""),
                "create_time": info.get("create_time", 0),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return results


def _get_procs_from_procfs() -> List[dict]:
    """Fallback: scan /proc for matching processes."""
    results: List[dict] = []
    my_pid = os.getpid()
    patterns = ("poc", "claude", "gdb", "tmux", "node")
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid == my_pid:
                continue
            try:
                with open(f"/proc/{pid}/cmdline", "r") as f:
                    cmdline = f.read().replace("\x00", " ").strip()[:500]
                if not cmdline:
                    continue
                if not any(p in cmdline.lower() for p in patterns):
                    continue
                with open(f"/proc/{pid}/stat", "r") as f:
                    stat = f.read().split()
                name = stat[1].strip("()")
                results.append({
                    "pid": pid, "name": name, "cmd": cmdline,
                    "cpu_percent": 0.0, "memory_mb": 0.0,
                    "status": stat[2] if len(stat) > 2 else "",
                    "create_time": 0,
                })
            except (OSError, IndexError):
                continue
    except Exception:
        pass
    return results


def kill_local_orphan_processes() -> dict:
    """Kill residual poc/claude/gdb processes on this pod.

    Returns {"killed": count, "pids": [list of killed PIDs]}.
    """
    procs = get_local_process_snapshot()
    killed: list[int] = []
    for proc in procs:
        pid = proc["pid"]
        # Don't kill our own celery worker process (it matches "celery")
        cmd = proc.get("cmd", "").lower()
        if "celery" in cmd and "poc" not in cmd:
            continue
        try:
            os.kill(pid, signal.SIGKILL)
            killed.append(pid)
            logger.info("killed orphan process pid=%s name=%s", pid, proc.get("name"))
        except ProcessLookupError:
            pass
        except PermissionError:
            pass
    return {"killed": len(killed), "pids": killed, "message": f"Killed {len(killed)} orphan processes"}
