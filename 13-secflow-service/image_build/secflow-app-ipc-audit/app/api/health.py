from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from fastapi import APIRouter

from app.core.config import get_config
from app.db.database import get_database
from app.schemas import HealthResponse, ReadyResponse
from app.workers.scheduler import get_scheduler_service

router = APIRouter()


def _parse_ready_check_paths() -> list[str]:
    raw = os.environ.get("IPC_AUDIT_READY_CHECK_FILE_PATHS", "")
    if not raw.strip():
        return []
    normalized: list[str] = []
    seen: set[str] = set()
    for item in raw.replace("\n", ",").split(","):
        candidate = str(item or "").strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)
    return normalized


def _validate_opencode_config(opencode_bin: str) -> bool:
    if shutil.which(opencode_bin) is None:
        return False
    try:
        with tempfile.TemporaryDirectory(prefix="ipc-audit-opencode-ready-") as temp_dir:
            root = Path(temp_dir)
            env = os.environ.copy()
            for key, dirname in (
                ("XDG_DATA_HOME", "data"),
                ("XDG_CACHE_HOME", "cache"),
                ("XDG_STATE_HOME", "state"),
            ):
                value = root / dirname
                value.mkdir(parents=True, exist_ok=True)
                env[key] = str(value)
            result = subprocess.run(
                [opencode_bin, "debug", "config"],
                cwd="/tmp",
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
                timeout=15,
                check=False,
            )
            return result.returncode == 0
    except Exception:
        return False


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", service="secflow-app-ipc-audit")


@router.get("/ready", response_model=ReadyResponse)
def ready() -> ReadyResponse:
    cfg = get_config()
    workspace_ready = False
    for workspace in cfg.workspaces:
        try:
            if Path(workspace.repo_root).resolve().exists():
                workspace_ready = True
                break
        except Exception:
            continue
    checks = {
        "database": False,
        "state_root": False,
        "workspace": workspace_ready,
        "scheduler": get_scheduler_service().is_running,
        "executor_binary": True,
        "executor_binary:codex_cli": shutil.which(cfg.execution.codex_bin) is not None,
        "executor_binary:opencode_cli": shutil.which(cfg.execution.opencode_bin) is not None,
        "executor_config:opencode_cli": True,
    }
    try:
        with get_database().connect() as conn:
            conn.execute("SELECT 1")
        checks["database"] = True
    except Exception:
        checks["database"] = False
    try:
        state_root = Path(cfg.state_root)
        state_root.mkdir(parents=True, exist_ok=True)
        probe = state_root / ".ready-check"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        checks["state_root"] = True
    except Exception:
        checks["state_root"] = False
    if cfg.execution.mode == "codex_cli":
        checks["executor_binary"] = checks["executor_binary:codex_cli"]
    elif cfg.execution.mode == "opencode_cli":
        checks["executor_binary"] = checks["executor_binary:opencode_cli"]
        checks["executor_config:opencode_cli"] = _validate_opencode_config(cfg.execution.opencode_bin)
    for ready_path in _parse_ready_check_paths():
        checks[f"bound_file:{ready_path}"] = Path(ready_path).exists()
    return ReadyResponse(
        status="ok" if all(checks.values()) else "degraded",
        service="secflow-app-ipc-audit",
        ready=all(checks.values()),
        checks=checks,
    )
