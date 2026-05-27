from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from fastapi import APIRouter

from app.build_info import build_service_meta
from app.core.config import get_config, resolve_agentflow_root
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
    if any(
        str(os.environ.get(key) or "").strip()
        for key in ("OPENAI_API_KEY", "OPENCODE_API_KEY", "AZURE_OPENAI_API_KEY", "ANTHROPIC_API_KEY")
    ):
        return True
    config_path = Path(
        str(
            os.environ.get("IPC_AUDIT_OPENCODE_CONFIG_PATH")
            or os.environ.get("OPENCODE_CONFIG_PATH")
            or "/root/.config/opencode/opencode.json"
        )
    )
    if not config_path.exists() or not config_path.is_file():
        return False
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        return False
    return isinstance(payload, dict) and bool(payload)


def _validate_agentflow_root(agentflow_python_bin: str) -> bool:
    return resolve_agentflow_root() is not None and shutil.which(agentflow_python_bin) is not None


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", service="secflow-app-ipc-audit", **build_service_meta())


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
        "executor_binary:agentflow_cli": shutil.which(cfg.execution.agentflow_python_bin) is not None,
        "executor_config:agentflow_cli": _validate_agentflow_root(cfg.execution.agentflow_python_bin),
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
    if cfg.execution.mode == "agentflow_cli":
        checks["executor_binary"] = (
            checks["executor_binary:agentflow_cli"] and checks["executor_config:agentflow_cli"]
        )
    elif cfg.execution.mode == "codex_cli":
        checks["executor_binary"] = checks["executor_binary:codex_cli"]
    elif cfg.execution.mode == "opencode_cli":
        checks["executor_binary"] = checks["executor_binary:opencode_cli"]
        checks["executor_config:opencode_cli"] = _validate_opencode_config(cfg.execution.opencode_bin)
    for ready_path in _parse_ready_check_paths():
        checks[f"bound_file:{ready_path}"] = Path(ready_path).exists()
    critical_checks = (
        checks["database"],
        checks["state_root"],
        checks["workspace"],
        checks["scheduler"],
        checks["executor_binary"],
    )
    return ReadyResponse(
        status="ok" if all(critical_checks) else "degraded",
        service="secflow-app-ipc-audit",
        ready=all(critical_checks),
        checks=checks,
        **build_service_meta(),
    )
