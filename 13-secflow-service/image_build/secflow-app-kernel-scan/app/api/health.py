from __future__ import annotations

import shutil
from pathlib import Path

from fastapi import APIRouter

from app.build_info import build_service_meta
from app.core.config import get_config
from app.db.database import get_database
from app.workers.scheduler import get_scheduler_service

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok", "service": "secflow-app-kernel-scan", **build_service_meta()}


@router.get("/ready")
def ready():
    cfg = get_config()
    checks = {
        "database": False,
        "state_root": False,
        "kernel_dir": Path(cfg.kernel_dir).is_dir(),
        "scheduler": get_scheduler_service().is_running,
        "claude_binary": shutil.which(cfg.execution.claude_bin) is not None,
    }
    try:
        with get_database().connect() as conn:
            conn.execute("SELECT 1")
        checks["database"] = True
    except Exception:
        pass
    try:
        state_root = Path(cfg.state_root)
        state_root.mkdir(parents=True, exist_ok=True)
        probe = state_root / ".ready-check"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        checks["state_root"] = True
    except Exception:
        pass

    return {
        "status": "ok" if all(checks.values()) else "degraded",
        "service": "secflow-app-kernel-scan",
        "ready": all(checks.values()),
        "checks": checks,
        **build_service_meta(),
    }
