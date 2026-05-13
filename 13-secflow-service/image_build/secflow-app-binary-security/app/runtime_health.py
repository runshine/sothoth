"""Runtime health and readiness checks."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from app.config import get_config
from app.model import get_engine
from app.service.http_client import get_shared_async_client
from app.service.task_manager import get_task_manager


def _data_mount_path() -> Path:
    return Path(get_config().services.fileserver.data_mount_path).resolve()


def _check_database() -> tuple[bool, str]:
    try:
        with get_engine().connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        return True, "ok"
    except Exception as exc:
        return False, str(exc)


def _check_data_mount() -> tuple[bool, str]:
    root = _data_mount_path()
    try:
        if not root.exists():
            return False, f"data mount missing: {root}"
        if not root.is_dir():
            return False, f"data mount is not a directory: {root}"
        if not os.access(root, os.R_OK | os.W_OK | os.X_OK):
            return False, f"data mount not accessible: {root}"
        usage = shutil.disk_usage(root)
        required = max(0, int(get_config().storage.min_free_disk_bytes or 0))
        if usage.free < required:
            return False, f"free disk {usage.free} below required {required}"
        probe_dir = root / ".binary-security-health"
        probe_dir.mkdir(parents=True, exist_ok=True)
        probe_file = probe_dir / "ready.tmp"
        probe_file.write_text("ok", encoding="utf-8")
        probe_file.unlink(missing_ok=True)
        return True, "ok"
    except Exception as exc:
        return False, str(exc)


async def _check_auth_service() -> tuple[bool, str]:
    cfg = get_config().auth_service
    url = f"http://{cfg.host}:{cfg.port}/api/auth/health"
    try:
        client = await get_shared_async_client("auth-health", timeout=cfg.timeout)
        resp = await client.get(url)
        if resp.status_code != 200:
            return False, f"status={resp.status_code}"
        return True, "ok"
    except Exception as exc:
        return False, str(exc)


async def collect_readiness() -> dict[str, object]:
    db_ok, db_detail = _check_database()
    data_ok, data_detail = _check_data_mount()
    auth_ok, auth_detail = await _check_auth_service()
    scheduler_cfg = get_task_manager().runtime_status()
    scheduler_checks = scheduler_cfg["loops"] if isinstance(scheduler_cfg.get("loops"), dict) else {}
    scheduler_required = any(bool(value) for value in scheduler_checks.values())
    scheduler_ok = (not get_config().scheduler.enabled) or (not scheduler_required) or all(
        bool(value) for value in scheduler_checks.values()
    )
    checks = {
        "database": {"ok": db_ok, "detail": db_detail},
        "data_mount": {"ok": data_ok, "detail": data_detail},
        "auth_service": {"ok": auth_ok, "detail": auth_detail},
        "scheduler": {"ok": scheduler_ok, "detail": scheduler_cfg},
    }
    return {
        "status": "ready" if all(item["ok"] for item in checks.values()) else "not_ready",
        "checks": checks,
    }
