"""Role + lease/heartbeat config for secflow-app-poc-gen-verify (env-driven).

Mirrors dataflow-vuln-scan's runtime_context, trimmed: poc-gen-verify has only an
API role (the worker pod runs `celery -A app.celery_app worker` as a separate CLI
process, the scheduler pod runs `python -m app.dispatcher`; neither goes through
runtime_bootstrap). DVS_* env names are mirrored as POC_*.
"""
from __future__ import annotations

import os
import uuid


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


POD_NAME = str(os.environ.get("POC_POD_NAME") or os.environ.get("HOSTNAME") or "local")
POD_IP = str(os.environ.get("POC_POD_IP") or "")
WORKER_ID = POD_NAME
INSTANCE_ID = f"{POD_NAME}:{uuid.uuid4().hex[:8]}"

# Dispatcher (scheduler pod) tuning.
DISPATCH_POLL_INTERVAL_SECONDS = float(os.environ.get("POC_DISPATCHER_PUMP_INTERVAL", "3"))
PUMP_BATCH = int(os.environ.get("POC_DISPATCHER_PUMP_BATCH", "20"))
INSPECT_TIMEOUT = float(os.environ.get("POC_DISPATCHER_INSPECT_TIMEOUT", "3"))

# Role gating for the FastAPI/uvicorn process (API pod only).
ROLE = str(os.environ.get("POC_ROLE", "all")).strip().lower() or "all"
PUBLIC_API_ENABLED = _env_bool("POC_ENABLE_PUBLIC_API", ROLE in {"all", "api"})
REGISTRY_ENABLED = _env_bool("POC_ENABLE_REGISTRY", ROLE in {"all", "api"})
DEBUGGER_ENABLED = _env_bool("POC_ENABLE_DEBUGGER", ROLE in {"all", "debugger"})


def is_api_role() -> bool:
    return PUBLIC_API_ENABLED
