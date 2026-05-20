from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field


class AppConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False


class ExecutionConfig(BaseModel):
    mode: Literal["claude_cli", "mock"] = "claude_cli"
    claude_bin: str = "claude"
    claude_model: str = "zai-org/GLM-5"
    entry_model: str = ""
    audit_model: str = ""
    poc_model: str = ""
    max_parallel_tasks: int = 10
    entry_threads: int = 4
    audit_threads: int = 4
    poc_threads: int = 2
    scheduler_tick_interval_seconds: float = 1.0
    heartbeat_interval_seconds: int = 5
    lease_duration_seconds: int = 30
    task_timeout_seconds: int = 14400
    cancel_check_interval_seconds: float = 1.0
    process_terminate_grace_seconds: float = 5.0
    mock_stage_delay_seconds: float = 0.0


class ServiceConfig(BaseModel):
    title: str = "SecFlow Kernel Scan Service"
    api_prefix: str = "/api/app/kernel-scan"
    database_url: str = "sqlite:////var/lib/secflow-kernel-scan/kernel-scan.db"
    state_root: str = "/var/lib/secflow-kernel-scan"
    kernel_dir: str = "/workspace/kernel"
    workspace_root: str = "/workspace"
    app: AppConfig = Field(default_factory=AppConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)


_config: ServiceConfig | None = None


def _as_bool(value: object) -> bool:
    return str(value).lower() in {"1", "true", "yes", "on"}


def _load_yaml_payload(config_path: str | None) -> dict[str, object]:
    if not config_path:
        return {}
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"config file not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _resolve_candidates(config_path: str | None) -> str | None:
    if config_path:
        return config_path
    candidates = [
        os.environ.get("KERNEL_SCAN_CONFIG"),
        "config.yaml",
        os.path.join(os.path.dirname(__file__), "..", "..", "config.yaml"),
    ]
    return next((v for v in candidates if v and os.path.exists(v)), None)


def _merge_env_overrides(payload: dict[str, object]) -> dict[str, object]:
    app_payload = dict(payload.get("app") or {})
    exec_payload = dict(payload.get("execution") or {})

    payload["database_url"] = os.environ.get("KERNEL_SCAN_DATABASE_URL", payload.get("database_url"))
    payload["state_root"] = os.environ.get("KERNEL_SCAN_STATE_ROOT", payload.get("state_root"))
    payload["kernel_dir"] = os.environ.get("KERNEL_SCAN_KERNEL_DIR", payload.get("kernel_dir"))
    payload["workspace_root"] = os.environ.get("KERNEL_SCAN_WORKSPACE_ROOT", payload.get("workspace_root", "/workspace"))

    app_payload["host"] = os.environ.get("KERNEL_SCAN_HOST", app_payload.get("host", "0.0.0.0"))
    app_payload["port"] = int(os.environ.get("KERNEL_SCAN_PORT", app_payload.get("port", 8080)))
    app_payload["debug"] = _as_bool(os.environ.get("KERNEL_SCAN_DEBUG", app_payload.get("debug", False)))

    exec_payload["mode"] = os.environ.get("KERNEL_SCAN_EXECUTION_MODE", exec_payload.get("mode", "claude_cli"))
    exec_payload["claude_bin"] = os.environ.get("KERNEL_SCAN_CLAUDE_BIN", exec_payload.get("claude_bin", "claude"))
    exec_payload["claude_model"] = os.environ.get("KERNEL_SCAN_CLAUDE_MODEL", exec_payload.get("claude_model", "zai-org/GLM-5"))
    exec_payload["entry_model"] = os.environ.get("KERNEL_SCAN_ENTRY_MODEL", exec_payload.get("entry_model", ""))
    exec_payload["audit_model"] = os.environ.get("KERNEL_SCAN_AUDIT_MODEL", exec_payload.get("audit_model", ""))
    exec_payload["poc_model"] = os.environ.get("KERNEL_SCAN_POC_MODEL", exec_payload.get("poc_model", ""))
    exec_payload["max_parallel_tasks"] = int(os.environ.get("KERNEL_SCAN_MAX_PARALLEL_TASKS", exec_payload.get("max_parallel_tasks", 1)))
    exec_payload["entry_threads"] = int(os.environ.get("KERNEL_SCAN_ENTRY_THREADS", exec_payload.get("entry_threads", 4)))
    exec_payload["audit_threads"] = int(os.environ.get("KERNEL_SCAN_AUDIT_THREADS", exec_payload.get("audit_threads", 4)))
    exec_payload["poc_threads"] = int(os.environ.get("KERNEL_SCAN_POC_THREADS", exec_payload.get("poc_threads", 2)))
    exec_payload["task_timeout_seconds"] = int(os.environ.get("KERNEL_SCAN_TASK_TIMEOUT_SECONDS", exec_payload.get("task_timeout_seconds", 14400)))
    exec_payload["mock_stage_delay_seconds"] = float(os.environ.get("KERNEL_SCAN_MOCK_STAGE_DELAY_SECONDS", exec_payload.get("mock_stage_delay_seconds", 0.0)))

    payload["app"] = app_payload
    payload["execution"] = exec_payload
    return payload


def load_config(config_path: str | None = None) -> ServiceConfig:
    global _config
    if _config is not None:
        return _config
    resolved = _resolve_candidates(config_path)
    payload = _load_yaml_payload(resolved)
    payload = _merge_env_overrides(payload)
    _config = ServiceConfig(**payload)
    return _config


def get_config() -> ServiceConfig:
    return _config or load_config()


def get_sqlite_db_path() -> Path:
    url = get_config().database_url
    if not url.startswith("sqlite:///"):
        raise ValueError(f"only sqlite URLs are supported: {url}")
    raw_path = url[len("sqlite:///"):]
    path = Path(raw_path)
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.resolve()
