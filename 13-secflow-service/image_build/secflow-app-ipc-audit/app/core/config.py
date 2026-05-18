from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal
from urllib.parse import quote, unquote, urlparse

import yaml
from pydantic import BaseModel, Field


class WorkspaceConfig(BaseModel):
    workspace_id: str
    display_name: str
    repo_root: str
    entries_file: str = ".audit/ipc_entries.txt"
    bundle_scan_roots: list[str] = Field(default_factory=lambda: ["base", "foundation"])
    allow_custom_project_path: bool = True
    supports_poc: bool = True
    default_pipeline_mode: Literal["audit_then_poc", "audit_only", "poc_only", "custom_graph"] = "custom_graph"
    is_default: bool = False


class AppConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False


class ExecutionConfig(BaseModel):
    mode: Literal["mock", "codex_cli", "opencode_cli", "agentflow_cli"] = "mock"
    max_parallel_tasks: int = 1
    scheduler_tick_interval_seconds: float = 1.0
    heartbeat_interval_seconds: int = 5
    lease_duration_seconds: int = 30
    task_timeout_seconds: int = 7200
    cancel_check_interval_seconds: float = 1.0
    process_terminate_grace_seconds: float = 5.0
    poc_enabled: bool = True
    poc_runtime_available: bool = True
    codex_bin: str = "codex"
    opencode_bin: str = "opencode"
    agentflow_root: str = "/home/icsl/agentflow-alpha"
    agentflow_python_bin: str = "python3"
    agentflow_agent: Literal["codex", "opencode"] = "opencode"
    codex_skip_git_repo_check: bool = True
    codex_json_output: bool = True
    codex_capture_last_message: bool = True
    opencode_missing_output_max_retries: int = 3
    poc_network_access: bool = True
    default_audit_skill: str = "openharmony-project-deep-oob-audit"
    default_poc_skill: str = "openharmony-ipc-project-report-poc"
    audit_sandbox_mode: Literal["read-only", "workspace-write", "danger-full-access"] = "workspace-write"
    audit_approval_policy: str = "never"
    audit_network_access: bool = False
    poc_sandbox_mode: Literal["read-only", "workspace-write", "danger-full-access"] = "workspace-write"
    poc_approval_policy: str = "never"
    mock_stage_delay_seconds: float = 0.0


class ProviderSourceConfig(BaseModel):
    enabled: bool = True
    backend: Literal["configcenter", "platform_agent"] = "configcenter"
    base_url: str = "http://secflow-platform-configcenter"
    api_prefix: str = "/api/configcenter/service/llm"
    timeout_seconds: int = 15
    machine_token: str | None = None
    fallback_file_path: str | None = None


class DatabaseConfig(BaseModel):
    type: Literal["sqlite", "mysql"] = "sqlite"
    path: str = "/var/lib/secflow-ipc-audit/ipc-audit.db"
    host: str = "localhost"
    port: int = 3306
    username: str = "root"
    password: str = ""
    name: str = "secflow"

    @property
    def url(self) -> str:
        if self.type == "sqlite":
            return f"sqlite:///{self.path}"
        username = quote(self.username, safe="")
        password = quote(self.password, safe="")
        name = quote(self.name, safe="")
        return f"mysql+pymysql://{username}:{password}@{self.host}:{self.port}/{name}"


class ServiceConfig(BaseModel):
    title: str = "SecFlow IPC Audit Service"
    api_prefix: str = "/api/app/ipc-audit"
    database_url: str = "sqlite:////var/lib/secflow-ipc-audit/ipc-audit.db"
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    state_root: str = "/var/lib/secflow-ipc-audit"
    default_workspace_id: str | None = None
    app: AppConfig = Field(default_factory=AppConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    provider_source: ProviderSourceConfig = Field(default_factory=ProviderSourceConfig)
    workspaces: list[WorkspaceConfig] = Field(default_factory=list)


_config: ServiceConfig | None = None


def _default_workspace_payload() -> list[dict[str, object]]:
    return [
        {
            "workspace_id": "oh61-main",
            "display_name": "OpenHarmony 6.1 Main Tree",
            "repo_root": "/workspace/openharmony_6_1",
            "entries_file": ".audit/ipc_entries.txt",
            "bundle_scan_roots": ["base", "foundation"],
            "allow_custom_project_path": True,
            "supports_poc": True,
            "default_pipeline_mode": "custom_graph",
            "is_default": True,
        }
    ]


def _load_yaml_payload(config_path: str | None) -> dict[str, object]:
    if not config_path:
        return {}
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"config file not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _parse_workspaces(raw: str | None) -> list[dict[str, object]]:
    if raw:
        return json.loads(raw)
    return _default_workspace_payload()


def _resolve_candidates(config_path: str | None) -> str | None:
    if config_path:
        return config_path
    candidates = [
        os.environ.get("SECFLOW_IPC_AUDIT_CONFIG"),
        "config.yaml",
        os.path.join(os.path.dirname(__file__), "..", "..", "config.yaml"),
    ]
    return next((value for value in candidates if value and os.path.exists(value)), None)


def _as_bool(value: object) -> bool:
    return str(value).lower() in {"1", "true", "yes", "on"}


def _database_payload_from_url(url: str | None) -> dict[str, object]:
    value = str(url or "").strip()
    if not value:
        return {}
    if value.startswith("sqlite:///"):
        return {"type": "sqlite", "path": value[len("sqlite:///") :]}
    parsed = urlparse(value)
    if parsed.scheme not in {"mysql", "mysql+pymysql"}:
        raise ValueError(f"unsupported database url: {value}")
    return {
        "type": "mysql",
        "host": parsed.hostname or "localhost",
        "port": int(parsed.port or 3306),
        "username": unquote(parsed.username or "root"),
        "password": unquote(parsed.password or ""),
        "name": unquote(parsed.path.lstrip("/") or "secflow"),
    }


def _normalize_database_payload(payload: dict[str, object]) -> None:
    raw_url = str(payload.get("database_url") or "").strip()
    raw_db = dict(payload.get("database") or {})
    env_url = str(os.environ.get("IPC_AUDIT_DATABASE_URL") or "").strip()
    if env_url:
        normalized = _database_payload_from_url(env_url)
    elif raw_url:
        normalized = _database_payload_from_url(raw_url)
    else:
        normalized = raw_db
    if not env_url:
        normalized["type"] = os.environ.get("IPC_AUDIT_DB_TYPE", normalized.get("type", "sqlite"))
        normalized["path"] = os.environ.get(
            "IPC_AUDIT_DB_PATH",
            normalized.get("path", "/var/lib/secflow-ipc-audit/ipc-audit.db"),
        )
        normalized["host"] = os.environ.get("IPC_AUDIT_DB_HOST", normalized.get("host", "localhost"))
        normalized["port"] = int(os.environ.get("IPC_AUDIT_DB_PORT", normalized.get("port", 3306)))
        normalized["username"] = os.environ.get("IPC_AUDIT_DB_USERNAME", normalized.get("username", "root"))
        normalized["password"] = os.environ.get("IPC_AUDIT_DB_PASSWORD", normalized.get("password", ""))
        normalized["name"] = os.environ.get("IPC_AUDIT_DB_NAME", normalized.get("name", "secflow"))
    database = DatabaseConfig(**normalized)
    payload["database"] = database.model_dump()
    payload["database_url"] = env_url or database.url


def _merge_env_overrides(payload: dict[str, object]) -> dict[str, object]:
    app_payload = dict(payload.get("app") or {})
    execution_payload = dict(payload.get("execution") or {})
    provider_source_payload = dict(payload.get("provider_source") or {})
    payload["state_root"] = os.environ.get(
        "IPC_AUDIT_STATE_ROOT",
        payload.get("state_root", "/var/lib/secflow-ipc-audit"),
    )
    payload["default_workspace_id"] = os.environ.get(
        "IPC_AUDIT_DEFAULT_WORKSPACE_ID",
        payload.get("default_workspace_id"),
    )
    if "IPC_AUDIT_WORKSPACES_JSON" in os.environ or "workspaces" not in payload:
        payload["workspaces"] = _parse_workspaces(os.environ.get("IPC_AUDIT_WORKSPACES_JSON"))
    app_payload["host"] = os.environ.get("IPC_AUDIT_HOST", app_payload.get("host", "0.0.0.0"))
    app_payload["port"] = int(os.environ.get("IPC_AUDIT_PORT", app_payload.get("port", 8080)))
    app_payload["debug"] = _as_bool(os.environ.get("IPC_AUDIT_DEBUG", app_payload.get("debug", False)))
    execution_payload["mode"] = os.environ.get("IPC_AUDIT_EXECUTION_MODE", execution_payload.get("mode", "mock"))
    execution_payload["max_parallel_tasks"] = int(
        os.environ.get("IPC_AUDIT_MAX_PARALLEL_TASKS", execution_payload.get("max_parallel_tasks", 1))
    )
    execution_payload["scheduler_tick_interval_seconds"] = float(
        os.environ.get(
            "IPC_AUDIT_SCHEDULER_TICK_INTERVAL_SECONDS",
            execution_payload.get("scheduler_tick_interval_seconds", 1),
        )
    )
    execution_payload["heartbeat_interval_seconds"] = int(
        os.environ.get(
            "IPC_AUDIT_HEARTBEAT_INTERVAL_SECONDS",
            execution_payload.get("heartbeat_interval_seconds", 5),
        )
    )
    execution_payload["lease_duration_seconds"] = int(
        os.environ.get(
            "IPC_AUDIT_LEASE_DURATION_SECONDS",
            execution_payload.get("lease_duration_seconds", 30),
        )
    )
    execution_payload["task_timeout_seconds"] = int(
        os.environ.get("IPC_AUDIT_TASK_TIMEOUT_SECONDS", execution_payload.get("task_timeout_seconds", 7200))
    )
    execution_payload["cancel_check_interval_seconds"] = float(
        os.environ.get(
            "IPC_AUDIT_CANCEL_CHECK_INTERVAL_SECONDS",
            execution_payload.get("cancel_check_interval_seconds", 1.0),
        )
    )
    execution_payload["process_terminate_grace_seconds"] = float(
        os.environ.get(
            "IPC_AUDIT_PROCESS_TERMINATE_GRACE_SECONDS",
            execution_payload.get("process_terminate_grace_seconds", 5.0),
        )
    )
    execution_payload["poc_enabled"] = _as_bool(
        os.environ.get("IPC_AUDIT_POC_ENABLED", execution_payload.get("poc_enabled", True))
    )
    execution_payload["poc_runtime_available"] = _as_bool(
        os.environ.get(
            "IPC_AUDIT_POC_RUNTIME_AVAILABLE",
            execution_payload.get("poc_runtime_available", True),
        )
    )
    execution_payload["codex_bin"] = os.environ.get(
        "IPC_AUDIT_CODEX_BIN",
        execution_payload.get("codex_bin", "codex"),
    )
    execution_payload["opencode_bin"] = os.environ.get(
        "IPC_AUDIT_OPENCODE_BIN",
        execution_payload.get("opencode_bin", "opencode"),
    )
    execution_payload["agentflow_root"] = os.environ.get(
        "IPC_AUDIT_AGENTFLOW_ROOT",
        execution_payload.get("agentflow_root", "/home/icsl/agentflow-alpha"),
    )
    execution_payload["agentflow_python_bin"] = os.environ.get(
        "IPC_AUDIT_AGENTFLOW_PYTHON_BIN",
        execution_payload.get("agentflow_python_bin", "python3"),
    )
    execution_payload["agentflow_agent"] = os.environ.get(
        "IPC_AUDIT_AGENTFLOW_AGENT",
        execution_payload.get("agentflow_agent", "opencode"),
    )
    execution_payload["codex_skip_git_repo_check"] = _as_bool(
        os.environ.get(
            "IPC_AUDIT_CODEX_SKIP_GIT_REPO_CHECK",
            execution_payload.get("codex_skip_git_repo_check", True),
        )
    )
    execution_payload["codex_json_output"] = _as_bool(
        os.environ.get(
            "IPC_AUDIT_CODEX_JSON_OUTPUT",
            execution_payload.get("codex_json_output", True),
        )
    )
    execution_payload["codex_capture_last_message"] = _as_bool(
        os.environ.get(
            "IPC_AUDIT_CODEX_CAPTURE_LAST_MESSAGE",
            execution_payload.get("codex_capture_last_message", True),
        )
    )
    execution_payload["opencode_missing_output_max_retries"] = int(
        os.environ.get(
            "IPC_AUDIT_OPENCODE_MISSING_OUTPUT_MAX_RETRIES",
            execution_payload.get("opencode_missing_output_max_retries", 3),
        )
    )
    execution_payload["audit_sandbox_mode"] = os.environ.get(
        "IPC_AUDIT_AUDIT_SANDBOX_MODE",
        execution_payload.get("audit_sandbox_mode", "workspace-write"),
    )
    execution_payload["audit_approval_policy"] = os.environ.get(
        "IPC_AUDIT_AUDIT_APPROVAL_POLICY",
        execution_payload.get("audit_approval_policy", "never"),
    )
    execution_payload["audit_network_access"] = _as_bool(
        os.environ.get(
            "IPC_AUDIT_AUDIT_NETWORK_ACCESS",
            execution_payload.get("audit_network_access", False),
        )
    )
    execution_payload["poc_sandbox_mode"] = os.environ.get(
        "IPC_AUDIT_POC_SANDBOX_MODE",
        execution_payload.get("poc_sandbox_mode", "workspace-write"),
    )
    execution_payload["poc_approval_policy"] = os.environ.get(
        "IPC_AUDIT_POC_APPROVAL_POLICY",
        execution_payload.get("poc_approval_policy", "never"),
    )
    execution_payload["poc_network_access"] = _as_bool(
        os.environ.get(
            "IPC_AUDIT_POC_NETWORK_ACCESS",
            execution_payload.get("poc_network_access", True),
        )
    )
    execution_payload["mock_stage_delay_seconds"] = float(
        os.environ.get(
            "IPC_AUDIT_MOCK_STAGE_DELAY_SECONDS",
            execution_payload.get("mock_stage_delay_seconds", 0.0),
        )
    )
    provider_source_payload["enabled"] = _as_bool(
        os.environ.get(
            "IPC_AUDIT_PROVIDER_ENABLED",
            provider_source_payload.get("enabled", True),
        )
    )
    provider_source_payload["backend"] = os.environ.get(
        "IPC_AUDIT_PROVIDER_BACKEND",
        provider_source_payload.get("backend", "configcenter"),
    )
    provider_source_payload["base_url"] = os.environ.get(
        "IPC_AUDIT_PROVIDER_BASE_URL",
        provider_source_payload.get("base_url", "http://secflow-platform-configcenter"),
    )
    provider_source_payload["api_prefix"] = os.environ.get(
        "IPC_AUDIT_PROVIDER_API_PREFIX",
        provider_source_payload.get("api_prefix", "/api/configcenter/service/llm"),
    )
    provider_source_payload["timeout_seconds"] = int(
        os.environ.get(
            "IPC_AUDIT_PROVIDER_TIMEOUT_SECONDS",
            provider_source_payload.get("timeout_seconds", 15),
        )
    )
    provider_source_payload["machine_token"] = os.environ.get(
        "IPC_AUDIT_PROVIDER_MACHINE_TOKEN",
        provider_source_payload.get("machine_token"),
    )
    provider_source_payload["fallback_file_path"] = os.environ.get(
        "IPC_AUDIT_PROVIDER_FALLBACK_FILE",
        provider_source_payload.get("fallback_file_path"),
    )
    payload["app"] = app_payload
    payload["execution"] = execution_payload
    payload["provider_source"] = provider_source_payload
    _normalize_database_payload(payload)
    return payload


def load_config(config_path: str | None = None) -> ServiceConfig:
    global _config
    if _config is not None:
        return _config
    resolved = _resolve_candidates(config_path)
    payload = _load_yaml_payload(resolved)
    payload = _merge_env_overrides(payload)
    _config = ServiceConfig(**payload)
    if not _config.default_workspace_id and _config.workspaces:
        default_workspace = next((item for item in _config.workspaces if item.is_default), _config.workspaces[0])
        _config.default_workspace_id = default_workspace.workspace_id
    return _config


def get_config() -> ServiceConfig:
    return _config or load_config()


def get_sqlite_db_path() -> Path:
    if get_config().database.type != "sqlite":
        raise ValueError(f"database backend is not sqlite: {get_config().database.type}")
    raw_path = get_config().database.path
    path = Path(raw_path)
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.resolve()
