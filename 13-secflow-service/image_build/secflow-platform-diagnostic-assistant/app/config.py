from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger("diagnostic-assistant.config")

SERVICE_YAML_PATH = os.environ.get("SERVICE_YAML", "/app/service.yaml")


@dataclass
class DbConfig:
    sqlite_path: str = "/data/files/platform/secflow-platform-diagnostic-assistant/diagnostic_assistant.db"


@dataclass
class AuthConfig:
    host: str = "secflow-platform-auth"
    port: int = 80
    validate_token_path: str = "/api/auth/validate-token"
    service_machine_token: str = ""
    timeout: int = 10

    @property
    def validate_url(self) -> str:
        return f"http://{self.host}:{self.port}{self.validate_token_path}"


@dataclass
class AppConfig:
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False
    kubectl_timeout_seconds: int = 60
    max_command_output_bytes: int = 200_000
    max_history_messages: int = 12
    default_provider_key: str = "share_codex"


@dataclass
class AgentHelperConfig:
    base_url: str = "http://secflow.ai.icsl.huawei.com"
    timeout: int = 60
    default_agent_id: str = "pi"
    default_session_mode: str = "pipe"


@dataclass
class ConfigCenterConfig:
    base_url: str = "http://secflow-platform-configcenter/api/configcenter"
    timeout: int = 30


@dataclass
class ServiceYaml:
    database: DbConfig = field(default_factory=DbConfig)
    auth_service: AuthConfig = field(default_factory=AuthConfig)
    app: AppConfig = field(default_factory=AppConfig)
    configcenter: ConfigCenterConfig = field(default_factory=ConfigCenterConfig)
    agent_helper: AgentHelperConfig = field(default_factory=AgentHelperConfig)


def load_service_yaml(yaml_path: str = SERVICE_YAML_PATH) -> ServiceYaml:
    path = Path(yaml_path)
    if not path.is_file():
        logger.warning("service.yaml not found at %s, using defaults", yaml_path)
        return ServiceYaml()

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        logger.warning("failed to parse service.yaml: %s", exc)
        return ServiceYaml()

    db_raw = raw.get("database", {})
    auth_raw = raw.get("auth_service", {})
    app_raw = raw.get("app", {})
    cc_raw = raw.get("configcenter_service", raw.get("configcenter", {}))
    agent_raw = raw.get("agent_helper", {})
    return ServiceYaml(
        database=DbConfig(
            sqlite_path=str(db_raw.get("sqlite_path", "/data/files/platform/secflow-platform-diagnostic-assistant/diagnostic_assistant.db")),
        ),
        auth_service=AuthConfig(
            host=str(auth_raw.get("host", "secflow-platform-auth")),
            port=int(auth_raw.get("port", 80)),
            validate_token_path=str(auth_raw.get("validate_token_path", "/api/auth/validate-token")),
            service_machine_token=str(auth_raw.get("service_machine_token", "")),
            timeout=int(auth_raw.get("timeout", 10)),
        ),
        app=AppConfig(
            host=str(app_raw.get("host", "0.0.0.0")),
            port=int(app_raw.get("port", 8080)),
            debug=bool(app_raw.get("debug", False)),
            kubectl_timeout_seconds=int(app_raw.get("kubectl_timeout_seconds", 60)),
            max_command_output_bytes=int(app_raw.get("max_command_output_bytes", 200_000)),
            max_history_messages=int(app_raw.get("max_history_messages", 12)),
            default_provider_key=str(app_raw.get("default_provider_key", "share_codex")),
        ),
        configcenter=ConfigCenterConfig(
            base_url=str(cc_raw.get("base_url", "http://secflow-platform-configcenter/api/configcenter")),
            timeout=int(cc_raw.get("timeout", 30)),
        ),
        agent_helper=AgentHelperConfig(
            base_url=str(agent_raw.get("base_url", "http://secflow.ai.icsl.huawei.com")),
            timeout=int(agent_raw.get("timeout", 60)),
            default_agent_id=str(agent_raw.get("default_agent_id", "pi")),
            default_session_mode=str(agent_raw.get("default_session_mode", "pipe")),
        ),
    )


_service_yaml: Optional[ServiceYaml] = None


def get_service_yaml() -> ServiceYaml:
    global _service_yaml
    if _service_yaml is None:
        _service_yaml = load_service_yaml()
    return _service_yaml


def ensure_runtime_dirs() -> None:
    cfg = get_service_yaml()
    db_path = Path(cfg.database.sqlite_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
