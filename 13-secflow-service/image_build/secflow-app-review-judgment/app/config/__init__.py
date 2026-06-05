from __future__ import annotations

import os
import re
from typing import Any, Dict, Optional

import yaml
from pydantic import BaseModel, Field


class AppConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False


class DatabaseConfig(BaseModel):
    url: Optional[str] = None
    host: str = "127.0.0.1"
    port: int = 3306
    username: str = "secflow"
    password: str = ""
    name: str = "secflow"
    table_prefix: str = "secflow_review_judgment_"
    pool_size: int = 20
    max_overflow: int = 10
    pool_timeout: int = 30

    @property
    def sqlalchemy_url(self) -> str:
        if self.url:
            return self.url
        return f"mysql+pymysql://{self.username}:{self.password}@{self.host}:{self.port}/{self.name}"


class AuthServiceConfig(BaseModel):
    enabled: bool = True
    host: str = "secflow-platform-auth"
    port: int = 80
    validate_human_token_path: str = "/api/auth/validate-human-token"
    validate_machine_token_path: str = "/api/auth/validate-token"
    service_machine_token: Optional[str] = None
    timeout: int = 10
    token_cache_enabled: bool = True
    token_cache_ttl_seconds: int = 300
    token_cache_max_entries: int = 10000
    max_connections: int = 100
    max_keepalive_connections: int = 20
    keepalive_expiry_seconds: int = 15
    retry_count: int = 0

    @property
    def human_validate_url(self) -> str:
        return f"http://{self.host}:{self.port}{self.validate_human_token_path}"

    @property
    def machine_validate_url(self) -> str:
        return f"http://{self.host}:{self.port}{self.validate_machine_token_path}"


class ProjectServiceConfig(BaseModel):
    enabled: bool = True
    host: str = "secflow-platform-project"
    port: int = 80
    get_project_path: str = "/api/project"
    health_path: str = "/api/project/health"
    timeout: int = 10

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def health_url(self) -> str:
        return f"{self.base_url}{self.health_path}"


class VulnEngineServiceConfig(BaseModel):
    enabled: bool = True
    base_url: str = "http://secflow-platform-vuln"
    timeout: int = 30
    service_machine_token: Optional[str] = None


class RegistryConfig(BaseModel):
    enabled: bool = False
    menu_service_url: str = "http://secflow-platform-menu"
    service_id: str = "secflow-app-review-judgment"
    service_name: str = "评审研判服务"
    host: str = "secflow-app-review-judgment"
    port: int = 80
    maturity: str = "开发中"
    description: str = "提供漏洞评审研判 CLI 调用与任务管理能力"
    api_prefix: str = "/api/review-judgment"
    unregister_on_shutdown: bool = False
    heartbeat_interval_seconds: int = 30


class ServiceConfig(BaseModel):
    workspace_base_dir: str = "/data/files"
    public_api_prefix: str = "/api/review-judgment"
    admin_proxy_prefix: str = "/api/review-judgment-admin-proxy"


class SchedulerConfig(BaseModel):
    enabled: bool = True
    role: str = Field(default_factory=lambda: os.getenv("SECFLOW_REVIEW_JUDGMENT_ROLE") or os.getenv("ROLE") or "standalone")
    pod_id: str = Field(default_factory=lambda: os.getenv("POD_ID") or os.getenv("HOSTNAME") or "local-pod")
    host_name: str = Field(default_factory=lambda: os.getenv("HOSTNAME") or "localhost")
    pod_namespace: str = Field(default_factory=lambda: os.getenv("POD_NAMESPACE") or "secflow-ns")


class LoggingConfig(BaseModel):
    level: str = "INFO"


class Config(BaseModel):
    app: AppConfig = Field(default_factory=AppConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    auth_service: AuthServiceConfig = Field(default_factory=AuthServiceConfig)
    project_service: ProjectServiceConfig = Field(default_factory=ProjectServiceConfig)
    vuln_engine_service: VulnEngineServiceConfig = Field(default_factory=VulnEngineServiceConfig)
    registry: RegistryConfig = Field(default_factory=RegistryConfig)
    service: ServiceConfig = Field(default_factory=ServiceConfig)
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


_config: Optional[Config] = None


def _candidate_paths(config_path: Optional[str]) -> list[str]:
    if config_path:
        return [config_path]
    return [
        os.environ.get("CONFIG_PATH", ""),
        "config.yaml",
        os.path.join(os.path.dirname(__file__), "..", "config.yaml"),
        os.path.join(os.path.dirname(__file__), "..", "..", "config.yaml"),
    ]


def _resolve_env_vars(text: str) -> str:
    def _replace(match: re.Match) -> str:
        name = match.group(1)
        return os.environ.get(name, match.group(0))

    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", _replace, text)


def load_config(config_path: Optional[str] = None) -> Config:
    global _config
    if _config is not None:
        return _config

    for path in _candidate_paths(config_path):
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as file:
                raw_text = file.read()
            data: Dict[str, Any] = yaml.safe_load(_resolve_env_vars(raw_text)) or {}
            _config = Config(**data)
            return _config

    _config = Config()
    return _config


def reset_config() -> None:
    global _config
    _config = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = load_config()
    return _config