"""Configuration loader for local SecFlow vuln-verify app."""

from __future__ import annotations

import os
from typing import Optional
from urllib.parse import quote_plus

import yaml
from pydantic import BaseModel, Field


class DatabaseConfig(BaseModel):
    # Local-first: sqlite works without installing any external service.
    # Set url=mysql+pymysql://user:pass@host:3306/db or fill mysql fields below.
    url: str | None = None
    driver: str = "sqlite"  # sqlite | mysql
    sqlite_path: str = "/data/vuln-verify/vuln_verify.db"
    host: str = "127.0.0.1"
    port: int = 3306
    username: str = "secflow"
    password: str = ""
    name: str = "secflow"
    pool_size: int = 10
    max_overflow: int = 20

    @property
    def sqlalchemy_url(self) -> str:
        env_url = os.environ.get("DATABASE_URL") or os.environ.get("SECFLOW_DATABASE_URL")
        if env_url:
            return env_url
        if self.url:
            return self.url
        if self.driver.lower() in {"mysql", "mariadb"}:
            user = quote_plus(self.username)
            password = quote_plus(self.password)
            return f"mysql+pymysql://{user}:{password}@{self.host}:{self.port}/{self.name}"
        return f"sqlite:///{self.sqlite_path}"


class AuthServiceConfig(BaseModel):
    enabled: bool = False
    # Optional local shared token. Empty means no auth required.
    dev_token: str | None = None


class ProjectServiceConfig(BaseModel):
    enabled: bool = False


class ConfigCenterConfig(BaseModel):
    # Kept only for backwards compatibility; local mode no longer requires it.
    enabled: bool = False
    base_url: str = ""
    timeout: int = 30
    sync_on_startup: bool = False
    sync_before_task: bool = False
    default_provider_key: str | None = None


class LocalLLMConfig(BaseModel):
    # Direct local LLM configuration. Environment variables override these values.
    provider_key: str = "local_openai"
    provider_type: str = "openai"
    api_base: str = "https://api.openai.com/v1"
    api_key: str | None = None
    model: str = "gpt-4.1"
    context_window: int = 128000
    max_tokens: int | None = None
    sync_on_startup: bool = True
    sync_before_task: bool = True


class StorageConfig(BaseModel):
    project_root_template: str = "/data/files/{project_id}"
    app_root_name: str = "app/secflow-app-vuln-verify"
    require_input_exists: bool = True
    # Local development convenience: allow reports/source paths from any mounted path.
    allow_external_input_paths: bool = True


class WorkerConfig(BaseModel):
    enabled: bool = True
    poll_interval_seconds: int = 3
    lease_seconds: int = 300
    heartbeat_interval_seconds: int = 15
    max_local_running_tasks: int = 1
    default_concurrency: int = 4
    max_concurrency: int = 16
    task_timeout_seconds: int = 0


class RegistryConfig(BaseModel):
    enabled: bool = False
    service_id: str = "secflow-app-vuln-verify"
    service_name: str = "漏洞验证服务"
    host: str = "localhost"
    port: int = 8080
    maturity: str = "local"
    description: str = "本地漏洞验证服务"
    api_prefix: str = "/api/app/vuln-verify"


class AppConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False


class LoggingConfig(BaseModel):
    level: str = "INFO"


class Config(BaseModel):
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    auth_service: AuthServiceConfig = Field(default_factory=AuthServiceConfig)
    project_service: ProjectServiceConfig = Field(default_factory=ProjectServiceConfig)
    configcenter: ConfigCenterConfig = Field(default_factory=ConfigCenterConfig)
    local_llm: LocalLLMConfig = Field(default_factory=LocalLLMConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    worker: WorkerConfig = Field(default_factory=WorkerConfig)
    registry: RegistryConfig = Field(default_factory=RegistryConfig)
    app: AppConfig = Field(default_factory=AppConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


_config: Optional[Config] = None


def _deep_update(base: dict, patch: dict) -> dict:
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_update(base[key], value)
        else:
            base[key] = value
    return base


def _env_overrides() -> dict:
    overrides: dict = {}
    if os.environ.get("OPENAI_API_KEY") or os.environ.get("LLM_API_KEY"):
        overrides.setdefault("local_llm", {})["api_key"] = os.environ.get("OPENAI_API_KEY") or os.environ.get("LLM_API_KEY")
    if os.environ.get("OPENAI_BASE_URL") or os.environ.get("LLM_API_BASE"):
        overrides.setdefault("local_llm", {})["api_base"] = os.environ.get("OPENAI_BASE_URL") or os.environ.get("LLM_API_BASE")
    if os.environ.get("OPENAI_MODEL") or os.environ.get("LLM_MODEL"):
        overrides.setdefault("local_llm", {})["model"] = os.environ.get("OPENAI_MODEL") or os.environ.get("LLM_MODEL")
    if os.environ.get("LLM_PROVIDER_KEY"):
        overrides.setdefault("local_llm", {})["provider_key"] = os.environ["LLM_PROVIDER_KEY"]
    if os.environ.get("LLM_PROVIDER_TYPE"):
        overrides.setdefault("local_llm", {})["provider_type"] = os.environ["LLM_PROVIDER_TYPE"]
    if os.environ.get("SECFLOW_DEV_TOKEN"):
        overrides.setdefault("auth_service", {})["dev_token"] = os.environ["SECFLOW_DEV_TOKEN"]
        overrides.setdefault("auth_service", {})["enabled"] = True
    return overrides


def load_config(config_path: Optional[str] = None) -> Config:
    global _config
    if _config is not None:
        return _config
    if config_path is None:
        candidates = [
            os.environ.get("SECFLOW_VULN_VERIFY_CONFIG"),
            os.environ.get("SERVICE_YAML"),
            "config.yaml",
            os.path.join(os.path.dirname(__file__), "..", "config.yaml"),
        ]
        config_path = next((p for p in candidates if p and os.path.exists(p)), None)
    raw: dict = {}
    if config_path:
        with open(config_path, "r", encoding="utf-8") as file:
            raw = yaml.safe_load(file) or {}
    raw = _deep_update(raw, _env_overrides())
    _config = Config(**raw)
    return _config


def get_config() -> Config:
    return _config or load_config()
