"""Configuration loader for SecFlow vuln-verify app."""

from __future__ import annotations

import os
from typing import Optional

import yaml
from pydantic import BaseModel, Field


class DatabaseConfig(BaseModel):
    host: str
    port: int
    username: str
    password: str
    name: str
    pool_size: int = 10
    max_overflow: int = 20

    @property
    def url(self) -> str:
        return f"mysql+pymysql://{self.username}:{self.password}@{self.host}:{self.port}/{self.name}"


class AuthServiceConfig(BaseModel):
    host: str
    port: int
    validate_token_path: str = "/api/auth/validate-token"
    service_machine_token: Optional[str] = None
    timeout: int = 10
    token_cache_enabled: bool = True
    token_cache_ttl_minutes: int = 15

    @property
    def validate_url(self) -> str:
        return f"http://{self.host}:{self.port}{self.validate_token_path}"


class ProjectServiceConfig(BaseModel):
    host: str
    port: int
    get_project_path: str = "/api/project"
    timeout: int = 10

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


class StorageConfig(BaseModel):
    project_root_template: str = "/data/files/{project_id}"
    app_root_name: str = "app/secflow-app-vuln-verify"
    require_input_exists: bool = True


class WorkerConfig(BaseModel):
    enabled: bool = True
    poll_interval_seconds: int = 3
    lease_seconds: int = 300
    heartbeat_interval_seconds: int = 15
    max_local_running_tasks: int = 1
    default_concurrency: int = 4
    max_concurrency: int = 16
    task_timeout_seconds: int = 0


class RegistryMenuLevelConfig(BaseModel):
    name: Optional[str] = None
    name_en: Optional[str] = None


class RegistryMenuConfig(BaseModel):
    id: str
    path: str
    icon: Optional[str] = None
    order: int = 0
    level1: Optional[RegistryMenuLevelConfig] = None
    level2: Optional[RegistryMenuLevelConfig] = None
    level3: Optional[RegistryMenuLevelConfig] = None


class RegistryConfig(BaseModel):
    enabled: bool = True
    menu_service_url: str = "http://secflow-platform-menu"
    service_id: str = "secflow-app-vuln-verify"
    service_name: str = "漏洞验证服务"
    host: str = "secflow-app-vuln-verify"
    port: int = 80
    maturity: str = "已上线"
    description: str = "基于漏洞报告、源码、二进制与威胁模型的自动化漏洞验证服务"
    api_prefix: str = "/api/app/vuln-verify"
    menu: Optional[RegistryMenuConfig] = None


class AppConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False


class LoggingConfig(BaseModel):
    level: str = "INFO"


class Config(BaseModel):
    database: DatabaseConfig
    auth_service: AuthServiceConfig
    project_service: ProjectServiceConfig
    storage: StorageConfig = Field(default_factory=StorageConfig)
    worker: WorkerConfig = Field(default_factory=WorkerConfig)
    registry: RegistryConfig = Field(default_factory=RegistryConfig)
    app: AppConfig = Field(default_factory=AppConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


_config: Optional[Config] = None


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
    if not config_path:
        raise FileNotFoundError("vuln-verify配置文件未找到")
    with open(config_path, "r", encoding="utf-8") as file:
        _config = Config(**(yaml.safe_load(file) or {}))
    return _config


def get_config() -> Config:
    return _config or load_config()
