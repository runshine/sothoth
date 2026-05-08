"""Configuration loader for firmware unpacker service."""

from __future__ import annotations

import os
from typing import Optional

import yaml
from pydantic import BaseModel, Field


class DatabaseConfig(BaseModel):
    """Database configuration."""

    type: str = "sqlite"
    host: str = "localhost"
    port: int = 3306
    username: str = "root"
    password: str = ""
    name: str = "secflow"
    table_prefix: str = "secflow_app_firmware_unpacker_"
    pool_size: int = 10
    max_overflow: int = 20
    path: str = "./firmware_unpacker.db"

    @property
    def url(self) -> str:
        if self.type == "sqlite":
            return f"sqlite:///{self.path}"
        return (
            f"mysql+pymysql://{self.username}:{self.password}"
            f"@{self.host}:{self.port}/{self.name}"
        )


class AuthServiceConfig(BaseModel):
    """Authentication service configuration."""

    enabled: bool = True
    host: str = "secflow-platform-auth"
    port: int = 80
    validate_token_path: str = "/api/auth/validate-token"
    service_machine_token: Optional[str] = None
    timeout: int = 10
    token_cache_enabled: bool = True
    token_cache_ttl_minutes: int = 15

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def validate_url(self) -> str:
        return f"{self.base_url}{self.validate_token_path}"

    @property
    def health_url(self) -> str:
        return f"{self.base_url}/api/auth/health"


class ProjectServiceConfig(BaseModel):
    """Project service configuration."""

    enabled: bool = True
    host: str = "secflow-platform-project"
    port: int = 80
    get_project_path: str = "/api/project"
    timeout: int = 10

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}{self.get_project_path}"


class ConfigCenterServiceConfig(BaseModel):
    """Config center service configuration."""

    enabled: bool = True
    base_url: str = "http://secflow-platform-configcenter/api/configcenter"
    timeout: int = 30


class ServiceConfig(BaseModel):
    """Service runtime configuration."""

    max_background_workers: int = 8
    task_retention_days: int = 7


class WorkerConfig(BaseModel):
    """Worker runtime configuration."""

    heartbeat_interval_seconds: int = 15
    dead_threshold_seconds: int = 90
    claim_interval_seconds: int = 2
    claim_batch_size: int = 8
    task_lease_seconds: int = 45
    task_lease_renew_interval_seconds: int = 10
    cancel_timeout_seconds: int = 120


class RegistryMenuLevelConfig(BaseModel):
    name: Optional[str] = None
    name_en: Optional[str] = None


class RegistryMenuConfig(BaseModel):
    id: str = "firmware-unpacker"
    path: str = "/firmware-unpacker"
    icon: str = "box"
    order: int = 20
    parent_id: Optional[str] = None
    level1: RegistryMenuLevelConfig = Field(
        default_factory=lambda: RegistryMenuLevelConfig(
            name="开发工具",
            name_en="DevTools",
        )
    )
    level2: RegistryMenuLevelConfig = Field(
        default_factory=lambda: RegistryMenuLevelConfig(
            name="逆向分析",
            name_en="Reverse",
        )
    )
    level3: RegistryMenuLevelConfig = Field(
        default_factory=lambda: RegistryMenuLevelConfig(
            name="固件解包",
            name_en="Firmware Unpacker",
        )
    )


class RegistryConfig(BaseModel):
    """Service registry configuration."""

    enabled: bool = True
    menu_service_url: str = "http://secflow-platform-menu:80"
    service_id: str = "secflow-app-firmware-unpacker"
    service_name: str = "固件解包服务"
    host: str = "secflow-app-firmware-unpacker"
    port: int = 80
    maturity: str = "开发中"
    description: str = "基于 pi coding agent 的固件自动解包服务"
    api_prefix: str = "/api/app/firmware-unpacker"
    unregister_on_shutdown: bool = False
    heartbeat_interval_seconds: int = 30
    menu: RegistryMenuConfig = Field(default_factory=RegistryMenuConfig)


class AppConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class Config(BaseModel):
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    auth_service: AuthServiceConfig = Field(default_factory=AuthServiceConfig)
    project_service: ProjectServiceConfig = Field(default_factory=ProjectServiceConfig)
    configcenter_service: ConfigCenterServiceConfig = Field(default_factory=ConfigCenterServiceConfig)
    service: ServiceConfig = Field(default_factory=ServiceConfig)
    worker: WorkerConfig = Field(default_factory=WorkerConfig)
    registry: RegistryConfig = Field(default_factory=RegistryConfig)
    app: AppConfig = Field(default_factory=AppConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


_config: Optional[Config] = None


def _candidate_paths(config_path: Optional[str]) -> list[str]:
    if config_path:
        return [config_path]
    return [
        os.environ.get("CONFIG_PATH", ""),
        os.environ.get("FIRMWARE_UNPACKER_CONFIG", ""),
        "config.yaml",
        os.path.join(os.path.dirname(__file__), "..", "config.yaml"),
        os.path.join(os.path.dirname(__file__), "..", "..", "config.yaml"),
        "/app/config.yaml",
    ]


def _ensure_local_database_dir(cfg: Config) -> None:
    if cfg.database.type != "sqlite":
        return
    db_dir = os.path.dirname(cfg.database.path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)


def load_config(config_path: Optional[str] = None) -> Config:
    global _config
    if _config is not None:
        return _config

    for path in _candidate_paths(config_path):
        if not path or not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}
        _config = Config(**data)
        _ensure_local_database_dir(_config)
        return _config

    _config = Config()
    _ensure_local_database_dir(_config)
    return _config


def get_config() -> Config:
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reload_config(config_path: Optional[str] = None) -> Config:
    global _config
    _config = None
    return load_config(config_path)
