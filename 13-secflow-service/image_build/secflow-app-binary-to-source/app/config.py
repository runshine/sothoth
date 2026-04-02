"""Configuration loader."""

import os
from typing import Optional

import yaml
from pydantic import BaseModel


class DatabaseConfig(BaseModel):
    type: str = "mysql"
    host: str = "localhost"
    port: int = 3306
    username: str = "root"
    password: str = ""
    name: str = "secflow"
    table_prefix: str = "secflow_app_binary_to_source_"
    pool_size: int = 10
    max_overflow: int = 20
    path: str = "./binary_to_source.db"

    @property
    def url(self) -> str:
        if self.type == "sqlite":
            return f"sqlite:///{self.path}"
        return f"mysql+pymysql://{self.username}:{self.password}@{self.host}:{self.port}/{self.name}"


class RedisConfig(BaseModel):
    url: str = "redis://localhost:6379/0"
    key_prefix: str = "secflow:binary-to-source"
    worker_ttl_seconds: int = 45
    lock_ttl_seconds: int = 15


class AuthServiceConfig(BaseModel):
    enabled: bool = True
    host: str = "secflow-platform-auth"
    port: int = 80
    validate_token_path: str = "/api/auth/validate-token"
    timeout: int = 10

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def validate_url(self) -> str:
        return f"{self.base_url}{self.validate_token_path}"


class ProjectServiceConfig(BaseModel):
    host: str = "secflow-platform-project"
    port: int = 80
    get_project_path: str = "/api/project"
    timeout: int = 10

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


class CeleryConfig(BaseModel):
    broker_url: str = "redis://localhost:6379/1"
    result_backend: str = "redis://localhost:6379/2"
    task_track_started: bool = True
    task_time_limit_seconds: int = 7200
    task_soft_time_limit_seconds: int = 7000
    worker_queue_prefix: str = "b2s-worker"


class SchedulerConfig(BaseModel):
    dispatch_interval_seconds: int = 3
    recovery_interval_seconds: int = 10
    stale_running_timeout_seconds: int = 3600
    queued_timeout_seconds: int = 300


class TaskPolicyConfig(BaseModel):
    auto_retry_enabled: bool = True
    max_auto_retries: int = 2
    transient_retry_delay_seconds: int = 30


class StorageConfig(BaseModel):
    shared_root: str = "/data/binary-to-source"


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
    service_id: str = "secflow-app-binary-to-source"
    service_name: str = "ELF源码还原服务"
    host: str = "secflow-app-binary-to-source-manager"
    port: int = 80
    maturity: str = "开发中"
    description: str = "ELF源码还原任务服务"
    api_prefix: str = "/api/app/binary-to-source"
    menu: Optional[RegistryMenuConfig] = None


class AppConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class Config(BaseModel):
    database: DatabaseConfig
    redis: RedisConfig
    auth_service: AuthServiceConfig
    project_service: ProjectServiceConfig
    celery: CeleryConfig
    scheduler: SchedulerConfig
    task_policy: TaskPolicyConfig
    storage: StorageConfig
    registry: RegistryConfig
    app: AppConfig
    logging: LoggingConfig = LoggingConfig()


_config: Optional[Config] = None


def load_config(config_path: Optional[str] = None) -> Config:
    global _config
    if _config is not None:
        return _config

    if config_path is None:
        possible_paths = [
            os.environ.get("B2S_CONFIG"),
            "config.yaml",
            os.path.join(os.path.dirname(__file__), "..", "config.yaml"),
            "/app/config.yaml",
        ]
        for path in possible_paths:
            if path and os.path.exists(path):
                config_path = path
                break

    if not config_path or not os.path.exists(config_path):
        raise FileNotFoundError(f"配置文件未找到: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    _config = Config(**data)
    return _config


def get_config() -> Config:
    if _config is None:
        return load_config()
    return _config
