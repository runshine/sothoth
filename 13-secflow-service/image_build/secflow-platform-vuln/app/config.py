"""Configuration loader for secflow-platform-vuln."""

import os
from typing import Optional

import yaml
from pydantic import BaseModel


class DatabaseConfig(BaseModel):
    host: str
    port: int
    username: str
    password: str
    name: str
    table_prefix: str = "secflow_vuln_"
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


class ProjectServiceConfig(BaseModel):
    host: str
    port: int
    get_project_path: str = "/api/project"
    timeout: int = 10


class StorageConfig(BaseModel):
    backend: str = "shared_pvc"
    base_path: str = "/data/vuln-storage"
    future_backend: str = "s3"


class ServiceRegistryConfig(BaseModel):
    heartbeat_timeout_seconds: int = 90
    allow_dynamic_register: bool = True


class EngineConfig(BaseModel):
    dispatch_interval_seconds: int = 5
    max_parallel_actions_per_case: int = 5
    action_timeout_default: int = 300
    retry_default: int = 1
    auto_transition_enabled: bool = True


class WorkflowConfig(BaseModel):
    default_workflow_code: str = "default_vuln_lifecycle"


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
    menu_service_url: str
    service_id: str
    service_name: str
    host: str
    port: int
    maturity: str
    description: str
    api_prefix: str
    menu: Optional[RegistryMenuConfig] = None


class AppConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False


class Config(BaseModel):
    database: DatabaseConfig
    auth_service: AuthServiceConfig
    project_service: ProjectServiceConfig
    storage: StorageConfig
    service_registry: ServiceRegistryConfig
    engine: EngineConfig
    workflow: WorkflowConfig
    registry: RegistryConfig
    app: AppConfig


_config: Optional[Config] = None


def load_config(config_path: Optional[str] = None) -> Config:
    global _config
    if _config is not None:
        return _config

    if config_path is None:
        possible_paths = [
            os.environ.get("CONFIG_PATH"),
            "config.yaml",
            os.path.join(os.path.dirname(__file__), "..", "config.yaml"),
        ]
        for path in possible_paths:
            if path and os.path.exists(path):
                config_path = path
                break

    if config_path is None or not os.path.exists(config_path):
        raise FileNotFoundError(f"config.yaml not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    _config = Config(**data)
    return _config


def get_config() -> Config:
    global _config
    if _config is None:
        return load_config()
    return _config
