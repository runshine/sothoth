"""Configuration loader for SecFlow Binary-to-Source adapter."""

from __future__ import annotations

import os
from typing import Literal, Optional

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


class PiReAgentConfig(BaseModel):
    base_url: str = "http://secflow-pi-re-agent:8000"
    api_key: Optional[str] = None
    timeout: int = 30
    batch_size: int = 8192
    max_retries: int = 3
    engine: Literal["agent", "hybrid"] = "hybrid"
    concurrency: int = 4
    model: Optional[str] = None


class StorageConfig(BaseModel):
    project_root_template: str = "/data/files/{project_id}"
    output_root_name: str = "binary-to-source-outputs"
    require_input_exists: bool = True


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
    description: str = "项目隔离的ELF到源码还原适配服务"
    api_prefix: str = "/api/app/binary-to-source"
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
    pi_re_agent: PiReAgentConfig = Field(default_factory=PiReAgentConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
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
            os.environ.get("SECFLOW_B2S_CONFIG"),
            "config.yaml",
            os.path.join(os.path.dirname(__file__), "..", "config.yaml"),
        ]
        config_path = next((p for p in candidates if p and os.path.exists(p)), None)

    if not config_path:
        raise FileNotFoundError("B2S配置文件未找到")

    with open(config_path, "r", encoding="utf-8") as file:
        _config = Config(**yaml.safe_load(file))
    return _config


def get_config() -> Config:
    return _config or load_config()
