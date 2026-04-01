"""Configuration loader for system analysis service."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field


class DatabaseConfig(BaseModel):
    host: str = "localhost"
    port: int = 3306
    username: str = "root"
    password: str = ""
    name: str = "secflow"
    table_prefix: str = "secflow_"
    pool_size: int = 10
    max_overflow: int = 20

    @property
    def url(self) -> str:
        return f"mysql+pymysql://{self.username}:{self.password}@{self.host}:{self.port}/{self.name}"


class AuthServiceConfig(BaseModel):
    host: str = "secflow-platform-auth"
    port: int = 80
    validate_token_path: str = "/api/auth/validate-token"
    service_machine_token: Optional[str] = None
    timeout: int = 10
    token_cache_enabled: bool = True
    token_cache_ttl_minutes: int = 15

    @property
    def validate_url(self) -> str:
        return f"http://{self.host}:{self.port}{self.validate_token_path}"


class AgentServiceConfig(BaseModel):
    base_url: str = "http://secflow-platform-agent"
    timeout: int = 20


class MenuLevelConfig(BaseModel):
    name: Optional[str] = None
    name_en: Optional[str] = None


class MenuConfig(BaseModel):
    id: str = "system-analysis"
    path: str = "/system-analysis"
    icon: str = "activity"
    order: int = 30
    level1: MenuLevelConfig = Field(
        default_factory=lambda: MenuLevelConfig(name="环境服务", name_en="Environment")
    )
    level2: MenuLevelConfig = Field(
        default_factory=lambda: MenuLevelConfig(name="系统分析", name_en="System Analysis")
    )
    level3: MenuLevelConfig = Field(default_factory=MenuLevelConfig)


class RegistryConfig(BaseModel):
    enabled: bool = True
    menu_service_url: str = "http://secflow-platform-menu"
    service_id: str = "secflow-platform-system-analysis"
    service_name: str = "系统分析服务"
    host: str = "secflow-platform-system-analysis"
    port: int = 80
    maturity: str = "开发中"
    description: str = "提供测试环境自动化系统分析能力"
    api_prefix: str = "/api/system-analysis"
    unregister_on_shutdown: bool = False
    heartbeat_interval_seconds: int = 30
    menu: MenuConfig = Field(default_factory=MenuConfig)


class ServiceConfig(BaseModel):
    worker_poll_interval_seconds: int = 1
    default_timeout_seconds: int = 600
    default_max_concurrency: int = 5
    max_timeout_seconds: int = 7200
    max_concurrency_limit: int = 50


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
    agent_service: AgentServiceConfig = Field(default_factory=AgentServiceConfig)
    registry: RegistryConfig = Field(default_factory=RegistryConfig)
    service: ServiceConfig = Field(default_factory=ServiceConfig)
    app: AppConfig = Field(default_factory=AppConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


_config: Optional[Config] = None


def _candidate_paths(config_path: Optional[str]) -> List[str]:
    if config_path:
        return [config_path]
    return [
        os.environ.get("CONFIG_PATH", ""),
        "config.yaml",
        os.path.join(os.path.dirname(__file__), "..", "config.yaml"),
        os.path.join(os.path.dirname(__file__), "..", "..", "config.yaml"),
    ]


def load_config(config_path: Optional[str] = None) -> Config:
    global _config
    if _config is not None:
        return _config

    for path in _candidate_paths(config_path):
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as file:
                data: Dict[str, Any] = yaml.safe_load(file) or {}
            _config = Config(**data)
            return _config

    _config = Config()
    return _config


def get_config() -> Config:
    global _config
    if _config is None:
        _config = load_config()
    return _config

