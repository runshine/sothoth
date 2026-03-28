"""Configuration loader for config center."""

import os
from typing import Any, Dict, Optional

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


class MenuLevelConfig(BaseModel):
    name: Optional[str] = None
    name_en: Optional[str] = None


class MenuConfig(BaseModel):
    id: str = "config-center-llm"
    path: str = "/config-center/llm"
    icon: str = "settings"
    order: int = 1
    level1: MenuLevelConfig = Field(
        default_factory=lambda: MenuLevelConfig(name="配置中心", name_en="Config Center")
    )
    level2: MenuLevelConfig = Field(
        default_factory=lambda: MenuLevelConfig(name="LLM 对接配置", name_en="LLM Integration")
    )
    level3: MenuLevelConfig = Field(default_factory=MenuLevelConfig)


class RegistryConfig(BaseModel):
    enabled: bool = True
    menu_service_url: str = "http://secflow-platform-menu"
    service_id: str = "secflow-platform-configcenter"
    service_name: str = "配置中心服务"
    host: str = "secflow-platform-configcenter"
    port: int = 80
    maturity: str = "开发中"
    description: str = "统一管理平台级动态系统配置项"
    api_prefix: str = "/api/configcenter"
    menu: MenuConfig = Field(default_factory=MenuConfig)


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
    registry: RegistryConfig = Field(default_factory=RegistryConfig)
    app: AppConfig = Field(default_factory=AppConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


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
            os.path.join(os.path.dirname(__file__), "..", "..", "config.yaml"),
        ]
        for path in possible_paths:
            if path and os.path.exists(path):
                config_path = path
                break

    if config_path is None or not os.path.exists(config_path):
        _config = Config()
        return _config

    with open(config_path, "r", encoding="utf-8") as file:
        config_data: Dict[str, Any] = yaml.safe_load(file) or {}

    _config = Config(**config_data)
    return _config


def get_config() -> Config:
    global _config
    if _config is None:
        return load_config()
    return _config
