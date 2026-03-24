"""Configuration loader for secflow platform fileserver."""

import logging
import os
from typing import Optional

import yaml
from pydantic import BaseModel


logger = logging.getLogger(__name__)


class DatabaseConfig(BaseModel):
    host: str
    port: int
    username: str
    password: str
    name: str
    table_prefix: str = "secflow_"
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
    host: str = "0.0.0.0"
    port: int
    maturity: str = "开发中"
    description: str
    api_prefix: str
    menu: Optional[RegistryMenuConfig] = None


class StorageConfig(BaseModel):
    root_dir: str = "/data"
    temp_dir: str = "/data/tmp"
    max_upload_size: int = 2147483648


class AppConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class Config(BaseModel):
    database: DatabaseConfig
    auth_service: AuthServiceConfig
    project_service: ProjectServiceConfig
    registry: RegistryConfig
    storage: StorageConfig
    app: AppConfig
    logging: LoggingConfig = LoggingConfig()


_config: Optional[Config] = None


def load_config(config_path: Optional[str] = None) -> Config:
    global _config

    if _config is not None:
        return _config

    if config_path is None:
        possible_paths = [
            "config.yaml",
            os.path.join(os.path.dirname(__file__), "config.yaml"),
            os.path.join(os.path.dirname(__file__), "..", "config.yaml"),
        ]
        for path in possible_paths:
            if os.path.exists(path):
                config_path = path
                break

    if config_path is None or not os.path.exists(config_path):
        raise FileNotFoundError(f"配置文件未找到: {config_path}")

    with open(config_path, "r", encoding="utf-8") as file:
        config_data = yaml.safe_load(file)

    _config = Config(**config_data)
    return _config


def get_config() -> Config:
    global _config
    if _config is None:
        return load_config()
    return _config
