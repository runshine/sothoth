"""
Configuration module for workflow service
"""

import os
import logging
from typing import Optional

import yaml
from pydantic import BaseModel


logger = logging.getLogger(__name__)


class DatabaseConfig(BaseModel):
    """Database configuration"""
    host: str
    port: int
    username: str
    password: str
    name: str
    table_prefix: str = "secflow_platform_workflow_"
    pool_size: int = 10
    max_overflow: int = 20

    @property
    def url(self) -> str:
        """Generate database connection URL"""
        return f"mysql+pymysql://{self.username}:{self.password}@{self.host}:{self.port}/{self.name}"


class AuthServiceConfig(BaseModel):
    """Auth service configuration"""
    enabled: bool = True  # Set to False to disable authentication
    host: str
    port: int
    validate_token_path: str = "/api/auth/validate-human-token"
    timeout: int = 10
    token_cache_enabled: bool = True
    token_cache_ttl_minutes: int = 15

    @property
    def validate_url(self) -> str:
        """Generate token validation URL"""
        return f"http://{self.host}:{self.port}{self.validate_token_path}"


class RegistryMenuLevelConfig(BaseModel):
    """Menu level configuration"""
    name: Optional[str] = None
    name_en: Optional[str] = None


class RegistryMenuConfig(BaseModel):
    """Menu configuration"""
    id: str
    path: str
    icon: Optional[str] = None
    order: int = 0
    level1: Optional[RegistryMenuLevelConfig] = None
    level2: Optional[RegistryMenuLevelConfig] = None
    level3: Optional[RegistryMenuLevelConfig] = None


class RegistryConfig(BaseModel):
    """Menu registration center configuration"""
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


class KubernetesConfig(BaseModel):
    """K8S configuration"""
    connection_mode: str = "incluster"  # "incluster" or "kubeconfig"
    kubeconfig_path: Optional[str] = None
    connection_timeout: int = 30


class AppConfig(BaseModel):
    """Application configuration"""
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False


class LoggingConfig(BaseModel):
    """Logging configuration"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class Config(BaseModel):
    """Main configuration class"""
    database: DatabaseConfig
    auth_service: AuthServiceConfig
    registry: RegistryConfig
    kubernetes: KubernetesConfig
    app: AppConfig
    logging: LoggingConfig = LoggingConfig()


_config: Optional[Config] = None


def load_config(config_path: Optional[str] = None) -> Config:
    """
    Load configuration file

    Args:
        config_path: Configuration file path, default is config.yaml

    Returns:
        Config object
    """
    global _config

    if _config is not None:
        return _config

    if config_path is None:
        # Default to environment variable or search common paths
        config_path = os.environ.get("CONFIG_PATH")
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
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, 'r', encoding='utf-8') as f:
        config_data = yaml.safe_load(f)

    _config = Config(**config_data)
    return _config


def get_config() -> Config:
    """Get configuration object"""
    global _config
    if _config is None:
        return load_config()
    return _config


def reload_config(config_path: Optional[str] = None) -> Config:
    """Reload configuration"""
    global _config
    _config = None
    return load_config(config_path)
