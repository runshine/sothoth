"""
配置文件加载模块
"""

import os
import logging
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel


logger = logging.getLogger(__name__)


class DatabaseConfig(BaseModel):
    """数据库配置"""
    host: str
    port: int
    username: str
    password: str
    name: str
    table_prefix: str = "secflow_workflow_status_"
    pool_size: int = 10
    max_overflow: int = 20

    @property
    def url(self) -> str:
        """生成数据库连接URL"""
        return f"mysql+pymysql://{self.username}:{self.password}@{self.host}:{self.port}/{self.name}"


class AuthServiceConfig(BaseModel):
    """Auth服务配置"""
    enabled: bool = True
    host: str
    port: int
    validate_token_path: str = "/api/auth/validate-human-token"
    service_machine_token: Optional[str] = None
    timeout: int = 10
    token_cache_enabled: bool = True
    token_cache_ttl_minutes: int = 15

    @property
    def validate_url(self) -> str:
        """生成验证token的URL"""
        return f"http://{self.host}:{self.port}{self.validate_token_path}"


class K8SServiceConfig(BaseModel):
    """K8S微服务配置"""
    enabled: bool = True
    host: str = "localhost"
    port: int = 10005
    timeout: int = 30
    scheme: str = "http"

    @property
    def base_url(self) -> str:
        """生成K8S服务基础URL"""
        return f"{self.scheme}://{self.host}:{self.port}/api/k8s"


class WorkflowServiceConfig(BaseModel):
    """Workflow服务配置"""
    host: str
    port: int
    timeout: int = 30

    @property
    def base_url(self) -> str:
        """生成基础URL"""
        return f"http://{self.host}:{self.port}"


class RegistryMenuLevelConfig(BaseModel):
    """菜单层级配置"""
    name: Optional[str] = None
    name_en: Optional[str] = None


class RegistryMenuConfig(BaseModel):
    """菜单配置"""
    id: str
    path: str
    icon: Optional[str] = None
    order: int = 0
    level1: Optional[RegistryMenuLevelConfig] = None
    level2: Optional[RegistryMenuLevelConfig] = None
    level3: Optional[RegistryMenuLevelConfig] = None


class RegistryConfig(BaseModel):
    """Menu注册中心配置"""
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


class StatusSyncConfig(BaseModel):
    """状态同步配置"""
    batch_size: int = 10
    retry_count: int = 3
    retry_interval: int = 2


class AppConfig(BaseModel):
    """应用配置"""
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False


class LoggingConfig(BaseModel):
    """日志配置"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class Config(BaseModel):
    """主配置类"""
    database: DatabaseConfig
    auth_service: AuthServiceConfig
    k8s_service: K8SServiceConfig = K8SServiceConfig()
    workflow_service: WorkflowServiceConfig
    registry: RegistryConfig
    status_sync: StatusSyncConfig = StatusSyncConfig()
    app: AppConfig
    logging: LoggingConfig = LoggingConfig()


_config: Optional[Config] = None


def load_config(config_path: Optional[str] = None) -> Config:
    """
    加载配置文件

    Args:
        config_path: 配置文件路径，默认使用config.yaml

    Returns:
        Config对象
    """
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

    with open(config_path, 'r', encoding='utf-8') as f:
        config_data = yaml.safe_load(f)

    _config = Config(**config_data)

    return _config


def get_config() -> Config:
    """获取配置对象"""
    global _config
    if _config is None:
        return load_config()
    return _config


def reload_config(config_path: Optional[str] = None) -> Config:
    """重新加载配置"""
    global _config
    _config = None
    return load_config(config_path)
