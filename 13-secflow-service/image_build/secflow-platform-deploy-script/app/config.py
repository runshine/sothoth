"""
配置加载模块
"""

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field


class AppConfig(BaseModel):
    """应用配置"""
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False


class AuthServiceConfig(BaseModel):
    """认证服务配置"""
    enabled: bool = True
    host: str = "localhost"
    port: int = 10000
    validate_token_path: str = "/api/auth/validate-token"
    service_machine_token: Optional[str] = None
    timeout: int = 10
    token_cache_enabled: bool = True
    token_cache_ttl_minutes: int = 15

    @property
    def validate_url(self) -> str:
        """获取Token验证URL"""
        return f"http://{self.host}:{self.port}{self.validate_token_path}"


class MenuLevelConfig(BaseModel):
    """菜单级别配置"""
    name: Optional[str] = None
    name_en: Optional[str] = None


class RegistryMenuConfig(BaseModel):
    """注册菜单配置"""
    id: str
    path: str
    icon: Optional[str] = None
    order: int = 0
    level1: Optional[MenuLevelConfig] = None
    level2: Optional[MenuLevelConfig] = None
    level3: Optional[MenuLevelConfig] = None


class RegistryConfig(BaseModel):
    """注册中心配置"""
    enabled: bool = True
    menu_service_url: str = "http://localhost:10003"
    service_id: str = "secflow-deploy-script"
    service_name: str = "部署脚本管理服务"
    host: str = "0.0.0.0"
    port: int = 8080
    maturity: str = "已上线"
    description: str = "提供部署脚本的文件管理功能"
    api_prefix: str = "/api/deploy-script"
    menu: Optional[RegistryMenuConfig] = None


class Config(BaseModel):
    """主配置类"""
    app: AppConfig = Field(default_factory=AppConfig)
    file_root: str = "/app/resource"
    auth_service: AuthServiceConfig = Field(default_factory=AuthServiceConfig)
    registry: RegistryConfig = Field(default_factory=RegistryConfig)


_config: Optional[Config] = None


def load_config(config_path: Optional[str] = None) -> Config:
    """
    加载配置文件

    Args:
        config_path: 配置文件路径，默认从环境变量或默认位置查找

    Returns:
        Config配置对象
    """
    global _config

    if _config is not None:
        return _config

    # 确定配置文件路径
    if config_path is None:
        # 默认查找路径
        possible_paths = [
            "config.yaml",
            os.path.join(os.path.dirname(__file__), "config.yaml"),
            os.path.join(os.path.dirname(__file__), "..", "config.yaml"),
            os.path.join(Path(__file__).parent.parent, "config.yaml"),
        ]
        # 从环境变量读取
        env_config_path = os.environ.get("SECFLOW_CONFIG_PATH")
        if env_config_path:
            possible_paths.insert(0, env_config_path)

        for path in possible_paths:
            if os.path.exists(path):
                config_path = path
                break
    else:
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"配置文件不存在: {config_path}")

    # 加载YAML配置
    config_data = {}
    if config_path and os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            config_data = yaml.safe_load(f) or {}

    # 创建配置对象
    _config = Config(**config_data)

    return _config


def get_config() -> Config:
    """
    获取配置对象（单例模式）

    Returns:
        Config配置对象
    """
    global _config
    if _config is None:
        return load_config()
    return _config


def reset_config():
    """重置配置（用于测试）"""
    global _config
    _config = None
