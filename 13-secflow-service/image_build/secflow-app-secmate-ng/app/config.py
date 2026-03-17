"""
Secmate-NG Manager - 配置模块
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any

import yaml
from pydantic import BaseModel, Field


class DatabaseConfig(BaseModel):
    """数据库配置"""
    type: str = "sqlite"  # mysql 或 sqlite
    # MySQL配置
    host: str = "localhost"
    port: int = 3306
    username: str = "root"
    password: str = ""
    name: str = "secmate_ng_manager"
    table_prefix: str = "secflow_app_secmate_ng_"
    pool_size: int = 10
    max_overflow: int = 20
    # SQLite配置
    path: str = "./secmate_ng_manager.db"

    @property
    def url(self) -> str:
        """
        生成数据库连接URL

        支持环境变量覆盖配置文件中的值：
        - DB_HOST: 数据库主机
        - DB_PORT: 数据库端口
        - DB_USERNAME: 数据库用户名
        - DB_PASSWORD: 数据库密码（强烈建议使用环境变量）
        - DB_NAME: 数据库名称

        优先级：环境变量 > 配置文件值
        """
        # 支持环境变量覆盖（向后兼容）
        host = os.getenv("DB_HOST", self.host)
        port = int(os.getenv("DB_PORT", str(self.port)))
        username = os.getenv("DB_USERNAME", self.username)
        password = os.getenv("DB_PASSWORD", self.password)
        name = os.getenv("DB_NAME", self.name)

        if self.type == "mysql":
            return f"mysql+pymysql://{username}:{password}@{host}:{port}/{name}"
        else:
            return f"sqlite:///{self.path}"


class K8sApiServiceConfig(BaseModel):
    """K8s API Service配置（通过secflow-platform-k8s管理K8s资源）"""
    host: str = "secflow-platform-k8s"
    port: int = 80
    timeout: int = 30
    use_user_token: bool = True

    @property
    def base_url(self) -> str:
        """生成API基础URL"""
        return f"http://{self.host}:{self.port}"


class AuthServiceConfig(BaseModel):
    """认证服务配置"""
    enabled: bool = True
    host: str = "secflow-platform-auth"
    port: int = 80
    validate_token_path: str = "/api/auth/validate-human-token"
    timeout: int = 10
    token_cache_enabled: bool = True
    token_cache_ttl_minutes: int = 15

    @property
    def validate_url(self) -> str:
        """生成Token验证URL"""
        return f"http://{self.host}:{self.port}{self.validate_token_path}"


class SecmateNgConfig(BaseModel):
    """Secmate-NG配置"""
    image: str = "your-registry/secmate-ng:latest"
    image_pull_policy: str = "Always"
    service_type: str = "ClusterIP"  # ClusterIP, NodePort, LoadBalancer
    service_port: int = 80
    container_port: int = 80
    # 通用环境变量（所有实例共享）
    common_env: Dict[str, str] = Field(default_factory=dict)
    # Secmate-NG 特定环境变量（镜像默认值）
    default_secmate_env: Dict[str, Any] = Field(default_factory=dict)
    resources: Dict[str, Dict[str, str]] = Field(default_factory=lambda: {
        "requests": {"cpu": "100m", "memory": "256Mi"},
        "limits": {"cpu": "1000m", "memory": "2Gi"}
    })


class PVCConfig(BaseModel):
    """PVC配置"""
    storage_class: str = "standard"
    storage_size: str = "5Gi"
    access_mode: str = "ReadWriteOnce"


class IngressConfig(BaseModel):
    """Ingress配置"""
    base_domain: str = "secmate-ng.sothothv2.com"
    tls_secret_name: str = "wildcard-secmate-ng.sothothv2.com-tls"
    ingress_class: str = "nginx"
    tls_enabled: bool = True


class TasksConfig(BaseModel):
    """任务管理配置"""
    retention_days: int = 7
    cleanup_interval_hours: int = 24
    max_concurrent_tasks: int = 10


class AppConfig(BaseModel):
    """应用配置"""
    host: str = "0.0.0.0"
    port: int = 10011
    debug: bool = False
    allowed_origins: list = Field(default_factory=list)  # CORS允许的源列表


class LoggingConfig(BaseModel):
    """日志配置"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class MenuLevelConfig(BaseModel):
    """菜单层级配置"""
    name: Optional[str] = None
    name_en: Optional[str] = None


class MenuConfig(BaseModel):
    """菜单配置"""
    id: str = "secmate-ng-manager"
    path: str = "/secmate-ng-manager"
    icon: str = "security"
    order: int = 20
    parent_id: Optional[str] = None
    level1: MenuLevelConfig = Field(default_factory=lambda: MenuLevelConfig(name="安全工具", name_en="SecurityTools"))
    level2: MenuLevelConfig = Field(default_factory=lambda: MenuLevelConfig(name="Secmate-NG", name_en="Secmate-NG"))
    level3: MenuLevelConfig = Field(default_factory=MenuLevelConfig)


class RegistryConfig(BaseModel):
    """服务注册配置"""
    enabled: bool = False
    menu_service_url: str = "http://secflow-platform-menu:80"
    service_id: str = "secmate-ng-manager"
    service_name: str = "Secmate-NG管理器"
    host: str = "0.0.0.0"
    port: int = 10011
    maturity: str = "开发中"
    description: str = "Secmate-NG实例管理微服务"
    api_prefix: str = "/api/app/secmate-ng"
    menu: MenuConfig = Field(default_factory=MenuConfig)


class Config(BaseModel):
    """主配置类"""
    app: AppConfig = Field(default_factory=AppConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    k8s_api_service: K8sApiServiceConfig = Field(default_factory=K8sApiServiceConfig)
    auth_service: AuthServiceConfig = Field(default_factory=AuthServiceConfig)
    secmate_ng: SecmateNgConfig = Field(default_factory=SecmateNgConfig)
    pvc: PVCConfig = Field(default_factory=PVCConfig)
    ingress: IngressConfig = Field(default_factory=IngressConfig)
    tasks: TasksConfig = Field(default_factory=TasksConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    registry: RegistryConfig = Field(default_factory=RegistryConfig)


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
            os.path.join(os.path.dirname(__file__), "..", "config.yaml"),
            os.path.join(os.path.dirname(__file__), "..", "..", "config.yaml"),
        ]
        for path in possible_paths:
            if os.path.exists(path):
                config_path = path
                break

    if config_path is None or not os.path.exists(config_path):
        _config = Config()
        return _config

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
