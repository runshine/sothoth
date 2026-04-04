"""
Code Server Manager - 配置模块
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
    name: str = "codeserver_manager"
    table_prefix: str = "code_server_"
    pool_size: int = 10
    max_overflow: int = 20
    # SQLite配置
    path: str = "./codeserver_manager.db"

    @property
    def url(self) -> str:
        """生成数据库连接URL"""
        if self.type == "mysql":
            return f"mysql+pymysql://{self.username}:{self.password}@{self.host}:{self.port}/{self.name}"
        else:
            return f"sqlite:///{self.path}"


class KubernetesConfig(BaseModel):
    """K8S配置"""
    in_cluster: bool = False
    kubeconfig: Optional[str] = None
    connection_timeout: int = 30


class K8sServiceConfig(BaseModel):
    """platform-k8s 服务配置"""
    host: str = "secflow-platform-k8s"
    port: int = 80
    timeout: int = 30


class AuthServiceConfig(BaseModel):
    """认证服务配置"""
    host: str = "secflow-platform-auth"
    port: int = 80
    validate_token_path: str = "/api/auth/validate-token"
    service_machine_token: Optional[str] = None
    timeout: int = 10

    @property
    def validate_url(self) -> str:
        """Token验证URL"""
        return f"http://{self.host}:{self.port}{self.validate_token_path}"


class ConfigCenterServiceConfig(BaseModel):
    """配置中心服务配置"""
    enabled: bool = True
    host: str = "secflow-platform-configcenter"
    port: int = 80
    timeout: int = 30

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}/api/configcenter"


class ProjectServiceConfig(BaseModel):
    """项目服务配置"""
    enabled: bool = True
    host: str = "secflow-platform-project"
    port: int = 80
    timeout: int = 15

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}/api/project"


class CodeServerResources(BaseModel):
    """Code Server资源限制"""
    cpu: str = "100m"
    memory: str = "256Mi"


class CodeServerConfig(BaseModel):
    """Code Server配置"""
    image: str = "codercom/code-server:latest"
    image_pull_policy: str = "Always"
    service_type: str = "ClusterIP"  # ClusterIP, NodePort, LoadBalancer
    service_port: int = 80
    container_port: int = 8080
    env: Dict[str, str] = Field(default_factory=dict)
    # Code Server镜像专属环境变量配置
    code_server_env: Dict[str, Any] = Field(default_factory=lambda: {
        "PUID": 1000,
        "PGID": 1000,
        "TZ": "Asia/Shanghai",
        "DEFAULT_WORKSPACE": "/config/workspace",
        "PWA_APPNAME": "code-server"
    })
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
    base_domain: str = "code-server.sothothv2.com"
    tls_secret_name: str = "wildcard-code-server.sothothv2.com-tls"
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
    port: int = 8080
    debug: bool = False


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
    id: str = "vscode-web-manager"
    path: str = "/vscode-web-manager"
    icon: str = "code"
    order: int = 0
    parent_id: Optional[str] = None
    # 一级菜单
    level1: MenuLevelConfig = Field(default_factory=lambda: MenuLevelConfig(name="开发工具", name_en="DevTools"))
    # 二级菜单
    level2: MenuLevelConfig = Field(default_factory=lambda: MenuLevelConfig(name="VSCode Web", name_en="VSCode Web"))
    # 三级菜单
    level3: MenuLevelConfig = Field(default_factory=MenuLevelConfig)


class RegistryConfig(BaseModel):
    """服务注册配置"""
    enabled: bool = False
    menu_service_url: str = "http://secflow-menu:5000"
    service_id: str = "vscode-web-manager"
    service_name: str = "VSCode Web管理器"
    host: str = "0.0.0.0"
    port: int = 10004
    maturity: str = "开发中"  # 可选: 已上线、开发中、规划中
    description: str = "VSCode Web实例管理微服务"
    api_prefix: str = "/api/code-server"
    menu: MenuConfig = Field(default_factory=MenuConfig)


class Config(BaseModel):
    """主配置类"""
    app: AppConfig = Field(default_factory=AppConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    kubernetes: KubernetesConfig = Field(default_factory=KubernetesConfig)
    k8s_service: K8sServiceConfig = Field(default_factory=K8sServiceConfig)
    auth_service: AuthServiceConfig = Field(default_factory=AuthServiceConfig)
    configcenter_service: ConfigCenterServiceConfig = Field(default_factory=ConfigCenterServiceConfig)
    project_service: ProjectServiceConfig = Field(default_factory=ProjectServiceConfig)
    code_server: CodeServerConfig = Field(default_factory=CodeServerConfig)
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
        # 默认查找当前目录或父目录的config.yaml
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
        # 使用默认配置
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
