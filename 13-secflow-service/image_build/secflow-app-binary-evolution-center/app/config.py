from __future__ import annotations

import os
import re
from typing import Any, Dict, Optional

import yaml
from pydantic import BaseModel, Field


class AppConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False


class DatabaseConfig(BaseModel):
    url: Optional[str] = None
    host: str = "127.0.0.1"
    port: int = 3306
    username: str = "secflow"
    password: str = ""
    name: str = "secflow"
    table_prefix: str = "secflow_binary_evolution_"
    pool_size: int = 10
    max_overflow: int = 20

    @property
    def sqlalchemy_url(self) -> str:
        if self.url:
            return self.url
        return f"mysql+pymysql://{self.username}:{self.password}@{self.host}:{self.port}/{self.name}"


class AuthServiceConfig(BaseModel):
    enabled: bool = True
    host: str = "secflow-platform-auth"
    port: int = 80
    validate_human_token_path: str = "/api/auth/validate-human-token"
    validate_machine_token_path: str = "/api/auth/validate-token"
    service_machine_token: Optional[str] = None
    timeout: int = 10

    @property
    def human_validate_url(self) -> str:
        return f"http://{self.host}:{self.port}{self.validate_human_token_path}"

    @property
    def machine_validate_url(self) -> str:
        return f"http://{self.host}:{self.port}{self.validate_machine_token_path}"


class ProjectServiceConfig(BaseModel):
    enabled: bool = True
    host: str = "secflow-platform-project"
    port: int = 80
    get_project_path: str = "/api/project"
    health_path: str = "/api/project/health"
    timeout: int = 10

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def health_url(self) -> str:
        return f"{self.base_url}{self.health_path}"


class FileserverServiceConfig(BaseModel):
    data_mount_path: str = "/data"
    project_files_dirname: str = "files"
    dataflow_subproject_name: str = "DATAFLOW_VULN_SCANNER"
    evolution_subproject_name: str = "secflow-app-binary-evolution-center"


class MenuConfig(BaseModel):
    id: str = "binary-evolution-center"
    path: str = "/binary-evolution-center"
    icon: str = "sparkles"
    order: int = 38
    level1_name: str = "安全执行"
    level2_name: str = "进化中心"
    level3_name: str = ""


class RegistryConfig(BaseModel):
    enabled: bool = False
    menu_service_url: str = "http://secflow-platform-menu"
    service_id: str = "secflow-app-binary-evolution-center"
    service_name: str = "二进制安全进化中心"
    host: str = "secflow-app-binary-evolution-center"
    port: int = 80
    maturity: str = "开发中"
    description: str = "围绕数据流漏洞结果做多轮智能体进化"
    api_prefix: str = "/api/app/binary-evolution"
    unregister_on_shutdown: bool = False
    heartbeat_interval_seconds: int = 30
    menu: MenuConfig = Field(default_factory=MenuConfig)


class DataflowVulnServiceConfig(BaseModel):
    base_url: str = "http://secflow-app-dataflow-vuln-scanner"
    api_prefix: str = "/api/dataflow-vuln-scanner"
    timeout: int = 30

    @property
    def api_base(self) -> str:
        return f"{self.base_url.rstrip('/')}{self.api_prefix}"


class VulnServiceConfig(BaseModel):
    base_url: str = "http://secflow-platform-vuln"
    api_prefix: str = "/api/vuln"
    timeout: int = 30

    @property
    def api_base(self) -> str:
        return f"{self.base_url.rstrip('/')}{self.api_prefix}"


class ServiceConfig(BaseModel):
    workspace_base_dir: str = "/data/files"
    public_api_prefix: str = "/api/app/binary-evolution"
    default_max_concurrent_tasks: int = 2
    default_max_concurrent_source_tasks: int = 4
    default_min_rounds: int = 1
    default_max_rounds: int = 3
    default_evolution_agent_model: str = "pi-agent"
    default_evolution_agent_timeout_seconds: int = 1800
    default_context_window: int = 131072
    preview_auto_expand_missing_cases: bool = True


class SchedulerConfig(BaseModel):
    enabled: bool = True
    role: str = Field(default_factory=lambda: os.getenv("SECFLOW_BINARY_EVOLUTION_ROLE") or os.getenv("ROLE") or "standalone")
    pod_id: str = Field(default_factory=lambda: os.getenv("POD_ID") or os.getenv("HOSTNAME") or "local-pod")
    host_name: str = Field(default_factory=lambda: os.getenv("HOSTNAME") or "localhost")
    worker_capacity: int = 2
    poll_interval_seconds: int = 2
    heartbeat_interval_seconds: int = 5
    worker_timeout_seconds: int = 300
    cleanup_interval_seconds: int = 10
    retry_delay_seconds: int = 15


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class Config(BaseModel):
    app: AppConfig = Field(default_factory=AppConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    auth_service: AuthServiceConfig = Field(default_factory=AuthServiceConfig)
    project_service: ProjectServiceConfig = Field(default_factory=ProjectServiceConfig)
    fileserver_service: FileserverServiceConfig = Field(default_factory=FileserverServiceConfig)
    registry: RegistryConfig = Field(default_factory=RegistryConfig)
    dataflow_vuln_service: DataflowVulnServiceConfig = Field(default_factory=DataflowVulnServiceConfig)
    vuln_service: VulnServiceConfig = Field(default_factory=VulnServiceConfig)
    service: ServiceConfig = Field(default_factory=ServiceConfig)
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


_config: Optional[Config] = None


def _candidate_paths(config_path: Optional[str]) -> list[str]:
    if config_path:
        return [config_path]
    return [
        os.environ.get("CONFIG_PATH", ""),
        "config.yaml",
        os.path.join(os.path.dirname(__file__), "..", "config.yaml"),
        os.path.join(os.path.dirname(__file__), "..", "..", "config.yaml"),
    ]


def _resolve_env_vars(text: str) -> str:
    def _replace(match: re.Match) -> str:
        name = match.group(1)
        return os.environ.get(name, match.group(0))

    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", _replace, text)


def load_config(config_path: Optional[str] = None) -> Config:
    global _config
    if _config is not None:
        return _config
    for path in _candidate_paths(config_path):
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as file:
                raw_text = file.read()
            data: Dict[str, Any] = yaml.safe_load(_resolve_env_vars(raw_text)) or {}
            _config = Config(**data)
            return _config
    _config = Config()
    return _config


def get_config() -> Config:
    global _config
    if _config is None:
        _config = load_config()
    return _config
