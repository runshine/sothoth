from __future__ import annotations

import os
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
    table_prefix: str = "secflow_aiwf_"
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


class MenuConfig(BaseModel):
    id: str = "ai-agent-framework"
    path: str = "/ai-agent-framework"
    icon: str = "workflow"
    order: int = 35
    level1_name: str = "漏洞分析"
    level2_name: str = "AI工作流"
    level3_name: str = ""


class RegistryConfig(BaseModel):
    enabled: bool = False
    menu_service_url: str = "http://secflow-platform-menu"
    service_id: str = "secflow-platform-ai-agent-framework"
    service_name: str = "AI智能体工作流服务"
    host: str = "secflow-platform-ai-agent-framework"
    port: int = 80
    maturity: str = "开发中"
    description: str = "提供多智能体漏洞工作流定义、触发、执行和调度能力"
    api_prefix: str = "/api/ai-agent-framework"
    unregister_on_shutdown: bool = False
    heartbeat_interval_seconds: int = 30
    menu: MenuConfig = Field(default_factory=MenuConfig)


class ServiceConfig(BaseModel):
    workspace_base_dir: str = "/tmp/secflow-ai-agent-framework"
    default_execution_timeout_seconds: int = 7200
    execution_cancel_check_interval_seconds: int = 1
    trigger_retry_limit: int = 3


class SchedulerConfig(BaseModel):
    enabled: bool = True
    pod_id: str = Field(default_factory=lambda: os.getenv("POD_ID") or os.getenv("HOSTNAME") or "local-pod")
    host_name: str = Field(default_factory=lambda: os.getenv("HOSTNAME") or "localhost")
    worker_capacity: int = 2
    poll_interval_seconds: int = 2
    heartbeat_interval_seconds: int = 5
    worker_timeout_seconds: int = 20
    lease_duration_seconds: int = 30
    cleanup_interval_seconds: int = 10


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class Config(BaseModel):
    app: AppConfig = Field(default_factory=AppConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    auth_service: AuthServiceConfig = Field(default_factory=AuthServiceConfig)
    registry: RegistryConfig = Field(default_factory=RegistryConfig)
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


def reset_config() -> None:
    global _config
    _config = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = load_config()
    return _config
