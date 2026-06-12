"""Configuration loader for chirmera-platform-schedule."""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

import yaml
from pydantic import BaseModel, Field


class DatabaseConfig(BaseModel):
    host: str = "secflow-platform-mysql"
    port: int = 3306
    username: str = "root"
    password: str = ""
    name: str = "secflow"
    table_prefix: str = "secflow_chirmera_platform_schedule_"
    pool_size: int = 10
    max_overflow: int = 20
    url: Optional[str] = None

    @property
    def database_url(self) -> str:
        if self.url:
            return self.url
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


class ProjectServiceConfig(BaseModel):
    base_url: str = "http://secflow-platform-project"
    get_project_path: str = "/api/project"
    timeout: int = 10


class FileserverServiceConfig(BaseModel):
    base_url: str = "http://secflow-platform-fileserver"
    project_input_uploads_path: str = "/api/fileserver/project-input/uploads"
    timeout: int = 30


class AiGatewayServiceConfig(BaseModel):
    base_url: str = "http://gaiasec-llm-gateway"
    # Management-side task key creation endpoint.
    llm_keys_path: str = "/api/aigw/llm-keys"
    # Bearer token used for AI Gateway management-side APIs, not task/work key auth.
    management_bearer_token: Optional[str] = None
    timeout: int = 30


class SecurityConfig(BaseModel):
    task_key_secret_master_key: str = "chirmera-platform-schedule-task-key-master"


class BinarySecurityServiceConfig(BaseModel):
    base_url: str = "http://secflow-app-binary-security"
    timeout: int = 120


class Ai4RedServiceConfig(BaseModel):
    base_url: str = "http://ai4red-platform-service:12345"
    timeout: int = 120


class TuringAppSecurityServiceConfig(BaseModel):
    base_url: str = "http://turing-app-security"
    timeout: int = 120


class RootTaskKeyPolicyConfig(BaseModel):
    capacity_pool_ids: list[int] = Field(default_factory=list)
    root_task_key_max_concurrency: int = 0
    root_task_key_expires_at: Optional[str] = None


class UserTaskDispatchPolicyConfig(BaseModel):
    binary_firmware_e2e: RootTaskKeyPolicyConfig = Field(default_factory=RootTaskKeyPolicyConfig)
    source_scan_e2e: RootTaskKeyPolicyConfig = Field(default_factory=RootTaskKeyPolicyConfig)
    binary_module_e2e: RootTaskKeyPolicyConfig = Field(default_factory=RootTaskKeyPolicyConfig)
    ai4red: RootTaskKeyPolicyConfig = Field(default_factory=RootTaskKeyPolicyConfig)
    ai4apk: RootTaskKeyPolicyConfig = Field(default_factory=RootTaskKeyPolicyConfig)


class MenuLevelConfig(BaseModel):
    name: Optional[str] = None
    name_en: Optional[str] = None


class MenuConfig(BaseModel):
    id: str = "chirmera-platform-schedule"
    path: str = "/chirmera-platform-schedule"
    icon: str = "schedule"
    order: int = 20
    level1: MenuLevelConfig = Field(default_factory=lambda: MenuLevelConfig(name="平台服务", name_en="Platform"))
    level2: MenuLevelConfig = Field(default_factory=lambda: MenuLevelConfig(name="任务调度", name_en="Schedule"))
    level3: MenuLevelConfig = Field(default_factory=lambda: MenuLevelConfig(name="LiteLLM Key", name_en="LiteLLM Key"))


class RegistryConfig(BaseModel):
    enabled: bool = True
    menu_service_url: str = "http://secflow-platform-menu"
    service_id: str = "chirmera-platform-schedule"
    service_name: str = "Chirmera 平台调度服务"
    host: str = "chirmera-platform-schedule"
    port: int = 80
    maturity: str = "开发中"
    description: str = "统一管理 REST 调度任务与 LiteLLM 虚拟 Key"
    api_prefix: str = "/api/chirmera-platform-schedule"
    unregister_on_shutdown: bool = False
    menu: MenuConfig = Field(default_factory=MenuConfig)


class AppConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class HttpClientConfig(BaseModel):
    max_connections: int = 100
    max_keepalive_connections: int = 20
    keepalive_expiry_seconds: float = 30.0
    retry_count: int = 0


class SchedulerConfig(BaseModel):
    enabled: bool = True
    poll_interval_seconds: int = 15
    batch_size: int = 20
    execution_timeout_seconds: int = 120
    max_dispatch_workers: int = 4
    leader_lease_seconds: int = 15
    leader_renew_seconds: int = 5
    reclaim_interval_seconds: int = 15
    delay_promote_batch_size: int = 50
    ready_backfill_batch_size: int = 100


class RedisConfig(BaseModel):
    enabled: bool = True
    url: str = "redis://ecflow-platform-redis:6379/0"
    key_prefix: str = "chirmera:schedule"
    socket_timeout_seconds: int = 5


class RuntimeConfig(BaseModel):
    role: str = "all"
    redis_degraded_ready: bool = True


class WorkerConfig(BaseModel):
    concurrency: int = 32
    prefetch: int = 1
    lease_seconds: int = 45
    heartbeat_seconds: int = 10
    drain_timeout_seconds: int = 60
    idle_sleep_seconds: float = 0.5
    db_fallback_batch_size: int = 20


class UserTaskSyncConfig(BaseModel):
    enabled: bool = True
    lease_seconds: int = 45
    heartbeat_interval_seconds: int = 10
    db_fallback_batch_size: int = 20
    queue_pop_timeout_seconds: int = 1
    reclaim_batch_size: int = 50
    dispatching_seconds: int = 5
    running_seconds: int = 15
    paused_seconds: int = 60
    terminal_verify_seconds: int = 10
    retry_initial_seconds: int = 30
    retry_max_seconds: int = 300
    failure_threshold: int = 5


class LimitsConfig(BaseModel):
    project_default_concurrency: int = 16
    target_default_concurrency: int = 8
    queue_requeue_delay_seconds: int = 10


class RetryConfig(BaseModel):
    default_max_attempts: int = 3
    default_initial_delay_seconds: int = 10
    default_max_delay_seconds: int = 300


class LiteLLMConfig(BaseModel):
    api_base: str = "http://litellm:4000"
    admin_key: str = ""
    timeout_seconds: int = 30
    create_key_path: str = "/key/generate"
    list_key_path: str = "/key/list"
    disable_key_path: str = "/key/delete"
    get_key_path: str = "/key/info"
    default_duration: str = "30d"
    verify_tls: bool = True


class Config(BaseModel):
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    auth_service: AuthServiceConfig = Field(default_factory=AuthServiceConfig)
    project_service: ProjectServiceConfig = Field(default_factory=ProjectServiceConfig)
    fileserver_service: FileserverServiceConfig = Field(default_factory=FileserverServiceConfig)
    aigw_service: AiGatewayServiceConfig = Field(default_factory=AiGatewayServiceConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    binary_security_service: BinarySecurityServiceConfig = Field(default_factory=BinarySecurityServiceConfig)
    ai4red_service: Ai4RedServiceConfig = Field(default_factory=Ai4RedServiceConfig)
    turing_app_security_service: TuringAppSecurityServiceConfig = Field(default_factory=TuringAppSecurityServiceConfig)
    user_task_dispatch_policy: UserTaskDispatchPolicyConfig = Field(default_factory=UserTaskDispatchPolicyConfig)
    registry: RegistryConfig = Field(default_factory=RegistryConfig)
    app: AppConfig = Field(default_factory=AppConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    http_client: HttpClientConfig = Field(default_factory=HttpClientConfig)
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    worker: WorkerConfig = Field(default_factory=WorkerConfig)
    user_task_sync: UserTaskSyncConfig = Field(default_factory=UserTaskSyncConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    retry: RetryConfig = Field(default_factory=RetryConfig)
    litellm: LiteLLMConfig = Field(default_factory=LiteLLMConfig)


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
