"""Configuration loader for SecFlow Binary Security."""

from __future__ import annotations

import os
from typing import Optional

import yaml
from pydantic import BaseModel, Field


class DatabaseConfig(BaseModel):
    host: str
    port: int
    username: str
    password: str
    name: str
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
    menu_service_url: str = "http://secflow-platform-menu"
    service_id: str = "secflow-app-binary-security"
    service_name: str = "二进制安全编排服务"
    host: str = "secflow-app-binary-security"
    port: int = 80
    maturity: str = "开发中"
    description: str = "面向固件与二进制软件包的统一安全分析编排服务"
    api_prefix: str = "/api/app/binary-security"
    menu: Optional[RegistryMenuConfig] = None


class StorageConfig(BaseModel):
    project_root_template: str = "/data/files/{project_id}"
    app_root_name: str = "app/secflow-app-binary-security"
    fileserver_subproject_name: str = "__binary_security__"
    require_input_exists: bool = True
    min_free_disk_bytes: int = 1073741824
    max_upload_file_bytes: int = 2147483648
    max_source_archive_bytes: int = 2147483648
    max_source_extract_bytes: int = 8589934592
    max_source_extract_files: int = 200000


class SchedulerConfig(BaseModel):
    enabled: bool = True
    poll_interval_seconds: int = 5
    task_concurrency: int = 2
    stage_poll_interval_seconds: int = 5
    downstream_reconcile_interval_seconds: int = 30
    heartbeat_update_interval_seconds: int = 15
    downstream_reconcile_grace_seconds: int = 30
    shutdown_grace_seconds: int = 10
    archive_job_concurrency: int = 4
    downstream_sync_concurrency: int = 8
    downstream_sync_batch_size: int = 50
    downstream_action_concurrency: int = 8
    downstream_request_timeout_seconds: int = 120


class QueueConfig(BaseModel):
    enabled: bool = True
    redis_url: str = "redis://redis.sothothv2-ns.svc.cluster.local:6379/0"
    task_queue_key: str = "secflow:binary-security:tasks"
    action_queue_key: str = "secflow:binary-security:actions"
    block_timeout_seconds: int = 5
    reconcile_interval_seconds: int = 30
    seed_batch_size: int = 20


class RuntimePolicyConfig(BaseModel):
    pipeline_mode: str = "barrier"
    max_stage_parallelism: int = 4
    max_retries_per_item: int = 2
    continue_on_item_failure: bool = True


class AppConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False


class LoggingConfig(BaseModel):
    level: str = "INFO"


class SimpleServiceConfig(BaseModel):
    base_url: str
    timeout: int = 30


class FileserverServiceConfig(BaseModel):
    base_url: str = "http://secflow-platform-fileserver/api/fileserver"
    timeout: int = 30
    data_mount_path: str = "/data"
    project_files_dirname: str = "files"
    subproject_name: str = "__binary_security__"


class VulnerabilityServiceConfig(BaseModel):
    base_url: str = "http://secflow-app-dataflow-vuln-scanner"
    timeout: int = 60


class ServicesConfig(BaseModel):
    firmware_unpacker: SimpleServiceConfig = Field(
        default_factory=lambda: SimpleServiceConfig(base_url="http://secflow-app-firmware-unpacker")
    )
    system_analyse: SimpleServiceConfig = Field(
        default_factory=lambda: SimpleServiceConfig(base_url="http://secflow-app-system-analyse/api/app/system-analyse")
    )
    binary_to_source: SimpleServiceConfig = Field(
        default_factory=lambda: SimpleServiceConfig(base_url="http://secflow-app-binary-to-source-manager/api/app/binary-to-source")
    )
    entry_analyse: SimpleServiceConfig = Field(
        default_factory=lambda: SimpleServiceConfig(base_url="http://secflow-app-entry-analyse/api/app/entry-analyse")
    )
    dataflow_analyse: SimpleServiceConfig = Field(
        default_factory=lambda: SimpleServiceConfig(base_url="http://secflow-app-dataflow-analyse/api/app/dataflow-analyse")
    )
    dataflow_vuln_scanner: VulnerabilityServiceConfig = Field(
        default_factory=VulnerabilityServiceConfig
    )
    fileserver: FileserverServiceConfig = Field(default_factory=FileserverServiceConfig)


class Config(BaseModel):
    database: DatabaseConfig
    auth_service: AuthServiceConfig
    project_service: ProjectServiceConfig
    registry: RegistryConfig = Field(default_factory=RegistryConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)
    queue: QueueConfig = Field(default_factory=QueueConfig)
    runtime_policy: RuntimePolicyConfig = Field(default_factory=RuntimePolicyConfig)
    services: ServicesConfig = Field(default_factory=ServicesConfig)
    app: AppConfig = Field(default_factory=AppConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


_config: Optional[Config] = None


def load_config(config_path: Optional[str] = None) -> Config:
    global _config
    if _config is not None:
        return _config

    if config_path is None:
        candidates = [
            os.environ.get("SECFLOW_BINARY_SECURITY_CONFIG"),
            "config.yaml",
            os.path.join(os.path.dirname(__file__), "..", "config.yaml"),
        ]
        config_path = next((path for path in candidates if path and os.path.exists(path)), None)

    if not config_path:
        raise FileNotFoundError("binary security 配置文件未找到")

    with open(config_path, "r", encoding="utf-8") as file:
        _config = Config(**yaml.safe_load(file))
    return _config


def get_config() -> Config:
    return _config or load_config()
