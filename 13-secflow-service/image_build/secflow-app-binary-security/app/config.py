"""Configuration loader for SecFlow Binary Security."""

from __future__ import annotations

import os
from urllib.parse import urlsplit
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


class HttpClientConfig(BaseModel):
    keepalive_expiry_seconds: int = 5
    max_keepalive_connections: int = 20
    max_connections: int = 100
    retry_count: int = 1


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
    stage_item_sync_reconcile_interval_seconds: int = 30
    readless_reconcile_interval_seconds: int = 300
    heartbeat_update_interval_seconds: int = 15
    task_lease_ttl_seconds: int = 120
    task_reclaim_grace_seconds: int = 180
    task_lease_write_retry_attempts: int = 3
    task_operation_lock_ttl_seconds: int = 60
    task_operation_lock_heartbeat_interval_seconds: int = 15
    stale_operation_requeue_interval_seconds: int = 15
    operation_step_batch_size: int = 10
    worker_ready_loop_stale_seconds: int = 90
    worker_liveness_loop_stale_seconds: int = 180
    downstream_reconcile_grace_seconds: int = 30
    shutdown_grace_seconds: int = 10
    archive_job_concurrency: int = 4
    archive_reclaim_timeout_seconds: int = 300
    archive_reclaim_max_attempts: int = 3
    archive_copy_missing_source_retry_schedule_seconds: list[int] = [60, 120, 180]
    downstream_sync_concurrency: int = 8
    downstream_sync_batch_size: int = 50
    downstream_action_concurrency: int = 8
    downstream_request_timeout_seconds: int = 120
    stage_downstream_sync_max_consecutive_errors: int = 10
    stage_downstream_sync_backoff_base_seconds: int = 2
    stage_downstream_sync_backoff_max_seconds: int = 60
    stage_item_sync_stale_seconds: int = 300
    stage_item_sync_reconcile_batch_size: int = 100
    stage_orchestration_max_consecutive_errors: int = 10
    stage_orchestration_backoff_base_seconds: int = 2
    stage_orchestration_backoff_max_seconds: int = 60
    archive_runtime_reconcile_interval_seconds: int = 30
    archive_runtime_stale_seconds: int = 300
    state_repair_reconcile_interval_seconds: int = 30
    state_repair_reconcile_batch_size: int = 100


class QueueConfig(BaseModel):
    enabled: bool = True
    redis_url: str = "redis://secflow-app-binary-security-redis.secflow-ns.svc.cluster.local:6379/0"
    task_queue_key: str = "secflow:binary-security:tasks"
    task_sync_queue_prefix: str = "bs:task_sync_queue"
    block_timeout_seconds: int = 5
    reconcile_interval_seconds: int = 30
    seed_batch_size: int = 20
    startup_ready_timeout_seconds: int = 60
    startup_retry_interval_seconds: int = 2


class RuntimePolicyConfig(BaseModel):
    pipeline_mode: str = "barrier"
    max_stage_parallelism: int = 4
    max_retries_per_item: int = 2
    continue_on_item_failure: bool = True


class AppConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False
    timeout_keep_alive_seconds: int = 30


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
    base_url: str = "http://secflow-app-dataflow-vuln-scan"
    timeout: int = 60


class KnowledgeGraphAuditConfig(BaseModel):
    base_url: str = "http://codemap-manager.secflow-ns.svc.cluster.local:8090"
    upload_sources_path_template: str = "/uploads/{upload_id}/audit/sources"
    project_sources_path_template: str = "/projects/{db_name}/audit/sources"
    timeout_seconds: int = 60
    default_status_filter: str = "identified"
    default_include_excluded: bool = False


class ServicesConfig(BaseModel):
    firmware_unpacker: SimpleServiceConfig = Field(
        default_factory=lambda: SimpleServiceConfig(base_url="http://secflow-app-firmware-unpacker")
    )
    system_analyse: SimpleServiceConfig = Field(
        default_factory=lambda: SimpleServiceConfig(base_url="http://secflow-app-system-analyse")
    )
    binary_to_source: SimpleServiceConfig = Field(
        default_factory=lambda: SimpleServiceConfig(base_url="http://secflow-app-binary-to-source-manager")
    )
    entry_analyse: SimpleServiceConfig = Field(
        default_factory=lambda: SimpleServiceConfig(base_url="http://secflow-app-entry-analyse")
    )
    dataflow_vuln_scan: VulnerabilityServiceConfig = Field(
        default_factory=VulnerabilityServiceConfig
    )
    knowledge_graph_audit: KnowledgeGraphAuditConfig = Field(
        default_factory=KnowledgeGraphAuditConfig
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
    http_client: HttpClientConfig = Field(default_factory=HttpClientConfig)
    app: AppConfig = Field(default_factory=AppConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


_config: Optional[Config] = None


def validate_downstream_service_base_urls(config: Config) -> None:
    services_to_validate = {
        "firmware_unpacker": config.services.firmware_unpacker.base_url,
        "system_analyse": config.services.system_analyse.base_url,
        "binary_to_source": config.services.binary_to_source.base_url,
        "entry_analyse": config.services.entry_analyse.base_url,
        "dataflow_vuln_scan": config.services.dataflow_vuln_scan.base_url,
    }
    for service_name, raw_url in services_to_validate.items():
        value = str(raw_url or "").strip()
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(
                f"下游服务 {service_name} 的 base_url 非法: {value!r}；期望格式为 http(s)://host[:port]"
            )
        normalized_path = (parsed.path or "").strip()
        if normalized_path and normalized_path != "/":
            raise ValueError(
                f"下游服务 {service_name} 的 base_url 不允许包含路径: {value!r}；"
                "请仅配置服务根，不要包含 /api/... 前缀"
            )


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
    validate_downstream_service_base_urls(_config)
    return _config


def get_config() -> Config:
    return _config or load_config()
