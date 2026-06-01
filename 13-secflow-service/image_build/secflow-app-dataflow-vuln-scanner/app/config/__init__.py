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
    table_prefix: str = "secflow_dataflow_vuln_scanner_"
    pool_size: int = 40
    max_overflow: int = 20
    pool_timeout: int = 30

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
    token_cache_enabled: bool = True
    token_cache_ttl_seconds: int = 300
    token_cache_max_entries: int = 10000
    max_connections: int = 100
    max_keepalive_connections: int = 20
    keepalive_expiry_seconds: int = 15
    retry_count: int = 0

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
    enabled: bool = True
    base_url: str = "http://secflow-platform-fileserver/api/fileserver"
    timeout: int = 10
    data_mount_path: str = "/data"
    project_files_dirname: str = "files"
    dataflow_subproject_name: str = "DATAFLOW_VULN_SCANNER"


class ConfigCenterServiceConfig(BaseModel):
    enabled: bool = True
    base_url: str = "http://secflow-platform-configcenter/api/configcenter"
    timeout: int = 30


class VulnEngineServiceConfig(BaseModel):
    enabled: bool = True
    base_url: str = "http://secflow-platform-vuln"
    submit_path: str = "/api/vuln/public/intake/submissions"
    timeout: int = 30
    service_machine_token: Optional[str] = None

    @property
    def submit_url(self) -> str:
        return f"{self.base_url.rstrip('/')}{self.submit_path}"


class RunsConfig(BaseModel):
    enabled: bool = True


class MenuConfig(BaseModel):
    id: str = "dataflow-vuln-scanner"
    path: str = "/dataflow-vuln-scanner"
    icon: str = "scan-search"
    order: int = 36
    level1_name: str = "漏洞分析"
    level2_name: str = "数据流扫描"
    level3_name: str = ""


class RegistryConfig(BaseModel):
    enabled: bool = False
    menu_service_url: str = "http://secflow-platform-menu"
    service_id: str = "secflow-app-dataflow-vuln-scanner"
    service_name: str = "数据流漏洞扫描服务"
    host: str = "secflow-app-dataflow-vuln-scanner"
    port: int = 80
    maturity: str = "开发中"
    description: str = "提供数据流漏洞扫描任务、配置、调度与执行能力"
    api_prefix: str = "/api/dataflow-vuln-scanner"
    unregister_on_shutdown: bool = False
    heartbeat_interval_seconds: int = 30
    menu: MenuConfig = Field(default_factory=MenuConfig)


class ServiceConfig(BaseModel):
    workspace_base_dir: str = "/data/files"
    # Deprecated compatibility field. Service-side run_vuln_scan.py process
    # timeout enforcement is disabled; only explicit user cancel/delete stops it.
    default_execution_timeout_seconds: int = 0
    execution_cancel_check_interval_seconds: int = 1
    # run_vuln_scan.py can keep working while the API pod or mounted storage has
    # short heartbeat stalls. Treat the process as lost only after a long grace
    # window so transient network/storage jitter does not incorrectly invite
    # users to resume an already-running scan.
    process_heartbeat_stale_after_seconds: int = 300
    trigger_retry_limit: int = 0
    public_api_prefix: str = "/api/dataflow-vuln-scanner"
    admin_proxy_prefix: str = "/api/dataflow-vuln-scanner-admin-proxy"
    default_entry_task_type: str = "package_list"
    default_artifact_subdir: str = "assets"
    default_profile_template_kind: str = "vuln_scan_default"
    allow_absolute_input_refs: bool = False


class SchedulerConfig(BaseModel):
    enabled: bool = True
    # api serves public management traffic only; manager owns registry-based
    # dispatch; worker accepts explicitly assigned HTTP jobs. standalone keeps a
    # single-process development topology while still using registry-based
    # worker discovery/dispatch semantics.
    role: str = Field(default_factory=lambda: os.getenv("SECFLOW_DATAFLOW_ROLE") or os.getenv("ROLE") or "standalone")
    pod_id: str = Field(default_factory=lambda: os.getenv("POD_ID") or os.getenv("HOSTNAME") or "local-pod")
    host_name: str = Field(default_factory=lambda: os.getenv("HOSTNAME") or "localhost")
    pod_namespace: str = Field(default_factory=lambda: os.getenv("POD_NAMESPACE") or "secflow-ns")
    worker_headless_service_name: str = "secflow-app-dataflow-vuln-scanner-worker-headless"
    manager_service_name: str = "secflow-app-dataflow-vuln-scanner-manager"
    manager_service_port: int = 80
    # worker_capacity <= 0 means no scheduler-side concurrency limit.
    worker_capacity: int = 5
    poll_interval_seconds: int = 2
    heartbeat_interval_seconds: int = 5
    worker_timeout_seconds: int = 300
    worker_retention_seconds: int = 1800
    cleanup_interval_seconds: int = 10
    reservation_lease_seconds: int = 30
    worker_queue_depth: int = 0
    dispatch_batch_size: int = 8
    requeue_stuck_dispatch_after_seconds: int = 60
    active_reconcile_interval_seconds: int = 30
    active_reconcile_limit: int = 100


class DataflowWorkerConfig(BaseModel):
    advertise_url_template: str = ""
    api_key: Optional[str] = None
    timeout: int = 30
    dispatch_retry_interval_seconds: int = 2
    dispatch_max_retries: int = 1


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class Config(BaseModel):
    app: AppConfig = Field(default_factory=AppConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    auth_service: AuthServiceConfig = Field(default_factory=AuthServiceConfig)
    project_service: ProjectServiceConfig = Field(default_factory=ProjectServiceConfig)
    fileserver_service: FileserverServiceConfig = Field(default_factory=FileserverServiceConfig)
    configcenter_service: ConfigCenterServiceConfig = Field(default_factory=ConfigCenterServiceConfig)
    vuln_engine_service: VulnEngineServiceConfig = Field(default_factory=VulnEngineServiceConfig)
    runs: RunsConfig = Field(default_factory=RunsConfig)
    registry: RegistryConfig = Field(default_factory=RegistryConfig)
    service: ServiceConfig = Field(default_factory=ServiceConfig)
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)
    dataflow_worker: DataflowWorkerConfig = Field(default_factory=DataflowWorkerConfig)
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


def reset_config() -> None:
    global _config
    _config = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = load_config()
    return _config
