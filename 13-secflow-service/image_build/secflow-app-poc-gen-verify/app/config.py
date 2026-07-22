"""Config for secflow-app-poc-gen-verify.

Two layers coexist:
- `Settings` (env-driven, @lru_cache): runtime knobs — state_root, poc_bin, model,
  timeout, host/port, api_prefix. Used by the API + worker subprocess invocation.
- `service.yaml` (`get_service_yaml()`): DB + registry registration, shared with
  the rest of the SecFlow platform. Loaded once, module-level singleton.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

logger = logging.getLogger("poc.config")

SERVICE_YAML_PATH = os.environ.get("SERVICE_YAML", "/app/service.yaml")


# ─── env-driven runtime settings ────────────────────────────────────────────

class Settings:
    def __init__(self) -> None:
        self.state_root = Path(os.getenv("POC_GEN_VERIFY_STATE_ROOT", "/var/lib/secflow-poc-gen-verify"))
        self.workspace_root = Path(os.getenv("POC_GEN_VERIFY_WORKSPACE", "/workspace"))
        # fileserver shared volume (mounted in pods at /data); per-project work dirs
        # are generated under <fileserver_root>/<project_id>/app/secflow-app-poc-gen-verify/workspaces/
        self.fileserver_root = Path(os.getenv("POC_GEN_VERIFY_FILESERVER_ROOT", "/data/files"))
        self.default_model = os.getenv("POC_GEN_VERIFY_CLAUDE_MODEL", "glm-5.2")
        self.poc_bin = os.getenv("POC_GEN_VERIFY_POC_BIN", "poc")
        self.host = os.getenv("POC_GEN_VERIFY_HOST", "0.0.0.0")
        self.port = int(os.getenv("POC_GEN_VERIFY_PORT", "8080"))
        self.api_prefix = os.getenv("POC_GEN_VERIFY_API_PREFIX", "/api/app/poc-gen-verify")
        self.service_id = os.getenv("POC_GEN_VERIFY_SERVICE_ID", "secflow-app-poc-gen-verify")


@lru_cache
def get_config() -> Settings:
    s = Settings()
    s.state_root.mkdir(parents=True, exist_ok=True)
    (s.state_root / "tasks").mkdir(parents=True, exist_ok=True)
    return s


# ─── service.yaml dataclasses (DB + registry) ───────────────────────────────

@dataclass
class DbConfig:
    host: str = "127.0.0.1"
    port: int = 3306
    username: str = "secflow"
    password: str = ""
    name: str = "secflow"
    pool_size: int = 5
    max_overflow: int = 10

    @property
    def url(self) -> str:
        return f"mysql+pymysql://{self.username}:{self.password}@{self.host}:{self.port}/{self.name}?charset=utf8mb4"


@dataclass
class AuthConfig:
    host: str = "secflow-platform-auth"
    port: int = 80
    validate_token_path: str = "/api/auth/validate-token"
    service_machine_token: str = ""
    timeout: int = 10
    token_cache_enabled: bool = True
    token_cache_ttl_minutes: int = 15

    @property
    def validate_url(self) -> str:
        return f"http://{self.host}:{self.port}{self.validate_token_path}"


@dataclass
class MenuLevelConfig:
    name: Optional[str] = None
    name_en: Optional[str] = None


@dataclass
class MenuConfig:
    id: str = "app-poc-gen-verify"
    path: str = "/app/poc-gen-verify"
    icon: str = "bug"
    order: int = 115
    level1: MenuLevelConfig = field(default_factory=MenuLevelConfig)
    level2: MenuLevelConfig = field(default_factory=MenuLevelConfig)
    level3: MenuLevelConfig = field(default_factory=MenuLevelConfig)


@dataclass
class RegistryConfig:
    enabled: bool = True
    menu_service_url: str = "http://secflow-platform-menu:80"
    service_id: str = "secflow-app-poc-gen-verify"
    service_name: str = "PoC 生成与验证服务"
    host: str = "secflow-app-poc-gen-verify"
    port: int = 80
    maturity: str = "alpha"
    description: str = ""
    api_prefix: str = "/api/app/poc-gen-verify"
    unregister_on_shutdown: bool = False
    heartbeat_interval_seconds: int = 30
    menu: MenuConfig = field(default_factory=MenuConfig)


@dataclass
class EngineConfig:
    """漏洞判定引擎契约（Contract v2.3）相关配置。

    engine.name 必须与平台管理员预注册的 engine_name 完全一致（契约 §5.1 C6）。
    所有字段为部署期静态参数，由 service.yaml `engine` 段 + 环境变量覆盖。
    """
    name: str = "secflow-app-poc-gen-verify"
    version: str = "1.0.0"
    endpoint_prefix: str = "/api/app/poc-gen-verify/intake"
    heartbeat_url: str = "http://secflow-platform-vuln/api/vuln/internal/vuln-confirm/engines/heartbeat"
    heartbeat_interval_seconds: int = 30
    heartbeat_request_timeout_seconds: float = 5.0
    results_push_url: str = "http://secflow-platform-vuln/api/vuln/internal/vuln-confirm/results/push"
    results_push_timeout_seconds: float = 5.0
    vuln_categories_url: str = "http://secflow-platform-vuln/api/vuln/vuln-categories"
    vuln_categories_timeout_seconds: float = 5.0
    vuln_categories_cache_ttl_seconds: int = 1800
    # 路径A（GDB 触发崩溃 = 内存安全类）默认分类候选；推送前经接口6校验存在才填
    emit_confirmed_category: bool = True
    default_confirmed_category: str = "内存安全类型"


@dataclass
class AppConfig:
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False


@dataclass
class ServiceYaml:
    database: DbConfig = field(default_factory=DbConfig)
    auth_service: AuthConfig = field(default_factory=AuthConfig)
    registry: RegistryConfig = field(default_factory=RegistryConfig)
    engine: EngineConfig = field(default_factory=EngineConfig)
    app: AppConfig = field(default_factory=AppConfig)


def _parse_menu(raw: Dict[str, Any]) -> MenuConfig:
    def parse_level(d: Any) -> MenuLevelConfig:
        if isinstance(d, dict):
            return MenuLevelConfig(name=d.get("name"), name_en=d.get("name_en"))
        return MenuLevelConfig()
    return MenuConfig(
        id=raw.get("id", "app-poc-gen-verify"),
        path=raw.get("path", "/app/poc-gen-verify"),
        icon=raw.get("icon", "bug"),
        order=int(raw.get("order", 115)),
        level1=parse_level(raw.get("level1", {})),
        level2=parse_level(raw.get("level2", {})),
        level3=parse_level(raw.get("level3", {})),
    )


def load_service_yaml(yaml_path: str = SERVICE_YAML_PATH) -> ServiceYaml:
    """Load service.yaml. Falls back to defaults if file not found."""
    p = Path(yaml_path)
    if not p.is_file():
        logger.warning("service.yaml not found at %s, using defaults", yaml_path)
        return ServiceYaml()
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        logger.warning("Failed to parse service.yaml: %s, using defaults", exc)
        return ServiceYaml()

    db_raw = raw.get("database", {})
    db = DbConfig(
        host=db_raw.get("host", "127.0.0.1"),
        port=int(db_raw.get("port", 3306)),
        username=db_raw.get("username", "secflow"),
        password=db_raw.get("password", ""),
        name=db_raw.get("name", "secflow"),
        pool_size=int(db_raw.get("pool_size", 5)),
        max_overflow=int(db_raw.get("max_overflow", 10)),
    )

    auth_raw = raw.get("auth_service", {})
    auth = AuthConfig(
        host=auth_raw.get("host", "secflow-platform-auth"),
        port=int(auth_raw.get("port", 80)),
        validate_token_path=auth_raw.get("validate_token_path", "/api/auth/validate-token"),
        service_machine_token=auth_raw.get("service_machine_token", ""),
        timeout=int(auth_raw.get("timeout", 10)),
        token_cache_enabled=bool(auth_raw.get("token_cache_enabled", True)),
        token_cache_ttl_minutes=int(auth_raw.get("token_cache_ttl_minutes", 15)),
    )

    reg_raw = raw.get("registry", {})
    registry = RegistryConfig(
        enabled=bool(reg_raw.get("enabled", True)),
        menu_service_url=reg_raw.get("menu_service_url", "http://secflow-platform-menu:80"),
        service_id=reg_raw.get("service_id", "secflow-app-poc-gen-verify"),
        service_name=reg_raw.get("service_name", "PoC 生成与验证服务"),
        host=reg_raw.get("host", "secflow-app-poc-gen-verify"),
        port=int(reg_raw.get("port", 80)),
        maturity=reg_raw.get("maturity", "alpha"),
        description=reg_raw.get("description", ""),
        api_prefix=reg_raw.get("api_prefix", "/api/app/poc-gen-verify"),
        unregister_on_shutdown=bool(reg_raw.get("unregister_on_shutdown", False)),
        heartbeat_interval_seconds=int(reg_raw.get("heartbeat_interval_seconds", 30)),
        menu=_parse_menu(reg_raw.get("menu", {})),
    )

    eng_raw = raw.get("engine", {})
    engine = EngineConfig(
        name=eng_raw.get("name", "secflow-app-poc-gen-verify"),
        version=eng_raw.get("version", "1.0.0"),
        endpoint_prefix=eng_raw.get("endpoint_prefix", "/api/app/poc-gen-verify/intake"),
        heartbeat_url=eng_raw.get("heartbeat_url", "http://secflow-platform-vuln/api/vuln/internal/vuln-confirm/engines/heartbeat"),
        heartbeat_interval_seconds=int(eng_raw.get("heartbeat_interval_seconds", 30)),
        heartbeat_request_timeout_seconds=float(eng_raw.get("heartbeat_request_timeout_seconds", 5.0)),
        results_push_url=eng_raw.get("results_push_url", "http://secflow-platform-vuln/api/vuln/internal/vuln-confirm/results/push"),
        results_push_timeout_seconds=float(eng_raw.get("results_push_timeout_seconds", 5.0)),
        vuln_categories_url=eng_raw.get("vuln_categories_url", "http://secflow-platform-vuln/api/vuln/vuln-categories"),
        vuln_categories_timeout_seconds=float(eng_raw.get("vuln_categories_timeout_seconds", 5.0)),
        vuln_categories_cache_ttl_seconds=int(eng_raw.get("vuln_categories_cache_ttl_seconds", 1800)),
        emit_confirmed_category=bool(eng_raw.get("emit_confirmed_category", True)),
        default_confirmed_category=eng_raw.get("default_confirmed_category", "内存安全类型"),
    )

    app_raw = raw.get("app", {})
    app_cfg = AppConfig(
        host=app_raw.get("host", "0.0.0.0"),
        port=int(app_raw.get("port", 8080)),
        debug=bool(app_raw.get("debug", False)),
    )

    return ServiceYaml(database=db, auth_service=auth, registry=registry, engine=engine, app=app_cfg)


_service_yaml: Optional[ServiceYaml] = None


def get_service_yaml() -> ServiceYaml:
    global _service_yaml
    if _service_yaml is None:
        _service_yaml = load_service_yaml()
    return _service_yaml


# ─── engine contract config (service.yaml + env overrides) ───────────────────

def _env_str(name: str, default: str) -> str:
    v = os.environ.get(name)
    return v.strip() if v and v.strip() else default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


_engine_config: Optional[EngineConfig] = None


def get_engine_config() -> EngineConfig:
    """Return engine contract config: service.yaml `engine` section + env overrides.

    Env overrides mirror vuln-verify-v2 naming (SECFLOW_ENGINE_*, SECFLOW_VULN_CONFIRM_*).
    """
    global _engine_config
    if _engine_config is None:
        base = get_service_yaml().engine
        _engine_config = EngineConfig(
            name=_env_str("SECFLOW_ENGINE_NAME", base.name),
            version=_env_str("SECFLOW_ENGINE_VERSION", base.version),
            endpoint_prefix=_env_str("SECFLOW_ENGINE_ENDPOINT_PREFIX", base.endpoint_prefix),
            heartbeat_url=_env_str("SECFLOW_VULN_CONFIRM_HEARTBEAT_URL", base.heartbeat_url),
            heartbeat_interval_seconds=_env_int("SECFLOW_ENGINE_HEARTBEAT_INTERVAL_SECONDS", base.heartbeat_interval_seconds),
            heartbeat_request_timeout_seconds=_env_float("SECFLOW_ENGINE_HEARTBEAT_REQUEST_TIMEOUT_SECONDS", base.heartbeat_request_timeout_seconds),
            results_push_url=_env_str("SECFLOW_ENGINE_RESULTS_PUSH_URL", base.results_push_url),
            results_push_timeout_seconds=_env_float("SECFLOW_ENGINE_RESULTS_PUSH_TIMEOUT_SECONDS", base.results_push_timeout_seconds),
            vuln_categories_url=_env_str("SECFLOW_ENGINE_VULN_CATEGORIES_URL", base.vuln_categories_url),
            vuln_categories_timeout_seconds=_env_float("SECFLOW_ENGINE_VULN_CATEGORIES_TIMEOUT_SECONDS", base.vuln_categories_timeout_seconds),
            vuln_categories_cache_ttl_seconds=_env_int("SECFLOW_ENGINE_VULN_CATEGORIES_CACHE_TTL_SECONDS", base.vuln_categories_cache_ttl_seconds),
            emit_confirmed_category=_env_bool("SECFLOW_ENGINE_EMIT_CONFIRMED_CATEGORY", base.emit_confirmed_category),
            default_confirmed_category=_env_str("SECFLOW_ENGINE_DEFAULT_CONFIRMED_CATEGORY", base.default_confirmed_category),
        )
    return _engine_config

# timeout mechanism removed per request (runner runs until done/aborted)
