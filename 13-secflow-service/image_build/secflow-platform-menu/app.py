"""
SecFlow Menu Service - 动态菜单注册管理微服务

该服务提供菜单的动态注册与查询功能，支持服务成熟度分类。
"""

import os
import json
import time
import threading
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from flask import Flask, jsonify, request, Blueprint
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

try:
    import redis
except ImportError:  # pragma: no cover - 允许本地无 redis 依赖时完成静态校验
    redis = None

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ServiceMaturity(Enum):
    """服务成熟度枚举"""
    ONLINE = "已上线"
    DEVELOPING = "开发中"
    PLANNING = "规划中"


class HealthStatus(Enum):
    """聚合健康状态"""
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"
    STALE = "stale"


@dataclass
class MenuItem:
    """菜单项数据类"""
    id: str
    name: str
    path: str
    parent_id: Optional[str] = None
    icon: Optional[str] = None
    order: int = 0
    maturity: ServiceMaturity = ServiceMaturity.DEVELOPING
    service_name: Optional[str] = None
    description: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


@dataclass
class ServiceInfo:
    """服务注册信息"""
    service_id: str
    service_name: str
    host: str
    port: int
    api_prefix: Optional[str] = None
    health_url: Optional[str] = None
    health_path: Optional[str] = None
    health_method: str = "GET"
    health_timeout_seconds: float = 2.0
    health_interval_seconds: float = 30.0
    register_time: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    maturity: ServiceMaturity = ServiceMaturity.DEVELOPING
    menu_items: Optional[MenuItem] = None
    last_health_check: float = 0.0
    last_health_ok: float = 0.0
    last_health_status: HealthStatus = HealthStatus.UNKNOWN
    last_health_http_status: Optional[int] = None
    last_health_latency_ms: Optional[int] = None
    last_health_error: Optional[str] = None
    consecutive_failures: int = 0


class MenuManager:
    """菜单管理类"""

    def __init__(
        self,
        heartbeat_timeout: float = 30.0,
        service_retention_seconds: float = 3600.0,
        default_health_interval: float = 30.0,
        default_health_timeout: float = 2.0,
        health_failure_threshold: int = 2,
        service_gateway_url: str = "",
        redis_url: str = "redis://localhost:6379/0",
        redis_enabled: bool = False,
        redis_strict_mode: bool = False,
        redis_key_prefix: str = "secflow:menu",
        pod_id: str = "menu-unknown",
        k8s_service_url: str = "",
        k8s_service_machine_token: str = "",
        k8s_service_namespace: str = "secflow-ns",
        k8s_service_name_prefix: str = "secflow-",
    ):
        self.services: Dict[str, ServiceInfo] = {}
        self.heartbeat_timeout = heartbeat_timeout
        self.service_retention_seconds = max(service_retention_seconds, heartbeat_timeout)
        self.default_health_interval = default_health_interval
        self.default_health_timeout = default_health_timeout
        self.health_failure_threshold = health_failure_threshold
        self.service_gateway_url = service_gateway_url.rstrip("/")
        self.redis_url = redis_url
        self.redis_enabled = redis_enabled
        self.redis_strict_mode = redis_strict_mode
        self.redis_key_prefix = redis_key_prefix.rstrip(":")
        self.pod_id = pod_id
        self.k8s_service_url = k8s_service_url.rstrip("?")
        self.k8s_service_machine_token = k8s_service_machine_token
        self.k8s_service_namespace = k8s_service_namespace
        self.k8s_service_name_prefix = k8s_service_name_prefix
        self.redis_client = None
        self.lock = threading.Lock()
        self._init_redis()

    def _init_redis(self) -> None:
        if not self.redis_enabled:
            return
        if redis is None:
            message = "redis dependency is not installed"
            if self.redis_strict_mode:
                raise RuntimeError(message)
            logger.warning(message + ", fallback to local memory store")
            self.redis_enabled = False
            return
        try:
            self.redis_client = redis.from_url(
                self.redis_url,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True,
                decode_responses=True,
                max_connections=20,
            )
            self.redis_client.ping()
            logger.info("Menu service connected to Redis: %s", self.redis_url)
        except Exception as exc:
            if self.redis_strict_mode:
                raise RuntimeError(f"redis init failed: {exc}") from exc
            logger.warning("Menu service Redis unavailable, fallback to local store: %s", exc)
            self.redis_enabled = False
            self.redis_client = None

    def _services_key(self) -> str:
        return f"{self.redis_key_prefix}:services"

    def _leader_lock_key(self) -> str:
        return f"{self.redis_key_prefix}:locks:healthcheck"

    def _leader_id_key(self) -> str:
        return f"{self.redis_key_prefix}:healthcheck:leader"

    def _service_to_dict(self, service: ServiceInfo) -> Dict[str, Any]:
        return {
            "service_id": service.service_id,
            "service_name": service.service_name,
            "host": service.host,
            "port": service.port,
            "api_prefix": service.api_prefix,
            "health_url": service.health_url,
            "health_path": service.health_path,
            "health_method": service.health_method,
            "health_timeout_seconds": service.health_timeout_seconds,
            "health_interval_seconds": service.health_interval_seconds,
            "register_time": service.register_time,
            "last_heartbeat": service.last_heartbeat,
            "maturity": service.maturity.value,
            "menu_items": {
                "id": service.menu_items.id,
                "name": service.menu_items.name,
                "path": service.menu_items.path,
                "parent_id": service.menu_items.parent_id,
                "icon": service.menu_items.icon,
                "order": service.menu_items.order,
                "maturity": service.menu_items.maturity.value,
                "service_name": service.menu_items.service_name,
                "description": service.menu_items.description,
                "created_at": service.menu_items.created_at,
                "updated_at": service.menu_items.updated_at,
            } if service.menu_items else None,
            "last_health_check": service.last_health_check,
            "last_health_ok": service.last_health_ok,
            "last_health_status": service.last_health_status.value,
            "last_health_http_status": service.last_health_http_status,
            "last_health_latency_ms": service.last_health_latency_ms,
            "last_health_error": service.last_health_error,
            "consecutive_failures": service.consecutive_failures,
        }

    def _service_from_dict(self, payload: Dict[str, Any]) -> ServiceInfo:
        menu_payload = payload.get("menu_items")
        menu_item = None
        if menu_payload:
            menu_item = MenuItem(
                id=menu_payload["id"],
                name=menu_payload["name"],
                path=menu_payload["path"],
                parent_id=menu_payload.get("parent_id"),
                icon=menu_payload.get("icon"),
                order=menu_payload.get("order", 0),
                maturity=ServiceMaturity(menu_payload.get("maturity", ServiceMaturity.DEVELOPING.value)),
                service_name=menu_payload.get("service_name"),
                description=menu_payload.get("description"),
                created_at=menu_payload.get("created_at", time.time()),
                updated_at=menu_payload.get("updated_at", time.time()),
            )
        return ServiceInfo(
            service_id=payload["service_id"],
            service_name=payload["service_name"],
            host=payload["host"],
            port=int(payload["port"]),
            api_prefix=payload.get("api_prefix"),
            health_url=payload.get("health_url"),
            health_path=payload.get("health_path"),
            health_method=payload.get("health_method", "GET"),
            health_timeout_seconds=float(payload.get("health_timeout_seconds", self.default_health_timeout)),
            health_interval_seconds=float(payload.get("health_interval_seconds", self.default_health_interval)),
            register_time=float(payload.get("register_time", time.time())),
            last_heartbeat=float(payload.get("last_heartbeat", time.time())),
            maturity=ServiceMaturity(payload.get("maturity", ServiceMaturity.DEVELOPING.value)),
            menu_items=menu_item,
            last_health_check=float(payload.get("last_health_check", 0.0)),
            last_health_ok=float(payload.get("last_health_ok", 0.0)),
            last_health_status=HealthStatus(payload.get("last_health_status", HealthStatus.UNKNOWN.value)),
            last_health_http_status=payload.get("last_health_http_status"),
            last_health_latency_ms=payload.get("last_health_latency_ms"),
            last_health_error=payload.get("last_health_error"),
            consecutive_failures=int(payload.get("consecutive_failures", 0)),
        )

    def _get_all_services(self) -> Dict[str, ServiceInfo]:
        if self.redis_enabled and self.redis_client:
            raw_services = self.redis_client.hgetall(self._services_key())
            return {
                service_id: self._service_from_dict(json.loads(raw_payload))
                for service_id, raw_payload in raw_services.items()
            }
        with self.lock:
            return dict(self.services)

    def _get_service(self, service_id: str) -> Optional[ServiceInfo]:
        if self.redis_enabled and self.redis_client:
            raw_payload = self.redis_client.hget(self._services_key(), service_id)
            if raw_payload is None:
                return None
            return self._service_from_dict(json.loads(raw_payload))
        with self.lock:
            return self.services.get(service_id)

    def _save_service(self, service: ServiceInfo) -> None:
        if self.redis_enabled and self.redis_client:
            self.redis_client.hset(
                self._services_key(),
                service.service_id,
                json.dumps(self._service_to_dict(service), ensure_ascii=False),
            )
            return
        with self.lock:
            self.services[service.service_id] = service

    def _delete_service(self, service_id: str) -> None:
        if self.redis_enabled and self.redis_client:
            self.redis_client.hdel(self._services_key(), service_id)
            return
        with self.lock:
            self.services.pop(service_id, None)

    def acquire_healthcheck_leader(self, timeout_seconds: int = 15) -> bool:
        if not (self.redis_enabled and self.redis_client):
            return True
        try:
            acquired = bool(self.redis_client.set(
                self._leader_lock_key(),
                self.pod_id,
                ex=timeout_seconds,
                nx=True,
            ))
            if acquired:
                self.redis_client.set(self._leader_id_key(), self.pod_id, ex=timeout_seconds)
            else:
                current_leader = self.redis_client.get(self._leader_lock_key())
                if current_leader == self.pod_id:
                    self.redis_client.expire(self._leader_lock_key(), timeout_seconds)
                    self.redis_client.set(self._leader_id_key(), self.pod_id, ex=timeout_seconds)
                    acquired = True
            return acquired
        except Exception as exc:
            logger.warning("acquire healthcheck leader failed: %s", exc)
            return not self.redis_strict_mode

    def _normalize_api_prefix(self, api_prefix: Optional[str]) -> Optional[str]:
        if not api_prefix:
            return None
        return api_prefix if api_prefix.startswith("/") else f"/{api_prefix}"

    def _resolve_health_path(self, api_prefix: Optional[str], explicit_path: Optional[str]) -> str:
        if explicit_path:
            return explicit_path if explicit_path.startswith("/") else f"/{explicit_path}"
        if api_prefix:
            return f"{api_prefix.rstrip('/')}/health"
        return "/health"

    def _resolve_health_url(
        self,
        host: str,
        port: int,
        api_prefix: Optional[str],
        explicit_url: Optional[str],
        explicit_path: Optional[str],
    ) -> str:
        if explicit_url:
            return explicit_url

        health_path = self._resolve_health_path(api_prefix, explicit_path)
        normalized_host = (host or "").strip()

        # 优先使用统一网关地址，规避部分服务注册时上报 0.0.0.0 / 127.0.0.1 的问题。
        if self.service_gateway_url and api_prefix:
            return f"{self.service_gateway_url}{health_path}"

        if normalized_host in ("", "0.0.0.0", "127.0.0.1", "localhost"):
            # 回退到统一网关，哪怕没有 api_prefix，也至少给出可观测的默认路径。
            if self.service_gateway_url:
                return f"{self.service_gateway_url}{health_path}"
            return f"http://{normalized_host or '127.0.0.1'}:{port}{health_path}"

        return f"http://{normalized_host}:{port}{health_path}"

    def _build_direct_health_url(
        self,
        host: str,
        port: int,
        api_prefix: Optional[str],
        explicit_path: Optional[str],
    ) -> Optional[str]:
        normalized_host = (host or "").strip()
        if normalized_host in ("", "0.0.0.0"):
            return None
        health_path = self._resolve_health_path(api_prefix, explicit_path)
        return f"http://{normalized_host}:{port}{health_path}"

    def _build_gateway_health_url(
        self,
        api_prefix: Optional[str],
        explicit_path: Optional[str],
    ) -> Optional[str]:
        if not self.service_gateway_url:
            return None
        health_path = self._resolve_health_path(api_prefix, explicit_path)
        return f"{self.service_gateway_url}{health_path}"

    def _get_health_probe_urls(self, service: ServiceInfo) -> List[str]:
        urls: List[str] = []

        def append_candidate(url: Optional[str]) -> None:
            normalized = (url or "").strip()
            if normalized and normalized not in urls:
                urls.append(normalized)

        append_candidate(service.health_url)
        append_candidate(self._build_gateway_health_url(service.api_prefix, service.health_path))
        append_candidate(self._build_direct_health_url(service.host, service.port, service.api_prefix, service.health_path))
        return urls

    def register_service(self, service_id: str, service_name: str, host: str, port: int,
                         maturity: str = "开发中", menu_id: str = None, menu_name: str = None,
                         menu_path: str = None, parent_id: str = None, icon: str = None,
                         order: int = 0, description: str = None, api_prefix: str = None,
                         health_url: str = None, health_path: str = None,
                         health_method: str = "GET",
                         health_timeout_seconds: Optional[float] = None,
                         health_interval_seconds: Optional[float] = None) -> Dict:
        """注册服务"""
        # 验证成熟度
        try:
            maturity_enum = ServiceMaturity(maturity)
        except ValueError:
            maturity_enum = ServiceMaturity.DEVELOPING

        normalized_api_prefix = self._normalize_api_prefix(api_prefix)
        resolved_health_path = self._resolve_health_path(normalized_api_prefix, health_path)
        resolved_health_url = self._resolve_health_url(
            host=host,
            port=port,
            api_prefix=normalized_api_prefix,
            explicit_url=health_url,
            explicit_path=health_path,
        )

        service = self._get_service(service_id)
        if service is not None:
            service.last_heartbeat = time.time()
            service.maturity = maturity_enum
            service.host = host
            service.port = port
            service.api_prefix = normalized_api_prefix
            service.health_path = resolved_health_path
            service.health_url = resolved_health_url
            service.health_method = (health_method or "GET").upper()
            service.health_timeout_seconds = float(health_timeout_seconds or self.default_health_timeout)
            service.health_interval_seconds = float(health_interval_seconds or self.default_health_interval)
            if menu_id and menu_name:
                service.menu_items = MenuItem(
                    id=menu_id,
                    name=menu_name,
                    path=menu_path or f"/{service_name}",
                    parent_id=parent_id,
                    icon=icon,
                    order=order,
                    maturity=maturity_enum,
                    service_name=service_name,
                    description=description,
                    updated_at=time.time()
                )
            self._save_service(service)
            logger.info(f"Service updated: {service_id}")
            return {"status": "updated", "service_id": service_id}

        menu_item = None
        if menu_id and menu_name:
            menu_item = MenuItem(
                id=menu_id,
                name=menu_name,
                path=menu_path or f"/{service_name}",
                parent_id=parent_id,
                icon=icon,
                order=order,
                maturity=maturity_enum,
                service_name=service_name,
                description=description
            )

        service = ServiceInfo(
            service_id=service_id,
            service_name=service_name,
            host=host,
            port=port,
            api_prefix=normalized_api_prefix,
            health_url=resolved_health_url,
            health_path=resolved_health_path,
            health_method=(health_method or "GET").upper(),
            health_timeout_seconds=float(health_timeout_seconds or self.default_health_timeout),
            health_interval_seconds=float(health_interval_seconds or self.default_health_interval),
            maturity=maturity_enum,
            menu_items=menu_item
        )
        self._save_service(service)
        logger.info(f"Service registered: {service_id}")
        return {"status": "registered", "service_id": service_id}

    def heartbeat(self, service_id: str) -> Dict:
        """心跳检测"""
        service = self._get_service(service_id)
        if service is None:
            return {"status": "error", "message": "Service not found"}
        service.last_heartbeat = time.time()
        self._save_service(service)
        return {"status": "ok", "service_id": service_id}

    def unregister_service(self, service_id: str) -> Dict:
        """注销服务"""
        service = self._get_service(service_id)
        if service is None:
            return {"status": "error", "message": "Service not found"}
        self._delete_service(service_id)
        logger.info(f"Service unregistered: {service_id}")
        return {"status": "ok", "service_id": service_id}

    def get_all_services_info(self) -> List[Dict]:
        """获取所有服务信息"""
        return [
                {
                    "service_id": s.service_id,
                    "service_name": s.service_name,
                    "host": s.host,
                    "port": s.port,
                    "api_prefix": s.api_prefix,
                    "health_url": s.health_url,
                    "health_path": s.health_path,
                    "health_method": s.health_method,
                    "health_timeout_seconds": s.health_timeout_seconds,
                    "health_interval_seconds": s.health_interval_seconds,
                    "register_time": s.register_time,
                    "last_heartbeat": s.last_heartbeat,
                    "maturity": s.maturity.value,
                    "health": {
                        "status": s.last_health_status.value,
                        "last_check": s.last_health_check,
                        "last_ok": s.last_health_ok,
                        "http_status": s.last_health_http_status,
                        "latency_ms": s.last_health_latency_ms,
                        "error": s.last_health_error,
                        "consecutive_failures": s.consecutive_failures,
                    },
                    "menu_item": {
                        "id": s.menu_items.id,
                        "name": s.menu_items.name,
                        "path": s.menu_items.path,
                        "parent_id": s.menu_items.parent_id,
                        "icon": s.menu_items.icon,
                        "order": s.menu_items.order,
                        "maturity": s.menu_items.maturity.value,
                        "service_name": s.menu_items.service_name,
                        "description": s.menu_items.description
                    } if s.menu_items else None
                }
                for s in self._get_all_services().values()
            ]

    def _probe_url(self, health_url: str, method: str, timeout_seconds: float) -> Dict[str, Any]:
        started_at = time.time()
        request_obj = Request(health_url, method=method)
        try:
            with urlopen(request_obj, timeout=timeout_seconds) as response:
                latency_ms = int((time.time() - started_at) * 1000)
                return {
                    "ok": 200 <= response.status < 400,
                    "http_status": response.status,
                    "latency_ms": latency_ms,
                    "error": None,
                }
        except HTTPError as exc:
            return {
                "ok": False,
                "http_status": exc.code,
                "latency_ms": int((time.time() - started_at) * 1000),
                "error": f"http_{exc.code}",
            }
        except URLError as exc:
            reason = getattr(exc, "reason", exc)
            return {
                "ok": False,
                "http_status": None,
                "latency_ms": int((time.time() - started_at) * 1000),
                "error": str(reason),
            }
        except Exception as exc:
            return {
                "ok": False,
                "http_status": None,
                "latency_ms": int((time.time() - started_at) * 1000),
                "error": str(exc),
            }

    def _probe_service(self, service: ServiceInfo) -> Dict[str, Any]:
        probe_urls = self._get_health_probe_urls(service)
        last_result: Dict[str, Any] = {
            "ok": False,
            "http_status": None,
            "latency_ms": 0,
            "error": "no health probe url",
        }

        for health_url in probe_urls:
            probe_result = self._probe_url(
                health_url=health_url,
                method=service.health_method,
                timeout_seconds=service.health_timeout_seconds,
            )
            if probe_result["ok"]:
                probe_result["probe_url"] = health_url
                return probe_result
            last_result = probe_result

        last_result["probe_url"] = probe_urls[-1] if probe_urls else None
        return last_result

    def refresh_service_health(self, service_id: str) -> Dict[str, Any]:
        """立即刷新单个服务健康状态"""
        service = self._get_service(service_id)
        if not service:
            return {"status": "error", "message": "Service not found"}

        probe_result = self._probe_service(service)
        current_time = time.time()
        service.last_health_check = current_time
        service.last_health_http_status = probe_result["http_status"]
        service.last_health_latency_ms = probe_result["latency_ms"]
        service.last_health_error = probe_result["error"]

        if probe_result["ok"]:
            service.last_health_ok = current_time
            service.consecutive_failures = 0
            service.last_health_status = HealthStatus.HEALTHY
        else:
            service.consecutive_failures += 1
            service.last_health_status = (
                HealthStatus.DEGRADED
                if service.consecutive_failures < self.health_failure_threshold
                else HealthStatus.UNHEALTHY
            )
        self._save_service(service)
        return {
            "status": "ok",
            "service_id": service_id,
            "health": self._build_health_payload(service),
        }

    def refresh_due_service_health(self) -> int:
        """刷新所有到期服务的健康状态"""
        current_time = time.time()
        due_service_ids: List[str] = []
        for service_id, service in self._get_all_services().items():
            if current_time - service.last_health_check >= service.health_interval_seconds:
                due_service_ids.append(service_id)

        refreshed = 0
        for service_id in due_service_ids:
            result = self.refresh_service_health(service_id)
            if result.get("status") == "ok":
                refreshed += 1
        return refreshed

    def _build_health_payload(self, service: ServiceInfo) -> Dict[str, Any]:
        now = time.time()
        heartbeat_age = now - service.last_heartbeat
        if heartbeat_age > self.heartbeat_timeout:
            status = HealthStatus.STALE
        elif service.last_health_check <= 0:
            status = HealthStatus.UNKNOWN
        else:
            status = service.last_health_status

        return {
            "status": status.value,
            "last_check": service.last_health_check,
            "last_ok": service.last_health_ok,
            "http_status": service.last_health_http_status,
            "latency_ms": service.last_health_latency_ms,
            "error": service.last_health_error,
            "consecutive_failures": service.consecutive_failures,
            "heartbeat_age_seconds": round(heartbeat_age, 3),
        }

    def get_services_health(self) -> List[Dict[str, Any]]:
        """获取所有服务的聚合健康信息"""
        services = list(self._get_all_services().values())

        results = []
        for service in services:
            results.append({
                "service_id": service.service_id,
                "service_name": service.service_name,
                "api_prefix": service.api_prefix,
                "menu_item_id": service.menu_items.id if service.menu_items else None,
                "menu_path": service.menu_items.path if service.menu_items else None,
                "health_url": service.health_url,
                "health": self._build_health_payload(service),
            })
        return results

    def get_services_health_summary(self) -> Dict[str, Any]:
        """获取前端友好的健康汇总"""
        services = self.get_services_health()
        deployment_summary = self.get_platform_deployment_summary()
        summary: Dict[str, Any] = {
            "generated_at": time.time(),
            "summary": {
                "total_services": 0,
                "registered_services": 0,
                "unregistered_services": 0,
                "total_replicas": 0,
                "ready_replicas": 0,
                "available_replicas": 0,
            },
            "totals": {
                "healthy": 0,
                "unhealthy": 0,
                "degraded": 0,
                "unknown": 0,
                "stale": 0,
                "unregistered": 0,
            },
            "services": {},
            "deployments": deployment_summary["items"],
        }
        deployment_lookup = {item["name"]: item for item in deployment_summary["items"]}
        matched_deployments = set()
        for service in services:
            health_status = service["health"]["status"]
            summary["totals"][health_status] = summary["totals"].get(health_status, 0) + 1
            deployment_info = self._match_service_deployment(service["service_id"], deployment_lookup)
            if deployment_info:
                matched_deployments.add(deployment_info["name"])
            service_payload = {
                "service_id": service["service_id"],
                "service_name": service["service_name"],
                "api_prefix": service["api_prefix"],
                "menu_item_id": service["menu_item_id"],
                "menu_path": service["menu_path"],
                "health": service["health"]["status"],
                "latency_ms": service["health"]["latency_ms"],
                "last_check_at": service["health"]["last_check"],
                "error": service["health"]["error"],
                "registered": True,
                "replicas": deployment_info.get("replicas") if deployment_info else None,
                "ready_replicas": deployment_info.get("ready_replicas") if deployment_info else None,
                "available_replicas": deployment_info.get("available_replicas") if deployment_info else None,
                "deployment_name": deployment_info.get("name") if deployment_info else None,
                "runtime_status": self._derive_runtime_status(deployment_info) if deployment_info else "unknown",
            }
            summary["services"][service["service_id"]] = service_payload

        for deployment in deployment_summary["items"]:
            if deployment["name"] in matched_deployments:
                continue
            summary["totals"]["unregistered"] += 1
            summary["services"][deployment["name"]] = {
                "service_id": deployment["name"],
                "service_name": deployment["name"],
                "api_prefix": None,
                "menu_item_id": None,
                "menu_path": None,
                "health": "unregistered",
                "latency_ms": None,
                "last_check_at": None,
                "error": None,
                "registered": False,
                "replicas": deployment.get("replicas"),
                "ready_replicas": deployment.get("ready_replicas"),
                "available_replicas": deployment.get("available_replicas"),
                "deployment_name": deployment.get("name"),
                "runtime_status": self._derive_runtime_status(deployment),
            }

        summary["summary"]["total_services"] = len(summary["services"])
        summary["summary"]["registered_services"] = len([item for item in summary["services"].values() if item["registered"]])
        summary["summary"]["unregistered_services"] = summary["summary"]["total_services"] - summary["summary"]["registered_services"]
        summary["summary"]["total_replicas"] = deployment_summary["total_replicas"]
        summary["summary"]["ready_replicas"] = deployment_summary["ready_replicas"]
        summary["summary"]["available_replicas"] = deployment_summary["available_replicas"]
        return summary

    def _service_deployment_candidates(self, service_id: str) -> List[str]:
        candidates = [service_id]
        if service_id.startswith("secflow-") and not service_id.startswith("secflow-platform-"):
            candidates.append(service_id.replace("secflow-", "secflow-platform-", 1))
        if service_id.startswith("secflow-platform-"):
            candidates.append(service_id.replace("secflow-platform-", "secflow-", 1))
        return list(dict.fromkeys(candidates))

    def _match_service_deployment(self, service_id: str, deployment_lookup: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        for candidate in self._service_deployment_candidates(service_id):
            if candidate in deployment_lookup:
                return deployment_lookup[candidate]
        return None

    def _derive_runtime_status(self, deployment: Optional[Dict[str, Any]]) -> str:
        if not deployment:
            return "unknown"
        replicas = int(deployment.get("replicas") or 0)
        ready_replicas = int(deployment.get("ready_replicas") or 0)
        available_replicas = int(deployment.get("available_replicas") or 0)
        if replicas == 0:
            return "scaled-to-zero"
        if ready_replicas >= replicas and available_replicas >= replicas:
            return "running"
        if ready_replicas > 0 or available_replicas > 0:
            return "degraded"
        return "unavailable"

    def get_platform_deployment_summary(self) -> Dict[str, Any]:
        if not self.k8s_service_url:
            return {
                "items": [],
                "total_replicas": 0,
                "ready_replicas": 0,
                "available_replicas": 0,
            }

        query = urlencode({
            "namespace": self.k8s_service_namespace,
            "name_prefix": self.k8s_service_name_prefix,
        })
        request_url = f"{self.k8s_service_url}?{query}"
        headers = {"Accept": "application/json"}
        if self.k8s_service_machine_token:
            headers["Authorization"] = f"Bearer {self.k8s_service_machine_token}"

        req = Request(request_url, headers=headers, method="GET")
        try:
            with urlopen(req, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            logger.warning("Failed to load deployment summary from k8s service: %s", exc)
            return {
                "items": [],
                "total_replicas": 0,
                "ready_replicas": 0,
                "available_replicas": 0,
            }

        items = payload.get("items") or payload.get("data", {}).get("items") or []
        total_replicas = sum(int(item.get("replicas") or 0) for item in items)
        ready_replicas = sum(int(item.get("ready_replicas") or 0) for item in items)
        available_replicas = sum(int(item.get("available_replicas") or 0) for item in items)
        return {
            "items": items,
            "total_replicas": total_replicas,
            "ready_replicas": ready_replicas,
            "available_replicas": available_replicas,
        }

    def get_dynamic_menu(self) -> List[Dict]:
        """获取动态菜单"""
        menu_items = []
        for service in self._get_all_services().values():
            if service.menu_items:
                menu_item = {
                    "id": service.menu_items.id,
                    "name": service.menu_items.name,
                    "path": service.menu_items.path,
                    "parentId": service.menu_items.parent_id,
                    "icon": service.menu_items.icon,
                    "order": service.menu_items.order,
                    "maturity": service.menu_items.maturity.value,
                    "service_name": service.menu_items.service_name,
                    "description": service.menu_items.description
                }
                menu_items.append(menu_item)

        menu_items.sort(key=lambda x: x.get("order", 0))
        return menu_items

    def cleanup_expired_services(self):
        """清理过期服务"""
        current_time = time.time()
        services = self._get_all_services()
        removed = 0
        retained = 0
        for sid, service in services.items():
            heartbeat_age = current_time - service.last_heartbeat
            if heartbeat_age <= self.heartbeat_timeout:
                continue

            if heartbeat_age <= self.service_retention_seconds:
                service.last_health_status = HealthStatus.STALE
                service.last_health_error = "heartbeat timeout"
                self._save_service(service)
                retained += 1
                continue

            self._delete_service(sid)
            logger.info(f"Service expired and removed: {sid}")
            removed += 1

        if retained > 0:
            logger.info("Marked %s expired services as stale", retained)
        return removed


# 创建Flask应用
app = Flask(__name__)

# 创建蓝图
menu_bp = Blueprint('menu', __name__, url_prefix='/api/menu')

# 全局菜单管理器实例
menu_manager: Optional[MenuManager] = None


def get_menu_manager() -> MenuManager:
    """获取菜单管理器单例"""
    global menu_manager
    if menu_manager is None:
        menu_manager = MenuManager()
    return menu_manager


@menu_bp.route('/health', methods=['GET'])
def health_check():
    """健康检查"""
    return jsonify({"status": "ok", "service": "secflow-menu"})


@menu_bp.route('/menu', methods=['GET'])
def get_menu():
    """
    获取动态菜单

    返回所有已注册的菜单项

    Response:
    {
        "code": 0,
        "message": "success",
        "data": [
            {
                "id": "home",
                "name": "首页",
                "path": "/home",
                "parentId": null,
                "icon": "home",
                "order": 0,
                "maturity": "已上线",
                "description": "系统首页"
            }
        ]
    }
    """
    manager = get_menu_manager()
    menu_items = manager.get_dynamic_menu()
    return jsonify({
        "code": 0,
        "message": "success",
        "data": menu_items
    })


@menu_bp.route('/services', methods=['GET'])
def get_all_services():
    """
    获取所有已注册服务信息

    返回所有已注册服务的详细信息

    Response:
    {
        "code": 0,
        "message": "success",
        "data": [...]
    }
    """
    manager = get_menu_manager()
    services = manager.get_all_services_info()
    return jsonify({
        "code": 0,
        "message": "success",
        "data": services
    })


@menu_bp.route('/services/health', methods=['GET'])
def get_services_health():
    """获取所有已注册服务的聚合健康状态"""
    manager = get_menu_manager()
    services = manager.get_services_health()
    return jsonify({
        "code": 0,
        "message": "success",
        "data": services
    })


@menu_bp.route('/services/health/summary', methods=['GET'])
def get_services_health_summary():
    """获取供前端菜单使用的健康状态汇总"""
    manager = get_menu_manager()
    summary = manager.get_services_health_summary()
    return jsonify({
        "code": 0,
        "message": "success",
        "data": summary
    })


@menu_bp.route('/services/health/check/<service_id>', methods=['POST'])
def check_service_health(service_id: str):
    """手动触发单个服务健康检查"""
    manager = get_menu_manager()
    result = manager.refresh_service_health(service_id)
    if result["status"] == "error":
        return jsonify({"code": -1, "message": result["message"]}), 404
    return jsonify({
        "code": 0,
        "message": "success",
        "data": result["health"]
    })


@menu_bp.route('/register', methods=['POST'])
def register_service():
    """
    注册服务

    请求体 (JSON):
    {
        "service_id": "secflow-user",
        "service_name": "用户服务",
        "host": "192.168.1.100",
        "port": 8080,
        "maturity": "已上线",  // 可选: 已上线、开发中、规划中
        "menu_item": {
            "id": "user-manage",
            "name": "用户管理",
            "path": "/user",
            "parent_id": null,  // 可选，父菜单ID
            "icon": "user",      // 可选
            "order": 1,         // 可选
            "description": "用户管理模块"  // 可选
        }
    }

    Response:
    {
        "code": 0,
        "message": "success",
        "status": "registered"  // 或 "updated"
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({"code": -1, "message": "Request body required"}), 400

    required_fields = ['service_id', 'service_name', 'host', 'port']
    for field in required_fields:
        if field not in data:
            return jsonify({"code": -1, "message": f"Field '{field}' is required"}), 400

    manager = get_menu_manager()
    menu_data = data.get('menu_item', {})

    health_data = data.get('health_check', {})

    result = manager.register_service(
        service_id=data['service_id'],
        service_name=data['service_name'],
        host=data['host'],
        port=data['port'],
        maturity=data.get('maturity', '开发中'),
        menu_id=menu_data.get('id'),
        menu_name=menu_data.get('name'),
        menu_path=menu_data.get('path'),
        parent_id=menu_data.get('parent_id'),
        icon=menu_data.get('icon'),
        order=menu_data.get('order', 0),
        description=menu_data.get('description'),
        api_prefix=data.get('api_prefix'),
        health_url=health_data.get('url') or data.get('health_url'),
        health_path=health_data.get('path') or data.get('health_path'),
        health_method=health_data.get('method') or data.get('health_method', 'GET'),
        health_timeout_seconds=health_data.get('timeout_seconds') or data.get('health_timeout_seconds'),
        health_interval_seconds=health_data.get('interval_seconds') or data.get('health_interval_seconds'),
    )

    return jsonify({
        "code": 0,
        "message": "success",
        "status": result['status']
    })


@menu_bp.route('/unregister/<service_id>', methods=['DELETE'])
def unregister_service(service_id: str):
    """
    注销服务

    URL参数:
        service_id: 服务ID

    Response:
    {
        "code": 0,
        "message": "success"
    }
    """
    manager = get_menu_manager()
    result = manager.unregister_service(service_id)

    if result['status'] == 'error':
        return jsonify({"code": -1, "message": result['message']}), 404

    return jsonify({"code": 0, "message": "success"})


@menu_bp.route('/heartbeat/<service_id>', methods=['POST'])
def heartbeat(service_id: str):
    """
    心跳检测

    URL参数:
        service_id: 服务ID

    Response:
    {
        "code": 0,
        "message": "success"
    }
    """
    manager = get_menu_manager()
    result = manager.heartbeat(service_id)

    if result['status'] == 'error':
        return jsonify({"code": -1, "message": result['message']}), 404

    return jsonify({"code": 0, "message": "success"})


@menu_bp.route('/maturity/list', methods=['GET'])
def get_maturity_list():
    """
    获取成熟度列表

    Response:
    {
        "code": 0,
        "message": "success",
        "data": ["已上线", "开发中", "规划中"]
    }
    """
    return jsonify({
        "code": 0,
        "message": "success",
        "data": [m.value for m in ServiceMaturity]
    })


def create_app(config: Dict = None) -> Flask:
    """创建Flask应用"""
    global menu_manager

    if config:
        menu_manager = MenuManager(
            heartbeat_timeout=config.get('heartbeat_timeout', 30.0),
            service_retention_seconds=config.get('service_retention_seconds', 3600.0),
            default_health_interval=config.get('health_check_interval', 30.0),
            default_health_timeout=config.get('health_check_timeout', 2.0),
            health_failure_threshold=config.get('health_failure_threshold', 2),
            service_gateway_url=config.get('service_gateway_url', ''),
            redis_url=config.get('redis_url', 'redis://localhost:6379/0'),
            redis_enabled=config.get('redis_enabled', False),
            redis_strict_mode=config.get('redis_strict_mode', False),
            redis_key_prefix=config.get('redis_key_prefix', 'secflow:menu'),
            pod_id=os.environ.get('POD_NAME', 'menu-local'),
            k8s_service_url=config.get('k8s_service_url', ''),
            k8s_service_machine_token=config.get('k8s_service_machine_token', ''),
            k8s_service_namespace=config.get('k8s_service_namespace', 'secflow-ns'),
            k8s_service_name_prefix=config.get('k8s_service_name_prefix', 'secflow-'),
        )

    app.register_blueprint(menu_bp)
    return app


def cleanup_task(interval: int = 10):
    """定期清理过期服务"""
    while True:
        try:
            manager = get_menu_manager()
            if manager.acquire_healthcheck_leader():
                removed = manager.cleanup_expired_services()
                if removed > 0:
                    logger.info(f"Cleaned up {removed} expired services")
        except Exception as e:
            logger.error(f"Error in cleanup task: {e}")
        time.sleep(interval)


def health_check_task(interval: int = 5):
    """定期刷新服务健康状态"""
    while True:
        try:
            manager = get_menu_manager()
            if manager.acquire_healthcheck_leader():
                refreshed = manager.refresh_due_service_health()
                if refreshed > 0:
                    logger.debug("Refreshed health for %s services", refreshed)
        except Exception as e:
            logger.error(f"Error in health check task: {e}")
        time.sleep(interval)


if __name__ == '__main__':
    import argparse
    import yaml

    parser = argparse.ArgumentParser(description='SecFlow Menu Service')
    parser.add_argument('--config', type=str, default='config.yaml',
                       help='配置文件路径')
    args = parser.parse_args()

    # 读取配置文件
    config = {}
    if os.path.exists(args.config):
        with open(args.config, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f) or {}

    # 初始化菜单管理器
    menu_manager = MenuManager(
        heartbeat_timeout=config.get('heartbeat_timeout', 30.0),
        service_retention_seconds=config.get('service_retention_seconds', 3600.0),
        default_health_interval=config.get('health_check_interval', 30.0),
        default_health_timeout=config.get('health_check_timeout', 2.0),
        health_failure_threshold=config.get('health_failure_threshold', 2),
        service_gateway_url=config.get('service_gateway_url', ''),
        redis_url=config.get('redis_url', 'redis://localhost:6379/0'),
        redis_enabled=config.get('redis_enabled', False),
        redis_strict_mode=config.get('redis_strict_mode', False),
        redis_key_prefix=config.get('redis_key_prefix', 'secflow:menu'),
        pod_id=os.environ.get('POD_NAME', 'menu-local'),
        k8s_service_url=config.get('k8s_service_url', ''),
        k8s_service_machine_token=config.get('k8s_service_machine_token', ''),
        k8s_service_namespace=config.get('k8s_service_namespace', 'secflow-ns'),
        k8s_service_name_prefix=config.get('k8s_service_name_prefix', 'secflow-'),
    )

    # 注册蓝图
    app.register_blueprint(menu_bp)

    # 启动清理任务
    cleanup_interval = config.get('cleanup_interval', 10)
    cleanup_thread = threading.Thread(target=cleanup_task, args=(cleanup_interval,), daemon=True)
    cleanup_thread.start()
    health_interval = config.get('health_scheduler_interval', 5)
    health_thread = threading.Thread(target=health_check_task, args=(health_interval,), daemon=True)
    health_thread.start()

    # 启动服务
    host = config.get('host', '0.0.0.0')
    port = config.get('port', 5000)
    debug = config.get('debug', False)

    logger.info(f"Starting SecFlow Menu Service on {host}:{port}")
    app.run(host=host, port=port, debug=debug)
