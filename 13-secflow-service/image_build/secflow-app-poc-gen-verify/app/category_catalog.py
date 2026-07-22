"""漏洞分类目录客户端（契约接口6，Contract v2.2+）。

引擎在通过接口4推送 / 接口2返回终态 `结果="是"` 时，可携带 `confirmed_category`
字段；其合法取值必须来自本接口返回的 `name`（契约 §5.3 / §6.2.6）。

设计：
- 启动时 / 缓存失效时拉取一次，缓存 `name` 列表（分类目录变动频率极低）。
- 拉取失败时退化为内置默认目录（与平台 `app/data/vuln_categories.json` 对齐），
  并在推送前用缓存校验分类名合法性，避免触发 422 整批拒绝。
- 不在关键确认链路上：失败只影响 `confirmed_category` 是否填写，不影响结果交付。
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

import httpx

from app.config import EngineConfig, get_engine_config

logger = logging.getLogger("poc.category_catalog")

# 与平台 app/data/vuln_categories.json 对齐的兜底目录（仅当接口6不可用时使用）。
DEFAULT_CATEGORY_CATALOG: list[dict[str, str]] = [
    {"name": "内存安全类型", "description": "涉及指针越界，缓冲区溢出"},
    {"name": "资源耗尽类", "description": "拒绝服务DOS"},
    {"name": "输入验证与注入类", "description": "涵盖SQL注入"},
    {"name": "逻辑控制与权限类", "description": "越权访问，身份验证绕过"},
    {"name": "配置错误与敏感信息", "description": "弱口令，不安全的默认配置，敏感路径泄露"},
    {"name": "数据安全与隐私合规", "description": "隐私政策未授权收集，超范围授权"},
    {"name": "认证与加密失效", "description": "算法太弱，传输明文，密钥管理不当"},
    {"name": "大模型特有漏洞", "description": "提示词注入，模型越狱"},
    {"name": "其他类型", "description": "已确认存在安全影响，但无法稳定映射到其他分类"},
]


@dataclass
class _CatalogCache:
    expires_at: float = 0.0
    items: list[dict[str, str]] | None = None
    lock: threading.Lock = threading.Lock()


_CACHE = _CatalogCache()


def _normalize_items(raw_items: Any) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    if not isinstance(raw_items, list):
        return items
    for raw in raw_items:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "").strip()
        if not name:
            continue
        status = str(raw.get("status") or "active").strip()
        if status and status != "active":
            continue
        description = raw.get("description")
        items.append({"name": name, "description": str(description or "")})
    return items


def fallback_category_catalog() -> list[dict[str, str]]:
    return [dict(item) for item in DEFAULT_CATEGORY_CATALOG]


def get_vuln_category_catalog(*, engine: EngineConfig | None = None, now: float | None = None) -> list[dict[str, str]]:
    """返回当前生效的分类目录（优先缓存，次选接口6，兜底内置默认）。

    线程安全：double-checked locking + 一次性网络请求（默认超时 5s）。
    """
    cfg = engine or get_engine_config()
    current = time.time() if now is None else now
    # fast path
    with _CACHE.lock:
        if _CACHE.items is not None and _CACHE.expires_at > current:
            return [dict(item) for item in _CACHE.items]

    url = (cfg.vuln_categories_url or "").strip()
    ttl = max(1, int(cfg.vuln_categories_cache_ttl_seconds))
    if not url:
        logger.warning("vuln category catalog url is empty; using built-in defaults")
        items = fallback_category_catalog()
    else:
        timeout = max(0.1, float(cfg.vuln_categories_timeout_seconds))
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(url)
            resp.raise_for_status()
            body = resp.json()
            items = _normalize_items(body.get("items") if isinstance(body, dict) else None)
            if not items:
                logger.warning("vuln category catalog response is empty/invalid; using built-in defaults")
                items = fallback_category_catalog()
        except Exception as exc:
            logger.warning("failed to fetch vuln category catalog from %s: %s; using built-in defaults", url, exc)
            items = fallback_category_catalog()

    with _CACHE.lock:
        # 另一个线程可能已刷新过；以最新一次结果为准
        _CACHE.items = items
        _CACHE.expires_at = current + ttl
    return [dict(item) for item in items]


def is_valid_category_name(name: str | None, *, engine: EngineConfig | None = None) -> bool:
    """校验 confirmed_category 是否在当前生效（active）目录中。"""
    if not name:
        return False
    items = get_vuln_category_catalog(engine=engine)
    return any(item["name"] == name for item in items)


def clear_category_catalog_cache() -> None:
    with _CACHE.lock:
        _CACHE.items = None
        _CACHE.expires_at = 0.0
