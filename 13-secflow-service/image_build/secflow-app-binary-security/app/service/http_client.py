"""Shared async HTTP client helpers."""

from __future__ import annotations

import asyncio
import logging
import threading

import httpx

from app.config import get_config


_CLIENTS: dict[tuple[int, str, float], httpx.AsyncClient] = {}
_CLIENTS_LOCK = threading.Lock()
logger = logging.getLogger(__name__)


def _normalize_timeout(timeout: int | float | None) -> float:
    try:
        value = float(timeout or 0)
    except (TypeError, ValueError):
        value = 0.0
    return value if value > 0 else 30.0


async def get_shared_async_client(name: str, *, timeout: int | float | None = None) -> httpx.AsyncClient:
    loop = asyncio.get_running_loop()
    loop_id = id(loop)
    key = (loop_id, str(name or "default").strip() or "default", _normalize_timeout(timeout))
    with _CLIENTS_LOCK:
        client = _CLIENTS.get(key)
        if client is None or client.is_closed:
            cfg = get_config().http_client
            client = httpx.AsyncClient(
                timeout=key[2],
                limits=httpx.Limits(
                    max_connections=max(1, int(cfg.max_connections)),
                    max_keepalive_connections=max(0, int(cfg.max_keepalive_connections)),
                    keepalive_expiry=max(0.0, float(cfg.keepalive_expiry_seconds)),
                ),
            )
            _CLIENTS[key] = client
        return client


async def invalidate_shared_async_client(name: str, *, timeout: int | float | None = None) -> bool:
    loop_id = id(asyncio.get_running_loop())
    key = (loop_id, str(name or "default").strip() or "default", _normalize_timeout(timeout))
    with _CLIENTS_LOCK:
        client = _CLIENTS.pop(key, None)
    if client is None:
        return False
    try:
        await client.aclose()
    finally:
        logger.warning("invalidated shared async client for loop_id=%s name=%s timeout=%s", key[0], key[1], key[2])
    return True


async def close_async_clients_for_current_loop() -> None:
    loop_id = id(asyncio.get_running_loop())
    with _CLIENTS_LOCK:
        keys = [key for key in list(_CLIENTS.keys()) if key[0] == loop_id]
        clients = [_CLIENTS.pop(key) for key in keys]
    for client in clients:
        await client.aclose()


async def close_all_async_clients() -> None:
    with _CLIENTS_LOCK:
        clients = list(_CLIENTS.values())
        _CLIENTS.clear()
    for client in clients:
        await client.aclose()
