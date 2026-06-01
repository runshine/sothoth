from __future__ import annotations

import asyncio
from typing import Dict

import httpx

from app.config import get_config
from app.observability.service_ops import observe_shared_http_client


_clients: Dict[str, httpx.AsyncClient] = {}
_lock = asyncio.Lock()


def _client_limits() -> httpx.Limits:
    config = get_config().auth_service
    return httpx.Limits(
        max_connections=max(int(config.max_connections or 100), 1),
        max_keepalive_connections=max(int(config.max_keepalive_connections or 20), 0),
        keepalive_expiry=max(float(config.keepalive_expiry_seconds or 15), 0.0),
    )


async def get_shared_async_client(name: str, *, timeout: float | None = None) -> httpx.AsyncClient:
    async with _lock:
        client = _clients.get(name)
        if client is not None and not client.is_closed:
            observe_shared_http_client(service=name, event="reuse")
            return client
        config = get_config().auth_service
        client = httpx.AsyncClient(
            timeout=timeout or config.timeout,
            limits=_client_limits(),
            follow_redirects=False,
            http2=False,
        )
        _clients[name] = client
        observe_shared_http_client(service=name, event="create")
        return client


async def invalidate_shared_async_client(name: str) -> None:
    async with _lock:
        client = _clients.pop(name, None)
    if client is not None and not client.is_closed:
        observe_shared_http_client(service=name, event="invalidate")
        await client.aclose()


async def close_all_shared_async_clients() -> None:
    async with _lock:
        clients = list(_clients.values())
        _clients.clear()
    for client in clients:
        if not client.is_closed:
            await client.aclose()
            observe_shared_http_client(service="all", event="close")
