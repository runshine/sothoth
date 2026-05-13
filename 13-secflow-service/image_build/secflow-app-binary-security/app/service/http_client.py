"""Shared async HTTP client helpers."""

from __future__ import annotations

import asyncio

import httpx


_CLIENTS: dict[tuple[str, float], httpx.AsyncClient] = {}
_CLIENTS_LOCK = asyncio.Lock()


def _normalize_timeout(timeout: int | float | None) -> float:
    try:
        value = float(timeout or 0)
    except (TypeError, ValueError):
        value = 0.0
    return value if value > 0 else 30.0


async def get_shared_async_client(name: str, *, timeout: int | float | None = None) -> httpx.AsyncClient:
    key = (str(name or "default").strip() or "default", _normalize_timeout(timeout))
    async with _CLIENTS_LOCK:
        client = _CLIENTS.get(key)
        if client is None or client.is_closed:
            client = httpx.AsyncClient(
                timeout=key[1],
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            )
            _CLIENTS[key] = client
        return client


async def close_all_async_clients() -> None:
    async with _CLIENTS_LOCK:
        clients = list(_CLIENTS.values())
        _CLIENTS.clear()
    for client in clients:
        await client.aclose()
