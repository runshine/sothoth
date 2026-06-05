from __future__ import annotations

import logging
from typing import Optional

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)

_clients: list[httpx.AsyncClient] = []


def register_client(client: httpx.AsyncClient) -> None:
    _clients.append(client)


async def close_all_shared_async_clients() -> None:
    for client in _clients:
        try:
            await client.aclose()
        except Exception:
            pass
    _clients.clear()