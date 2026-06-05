from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import asdict, dataclass
from typing import Awaitable, Callable, Optional

from app.models.database import init_database

logger = logging.getLogger(__name__)

DB_INIT_RETRY_SECONDS = float(os.environ.get("RJ_DB_INIT_RETRY_SECONDS", "5"))


@dataclass
class RuntimeBootstrapStatus:
    db_ready: bool = False
    services_ready: bool = False
    last_error: str | None = None
    attempts: int = 0


class RuntimeBootstrap:
    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None
        self._status = RuntimeBootstrapStatus()
        self._stop_event = asyncio.Event()

    async def start(self, after_db_ready: Callable[[], Awaitable[None]]) -> None:
        if self._task and not self._task.done():
            return
        self._status = RuntimeBootstrapStatus()
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(self._bootstrap_loop(after_db_ready), name="rj_bootstrap")

    async def stop(self) -> None:
        self._stop_event.set()
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None

    def status(self) -> dict[str, object]:
        return asdict(self._status)

    def ready(self) -> bool:
        return self._status.db_ready and self._status.services_ready

    async def _bootstrap_loop(self, after_db_ready: Callable[[], Awaitable[None]]) -> None:
        while not self._stop_event.is_set():
            self._status.attempts += 1
            try:
                db_ready = await asyncio.to_thread(init_database, 1, False)
                if not db_ready:
                    self._status.last_error = "db_init: waiting for schema init lock"
                    logger.warning("rj db init deferred on attempt %s", self._status.attempts)
                else:
                    self._status.db_ready = True
                    await after_db_ready()
                    self._status.services_ready = True
                    self._status.last_error = None
                    logger.info("rj bootstrap completed on attempt %s", self._status.attempts)
                    return
            except Exception as exc:
                self._status.last_error = f"startup: {exc}"
                logger.warning("rj bootstrap failed on attempt %s: %s", self._status.attempts, exc)

            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=DB_INIT_RETRY_SECONDS)
            except asyncio.TimeoutError:
                pass


_runtime_bootstrap: RuntimeBootstrap | None = None


def get_runtime_bootstrap() -> RuntimeBootstrap:
    global _runtime_bootstrap
    if _runtime_bootstrap is None:
        _runtime_bootstrap = RuntimeBootstrap()
    return _runtime_bootstrap