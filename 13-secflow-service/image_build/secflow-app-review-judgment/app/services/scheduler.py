from __future__ import annotations

import logging
from typing import Optional

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class SchedulerService:
    def __init__(self) -> None:
        config = get_config().scheduler
        self.role: str = config.role

    async def start(self) -> None:
        logger.info("scheduler started role=%s", self.role)

    async def stop(self) -> None:
        logger.info("scheduler stopped role=%s", self.role)

    def health_payload(self) -> dict[str, object]:
        return {"role": self.role, "scheduler": "running"}


_scheduler_service: Optional[SchedulerService] = None


def get_scheduler_service() -> SchedulerService:
    global _scheduler_service
    if _scheduler_service is None:
        _scheduler_service = SchedulerService()
    return _scheduler_service