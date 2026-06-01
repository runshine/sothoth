"""Adapter for secflow-app-firmware-unpacker."""

from __future__ import annotations

from typing import Any, Optional

from app.config import get_config
from app.service.downstream_base import JsonHttpClient


class FirmwareUnpackerClient(JsonHttpClient):
    API_PREFIX = "/api/app/firmware-unpacker"

    def __init__(self) -> None:
        app_cfg = get_config()
        cfg = app_cfg.services.firmware_unpacker
        super().__init__(base_url=cfg.base_url, timeout=app_cfg.scheduler.downstream_request_timeout_seconds)

    async def create_task(self, project_id: str, firmware_path: str, token: str, origin: dict[str, Any] | None = None) -> dict:
        return await self.post(
            f"{self.API_PREFIX}/projects/{project_id}/tasks",
            token=token,
            json_body={
                "project_id": project_id,
                "firmware_path": firmware_path,
                **(origin or {}),
            },
        )

    async def get_task(self, project_id: str, task_id: str, token: str) -> dict:
        return await self.get(f"{self.API_PREFIX}/projects/{project_id}/tasks/{task_id}", token=token)

    async def list_tasks(
        self,
        project_id: str,
        token: str,
        *,
        origin_mode: str | None = "linked",
        limit: int = 100,
        offset: int = 0,
    ) -> dict:
        params: dict[str, Any] = {
            "limit": limit,
            "offset": offset,
        }
        if origin_mode:
            params["origin_mode"] = origin_mode
        return await self.get(f"{self.API_PREFIX}/projects/{project_id}/tasks", token=token, params=params)

    async def cancel_task(self, task_id: str, token: str) -> dict:
        return await self.post(f"{self.API_PREFIX}/tasks/{task_id}/cancel", token=token)

    async def retry_task(self, task_id: str, token: str) -> dict:
        return await self.post(f"{self.API_PREFIX}/tasks/{task_id}/retry", token=token)

    async def delete_task(self, task_id: str, token: str) -> dict:
        return await self.delete(f"{self.API_PREFIX}/tasks/{task_id}", token=token)


_client: Optional[FirmwareUnpackerClient] = None


def get_firmware_unpacker_client() -> FirmwareUnpackerClient:
    global _client
    if _client is None:
        _client = FirmwareUnpackerClient()
    return _client
