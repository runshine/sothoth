"""Adapter for secflow-app-firmware-unpacker."""

from __future__ import annotations

from typing import Optional

from app.config import get_config
from app.service.downstream_base import JsonHttpClient


class FirmwareUnpackerClient(JsonHttpClient):
    def __init__(self) -> None:
        cfg = get_config().services.firmware_unpacker
        super().__init__(base_url=cfg.base_url, timeout=cfg.timeout)

    async def create_task(self, project_id: str, firmware_path: str, output_path: str, token: str) -> dict:
        return await self.post(
            f"/api/app/firmware-unpacker/projects/{project_id}/tasks",
            token=token,
            json_body={
                "project_id": project_id,
                "firmware_path": firmware_path,
                "output_path": output_path,
            },
        )

    async def get_task(self, project_id: str, task_id: str, token: str) -> dict:
        return await self.get(f"/api/app/firmware-unpacker/projects/{project_id}/tasks/{task_id}", token=token)

    async def cancel_task(self, task_id: str, token: str) -> dict:
        return await self.post(f"/api/app/firmware-unpacker/tasks/{task_id}/cancel", token=token)


_client: Optional[FirmwareUnpackerClient] = None


def get_firmware_unpacker_client() -> FirmwareUnpackerClient:
    global _client
    if _client is None:
        _client = FirmwareUnpackerClient()
    return _client
