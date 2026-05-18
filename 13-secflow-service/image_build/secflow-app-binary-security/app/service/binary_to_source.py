"""Adapter for secflow-app-binary-to-source."""

from __future__ import annotations

from typing import Any, Optional

from app.config import get_config
from app.service.downstream_base import JsonHttpClient


class BinaryToSourceClient(JsonHttpClient):
    def __init__(self) -> None:
        cfg = get_config().services.binary_to_source
        super().__init__(base_url=cfg.base_url, timeout=cfg.timeout)

    async def create_task(
        self,
        project_id: str,
        name: str,
        elf_tasks: list[dict[str, Any]],
        token: str,
        origin: dict[str, Any] | None = None,
    ) -> dict:
        return await self.post(
            f"/projects/{project_id}/tasks",
            token=token,
            json_body={
                "name": name,
                "description": "由 binary security 编排器触发的反编译任务",
                "priority": 5,
                "tags": ["binary-security", "b2s"],
                **(origin or {}),
                "elf_tasks": elf_tasks,
            },
        )

    async def get_task(self, project_id: str, task_id: str, token: str) -> dict:
        return await self.get(f"/projects/{project_id}/tasks/{task_id}", token=token)

    async def cancel_task(self, project_id: str, task_id: str, token: str) -> dict:
        return await self.post(f"/projects/{project_id}/tasks/{task_id}/terminate", token=token)

    async def terminate_task(self, project_id: str, task_id: str, token: str) -> dict:
        return await self.post(f"/projects/{project_id}/tasks/{task_id}/terminate", token=token)

    async def retry_task(self, project_id: str, task_id: str, token: str, item_ids: list[str] | None = None) -> dict:
        return await self.post(
            f"/projects/{project_id}/tasks/{task_id}/retry",
            token=token,
            json_body={"item_ids": item_ids},
        )

    async def rerun_task(
        self,
        project_id: str,
        task_id: str,
        token: str,
        *,
        clean_output: bool = True,
        cancel_running: bool = True,
    ) -> dict:
        return await self.post(
            f"/projects/{project_id}/tasks/{task_id}/rerun",
            token=token,
            json_body={
                "clean_output": clean_output,
                "cancel_running": cancel_running,
            },
        )

    async def delete_task(self, project_id: str, task_id: str, token: str) -> dict:
        return await self.delete(f"/projects/{project_id}/tasks/{task_id}", token=token)


_client: Optional[BinaryToSourceClient] = None


def get_binary_to_source_client() -> BinaryToSourceClient:
    global _client
    if _client is None:
        _client = BinaryToSourceClient()
    return _client
