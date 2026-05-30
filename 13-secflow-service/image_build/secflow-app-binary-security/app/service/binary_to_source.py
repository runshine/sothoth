"""Adapter for secflow-app-binary-to-source."""

from __future__ import annotations

from typing import Any, Optional

from app.config import get_config
from app.service.downstream_base import JsonHttpClient


class BinaryToSourceClient(JsonHttpClient):
    API_PREFIX = "/api/app/binary-to-source"

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
        *,
        mode: str | None = None,
        engine: str | None = None,
        reuse_cache: bool | None = None,
    ) -> dict:
        payload = {
            "name": name,
            "description": "由 binary security 编排器触发的反编译任务",
            "priority": 5,
            "tags": ["binary-security", "b2s"],
            **(origin or {}),
            "elf_tasks": elf_tasks,
        }
        if mode:
            payload["mode"] = mode
        if engine:
            payload["engine"] = engine
        if reuse_cache is not None:
            payload["reuse_cache"] = bool(reuse_cache)
        return await self.post(
            f"{self.API_PREFIX}/projects/{project_id}/tasks",
            token=token,
            json_body=payload,
        )

    async def get_task(self, project_id: str, task_id: str, token: str) -> dict:
        return await self.get(f"{self.API_PREFIX}/projects/{project_id}/tasks/{task_id}", token=token)

    async def list_tasks(
        self,
        project_id: str,
        token: str,
        *,
        parent_task_id: str | None = None,
        parent_stage_item_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
        status: str | None = None,
    ) -> dict:
        params: dict[str, Any] = {
            "limit": limit,
            "offset": offset,
        }
        if parent_task_id:
            params["parent_task_id"] = parent_task_id
        if parent_stage_item_id:
            params["parent_stage_item_id"] = parent_stage_item_id
        if status:
            params["status"] = status
        return await self.get(f"{self.API_PREFIX}/projects/{project_id}/tasks", token=token, params=params)

    async def cancel_task(self, project_id: str, task_id: str, token: str) -> dict:
        return await self.post(f"{self.API_PREFIX}/projects/{project_id}/tasks/{task_id}/terminate", token=token)

    async def terminate_task(self, project_id: str, task_id: str, token: str) -> dict:
        return await self.post(f"{self.API_PREFIX}/projects/{project_id}/tasks/{task_id}/terminate", token=token)

    async def retry_task(self, project_id: str, task_id: str, token: str, item_ids: list[str] | None = None) -> dict:
        return await self.post(
            f"{self.API_PREFIX}/projects/{project_id}/tasks/{task_id}/retry",
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
            f"{self.API_PREFIX}/projects/{project_id}/tasks/{task_id}/rerun",
            token=token,
            json_body={
                "clean_output": clean_output,
                "cancel_running": cancel_running,
            },
        )

    async def delete_task(self, project_id: str, task_id: str, token: str) -> dict:
        return await self.delete(f"{self.API_PREFIX}/projects/{project_id}/tasks/{task_id}", token=token)


_client: Optional[BinaryToSourceClient] = None


def get_binary_to_source_client() -> BinaryToSourceClient:
    global _client
    if _client is None:
        _client = BinaryToSourceClient()
    return _client
