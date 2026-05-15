"""Adapter for secflow-app-entry-analyse."""

from __future__ import annotations

from typing import Any, Optional

from app.config import get_config
from app.service.downstream_base import JsonHttpClient


class EntryAnalyseClient(JsonHttpClient):
    def __init__(self) -> None:
        cfg = get_config().services.entry_analyse
        super().__init__(base_url=cfg.base_url, timeout=cfg.timeout)

    async def create_task(
        self,
        project_id: str,
        task_name: str,
        input_path: str,
        module_name: str,
        token: str | None = None,
        source_path: str | None = None,
        origin: dict[str, Any] | None = None,
    ) -> dict:
        return await self.post(
            "/tasks",
            token=token,
            json_body={
                "project_id": project_id,
                "task_name": task_name,
                "input_path": input_path,
                "module_name": module_name,
                "source_path": source_path,
                "task_description": "由 binary security 编排器触发的入口分析任务",
                **(origin or {}),
            },
        )

    async def get_task(self, task_id: str, token: str | None = None) -> dict:
        return await self.get(f"/tasks/{task_id}", token=token)

    async def cancel_task(self, task_id: str, token: str | None = None) -> dict:
        return await self.post(f"/tasks/{task_id}/cancel", token=token)

    async def restart_task(self, task_id: str, token: str | None = None) -> dict:
        return await self.post(f"/tasks/{task_id}/restart", token=token)

    async def delete_task(self, task_id: str, token: str | None = None) -> dict:
        return await self.delete(f"/tasks/{task_id}", token=token)


_client: Optional[EntryAnalyseClient] = None


def get_entry_analyse_client() -> EntryAnalyseClient:
    global _client
    if _client is None:
        _client = EntryAnalyseClient()
    return _client
