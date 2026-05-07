"""Adapter for secflow-app-entry-analyse."""

from __future__ import annotations

from typing import Optional

from app.config import get_config
from app.service.downstream_base import JsonHttpClient


class EntryAnalyseClient(JsonHttpClient):
    def __init__(self) -> None:
        cfg = get_config().services.entry_analyse
        super().__init__(base_url=cfg.base_url, timeout=cfg.timeout)

    async def create_task(self, project_id: str, task_name: str, input_path: str) -> dict:
        return await self.post(
            "/tasks",
            json_body={
                "project_id": project_id,
                "task_name": task_name,
                "input_path": input_path,
                "task_description": "由 binary security 编排器触发的入口分析任务",
                "prompt_content": f"分析路径 `{input_path}` 下模块源码中的所有外部入口点，输出入口列表。",
            },
        )

    async def get_task(self, task_id: str) -> dict:
        return await self.get(f"/tasks/{task_id}")

    async def cancel_task(self, task_id: str) -> dict:
        return await self.post(f"/tasks/{task_id}/cancel")

    async def restart_task(self, task_id: str) -> dict:
        return await self.post(f"/tasks/{task_id}/restart")

    async def delete_task(self, task_id: str) -> dict:
        return await self.delete(f"/tasks/{task_id}")


_client: Optional[EntryAnalyseClient] = None


def get_entry_analyse_client() -> EntryAnalyseClient:
    global _client
    if _client is None:
        _client = EntryAnalyseClient()
    return _client
