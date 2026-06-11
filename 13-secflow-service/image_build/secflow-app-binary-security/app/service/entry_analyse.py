"""Adapter for secflow-app-entry-analyse."""

from __future__ import annotations

from typing import Any, Optional

from app.config import get_config
from app.service.downstream_base import JsonHttpClient


class EntryAnalyseClient(JsonHttpClient):
    API_PREFIX = "/api/app/entry-analyse"

    def __init__(self) -> None:
        app_cfg = get_config()
        cfg = app_cfg.services.entry_analyse
        super().__init__(base_url=cfg.base_url, timeout=app_cfg.scheduler.downstream_request_timeout_seconds)

    async def create_task(
        self,
        project_id: str,
        task_name: str,
        input_path: str,
        module_name: str,
        token: str | None = None,
        source_path: str | None = None,
        origin: dict[str, Any] | None = None,
        agent_task_key: dict[str, Any] | None = None,
    ) -> dict:
        return await self.post(
            f"{self.API_PREFIX}/tasks",
            token=token,
            json_body={
                "project_id": project_id,
                "task_name": task_name,
                "input_path": input_path,
                "module_name": module_name,
                "source_path": source_path,
                "task_description": "由 binary security 编排器触发的入口分析任务",
                **(origin or {}),
                **(agent_task_key or {}),
            },
        )

    async def get_task(self, task_id: str, token: str | None = None) -> dict:
        return await self.get(f"{self.API_PREFIX}/tasks/{task_id}", token=token)

    async def list_tasks(
        self,
        project_id: str,
        *,
        parent_task_id: str | None = None,
        parent_stage_name: str | None = None,
        parent_stage_item_id: str | None = None,
        parent_stage_item_key: str | None = None,
        page: int = 1,
        per_page: int = 100,
        sort_by: str = "updated_at",
        sort_order: str = "desc",
        token: str | None = None,
    ) -> dict:
        params: dict[str, Any] = {
            "project_id": project_id,
            "page": page,
            "per_page": per_page,
            "sort_by": sort_by,
            "sort_order": sort_order,
        }
        if parent_task_id:
            params["parent_task_id"] = parent_task_id
        if parent_stage_name:
            params["parent_stage_name"] = parent_stage_name
        if parent_stage_item_id:
            params["parent_stage_item_id"] = parent_stage_item_id
        elif parent_stage_item_key:
            params["parent_stage_item_key"] = parent_stage_item_key
        return await self.get(f"{self.API_PREFIX}/tasks", token=token, params=params)

    async def cancel_task(self, task_id: str, token: str | None = None) -> dict:
        return await self.post(f"{self.API_PREFIX}/tasks/{task_id}/cancel", token=token)

    async def restart_task(self, task_id: str, token: str | None = None) -> dict:
        return await self.post(f"{self.API_PREFIX}/tasks/{task_id}/restart", token=token)

    async def delete_task(self, task_id: str, token: str | None = None) -> dict:
        return await self.delete(f"{self.API_PREFIX}/tasks/{task_id}", token=token)


_client: Optional[EntryAnalyseClient] = None


def get_entry_analyse_client() -> EntryAnalyseClient:
    global _client
    if _client is None:
        _client = EntryAnalyseClient()
    return _client
