"""Adapter for secflow-app-system-analyse."""

from __future__ import annotations

from typing import Any, Optional

from app.config import get_config
from app.service.downstream_base import JsonHttpClient


class SystemAnalyseClient(JsonHttpClient):
    API_PREFIX = "/api/app/system-analyse"

    def __init__(self) -> None:
        app_cfg = get_config()
        cfg = app_cfg.services.system_analyse
        super().__init__(base_url=cfg.base_url, timeout=app_cfg.scheduler.downstream_request_timeout_seconds)

    async def create_task(
        self,
        project_id: str,
        task_name: str,
        input_path: str,
        token: str | None = None,
        origin: dict[str, Any] | None = None,
        analysis_mode: str = "binary",
        agent_task_key: dict[str, Any] | None = None,
    ) -> dict:
        mode = "source" if str(analysis_mode or "").strip().lower() == "source" else "binary"
        subject = "源码项目" if mode == "source" else "解包系统"
        return await self.post(
            f"{self.API_PREFIX}/tasks",
            token=token,
            json_body={
                "project_id": project_id,
                "task_name": task_name,
                "input_path": input_path,
                "analysis_mode": mode,
                "task_description": "由 binary security 编排器触发的系统分析任务",
                "prompt_content": f"对路径 `{input_path}` 下的{subject}进行系统模块分类和安全威胁分析，输出风险模块列表。",
                **(origin or {}),
                **(agent_task_key or {}),
            },
        )

    async def get_task(self, task_id: str) -> dict:
        return await self.get(f"{self.API_PREFIX}/tasks/{task_id}")

    async def list_tasks(
        self,
        project_id: str,
        *,
        parent_task_id: str | None = None,
        page: int = 1,
        per_page: int = 100,
        sort_by: str = "updated_at",
        sort_order: str = "desc",
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
        return await self.get(f"{self.API_PREFIX}/tasks", params=params)

    async def get_task_result(self, task_id: str) -> dict:
        return await self.get(f"{self.API_PREFIX}/tasks/{task_id}/result")

    async def cancel_task(self, task_id: str) -> dict:
        return await self.post(f"{self.API_PREFIX}/tasks/{task_id}/cancel")

    async def restart_task(self, task_id: str) -> dict:
        return await self.post(f"{self.API_PREFIX}/tasks/{task_id}/restart")

    async def delete_task(self, task_id: str) -> dict:
        return await self.delete(f"{self.API_PREFIX}/tasks/{task_id}")


_client: Optional[SystemAnalyseClient] = None


def get_system_analyse_client() -> SystemAnalyseClient:
    global _client
    if _client is None:
        _client = SystemAnalyseClient()
    return _client
