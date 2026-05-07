"""Adapter for secflow-app-dataflow-analyse."""

from __future__ import annotations

from typing import Optional

from app.config import get_config
from app.service.downstream_base import JsonHttpClient


class DataflowAnalyseClient(JsonHttpClient):
    def __init__(self) -> None:
        cfg = get_config().services.dataflow_analyse
        super().__init__(base_url=cfg.base_url, timeout=cfg.timeout)

    async def create_task(self, project_id: str, task_name: str, input_path: str, prompt_content: str) -> dict:
        return await self.post(
            "/tasks",
            json_body={
                "project_id": project_id,
                "task_name": task_name,
                "input_path": input_path,
                "task_description": "由 binary security 编排器触发的数据流分析任务",
                "prompt_content": prompt_content,
            },
        )

    async def get_task(self, task_id: str) -> dict:
        return await self.get(f"/tasks/{task_id}")

    async def cancel_task(self, task_id: str) -> dict:
        return await self.post(f"/tasks/{task_id}/cancel")

    async def restart_task(self, task_id: str) -> dict:
        return await self.post(f"/tasks/{task_id}/restart")


_client: Optional[DataflowAnalyseClient] = None


def get_dataflow_analyse_client() -> DataflowAnalyseClient:
    global _client
    if _client is None:
        _client = DataflowAnalyseClient()
    return _client
