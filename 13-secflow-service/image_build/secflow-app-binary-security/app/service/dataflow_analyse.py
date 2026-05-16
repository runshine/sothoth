"""Adapter for secflow-app-dataflow-analyse."""

from __future__ import annotations

from typing import Any, Optional

from app.config import get_config
from app.service.downstream_base import JsonHttpClient


class DataflowAnalyseClient(JsonHttpClient):
    def __init__(self) -> None:
        cfg = get_config().services.dataflow_analyse
        super().__init__(base_url=cfg.base_url, timeout=cfg.timeout)

    async def create_task(
        self,
        project_id: str,
        task_name: str,
        input_path: str,
        prompt_content: str,
        origin: dict[str, Any] | None = None,
        *,
        source_file: str | None = None,
        function_name: str | None = None,
        line_hint: str | None = None,
        taint_params: list[str] | None = None,
        function_description: str | None = None,
        entry_reason: str | None = None,
        taint_details: list[dict[str, Any]] | None = None,
        function_description_source: str | None = None,
        entry_reason_source: str | None = None,
    ) -> dict:
        return await self.post(
            "/tasks",
            json_body={
                "project_id": project_id,
                "task_name": task_name,
                "input_path": input_path,
                "task_description": "由 binary security 编排器触发的数据流分析任务",
                "prompt_content": prompt_content,
                "source_file": source_file,
                "function_name": function_name,
                "line_hint": line_hint,
                "taint_params": taint_params or [],
                "function_description": function_description or "",
                "function_description_source": function_description_source or "",
                "entry_reason": entry_reason or "",
                "entry_reason_source": entry_reason_source or "",
                "taint_details": taint_details or [],
                **(origin or {}),
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


_client: Optional[DataflowAnalyseClient] = None


def get_dataflow_analyse_client() -> DataflowAnalyseClient:
    global _client
    if _client is None:
        _client = DataflowAnalyseClient()
    return _client
