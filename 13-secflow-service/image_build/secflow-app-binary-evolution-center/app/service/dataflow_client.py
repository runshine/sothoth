from __future__ import annotations

from typing import Any

import httpx

from app.config import get_config


class DataflowVulnClient:
    async def get_task(self, task_id: str, token: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=get_config().dataflow_vuln_service.timeout) as client:
            response = await client.get(
                f"{get_config().dataflow_vuln_service.api_base}/tasks/{task_id}",
                headers={"Authorization": token},
            )
        response.raise_for_status()
        return response.json()

    async def get_replay_ready(self, task_id: str, token: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=get_config().dataflow_vuln_service.timeout) as client:
            response = await client.get(
                f"{get_config().dataflow_vuln_service.api_base}/tasks/{task_id}/replay-ready",
                headers={"Authorization": token},
            )
        response.raise_for_status()
        return response.json()

    async def get_service_effective_config(self, token: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=get_config().dataflow_vuln_service.timeout) as client:
            response = await client.get(
                f"{get_config().dataflow_vuln_service.api_base}/service/config/effective",
                headers={"Authorization": token},
            )
        response.raise_for_status()
        return response.json()

    async def create_evolution_task(self, source_task_id: str, payload: dict[str, Any], token: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=get_config().dataflow_vuln_service.timeout) as client:
            response = await client.post(
                f"{get_config().dataflow_vuln_service.api_base}/tasks/{source_task_id}/create-evolution",
                json=payload,
                headers={"Authorization": token},
            )
        response.raise_for_status()
        return response.json()


_client: DataflowVulnClient | None = None


def get_dataflow_vuln_client() -> DataflowVulnClient:
    global _client
    if _client is None:
        _client = DataflowVulnClient()
    return _client
