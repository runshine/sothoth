"""Adapter for secflow-app-dataflow-vuln-scanner."""

from __future__ import annotations

from typing import Optional

from app.config import get_config
from app.service.downstream_base import JsonHttpClient


class DataflowVulnScannerClient(JsonHttpClient):
    def __init__(self) -> None:
        cfg = get_config().services.dataflow_vuln_scanner
        super().__init__(base_url=cfg.base_url.rstrip("/"), timeout=cfg.timeout)

    async def create_task(self, project_id: str, title: str, token: str, data_flow_path: str, source_dir: str, workspace_dir: str, output_dir: str) -> dict:
        return await self.post(
            "/api/dataflow-vuln-scanner/tasks",
            token=token,
            json_body={
                "project_id": project_id,
                "title": title,
                "workspace_dir": {"source": "absolute", "path": workspace_dir},
                "output_dir": {"source": "absolute", "path": output_dir},
                "data_flow": {"source": "absolute", "path": data_flow_path},
                "source_dir": {"source": "absolute", "path": source_dir},
            },
        )

    async def get_task(self, task_id: str, token: str) -> dict:
        return await self.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}", token=token)

    async def get_artifacts(self, task_id: str, token: str) -> dict:
        return await self.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/artifacts", token=token)

    async def cancel_task(self, task_id: str, token: str) -> dict:
        return await self.post(f"/api/dataflow-vuln-scanner/tasks/{task_id}/cancel", token=token)

    async def retry_task(self, task_id: str, token: str) -> dict:
        return await self.post(f"/api/dataflow-vuln-scanner/tasks/{task_id}/retry", token=token)


_client: Optional[DataflowVulnScannerClient] = None


def get_dataflow_vuln_scanner_client() -> DataflowVulnScannerClient:
    global _client
    if _client is None:
        _client = DataflowVulnScannerClient()
    return _client
