"""Adapter for secflow-app-dataflow-vuln-scanner."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from app.config import get_config
from app.service.downstream_base import JsonHttpClient


class DataflowVulnScannerClient(JsonHttpClient):
    API_PREFIX = "/api/dataflow-vuln-scanner"

    def __init__(self) -> None:
        app_cfg = get_config()
        cfg = app_cfg.services.dataflow_vuln_scanner
        super().__init__(base_url=cfg.base_url.rstrip("/"), timeout=app_cfg.scheduler.downstream_request_timeout_seconds)

    def _project_filesystem_ref(self, project_id: str, path: str) -> dict[str, Any]:
        """Convert a shared /data/files/<project_id>/... path to DFVS input ref."""
        cfg = get_config().services.fileserver
        project_root = (Path(cfg.data_mount_path) / cfg.project_files_dirname / str(project_id)).resolve()
        candidate = Path(path).resolve()
        try:
            relative = candidate.relative_to(project_root)
        except ValueError as exc:
            raise ValueError(f"dataflow-vuln-scanner input must be under project root {project_root}: {candidate}") from exc
        project_path = "/" + relative.as_posix().lstrip("/")
        return {
            "source": "project_filesystem",
            "path": project_path if project_path != "/." else "/",
            "filename": candidate.name or None,
        }

    async def create_task(self, project_id: str, title: str, token: str, data_flow_path: str, source_dir: str, origin: dict[str, Any] | None = None) -> dict:
        # DFVS now owns its standard run/output layout under
        # /data/files/<project>/app/secflow-app-dataflow-vuln-scanner.  Do not
        # pass absolute workspace/output refs; send project-scoped input refs so
        # allow_absolute_input_refs can remain disabled.
        return await self.post(
            f"{self.API_PREFIX}/tasks",
            token=token,
            json_body={
                "project_id": project_id,
                "title": title,
                "data_flow": self._project_filesystem_ref(project_id, data_flow_path),
                "source_dir": self._project_filesystem_ref(project_id, source_dir),
                **(origin or {}),
            },
        )

    async def get_task(self, task_id: str, token: str) -> dict:
        return await self.get(f"{self.API_PREFIX}/tasks/{task_id}", token=token)

    async def list_tasks(
        self,
        project_id: str,
        token: str,
        *,
        limit: int = 100,
        offset: int = 0,
        status: str | None = None,
    ) -> list[dict]:
        params: dict[str, Any] = {
            "project_id": project_id,
            "limit": limit,
            "offset": offset,
        }
        if status:
            params["status"] = status
        return await self.get(f"{self.API_PREFIX}/tasks", token=token, params=params)

    async def get_artifacts(self, task_id: str, token: str) -> dict:
        return await self.get(f"{self.API_PREFIX}/tasks/{task_id}/artifacts", token=token)

    async def cancel_task(self, task_id: str, token: str) -> dict:
        return await self.post(f"{self.API_PREFIX}/tasks/{task_id}/cancel", token=token)

    async def retry_task(self, task_id: str, token: str) -> dict:
        return await self.post(f"{self.API_PREFIX}/tasks/{task_id}/retry", token=token)

    async def delete_task(self, task_id: str, token: str) -> dict:
        return await self.delete(f"{self.API_PREFIX}/tasks/{task_id}", token=token)


_client: Optional[DataflowVulnScannerClient] = None


def get_dataflow_vuln_scanner_client() -> DataflowVulnScannerClient:
    global _client
    if _client is None:
        _client = DataflowVulnScannerClient()
    return _client
