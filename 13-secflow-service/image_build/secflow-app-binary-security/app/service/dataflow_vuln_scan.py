"""Adapter for secflow-app-dataflow-vuln-scan."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from app.config import get_config
from app.service.downstream_base import JsonHttpClient


class DataflowVulnScanClient(JsonHttpClient):
    API_PREFIX = "/api/app/dataflow-vuln-scan"

    def __init__(self) -> None:
        app_cfg = get_config()
        cfg = app_cfg.services.dataflow_vuln_scan
        super().__init__(base_url=cfg.base_url.rstrip("/"), timeout=app_cfg.scheduler.downstream_request_timeout_seconds)

    def _project_filesystem_ref(self, project_id: str, path: str) -> dict[str, Any]:
        """Convert a shared /data/files/<project_id>/... path to DFVS input ref."""
        cfg = get_config().services.fileserver
        project_root = (Path(cfg.data_mount_path) / cfg.project_files_dirname / str(project_id)).resolve()
        candidate = Path(path).resolve()
        try:
            relative = candidate.relative_to(project_root)
        except ValueError as exc:
            raise ValueError(f"dataflow-vuln-scan input must be under project root {project_root}: {candidate}") from exc
        project_path = "/" + relative.as_posix().lstrip("/")
        return {
            "source": "project_filesystem",
            "path": project_path if project_path != "/." else "/",
            "filename": candidate.name or None,
        }

    async def create_task(
        self,
        project_id: str,
        task_name: str,
        module_input_path: str,
        source_root_path: str,
        prompt_content: str,
        origin: dict[str, Any] | None = None,
        token: str | None = None,
        agent_task_key: dict[str, Any] | None = None,
        *,
        source_file: str | None = None,
        function_name: str | None = None,
        line_hint: str | None = None,
        definition_kind: str | None = None,
        taint_params: list[str] | None = None,
        function_description: str | None = None,
        entry_reason: str | None = None,
        taint_details: list[dict[str, Any]] | None = None,
        function_description_source: str | None = None,
        entry_reason_source: str | None = None,
    ) -> dict:
        return await self.post(
            f"{self.API_PREFIX}/tasks",
            token=token,
            json_body={
                "project_id": project_id,
                "task_name": task_name,
                "input_path": module_input_path,
                "module_input_path": module_input_path,
                "source_root_path": source_root_path,
                "task_description": "由 binary security 编排器触发的漏洞扫描任务",
                "prompt_content": prompt_content,
                "source_file": source_file,
                "function_name": function_name,
                "line_hint": line_hint,
                "definition_kind": definition_kind,
                "taint_params": taint_params or [],
                "function_description": function_description or "",
                "function_description_source": function_description_source or "",
                "entry_reason": entry_reason or "",
                "entry_reason_source": entry_reason_source or "",
                "taint_details": taint_details or [],
                **(origin or {}),
                **(agent_task_key or {}),
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
        parent_task_id: str | None = None,
        parent_stage_item_id: str | None = None,
    ) -> list[dict]:
        safe_limit = max(1, int(limit or 100))
        safe_offset = max(0, int(offset or 0))
        params: dict[str, Any] = {
            "project_id": project_id,
            "page": (safe_offset // safe_limit) + 1,
            "per_page": safe_limit,
        }
        if status:
            params["status"] = status
        if parent_task_id:
            params["parent_task_id"] = parent_task_id
        if parent_stage_item_id:
            params["parent_stage_item_id"] = parent_stage_item_id
        return await self.get(f"{self.API_PREFIX}/tasks", token=token, params=params)

    async def get_artifacts(self, task_id: str, token: str) -> dict:
        return await self.get(f"{self.API_PREFIX}/tasks/{task_id}/artifacts", token=token)

    async def cancel_task(self, task_id: str, token: str) -> dict:
        return await self.post(f"{self.API_PREFIX}/tasks/{task_id}/cancel", token=token)

    async def retry_task(self, task_id: str, token: str) -> dict:
        return await self.post(f"{self.API_PREFIX}/tasks/{task_id}/restart", token=token)

    async def delete_task(self, task_id: str, token: str) -> dict:
        return await self.delete(f"{self.API_PREFIX}/tasks/{task_id}", token=token)


_client: Optional[DataflowVulnScanClient] = None


def get_dataflow_vuln_scan_client() -> DataflowVulnScanClient:
    global _client
    if _client is None:
        _client = DataflowVulnScanClient()
    return _client
