"""Fileserver client helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import httpx

from app.config import get_config
from app.exception import UpstreamError
from app.service.security import ensure_dir


class FileserverClient:
    def __init__(self) -> None:
        self.config = get_config().services.fileserver
        self.auth = get_config().auth_service

    def _headers(self, token: str | None) -> dict[str, str]:
        if token:
            return {"Authorization": f"Bearer {token}"}
        if self.auth.service_machine_token:
            return {"Authorization": f"Bearer {self.auth.service_machine_token}"}
        return {}

    def _fallback_root(self, project_id: str) -> Path:
        return ensure_dir(
            Path(self.config.data_mount_path)
            / self.config.project_files_dirname
            / project_id
            / self.config.subproject_name
        )

    async def ensure_subproject(self, project_id: str, authorization_token: str | None, created_by: str) -> dict[str, Any]:
        headers = self._headers(authorization_token)
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                resp = await client.get(
                    f"{self.config.base_url.rstrip('/')}/subprojects",
                    params={"project_id": project_id},
                    headers=headers,
                )
                if resp.status_code == 200:
                    payload = resp.json()
                    for item in payload.get("items", []):
                        if item.get("name") == self.config.subproject_name:
                            return {
                                "id": str(item.get("id")),
                                "name": item.get("name"),
                                "root_dir": str(self._fallback_root(project_id)),
                                "mode": "fileserver",
                            }
                create_resp = await client.post(
                    f"{self.config.base_url.rstrip('/')}/subprojects",
                    json={
                        "project_id": project_id,
                        "name": self.config.subproject_name,
                        "description": "Binary Security 编排结果工作区",
                    },
                    headers=headers,
                )
                if create_resp.status_code in (200, 201):
                    created = create_resp.json()
                    return {
                        "id": str(created.get("id")),
                        "name": created.get("name"),
                        "root_dir": str(self._fallback_root(project_id)),
                        "mode": "fileserver",
                    }
        except httpx.HTTPError:
            pass
        return {
            "id": self.config.subproject_name,
            "name": self.config.subproject_name,
            "root_dir": str(self._fallback_root(project_id)),
            "mode": "filesystem-fallback",
        }


_fileserver_client: Optional[FileserverClient] = None


def get_fileserver_client() -> FileserverClient:
    global _fileserver_client
    if _fileserver_client is None:
        _fileserver_client = FileserverClient()
    return _fileserver_client
