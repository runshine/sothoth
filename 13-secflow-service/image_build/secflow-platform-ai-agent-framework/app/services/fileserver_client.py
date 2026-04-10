from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from app.artifacts.io import ensure_dir, sanitize_name
from app.config import get_config


class FileserverClientError(RuntimeError):
    pass


class FileserverClient:
    def __init__(self) -> None:
        self.config = get_config().fileserver_service

    def _headers(self, token: str | None) -> dict[str, str]:
        if token:
            return {"Authorization": f"Bearer {token}"}
        return {}

    def _handle_response(self, response: httpx.Response) -> Any:
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            detail = ""
            try:
                payload = response.json()
                detail = payload.get("detail") or payload.get("message") or ""
            except Exception:
                detail = response.text
            raise FileserverClientError(detail or str(exc)) from exc
        return response.json() if response.text else {}

    def ensure_subproject(self, *, project_id: str, authorization_token: str | None, created_by: str) -> dict[str, Any]:
        if not self.config.enabled or not authorization_token:
            return self._fallback_subproject(project_id)

        headers = self._headers(authorization_token)
        try:
            with httpx.Client(timeout=self.config.timeout) as client:
                response = client.get(
                    f"{self.config.base_url}/subprojects",
                    params={"project_id": project_id},
                    headers=headers,
                )
                payload = self._handle_response(response)
                for item in payload.get("items", []):
                    if item.get("name") == self.config.aiwf_subproject_name:
                        return {
                            "id": item["id"],
                            "name": item["name"],
                            "root_dir": self._subproject_root(project_id, item["id"]),
                            "mode": "fileserver",
                        }

                create_response = client.post(
                    f"{self.config.base_url}/subprojects",
                    json={
                        "project_id": project_id,
                        "name": self.config.aiwf_subproject_name,
                        "description": "AI工作流共享工作区",
                    },
                    headers=headers,
                )
                created = self._handle_response(create_response)
                return {
                    "id": created["id"],
                    "name": created["name"],
                    "root_dir": self._subproject_root(project_id, created["id"]),
                    "mode": "fileserver",
                }
        except (httpx.HTTPError, FileserverClientError):
            return self._fallback_subproject(project_id)

    def _subproject_root(self, project_id: str, subproject_id: int | str) -> Path:
        return ensure_dir(
            Path(self.config.data_mount_path)
            / self.config.project_files_dirname
            / sanitize_name(project_id)
            / sanitize_name(str(subproject_id))
        )

    def _fallback_subproject(self, project_id: str) -> dict[str, Any]:
        root_dir = ensure_dir(
            Path(self.config.data_mount_path)
            / self.config.project_files_dirname
            / sanitize_name(project_id)
            / sanitize_name(self.config.aiwf_subproject_name)
        )
        return {
            "id": self.config.aiwf_subproject_name,
            "name": self.config.aiwf_subproject_name,
            "root_dir": root_dir,
            "mode": "filesystem-fallback",
        }


_fileserver_client: FileserverClient | None = None


def get_fileserver_client() -> FileserverClient:
    global _fileserver_client
    if _fileserver_client is None:
        _fileserver_client = FileserverClient()
    return _fileserver_client
