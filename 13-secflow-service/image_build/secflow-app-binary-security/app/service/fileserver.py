"""Fileserver client helpers."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Optional

import httpx

from app.config import get_config
from app.exception import UpstreamError
from app.service.http_client import get_shared_async_client
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
        )

    def project_files_root(self, project_id: str) -> Path:
        return self._fallback_root(project_id)

    def project_relative_path(self, *parts: str) -> str:
        cleaned = [str(part).strip("/").replace("\\", "/") for part in parts if str(part).strip("/")]
        return "/" + "/".join(cleaned)

    def project_absolute_path(self, project_id: str, path: str) -> Path:
        root = self.project_files_root(project_id).resolve()
        raw = Path(str(path or "").strip())
        target = raw.resolve() if raw.is_absolute() else (root / str(path or "").strip("/")).resolve()
        if root not in (target, *target.parents):
            raise UpstreamError(f"项目路径越权: {path}")
        return target

    async def ensure_subproject(self, project_id: str, authorization_token: str | None, created_by: str) -> dict[str, Any]:
        headers = self._headers(authorization_token)
        try:
            client = await get_shared_async_client("fileserver-service", timeout=self.config.timeout)
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

    async def ensure_project_directory(self, project_id: str, path: str, authorization_token: str | None) -> str:
        root = self.project_files_root(project_id).resolve()
        local_path = self.project_absolute_path(project_id, path)
        if local_path == root:
            return str(local_path)
        if local_path.is_dir():
            return str(local_path)
        headers = self._headers(authorization_token)
        try:
            client = await get_shared_async_client("fileserver-service", timeout=self.config.timeout)
            current_path = root
            for part in local_path.relative_to(root).parts:
                current_path = current_path / part
                resp = await client.post(
                    f"{self.config.base_url.rstrip('/')}/project-filesystem/directories",
                    json={"project_id": project_id, "path": str(current_path)},
                    headers=headers,
                )
                if resp.status_code in (200, 201, 409):
                    continue
                if resp.status_code == 404:
                    raise UpstreamError(f"父目录不存在: {current_path}")
                resp.raise_for_status()
        except Exception:
            ensure_dir(local_path)
        return str(local_path)

    async def delete_project_path(self, project_id: str, path: str, authorization_token: str | None, recursive: bool = True) -> None:
        target_path = self.project_absolute_path(project_id, path)
        if target_path == self.project_files_root(project_id).resolve():
            return
        headers = self._headers(authorization_token)
        try:
            client = await get_shared_async_client("fileserver-service", timeout=self.config.timeout)
            resp = await client.delete(
                f"{self.config.base_url.rstrip('/')}/project-filesystem",
                params={
                    "project_id": project_id,
                    "path": str(target_path),
                    "recursive": str(bool(recursive)).lower(),
                },
                headers=headers,
            )
            if resp.status_code in (200, 204, 404):
                return
            resp.raise_for_status()
        except Exception:
            local_path = self.project_files_root(project_id) / normalized.lstrip("/")
            if local_path.is_dir():
                shutil.rmtree(local_path, ignore_errors=True)
                return
            if local_path.exists():
                local_path.unlink(missing_ok=True)


_fileserver_client: Optional[FileserverClient] = None


def get_fileserver_client() -> FileserverClient:
    global _fileserver_client
    if _fileserver_client is None:
        _fileserver_client = FileserverClient()
    return _fileserver_client
