"""
Fileserver service client for workflow service.
"""

from typing import Any, Dict, Optional

import httpx

from app.config import get_config


class FileserverClientError(Exception):
    """Fileserver service error."""


class FileserverClient:
    """Fileserver service client."""

    def __init__(self):
        self.config = get_config().fileserver_service
        timeout = self.config.timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._timeout = timeout

    @property
    def client(self) -> httpx.AsyncClient:
        """Get async HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    def _headers(self, token: str) -> Dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    async def get_storage_pvc(self, token: str) -> Dict[str, Any]:
        response = await self.client.get(
            f"{self.config.base_url}/storage/pvc",
            headers=self._headers(token),
        )
        return self._handle_response(response)

    async def get_subproject_children(self, project_id: str, subproject_id: int, token: str) -> Dict[str, Any]:
        response = await self.client.get(
            f"{self.config.base_url}/subprojects/{subproject_id}/children",
            params={"project_id": project_id},
            headers=self._headers(token),
        )
        return self._handle_response(response)

    async def get_directory_children(self, project_id: str, directory_id: int, token: str) -> Dict[str, Any]:
        response = await self.client.get(
            f"{self.config.base_url}/directories/{directory_id}/children",
            params={"project_id": project_id},
            headers=self._headers(token),
        )
        return self._handle_response(response)

    @staticmethod
    def _handle_response(response: httpx.Response) -> Dict[str, Any]:
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
        return response.json()


_fileserver_client: Optional[FileserverClient] = None


def get_fileserver_client() -> FileserverClient:
    """Get singleton fileserver client."""
    global _fileserver_client
    if _fileserver_client is None:
        _fileserver_client = FileserverClient()
    return _fileserver_client
