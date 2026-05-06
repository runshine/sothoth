from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class ProjectServiceError(RuntimeError):
    pass


class ProjectService:
    def __init__(self) -> None:
        self.config = get_config().project_service
        self.auth_config = get_config().auth_service

    def _headers(self, token: Optional[str]) -> dict[str, str]:
        if token:
            return {"Authorization": f"Bearer {token}"}
        machine_token = self.auth_config.service_machine_token
        if machine_token:
            return {"Authorization": f"Bearer {machine_token}"}
        return {}

    def startup_validate(self) -> None:
        if not self.config.enabled:
            return
        try:
            with httpx.Client(timeout=self.config.timeout) as client:
                response = client.get(self.config.health_url, headers=self._headers(None))
                response.raise_for_status()
        except Exception as exc:
            raise ProjectServiceError(f"project service unavailable: {exc}") from exc

    def get_project(self, project_id: str, token: Optional[str] = None) -> Optional[dict[str, Any]]:
        if not self.config.enabled:
            return {
                "id": project_id,
                "name": project_id,
                "status": "active",
            }
        try:
            with httpx.Client(timeout=self.config.timeout) as client:
                response = client.get(
                    f"{self.config.base_url}{self.config.get_project_path}/{project_id}",
                    headers=self._headers(token),
                )
            if response.status_code == 200:
                return response.json()
            if response.status_code in {401, 403, 404}:
                return None
            raise ProjectServiceError(
                f"project service returned unexpected status {response.status_code}: {response.text}"
            )
        except ProjectServiceError:
            raise
        except Exception as exc:
            raise ProjectServiceError(f"project lookup failed: {exc}") from exc

    def validate_project_access(self, project_id: str, token: Optional[str] = None) -> tuple[bool, Optional[dict[str, Any]]]:
        project = self.get_project(project_id, token)
        if not project:
            return False, None
        if project.get("status") != "active":
            return False, project
        return True, project


_project_service: ProjectService | None = None


def get_project_service() -> ProjectService:
    global _project_service
    if _project_service is None:
        _project_service = ProjectService()
    return _project_service
