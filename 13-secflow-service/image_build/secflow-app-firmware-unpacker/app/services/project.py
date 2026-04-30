"""Project service client."""

from __future__ import annotations

from typing import Optional

import httpx

from app.config import get_config


class ProjectService:
    def __init__(self):
        self.config = get_config().project_service

    async def get_project(self, token: str, project_id: str) -> Optional[dict]:
        if not self.config.enabled:
            return {
                "id": project_id,
                "status": "active",
            }

        headers = {"Authorization": f"Bearer {token}"}
        url = f"{self.config.base_url.rstrip('/')}/{project_id}"
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.get(url, headers=headers)
        except httpx.HTTPError:
            return None

        if response.status_code != 200:
            return None
        return response.json() if response.content else {}

    async def validate_project_access(
        self,
        token: str,
        project_id: str,
    ) -> tuple[bool, Optional[dict]]:
        project = await self.get_project(token, project_id)
        if not project:
            return False, None
        if project.get("status") not in (None, "", "active"):
            return False, project
        return True, project


_project_service: Optional[ProjectService] = None


def get_project_service() -> ProjectService:
    global _project_service
    if _project_service is None:
        _project_service = ProjectService()
    return _project_service
