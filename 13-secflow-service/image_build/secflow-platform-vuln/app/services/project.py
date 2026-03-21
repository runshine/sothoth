"""Project service integration."""

from typing import Optional

import httpx


class ProjectService:
    def __init__(
        self,
        base_url: str,
        get_project_path: str = "/api/project",
        timeout: int = 10,
        service_machine_token: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.get_project_path = get_project_path
        self.timeout = timeout
        self.service_machine_token = service_machine_token

    def _build_headers(self, token: Optional[str]) -> dict:
        if token:
            return {"Authorization": f"Bearer {token}"}
        if self.service_machine_token:
            return {"Authorization": f"Bearer {self.service_machine_token}"}
        return {}

    async def get_project(self, project_id: str, token: Optional[str] = None) -> Optional[dict]:
        headers = self._build_headers(token)
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(f"{self.base_url}{self.get_project_path}/{project_id}", headers=headers)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    async def validate_project_access(self, project_id: str, token: Optional[str] = None) -> tuple[bool, Optional[dict]]:
        project = await self.get_project(project_id, token)
        if not project:
            return False, None
        if project.get("status") != "active":
            return False, project
        return True, project


_project_service: Optional[ProjectService] = None


def init_project_service(
    base_url: str,
    get_project_path: str = "/api/project",
    timeout: int = 10,
    service_machine_token: Optional[str] = None,
) -> None:
    global _project_service
    _project_service = ProjectService(
        base_url=base_url,
        get_project_path=get_project_path,
        timeout=timeout,
        service_machine_token=service_machine_token,
    )


def get_project_service() -> ProjectService:
    if _project_service is None:
        raise RuntimeError("Project service not initialized")
    return _project_service
