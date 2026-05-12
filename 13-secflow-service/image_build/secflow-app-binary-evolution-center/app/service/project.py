from __future__ import annotations

import httpx
from fastapi import HTTPException, status

from app.config import get_config


class ProjectService:
    def startup_validate(self) -> None:
        return None

    async def ensure_project_access(self, project_id: str, token: str) -> None:
        cfg = get_config().project_service
        async with httpx.AsyncClient(timeout=cfg.timeout) as client:
            response = await client.get(
                f"{cfg.base_url}{cfg.get_project_path}/{project_id}",
                headers={"Authorization": token},
            )
        if response.status_code != 200:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"project access denied: {project_id}")


_project_service: ProjectService | None = None


def get_project_service() -> ProjectService:
    global _project_service
    if _project_service is None:
        _project_service = ProjectService()
    return _project_service
