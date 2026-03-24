"""Project service client."""

from typing import Optional

import httpx

from app.config import get_config


class ProjectServiceError(Exception):
    pass


class ProjectService:
    def __init__(self):
        self.config = get_config().project_service

    async def get_project(self, token: str, project_id: str) -> Optional[dict]:
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.get(
                    f"{self.config.base_url}{self.config.get_project_path}/{project_id}",
                    headers={"Authorization": f"Bearer {token}"},
                )
                if response.status_code == 200:
                    return response.json()
                if response.status_code in (403, 404):
                    return None
                raise ProjectServiceError(f"Project服务返回异常状态码: {response.status_code}")
        except httpx.TimeoutException:
            raise ProjectServiceError("Project服务请求超时")
        except httpx.ConnectError as exc:
            raise ProjectServiceError(f"无法连接到Project服务: {exc}")


_project_service: Optional[ProjectService] = None


def get_project_service() -> ProjectService:
    global _project_service
    if _project_service is None:
        _project_service = ProjectService()
    return _project_service
