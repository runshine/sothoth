"""Project service client."""

from __future__ import annotations

from typing import Optional

import httpx

from app.config import get_config
from app.exception import ForbiddenError, UpstreamError


class ProjectService:
    def __init__(self):
        self.config = get_config().project_service

    async def require_access(self, token: str, project_id: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                resp = await client.get(
                    f"{self.config.base_url}{self.config.get_project_path}/{project_id}",
                    headers={"Authorization": f"Bearer {token}"},
                )
        except httpx.TimeoutException:
            raise UpstreamError("Project 服务请求超时")
        except httpx.ConnectError as exc:
            raise UpstreamError(f"无法连接 Project 服务: {exc}")

        if resp.status_code == 200:
            return resp.json()
        if resp.status_code in (403, 404):
            raise ForbiddenError(f"无权访问项目: {project_id}")
        raise UpstreamError(f"Project 服务返回异常状态码: {resp.status_code}")


_project_service: Optional[ProjectService] = None


def get_project_service() -> ProjectService:
    global _project_service
    if _project_service is None:
        _project_service = ProjectService()
    return _project_service
