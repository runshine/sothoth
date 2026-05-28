"""Project service client."""

from __future__ import annotations

import time
from typing import Optional

import httpx

from app.config import get_config
from app.exception import ForbiddenError, UpstreamError
from app.observability import observe_downstream_request
from app.service.http_client import get_shared_async_client


class ProjectService:
    def __init__(self):
        self.config = get_config().project_service

    async def require_access(self, token: str, project_id: str) -> dict:
        url = f"{self.config.base_url}{self.config.get_project_path}/{project_id}"
        headers = {"Authorization": f"Bearer {token}"}
        started = time.perf_counter()
        last_error: httpx.RequestError | None = None
        retry_count = max(0, int(get_config().http_client.retry_count))
        for attempt in range(retry_count + 1):
            try:
                client = await get_shared_async_client("project-service", timeout=self.config.timeout)
                resp = await client.get(url, headers=headers)
                if attempt > 0:
                    observe_downstream_request(
                        service="project_service",
                        method="GET",
                        operation="require_access",
                        status="retry_success",
                        duration_seconds=time.perf_counter() - started,
                    )
                break
            except httpx.TimeoutException:
                observe_downstream_request(
                    service="project_service",
                    method="GET",
                    operation="require_access",
                    status="timeout",
                    duration_seconds=time.perf_counter() - started,
                )
                raise UpstreamError("Project 服务请求超时")
            except httpx.ConnectError as exc:
                observe_downstream_request(
                    service="project_service",
                    method="GET",
                    operation="require_access",
                    status="connect_error",
                    duration_seconds=time.perf_counter() - started,
                )
                raise UpstreamError(f"无法连接 Project 服务: {exc}")
            except httpx.RequestError as exc:
                last_error = exc
                if attempt < retry_count:
                    continue
                observe_downstream_request(
                    service="project_service",
                    method="GET",
                    operation="require_access",
                    status="retry_failed",
                    duration_seconds=time.perf_counter() - started,
                )
                raise UpstreamError(f"Project 服务请求失败: {exc}")
        else:
            observe_downstream_request(
                service="project_service",
                method="GET",
                operation="require_access",
                status="retry_failed",
                duration_seconds=time.perf_counter() - started,
            )
            raise UpstreamError(f"Project 服务请求失败: {last_error}")

        observe_downstream_request(
            service="project_service",
            method="GET",
            operation="require_access",
            status=str(resp.status_code),
            duration_seconds=time.perf_counter() - started,
        )
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
