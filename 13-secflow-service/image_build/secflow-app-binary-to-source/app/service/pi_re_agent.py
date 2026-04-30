"""HTTP client for pi-re-agent REST API."""

from __future__ import annotations

import os
from typing import Any, Optional

import httpx

from app.config import get_config
from app.exception import ConflictError, NotFoundError, UpstreamError, ValidationError


class PiReAgentClient:
    def __init__(self):
        self.config = get_config().pi_re_agent

    @property
    def base_url(self) -> str:
        return os.environ.get("PI_RE_AGENT_URL") or self.config.base_url

    @property
    def api_key(self) -> str | None:
        return os.environ.get("PI_RE_AGENT_API_KEY") or self.config.api_key

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def create_job(self, payload: dict[str, Any]) -> dict:
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                resp = await client.post(
                    f"{self.base_url.rstrip('/')}/api/v1/jobs",
                    headers=self._headers(),
                    json=payload,
                )
        except httpx.TimeoutException:
            raise UpstreamError("pi-re-agent创建任务超时")
        except httpx.ConnectError as exc:
            raise UpstreamError(f"无法连接pi-re-agent: {exc}")
        return _handle(resp)

    async def get_job(self, job_id: str) -> Optional[dict]:
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                resp = await client.get(
                    f"{self.base_url.rstrip('/')}/api/v1/jobs/{job_id}",
                    headers=self._headers(),
                )
        except httpx.TimeoutException:
            raise UpstreamError("pi-re-agent查询任务超时")
        except httpx.ConnectError as exc:
            raise UpstreamError(f"无法连接pi-re-agent: {exc}")
        if resp.status_code == 404:
            return None
        return _handle(resp)

    async def cancel_job(self, job_id: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                resp = await client.post(
                    f"{self.base_url.rstrip('/')}/api/v1/jobs/{job_id}/cancel",
                    headers=self._headers(),
                )
        except httpx.TimeoutException:
            raise UpstreamError("pi-re-agent取消任务超时")
        except httpx.ConnectError as exc:
            raise UpstreamError(f"无法连接pi-re-agent: {exc}")
        if resp.status_code == 409:
            return {"status": "already_terminal"}
        return _handle(resp)


def _handle(resp: httpx.Response) -> dict:
    if 200 <= resp.status_code < 300:
        return resp.json() if resp.content else {}
    text = resp.text
    if resp.status_code == 404:
        raise NotFoundError("pi-re-agent任务不存在")
    if resp.status_code == 409:
        raise ConflictError(text or "pi-re-agent任务冲突")
    if resp.status_code in (403, 422):
        raise ValidationError(text or "pi-re-agent参数校验失败")
    raise UpstreamError(f"pi-re-agent返回异常状态码: {resp.status_code}, body={text[:500]}")


_pi_client: Optional[PiReAgentClient] = None


def get_pi_client() -> PiReAgentClient:
    global _pi_client
    if _pi_client is None:
        _pi_client = PiReAgentClient()
    return _pi_client
