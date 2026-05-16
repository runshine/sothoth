"""HTTP client for pi-re-agent REST API."""

from __future__ import annotations

import os
from typing import Any, Optional

import httpx

from app.config import get_config
from app.exception import ConflictError, NotFoundError, UpstreamError, ValidationError


class PiReAgentClient:
    def __init__(self, base_url: str | None = None):
        self.config = get_config().pi_re_agent
        self._base_url = base_url

    @property
    def base_url(self) -> str:
        return self._base_url or os.environ.get("PI_RE_AGENT_URL") or self.config.base_url

    @property
    def api_key(self) -> str | None:
        return os.environ.get("PI_RE_AGENT_API_KEY") or self.config.api_key

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def create_job(self, payload: dict[str, Any]) -> dict:
        headers = self._headers()
        idempotency_key = str(payload.get("idempotency_key") or "").strip()
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                resp = await client.post(
                    f"{self.base_url.rstrip('/')}/api/v1/jobs",
                    headers=headers,
                    json=payload,
                )
        except httpx.TimeoutException:
            raise UpstreamError("pi-re-agent创建任务超时")
        except httpx.ConnectError as exc:
            raise UpstreamError(f"无法连接pi-re-agent: {exc}")
        if resp.status_code == 409:
            try:
                data = resp.json()
            except Exception:
                data = {"error": resp.text or "pi-re-agent任务冲突"}
            if isinstance(data, dict) and data.get("error") == "active_job_exists":
                data["_conflict"] = True
                return data
        return _handle(resp)

    async def list_jobs(self, **params: Any) -> list[dict[str, Any]]:
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                resp = await client.get(
                    f"{self.base_url.rstrip('/')}/api/v1/jobs",
                    headers=self._headers(),
                    params={key: value for key, value in params.items() if value is not None},
                )
        except httpx.TimeoutException:
            raise UpstreamError("pi-re-agent查询任务列表超时")
        except httpx.ConnectError as exc:
            raise UpstreamError(f"无法连接pi-re-agent: {exc}")
        payload = _handle(resp)
        jobs = payload.get("jobs") if isinstance(payload, dict) else []
        return jobs if isinstance(jobs, list) else []

    async def get_job_by_target(self, target: str, *, active: bool = True) -> Optional[dict]:
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                resp = await client.get(
                    f"{self.base_url.rstrip('/')}/api/v1/jobs/by-target",
                    headers=self._headers(),
                    params={"target": target, "active": str(active).lower()},
                )
        except httpx.TimeoutException:
            raise UpstreamError("pi-re-agent按目标查询任务超时")
        except httpx.ConnectError as exc:
            raise UpstreamError(f"无法连接pi-re-agent: {exc}")
        if resp.status_code == 404:
            return None
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
_pi_clients: dict[str, PiReAgentClient] = {}


def get_pi_client(base_url: str | None = None) -> PiReAgentClient:
    global _pi_client
    if base_url:
        normalized = base_url.rstrip("/")
        if normalized not in _pi_clients:
            _pi_clients[normalized] = PiReAgentClient(normalized)
        return _pi_clients[normalized]
    if _pi_client is None:
        _pi_client = PiReAgentClient()
    return _pi_client
