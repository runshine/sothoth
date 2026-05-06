"""Shared helpers for downstream service clients."""

from __future__ import annotations

from typing import Any, Optional

import httpx

from app.exception import ConflictError, NotFoundError, UpstreamError, ValidationError


class JsonHttpClient:
    def __init__(self, *, base_url: str, timeout: int):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _headers(self, token: Optional[str]) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    async def get(self, path: str, *, token: str | None = None, params: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.base_url}{path}", headers=self._headers(token), params=params)
        except httpx.TimeoutException:
            raise UpstreamError(f"下游服务 GET 超时: {self.base_url}{path}")
        except httpx.ConnectError as exc:
            raise UpstreamError(f"无法连接下游服务: {exc}")
        return self._handle(resp)

    async def post(self, path: str, *, token: str | None = None, json_body: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(f"{self.base_url}{path}", headers=self._headers(token), json=json_body or {})
        except httpx.TimeoutException:
            raise UpstreamError(f"下游服务 POST 超时: {self.base_url}{path}")
        except httpx.ConnectError as exc:
            raise UpstreamError(f"无法连接下游服务: {exc}")
        return self._handle(resp)

    async def delete(self, path: str, *, token: str | None = None) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.delete(f"{self.base_url}{path}", headers=self._headers(token))
        except httpx.TimeoutException:
            raise UpstreamError(f"下游服务 DELETE 超时: {self.base_url}{path}")
        except httpx.ConnectError as exc:
            raise UpstreamError(f"无法连接下游服务: {exc}")
        return self._handle(resp)

    def _handle(self, resp: httpx.Response) -> dict[str, Any]:
        if 200 <= resp.status_code < 300:
            return resp.json() if resp.content else {}
        text = resp.text
        if resp.status_code == 404:
            raise NotFoundError(text or "下游资源不存在")
        if resp.status_code == 409:
            raise ConflictError(text or "下游资源冲突")
        if resp.status_code in (400, 403, 422):
            raise ValidationError(text or "下游请求无效")
        raise UpstreamError(f"下游服务返回异常状态码: {resp.status_code}, body={text[:500]}")
