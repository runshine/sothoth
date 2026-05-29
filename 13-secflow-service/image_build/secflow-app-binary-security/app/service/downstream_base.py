"""Shared helpers for downstream service clients."""

from __future__ import annotations

import time
from typing import Any, Optional

import httpx

from app.exception import ConflictError, NotFoundError, UpstreamError, ValidationError
from app.observability import observe_downstream_request, observe_task_error
from app.service.http_client import get_shared_async_client, invalidate_shared_async_client


class JsonHttpClient:
    def __init__(self, *, base_url: str, timeout: int):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _headers(self, token: Optional[str]) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _service_name(self) -> str:
        base = self.base_url.split("//", 1)[-1].split("/", 1)[0]
        return base.split(":", 1)[0] or "downstream"

    def _operation_name(self, path: str) -> str:
        value = str(path or "/").strip() or "/"
        parts = [part for part in value.split("/") if part]
        if len(parts) >= 2:
            return "/".join(parts[-2:])
        return parts[-1] if parts else "root"

    def _classify_request_error(self, exc: Exception) -> str:
        text = str(exc or "").strip().lower()
        if isinstance(exc, httpx.ConnectError):
            return "connect_error"
        if isinstance(exc, httpx.TimeoutException):
            return "timeout"
        stale_tokens = {
            "server disconnected without sending a response",
            "connection closed",
            "remote protocol error",
            "connection reset by peer",
            "broken pipe",
        }
        if any(token in text for token in stale_tokens):
            return "connection_reused_stale"
        if any(token in text for token in {"connect", "connection", "disconnected", "socket", "refused"}):
            return "connection_error"
        return "request_error"

    def _build_upstream_error(
        self,
        message: str,
        *,
        error_type_detail: str,
        retry_attempted: bool = False,
        client_recreated: bool = False,
    ) -> UpstreamError:
        exc = UpstreamError(message)
        exc.error_type_detail = error_type_detail
        exc.transport_error_kind = error_type_detail
        exc.retry_attempted = retry_attempted
        exc.client_recreated = client_recreated
        return exc

    async def _perform_get(
        self,
        path: str,
        *,
        token: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> tuple[httpx.Response, bool, bool]:
        client = await get_shared_async_client(self.base_url, timeout=self.timeout)
        try:
            resp = await client.get(f"{self.base_url}{path}", headers=self._headers(token), params=params)
            return resp, False, False
        except httpx.RequestError as exc:
            error_kind = self._classify_request_error(exc)
            if error_kind != "connection_reused_stale":
                raise
            client_recreated = await invalidate_shared_async_client(self.base_url, timeout=self.timeout)
            retry_client = await get_shared_async_client(self.base_url, timeout=self.timeout)
            try:
                resp = await retry_client.get(f"{self.base_url}{path}", headers=self._headers(token), params=params)
                return resp, True, client_recreated
            except httpx.RequestError as retry_exc:
                retry_exc.retry_attempted = True
                retry_exc.client_recreated = client_recreated
                retry_exc.error_type_detail = self._classify_request_error(retry_exc)
                retry_exc.transport_error_kind = retry_exc.error_type_detail
                raise retry_exc from exc

    async def get(self, path: str, *, token: str | None = None, params: dict[str, Any] | None = None) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            resp, retry_attempted, client_recreated = await self._perform_get(path, token=token, params=params)
        except httpx.TimeoutException as exc:
            observe_downstream_request(
                service=self._service_name(),
                method="GET",
                operation=self._operation_name(path),
                status="timeout",
                duration_seconds=time.perf_counter() - started,
            )
            observe_task_error("timeout", stage=self._service_name(), result="GET")
            raise self._build_upstream_error(
                f"下游服务 GET 超时: {self.base_url}{path}",
                error_type_detail=getattr(exc, "error_type_detail", "timeout"),
                retry_attempted=bool(getattr(exc, "retry_attempted", False)),
                client_recreated=bool(getattr(exc, "client_recreated", False)),
            )
        except httpx.ConnectError as exc:
            observe_downstream_request(
                service=self._service_name(),
                method="GET",
                operation=self._operation_name(path),
                status="connect_error",
                duration_seconds=time.perf_counter() - started,
            )
            observe_task_error("downstream_error", stage=self._service_name(), result="GET")
            raise self._build_upstream_error(
                f"无法连接下游服务: {exc}",
                error_type_detail=getattr(exc, "error_type_detail", "connect_error"),
                retry_attempted=bool(getattr(exc, "retry_attempted", False)),
                client_recreated=bool(getattr(exc, "client_recreated", False)),
            )
        except httpx.RequestError as exc:
            error_kind = getattr(exc, "error_type_detail", None) or self._classify_request_error(exc)
            observe_downstream_request(
                service=self._service_name(),
                method="GET",
                operation=self._operation_name(path),
                status=error_kind,
                duration_seconds=time.perf_counter() - started,
            )
            observe_task_error("downstream_error", stage=self._service_name(), result="GET")
            raise self._build_upstream_error(
                f"下游服务 GET 请求失败: {exc}",
                error_type_detail=error_kind,
                retry_attempted=bool(getattr(exc, "retry_attempted", False)),
                client_recreated=bool(getattr(exc, "client_recreated", False)),
            )
        return self._handle(resp, method="GET", path=path, duration_seconds=time.perf_counter() - started)

    async def post(self, path: str, *, token: str | None = None, json_body: dict[str, Any] | None = None) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            client = await get_shared_async_client(self.base_url, timeout=self.timeout)
            resp = await client.post(f"{self.base_url}{path}", headers=self._headers(token), json=json_body or {})
        except httpx.TimeoutException:
            observe_downstream_request(
                service=self._service_name(),
                method="POST",
                operation=self._operation_name(path),
                status="timeout",
                duration_seconds=time.perf_counter() - started,
            )
            observe_task_error("timeout", stage=self._service_name(), result="POST")
            raise UpstreamError(f"下游服务 POST 超时: {self.base_url}{path}")
        except httpx.ConnectError as exc:
            observe_downstream_request(
                service=self._service_name(),
                method="POST",
                operation=self._operation_name(path),
                status="connect_error",
                duration_seconds=time.perf_counter() - started,
            )
            observe_task_error("downstream_error", stage=self._service_name(), result="POST")
            raise UpstreamError(f"无法连接下游服务: {exc}")
        except httpx.RequestError as exc:
            observe_downstream_request(
                service=self._service_name(),
                method="POST",
                operation=self._operation_name(path),
                status="request_error",
                duration_seconds=time.perf_counter() - started,
            )
            observe_task_error("downstream_error", stage=self._service_name(), result="POST")
            raise UpstreamError(f"下游服务 POST 请求失败: {exc}")
        return self._handle(resp, method="POST", path=path, duration_seconds=time.perf_counter() - started)

    async def delete(self, path: str, *, token: str | None = None) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            client = await get_shared_async_client(self.base_url, timeout=self.timeout)
            resp = await client.delete(f"{self.base_url}{path}", headers=self._headers(token))
        except httpx.TimeoutException:
            observe_downstream_request(
                service=self._service_name(),
                method="DELETE",
                operation=self._operation_name(path),
                status="timeout",
                duration_seconds=time.perf_counter() - started,
            )
            observe_task_error("timeout", stage=self._service_name(), result="DELETE")
            raise UpstreamError(f"下游服务 DELETE 超时: {self.base_url}{path}")
        except httpx.ConnectError as exc:
            observe_downstream_request(
                service=self._service_name(),
                method="DELETE",
                operation=self._operation_name(path),
                status="connect_error",
                duration_seconds=time.perf_counter() - started,
            )
            observe_task_error("downstream_error", stage=self._service_name(), result="DELETE")
            raise UpstreamError(f"无法连接下游服务: {exc}")
        except httpx.RequestError as exc:
            observe_downstream_request(
                service=self._service_name(),
                method="DELETE",
                operation=self._operation_name(path),
                status="request_error",
                duration_seconds=time.perf_counter() - started,
            )
            observe_task_error("downstream_error", stage=self._service_name(), result="DELETE")
            raise UpstreamError(f"下游服务 DELETE 请求失败: {exc}")
        return self._handle(resp, method="DELETE", path=path, duration_seconds=time.perf_counter() - started)

    def _handle(self, resp: httpx.Response, *, method: str, path: str, duration_seconds: float) -> dict[str, Any]:
        observe_downstream_request(
            service=self._service_name(),
            method=method,
            operation=self._operation_name(path),
            status=str(resp.status_code),
            duration_seconds=duration_seconds,
        )
        if 200 <= resp.status_code < 300:
            return resp.json() if resp.content else {}
        text = resp.text
        if resp.status_code == 404:
            observe_task_error("downstream_error", stage=self._service_name(), result="404")
            raise NotFoundError(text or "下游资源不存在")
        if resp.status_code == 409:
            observe_task_error("downstream_error", stage=self._service_name(), result="409")
            raise ConflictError(text or "下游资源冲突")
        if resp.status_code in (400, 403, 422):
            observe_task_error("downstream_error", stage=self._service_name(), result=str(resp.status_code))
            raise ValidationError(text or "下游请求无效")
        observe_task_error("downstream_error", stage=self._service_name(), result=str(resp.status_code))
        raise UpstreamError(f"下游服务返回异常状态码: {resp.status_code}, body={text[:500]}")
