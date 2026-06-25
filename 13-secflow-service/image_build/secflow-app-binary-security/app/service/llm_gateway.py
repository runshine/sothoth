"""Client for GaiaSec LLM Gateway work key issuance."""

from __future__ import annotations

from typing import Any, Optional

import httpx

from app.config import get_config
from app.exception import ForbiddenError, UnauthorizedError, UpstreamError, ValidationError
from app.service.http_client import get_shared_async_client


class LLMGatewayWorkKeyIssueError(UpstreamError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        response_text: str | None = None,
        request_payload_preview: dict[str, Any] | None = None,
        retryable: bool = True,
    ) -> None:
        super().__init__(message)
        self.gateway_status_code = status_code
        self.response_text = response_text
        self.request_payload_preview = dict(request_payload_preview or {})
        self.retryable = bool(retryable)


class LLMGatewayClient:
    def __init__(self) -> None:
        cfg = get_config().llm_gateway
        self.config = cfg
        self.base_url = str(cfg.base_url or "").rstrip("/")
        self.work_key_path = str(cfg.work_key_path or "/api/aigw/work-keys").strip() or "/api/aigw/work-keys"
        self.timeout_seconds = max(1, int(cfg.timeout_seconds or 30))

    async def issue_work_key(
        self,
        *,
        task_key_secret: str,
        sub_task_id: str,
        key_name: str,
        description: str,
        max_concurrency: int = 0,
        enabled: bool = True,
        expires_at: str | None = None,
    ) -> dict[str, Any]:
        token = str(task_key_secret or "").strip()
        if not token:
            raise ValidationError("缺少 task key，无法申请 work key")
        payload: dict[str, Any] = {
            "sub_task_id": str(sub_task_id or "").strip(),
            "key_name": str(key_name or "").strip() or None,
            "max_concurrency": int(max_concurrency or 0),
            "enabled": bool(enabled),
            "description": str(description or "").strip() or None,
        }
        if expires_at:
            payload["expires_at"] = str(expires_at).strip()
        if not payload["sub_task_id"]:
            raise ValidationError("缺少 sub_task_id，无法申请 work key")
        if payload["key_name"] is None:
            payload.pop("key_name", None)
        if payload["description"] is None:
            payload.pop("description", None)

        url = f"{self.base_url}{self.work_key_path}"
        client = await get_shared_async_client("llm-gateway", timeout=self.timeout_seconds)
        try:
            response = await client.post(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
        except httpx.TimeoutException as exc:
            raise LLMGatewayWorkKeyIssueError(
                "LLM Gateway work key 签发超时",
                request_payload_preview=payload,
                retryable=True,
            ) from exc
        except httpx.RequestError as exc:
            raise LLMGatewayWorkKeyIssueError(
                f"无法连接 LLM Gateway: {exc}",
                request_payload_preview=payload,
                retryable=True,
            ) from exc

        text = response.text or ""
        if response.status_code == 201:
            try:
                body = response.json()
            except ValueError as exc:
                raise LLMGatewayWorkKeyIssueError(
                    "LLM Gateway 返回的 work key 响应不是合法 JSON",
                    status_code=response.status_code,
                    response_text=text[:500],
                    request_payload_preview=payload,
                    retryable=False,
                ) from exc
            if not isinstance(body, dict):
                raise LLMGatewayWorkKeyIssueError(
                    "LLM Gateway 返回的 work key 响应格式非法",
                    status_code=response.status_code,
                    response_text=text[:500],
                    request_payload_preview=payload,
                    retryable=False,
                )
            return body

        if response.status_code == 401:
            raise UnauthorizedError("LLM Gateway 拒绝签发 worker key：task key 无效或缺失")
        if response.status_code == 403:
            raise ForbiddenError("LLM Gateway 拒绝签发 worker key：当前 key 无权创建 work key")

        retryable = response.status_code in {429} or response.status_code >= 500
        raise LLMGatewayWorkKeyIssueError(
            f"LLM Gateway work key 签发失败: status={response.status_code}",
            status_code=response.status_code,
            response_text=text[:500],
            request_payload_preview=payload,
            retryable=retryable,
        )


_client: Optional[LLMGatewayClient] = None


def get_llm_gateway_client() -> LLMGatewayClient:
    global _client
    if _client is None:
        _client = LLMGatewayClient()
    return _client
