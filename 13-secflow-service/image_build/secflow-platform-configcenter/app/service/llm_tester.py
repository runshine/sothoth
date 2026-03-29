"""LLM provider availability test helpers."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlencode

import httpx

from app.exception import ValidationError
from app.schemas import LlmProviderTestRequest, LlmProviderTestResponse


TEST_PROMPT = "Reply with OK only."
DEFAULT_ANTHROPIC_VERSION = "2023-06-01"
PREVIEW_LIMIT = 160


def _trimmed(value: str | None) -> str:
    return (value or "").strip()


def _join_url(base: str, suffix: str) -> str:
    normalized_base = _trimmed(base).rstrip("/")
    normalized_suffix = suffix if suffix.startswith("/") else f"/{suffix}"
    if normalized_base.endswith(normalized_suffix):
        return normalized_base
    return f"{normalized_base}{normalized_suffix}"


def _append_query(url: str, query: dict[str, Any]) -> str:
    clean_query = {key: value for key, value in query.items() if value not in (None, "")}
    if not clean_query:
        return url
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{urlencode(clean_query)}"


def _coerce_preview(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
    elif isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, dict):
                text = item.get("text")
                if text:
                    parts.append(str(text))
            elif isinstance(item, str):
                parts.append(item)
        text = "".join(parts).strip()
    else:
        text = str(value).strip()
    if not text:
        return None
    if len(text) <= PREVIEW_LIMIT:
        return text
    return f"{text[:PREVIEW_LIMIT]}..."


def _response_preview(provider_type: str, payload: dict[str, Any]) -> str | None:
    if provider_type == "anthropic":
        return _coerce_preview(payload.get("content"))
    if provider_type == "ollama":
        message = payload.get("message") or {}
        return _coerce_preview(message.get("content"))
    choices = payload.get("choices") or []
    if choices:
        first_choice = choices[0] or {}
        message = first_choice.get("message") or {}
        preview = _coerce_preview(message.get("content"))
        if preview:
            return preview
        return _coerce_preview(first_choice.get("text"))
    return _coerce_preview(payload.get("output_text"))


def _read_success_payload(response: httpx.Response) -> tuple[dict[str, Any], str | None]:
    try:
        payload = response.json()
        if isinstance(payload, dict):
            return payload, _response_preview("", payload)
        return {}, _coerce_preview(payload)
    except Exception:
        return {}, _coerce_preview(response.text)


def _normalize_error_message(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        return str(exc.detail.get("message") or "测试配置不合法")
    if isinstance(exc, httpx.TimeoutException):
        return "请求超时，请检查网络、网关或模型服务响应时间"
    if isinstance(exc, httpx.ConnectError):
        return "连接失败，请检查 API Base 是否可达"
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        try:
            payload = exc.response.json()
            detail = payload.get("error") or payload.get("message") or payload.get("detail") or payload
            return f"上游返回 {status}: {detail}"
        except Exception:
            text = exc.response.text.strip()
            return f"上游返回 {status}: {text or exc.response.reason_phrase}"
    return str(exc) or "测试请求失败"


def _ensure_required(payload: LlmProviderTestRequest):
    if not _trimmed(payload.api_base):
        raise ValidationError("测试前请填写 API Base")
    if not _trimmed(payload.api_key):
        raise ValidationError("测试前请填写 API Key")
    if not _trimmed(payload.model):
        raise ValidationError("测试前请填写模型")
    if payload.provider_type == "azure-openai" and not _trimmed(payload.api_version):
        raise ValidationError("Azure OpenAI 测试前请填写 API Version")


def _build_openai_request(payload: LlmProviderTestRequest) -> tuple[str, dict[str, str], dict[str, Any]]:
    target = _join_url(payload.api_base, "/chat/completions")
    headers = {
        "Authorization": f"Bearer {_trimmed(payload.api_key)}",
        "Content-Type": "application/json",
    }
    if _trimmed(payload.organization):
        headers["OpenAI-Organization"] = _trimmed(payload.organization)
    body = {
        "model": _trimmed(payload.model),
        "messages": [{"role": "user", "content": TEST_PROMPT}],
        "max_tokens": 1,
    }
    if payload.temperature is not None:
        body["temperature"] = payload.temperature
    return target, headers, body


def _build_azure_request(payload: LlmProviderTestRequest) -> tuple[str, dict[str, str], dict[str, Any]]:
    base = _trimmed(payload.api_base)
    if "openai/deployments" in base and "chat/completions" in base:
        target = base
    else:
        target = _join_url(base, f"/openai/deployments/{_trimmed(payload.model)}/chat/completions")
    target = _append_query(target, {"api-version": _trimmed(payload.api_version)})
    headers = {
        "api-key": _trimmed(payload.api_key),
        "Content-Type": "application/json",
    }
    body = {
        "messages": [{"role": "user", "content": TEST_PROMPT}],
        "max_tokens": 1,
    }
    if payload.temperature is not None:
        body["temperature"] = payload.temperature
    return target, headers, body


def _build_anthropic_request(payload: LlmProviderTestRequest) -> tuple[str, dict[str, str], dict[str, Any]]:
    target = _join_url(payload.api_base, "/messages")
    headers = {
        "x-api-key": _trimmed(payload.api_key),
        "anthropic-version": _trimmed(payload.api_version) or DEFAULT_ANTHROPIC_VERSION,
        "Content-Type": "application/json",
    }
    body = {
        "model": _trimmed(payload.model),
        "max_tokens": 1,
        "messages": [{"role": "user", "content": TEST_PROMPT}],
    }
    if payload.temperature is not None:
        body["temperature"] = payload.temperature
    return target, headers, body


def _build_ollama_request(payload: LlmProviderTestRequest) -> tuple[str, dict[str, str], dict[str, Any]]:
    target = _join_url(payload.api_base, "/api/chat")
    options: dict[str, Any] = {"num_predict": 1}
    if payload.temperature is not None:
        options["temperature"] = payload.temperature
    body = {
        "model": _trimmed(payload.model),
        "messages": [{"role": "user", "content": TEST_PROMPT}],
        "stream": False,
        "options": options,
    }
    headers = {"Content-Type": "application/json"}
    if _trimmed(payload.api_key):
        headers["Authorization"] = f"Bearer {_trimmed(payload.api_key)}"
    return target, headers, body


def _build_request(payload: LlmProviderTestRequest) -> tuple[str, dict[str, str], dict[str, Any], str]:
    provider_type = _trimmed(payload.provider_type)
    if provider_type in {"openai-compatible", "deepseek", "qwen", "moonshot", "custom"}:
        target, headers, body = _build_openai_request(payload)
        return target, headers, body, "openai-compatible"
    if provider_type == "azure-openai":
        target, headers, body = _build_azure_request(payload)
        return target, headers, body, provider_type
    if provider_type == "anthropic":
        target, headers, body = _build_anthropic_request(payload)
        return target, headers, body, provider_type
    if provider_type == "ollama":
        target, headers, body = _build_ollama_request(payload)
        return target, headers, body, provider_type
    raise ValidationError(f"暂不支持该 Provider 类型的测试: {provider_type}")


async def test_llm_provider(payload: LlmProviderTestRequest) -> LlmProviderTestResponse:
    _ensure_required(payload)
    target, headers, body, normalized_type = _build_request(payload)
    start = time.perf_counter()

    try:
        async with httpx.AsyncClient(timeout=payload.timeout_seconds) as client:
            response = await client.post(target, headers=headers, json=body)
            response.raise_for_status()
        latency_ms = int((time.perf_counter() - start) * 1000)
        response_payload, fallback_preview = _read_success_payload(response)
        return LlmProviderTestResponse(
            ok=True,
            provider_type=normalized_type,
            request_target=target,
            latency_ms=latency_ms,
            status_code=response.status_code,
            response_preview=_response_preview(normalized_type, response_payload) or fallback_preview,
            error_message=None,
        )
    except Exception as exc:
        latency_ms = int((time.perf_counter() - start) * 1000)
        status_code = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
        return LlmProviderTestResponse(
            ok=False,
            provider_type=normalized_type,
            request_target=target,
            latency_ms=latency_ms,
            status_code=status_code,
            response_preview=None,
            error_message=_normalize_error_message(exc),
        )
