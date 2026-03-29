"""Runtime helpers for listing models and chatting with configured providers."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, AsyncIterator
from urllib.parse import urlencode

import httpx

from app.exception import ValidationError
from app.model import LlmProvider
from app.schemas import (
    LlmProviderChatMessage,
    LlmProviderChatResult,
    LlmProviderModelOption,
    LlmProviderModelsResponse,
)


DEFAULT_ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_CHAT_MAX_TOKENS = 512


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


def _normalize_error_message(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        return str(exc.detail.get("message") or "请求参数不合法")
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
    return str(exc) or "请求失败"


def _normalize_provider_type(provider_type: str) -> str:
    value = _trimmed(provider_type)
    if value in {"openai-compatible", "deepseek", "qwen", "moonshot", "custom"}:
        return "openai-compatible"
    if value in {"azure-openai", "anthropic", "ollama"}:
        return value
    raise ValidationError(f"暂不支持该 Provider 类型: {value}")


def _ensure_provider_ready(provider: LlmProvider, model: str | None = None) -> str:
    if not _trimmed(provider.api_base):
        raise ValidationError("请先配置 API Base")
    if not _trimmed(provider.api_key) and _normalize_provider_type(provider.provider_type) != "ollama":
        raise ValidationError("请先配置 API Key")
    resolved_model = _trimmed(model if model is not None else provider.model)
    if not resolved_model:
        raise ValidationError("请先选择或填写模型")
    if _normalize_provider_type(provider.provider_type) == "azure-openai" and not _trimmed(provider.api_version):
        raise ValidationError("Azure OpenAI 需要先配置 API Version")
    return resolved_model


def _dedupe_models(*groups: list[LlmProviderModelOption]) -> list[LlmProviderModelOption]:
    seen: set[str] = set()
    items: list[LlmProviderModelOption] = []
    for group in groups:
        for item in group:
            key = item.value.strip()
            if not key or key in seen:
                continue
            seen.add(key)
            items.append(item)
    return items


def _extract_text_content(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, dict):
                text = item.get("text")
                if text:
                    parts.append(str(text))
            elif isinstance(item, str):
                parts.append(item)
        joined = "".join(parts).strip()
        return joined or None
    if isinstance(value, dict):
        text = value.get("content") or value.get("text")
        return _extract_text_content(text)
    return str(value).strip() or None


def _extract_openai_reply(payload: dict[str, Any]) -> str | None:
    choices = payload.get("choices") or []
    if not choices:
        return _extract_text_content(payload.get("output_text"))
    first_choice = choices[0] or {}
    message = first_choice.get("message") or {}
    return _extract_text_content(message.get("content")) or _extract_text_content(first_choice.get("text"))


def _extract_anthropic_reply(payload: dict[str, Any]) -> str | None:
    return _extract_text_content(payload.get("content"))


def _extract_ollama_reply(payload: dict[str, Any]) -> str | None:
    message = payload.get("message") or {}
    return _extract_text_content(message.get("content"))


def _sse_encode(payload: dict[str, Any]) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


def _to_openai_messages(messages: list[LlmProviderChatMessage]) -> list[dict[str, str]]:
    return [{"role": item.role, "content": item.content} for item in messages]


def _to_anthropic_messages(messages: list[LlmProviderChatMessage]) -> tuple[str | None, list[dict[str, str]]]:
    system_parts: list[str] = []
    converted: list[dict[str, str]] = []
    for item in messages:
        if item.role == "system":
            system_parts.append(item.content)
            continue
        converted.append({"role": item.role, "content": item.content})
    return ("\n\n".join(system_parts).strip() or None, converted)


def _azure_base_root(api_base: str) -> str:
    base = _trimmed(api_base).rstrip("/")
    markers = ["/openai/deployments/", "/chat/completions", "/completions", "/models"]
    for marker in markers:
        if marker in base:
            base = base.split(marker)[0]
    return base


async def _iter_sse_events(response: httpx.Response) -> AsyncIterator[tuple[str, str]]:
    event_name = "message"
    data_lines: list[str] = []
    async for raw_line in response.aiter_lines():
        line = raw_line.rstrip("\r")
        if not line:
            if data_lines:
                yield event_name, "\n".join(data_lines)
                event_name = "message"
                data_lines = []
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            event_name = line[6:].strip() or "message"
            continue
        if line.startswith("data:"):
            data_lines.append(line[5:].strip())
    if data_lines:
        yield event_name, "\n".join(data_lines)


async def list_provider_models(provider: LlmProvider) -> LlmProviderModelsResponse:
    normalized_type = _normalize_provider_type(provider.provider_type)
    request_target: str | None = None
    status_code: int | None = None
    error_message: str | None = None
    remote_items: list[LlmProviderModelOption] = []
    configured_items = []
    configured_model = _trimmed(provider.model)
    if configured_model:
        configured_items.append(
            LlmProviderModelOption(value=configured_model, label=configured_model, source="configured")
        )

    try:
        if normalized_type == "anthropic":
            raise ValidationError("Anthropic 暂未提供稳定的模型列表接口，请手动填写模型")
        if normalized_type == "openai-compatible":
            request_target = _join_url(provider.api_base, "/models")
            headers = {
                "Authorization": f"Bearer {_trimmed(provider.api_key)}",
                "Content-Type": "application/json",
            }
            if _trimmed(provider.organization):
                headers["OpenAI-Organization"] = _trimmed(provider.organization)
            async with httpx.AsyncClient(timeout=provider.timeout_seconds) as client:
                response = await client.get(request_target, headers=headers)
                response.raise_for_status()
            status_code = response.status_code
            payload = response.json()
            data = payload.get("data") if isinstance(payload, dict) else []
            for item in data or []:
                model_id = _trimmed(item.get("id")) if isinstance(item, dict) else ""
                if model_id:
                    remote_items.append(LlmProviderModelOption(value=model_id, label=model_id, source="remote"))
        elif normalized_type == "azure-openai":
            request_target = _append_query(
                _join_url(_azure_base_root(provider.api_base), "/openai/models"),
                {"api-version": _trimmed(provider.api_version)},
            )
            headers = {"api-key": _trimmed(provider.api_key), "Content-Type": "application/json"}
            async with httpx.AsyncClient(timeout=provider.timeout_seconds) as client:
                response = await client.get(request_target, headers=headers)
                response.raise_for_status()
            status_code = response.status_code
            payload = response.json()
            data = payload.get("data") if isinstance(payload, dict) else []
            for item in data or []:
                model_id = _trimmed(item.get("id")) if isinstance(item, dict) else ""
                if model_id:
                    remote_items.append(LlmProviderModelOption(value=model_id, label=model_id, source="remote"))
        elif normalized_type == "ollama":
            request_target = _join_url(provider.api_base, "/api/tags")
            headers = {"Content-Type": "application/json"}
            if _trimmed(provider.api_key):
                headers["Authorization"] = f"Bearer {_trimmed(provider.api_key)}"
            async with httpx.AsyncClient(timeout=provider.timeout_seconds) as client:
                response = await client.get(request_target, headers=headers)
                response.raise_for_status()
            status_code = response.status_code
            payload = response.json()
            for item in payload.get("models") or []:
                model_name = _trimmed(item.get("name")) if isinstance(item, dict) else ""
                if model_name:
                    remote_items.append(LlmProviderModelOption(value=model_name, label=model_name, source="remote"))
    except Exception as exc:
        error_message = _normalize_error_message(exc)
        if isinstance(exc, httpx.HTTPStatusError):
            status_code = exc.response.status_code

    return LlmProviderModelsResponse(
        provider_key=provider.provider_key,
        provider_type=normalized_type,
        request_target=request_target,
        status_code=status_code,
        error_message=error_message,
        items=_dedupe_models(remote_items, configured_items),
    )


async def _chat_with_openai_like(provider: LlmProvider, model: str, messages: list[LlmProviderChatMessage]) -> tuple[str, int, str]:
    target = _join_url(provider.api_base, "/chat/completions")
    headers = {
        "Authorization": f"Bearer {_trimmed(provider.api_key)}",
        "Content-Type": "application/json",
    }
    if _trimmed(provider.organization):
        headers["OpenAI-Organization"] = _trimmed(provider.organization)
    body: dict[str, Any] = {
        "model": model,
        "messages": _to_openai_messages(messages),
    }
    if provider.max_tokens is not None:
        body["max_tokens"] = provider.max_tokens
    if provider.temperature is not None:
        body["temperature"] = provider.temperature
    async with httpx.AsyncClient(timeout=provider.timeout_seconds) as client:
        response = await client.post(target, headers=headers, json=body)
        response.raise_for_status()
    payload = response.json()
    return _extract_openai_reply(payload) or "", response.status_code, target


async def _chat_with_azure(provider: LlmProvider, model: str, messages: list[LlmProviderChatMessage]) -> tuple[str, int, str]:
    base = _trimmed(provider.api_base)
    if "openai/deployments" in base and "chat/completions" in base:
        target = base
    else:
        target = _join_url(base, f"/openai/deployments/{model}/chat/completions")
    target = _append_query(target, {"api-version": _trimmed(provider.api_version)})
    headers = {"api-key": _trimmed(provider.api_key), "Content-Type": "application/json"}
    body: dict[str, Any] = {
        "messages": _to_openai_messages(messages),
    }
    if provider.max_tokens is not None:
        body["max_tokens"] = provider.max_tokens
    if provider.temperature is not None:
        body["temperature"] = provider.temperature
    async with httpx.AsyncClient(timeout=provider.timeout_seconds) as client:
        response = await client.post(target, headers=headers, json=body)
        response.raise_for_status()
    payload = response.json()
    return _extract_openai_reply(payload) or "", response.status_code, target


async def _chat_with_anthropic(provider: LlmProvider, model: str, messages: list[LlmProviderChatMessage]) -> tuple[str, int, str]:
    system_message, anthropic_messages = _to_anthropic_messages(messages)
    target = _join_url(provider.api_base, "/messages")
    headers = {
        "x-api-key": _trimmed(provider.api_key),
        "anthropic-version": _trimmed(provider.api_version) or DEFAULT_ANTHROPIC_VERSION,
        "Content-Type": "application/json",
    }
    body: dict[str, Any] = {
        "model": model,
        "max_tokens": provider.max_tokens or DEFAULT_CHAT_MAX_TOKENS,
        "messages": anthropic_messages,
    }
    if provider.temperature is not None:
        body["temperature"] = provider.temperature
    if system_message:
        body["system"] = system_message
    async with httpx.AsyncClient(timeout=provider.timeout_seconds) as client:
        response = await client.post(target, headers=headers, json=body)
        response.raise_for_status()
    payload = response.json()
    return _extract_anthropic_reply(payload) or "", response.status_code, target


async def _chat_with_ollama(provider: LlmProvider, model: str, messages: list[LlmProviderChatMessage]) -> tuple[str, int, str]:
    target = _join_url(provider.api_base, "/api/chat")
    headers = {"Content-Type": "application/json"}
    if _trimmed(provider.api_key):
        headers["Authorization"] = f"Bearer {_trimmed(provider.api_key)}"
    options: dict[str, Any] = {}
    if provider.max_tokens is not None:
        options["num_predict"] = provider.max_tokens
    if provider.temperature is not None:
        options["temperature"] = provider.temperature
    body: dict[str, Any] = {
        "model": model,
        "messages": _to_openai_messages(messages),
        "stream": False,
    }
    if options:
        body["options"] = options
    async with httpx.AsyncClient(timeout=provider.timeout_seconds) as client:
        response = await client.post(target, headers=headers, json=body)
        response.raise_for_status()
    payload = response.json()
    return _extract_ollama_reply(payload) or "", response.status_code, target


async def _stream_openai_like(provider: LlmProvider, model: str, messages: list[LlmProviderChatMessage]) -> AsyncIterator[tuple[str, int, str]]:
    target = _join_url(provider.api_base, "/chat/completions")
    headers = {
        "Authorization": f"Bearer {_trimmed(provider.api_key)}",
        "Content-Type": "application/json",
    }
    if _trimmed(provider.organization):
        headers["OpenAI-Organization"] = _trimmed(provider.organization)
    body: dict[str, Any] = {
        "model": model,
        "messages": _to_openai_messages(messages),
        "stream": True,
    }
    if provider.max_tokens is not None:
        body["max_tokens"] = provider.max_tokens
    if provider.temperature is not None:
        body["temperature"] = provider.temperature
    async with httpx.AsyncClient(timeout=provider.timeout_seconds) as client:
        async with client.stream("POST", target, headers=headers, json=body) as response:
            response.raise_for_status()
            async for _event_name, data in _iter_sse_events(response):
                if data == "[DONE]":
                    break
                payload = json.loads(data)
                choices = payload.get("choices") or []
                if not choices:
                    continue
                delta = choices[0].get("delta") or {}
                chunk = _extract_text_content(delta.get("content"))
                if chunk:
                    yield chunk, response.status_code, target


async def _stream_azure(provider: LlmProvider, model: str, messages: list[LlmProviderChatMessage]) -> AsyncIterator[tuple[str, int, str]]:
    base = _trimmed(provider.api_base)
    if "openai/deployments" in base and "chat/completions" in base:
        target = base
    else:
        target = _join_url(base, f"/openai/deployments/{model}/chat/completions")
    target = _append_query(target, {"api-version": _trimmed(provider.api_version)})
    headers = {"api-key": _trimmed(provider.api_key), "Content-Type": "application/json"}
    body: dict[str, Any] = {
        "messages": _to_openai_messages(messages),
        "stream": True,
    }
    if provider.max_tokens is not None:
        body["max_tokens"] = provider.max_tokens
    if provider.temperature is not None:
        body["temperature"] = provider.temperature
    async with httpx.AsyncClient(timeout=provider.timeout_seconds) as client:
        async with client.stream("POST", target, headers=headers, json=body) as response:
            response.raise_for_status()
            async for _event_name, data in _iter_sse_events(response):
                if data == "[DONE]":
                    break
                payload = json.loads(data)
                choices = payload.get("choices") or []
                if not choices:
                    continue
                delta = choices[0].get("delta") or {}
                chunk = _extract_text_content(delta.get("content"))
                if chunk:
                    yield chunk, response.status_code, target


async def _stream_anthropic(provider: LlmProvider, model: str, messages: list[LlmProviderChatMessage]) -> AsyncIterator[tuple[str, int, str]]:
    system_message, anthropic_messages = _to_anthropic_messages(messages)
    target = _join_url(provider.api_base, "/messages")
    headers = {
        "x-api-key": _trimmed(provider.api_key),
        "anthropic-version": _trimmed(provider.api_version) or DEFAULT_ANTHROPIC_VERSION,
        "Content-Type": "application/json",
    }
    body: dict[str, Any] = {
        "model": model,
        "max_tokens": provider.max_tokens or DEFAULT_CHAT_MAX_TOKENS,
        "messages": anthropic_messages,
        "stream": True,
    }
    if provider.temperature is not None:
        body["temperature"] = provider.temperature
    if system_message:
        body["system"] = system_message
    async with httpx.AsyncClient(timeout=provider.timeout_seconds) as client:
        async with client.stream("POST", target, headers=headers, json=body) as response:
            response.raise_for_status()
            async for event_name, data in _iter_sse_events(response):
                if event_name not in {"content_block_delta", "content_block_start"}:
                    continue
                payload = json.loads(data)
                chunk = None
                if event_name == "content_block_delta":
                    delta = payload.get("delta") or {}
                    chunk = _extract_text_content(delta.get("text"))
                else:
                    content_block = payload.get("content_block") or {}
                    chunk = _extract_text_content(content_block.get("text"))
                if chunk:
                    yield chunk, response.status_code, target


async def _stream_ollama(provider: LlmProvider, model: str, messages: list[LlmProviderChatMessage]) -> AsyncIterator[tuple[str, int, str]]:
    target = _join_url(provider.api_base, "/api/chat")
    headers = {"Content-Type": "application/json"}
    if _trimmed(provider.api_key):
        headers["Authorization"] = f"Bearer {_trimmed(provider.api_key)}"
    options: dict[str, Any] = {}
    if provider.max_tokens is not None:
        options["num_predict"] = provider.max_tokens
    if provider.temperature is not None:
        options["temperature"] = provider.temperature
    body: dict[str, Any] = {
        "model": model,
        "messages": _to_openai_messages(messages),
        "stream": True,
    }
    if options:
        body["options"] = options
    async with httpx.AsyncClient(timeout=provider.timeout_seconds) as client:
        async with client.stream("POST", target, headers=headers, json=body) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if not line.strip():
                    continue
                payload = json.loads(line)
                if payload.get("done"):
                    break
                chunk = _extract_text_content((payload.get("message") or {}).get("content"))
                if chunk:
                    yield chunk, response.status_code, target


async def chat_with_provider(
    provider: LlmProvider,
    model: str,
    messages: list[LlmProviderChatMessage],
) -> LlmProviderChatResult:
    normalized_type = _normalize_provider_type(provider.provider_type)
    resolved_model = _ensure_provider_ready(provider, model)
    start = time.perf_counter()
    request_target: str | None = None

    try:
        if normalized_type == "openai-compatible":
            assistant_message, status_code, request_target = await _chat_with_openai_like(provider, resolved_model, messages)
        elif normalized_type == "azure-openai":
            assistant_message, status_code, request_target = await _chat_with_azure(provider, resolved_model, messages)
        elif normalized_type == "anthropic":
            assistant_message, status_code, request_target = await _chat_with_anthropic(provider, resolved_model, messages)
        elif normalized_type == "ollama":
            assistant_message, status_code, request_target = await _chat_with_ollama(provider, resolved_model, messages)
        else:
            raise ValidationError(f"暂不支持该 Provider 类型: {provider.provider_type}")
        return LlmProviderChatResult(
            provider_key=provider.provider_key,
            provider_type=normalized_type,
            model=resolved_model,
            ok=True,
            assistant_message=assistant_message or "(模型返回了空内容)",
            latency_ms=int((time.perf_counter() - start) * 1000),
            status_code=status_code,
            request_target=request_target,
            error_message=None,
        )
    except Exception as exc:
        status_code = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
        return LlmProviderChatResult(
            provider_key=provider.provider_key,
            provider_type=normalized_type,
            model=resolved_model,
            ok=False,
            assistant_message=None,
            latency_ms=int((time.perf_counter() - start) * 1000),
            status_code=status_code,
            request_target=request_target,
            error_message=_normalize_error_message(exc),
        )


async def stream_chat_with_provider(
    provider: LlmProvider,
    model: str,
    messages: list[LlmProviderChatMessage],
) -> AsyncIterator[dict[str, Any]]:
    normalized_type = _normalize_provider_type(provider.provider_type)
    resolved_model = _ensure_provider_ready(provider, model)
    start = time.perf_counter()
    chunks: list[str] = []
    request_target: str | None = None
    status_code: int | None = None
    yield {
        "type": "start",
        "provider_key": provider.provider_key,
        "provider_type": normalized_type,
        "model": resolved_model,
    }
    try:
        if normalized_type == "openai-compatible":
            stream = _stream_openai_like(provider, resolved_model, messages)
        elif normalized_type == "azure-openai":
            stream = _stream_azure(provider, resolved_model, messages)
        elif normalized_type == "anthropic":
            stream = _stream_anthropic(provider, resolved_model, messages)
        elif normalized_type == "ollama":
            stream = _stream_ollama(provider, resolved_model, messages)
        else:
            raise ValidationError(f"暂不支持该 Provider 类型: {provider.provider_type}")
        async for chunk, response_status, target in stream:
            status_code = response_status
            request_target = target
            chunks.append(chunk)
            yield {
                "type": "delta",
                "provider_key": provider.provider_key,
                "delta": chunk,
            }
        yield {
            "type": "done",
            "provider_key": provider.provider_key,
            "provider_type": normalized_type,
            "model": resolved_model,
            "ok": True,
            "assistant_message": "".join(chunks) or "(模型返回了空内容)",
            "latency_ms": int((time.perf_counter() - start) * 1000),
            "status_code": status_code,
            "request_target": request_target,
            "error_message": None,
        }
    except Exception as exc:
        yield {
            "type": "error",
            "provider_key": provider.provider_key,
            "provider_type": normalized_type,
            "model": resolved_model,
            "ok": False,
            "assistant_message": None,
            "latency_ms": int((time.perf_counter() - start) * 1000),
            "status_code": exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None,
            "request_target": request_target,
            "error_message": _normalize_error_message(exc),
        }


async def stream_chat_targets(
    targets: list[tuple[LlmProvider, str, list[LlmProviderChatMessage]]],
) -> AsyncIterator[str]:
    queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()

    async def _worker(provider: LlmProvider, model: str, messages: list[LlmProviderChatMessage]):
        async for event in stream_chat_with_provider(provider, model, messages):
            await queue.put(event)
        await queue.put(None)

    tasks = [asyncio.create_task(_worker(provider, model, messages)) for provider, model, messages in targets]
    remaining = len(tasks)
    try:
        while remaining > 0:
            event = await queue.get()
            if event is None:
                remaining -= 1
                continue
            yield _sse_encode(event)
        yield _sse_encode({"type": "all_done"})
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
