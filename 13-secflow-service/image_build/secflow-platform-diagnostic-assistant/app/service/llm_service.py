from __future__ import annotations

import json
from typing import Any, AsyncIterator

import httpx

from app.config import get_service_yaml
from app.models import LlmProviderConfig


class LlmServiceError(RuntimeError):
    pass


def _headers(provider: LlmProviderConfig) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {provider.api_key}",
        "Content-Type": "application/json",
    }


def _chat_url(provider: LlmProviderConfig) -> str:
    return provider.api_base.rstrip("/") + "/chat/completions"


def build_chat_messages(history: list[dict[str, str]], user_message: str) -> list[dict[str, str]]:
    system_prompt = (
        "你是诊断助手。"
        "当前阶段只需要进行自然语言对话。"
        "如果用户问 Kubernetes、平台、集群、故障定位相关问题，可以直接回答；"
        "如果缺少现场信息，就明确说明需要用户补充。"
        "不要输出 JSON 约束，不要假装已经执行了任何命令。"
    )
    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(history)
    messages.append({"role": "user", "content": user_message})
    return messages


def _extract_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise LlmServiceError("模型返回缺少 choices")
    message = choices[0].get("message") or {}
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        text_parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text_parts.append(str(item.get("text") or ""))
        return "".join(text_parts)
    raise LlmServiceError("模型返回 content 不可解析")


def chat(provider: LlmProviderConfig, history: list[dict[str, str]], user_message: str) -> str:
    payload = {
        "model": provider.model,
        "messages": build_chat_messages(history, user_message),
        "temperature": 0.2,
    }
    try:
        with httpx.Client(timeout=get_service_yaml().configcenter.timeout) as client:
            response = client.post(_chat_url(provider), headers=_headers(provider), json=payload)
    except httpx.HTTPError as exc:
        raise LlmServiceError(f"调用模型失败: {exc}") from exc
    if response.status_code != 200:
        raise LlmServiceError(f"模型接口返回异常状态码: {response.status_code}")
    return _extract_text(response.json())


async def stream_chat(provider: LlmProviderConfig, history: list[dict[str, str]], user_message: str) -> AsyncIterator[str]:
    payload = {
        "model": provider.model,
        "messages": build_chat_messages(history, user_message),
        "temperature": 0.2,
        "stream": True,
    }
    async with httpx.AsyncClient(timeout=None) as client:
        async with client.stream("POST", _chat_url(provider), headers=_headers(provider), json=payload) as response:
            if response.status_code != 200:
                detail = await response.aread()
                raise LlmServiceError(f"模型流式接口异常: {response.status_code} {detail[:200]!r}")
            async for line in response.aiter_lines():
                if not line or not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    payload = json.loads(data)
                except json.JSONDecodeError:
                    continue
                choices = payload.get("choices")
                if not isinstance(choices, list) or not choices:
                    continue
                delta = choices[0].get("delta") or {}
                content = delta.get("content")
                if isinstance(content, str) and content:
                    yield content
