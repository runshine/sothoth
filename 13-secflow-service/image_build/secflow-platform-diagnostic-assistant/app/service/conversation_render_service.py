from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from app.models import DiagnosticAssistantArtifacts, DiagnosticConversationBlock, DiagnosticReadableItem


def _stringify_tool_args(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    try:
        return json.dumps(value, ensure_ascii=False, indent=2)
    except Exception:
        return str(value)


def _merge_stream_text(previous: str, incoming: str) -> str:
    if not incoming:
        return previous
    if not previous:
        return incoming
    if incoming.startswith(previous):
        return incoming
    if previous.endswith(incoming):
        return previous
    return f"{previous}{incoming}"


def _extract_text_parts(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            parts.extend(_extract_text_parts(item))
        return parts
    if not isinstance(value, dict):
        return []
    if isinstance(value.get("text"), str) and str(value.get("text")).strip():
        return [str(value.get("text"))]
    if isinstance(value.get("thinking"), str) and str(value.get("thinking")).strip():
        return [str(value.get("thinking"))]
    parts: list[str] = []
    for key in ("content", "toolResults", "result", "message", "partialResult"):
        if key in value:
            parts.extend(_extract_text_parts(value.get(key)))
    return parts


def _extract_partial_content_item(assistant_event: dict[str, Any]) -> dict[str, Any] | None:
    partial = assistant_event.get("partial")
    content_index = assistant_event.get("contentIndex")
    if not isinstance(partial, dict) or not isinstance(content_index, int):
        return None
    content = partial.get("content")
    if not isinstance(content, list) or content_index < 0 or content_index >= len(content):
        return None
    item = content[content_index]
    return item if isinstance(item, dict) else None


def render_tool_command(name: str, arguments: object) -> str:
    if not isinstance(arguments, dict):
        return name

    command = arguments.get("command")
    if isinstance(command, str) and command.strip():
        return command.strip()
    cmd = arguments.get("cmd")
    if isinstance(cmd, str) and cmd.strip():
        return cmd.strip()

    if name == "ls":
        path = arguments.get("path")
        return f"ls {path}" if isinstance(path, str) and path else "ls"

    if name == "find":
        path = arguments.get("path")
        pattern = arguments.get("pattern")
        limit = arguments.get("limit")
        parts = ["find"]
        if isinstance(path, str) and path:
            parts.append(path)
        if isinstance(pattern, str) and pattern:
            parts.append(f'-name "{pattern}"')
        if isinstance(limit, int) and limit > 0:
            parts.append(f"| head -n {limit}")
        return " ".join(parts)

    if name == "bash":
        return command.strip() if isinstance(command, str) and command.strip() else "bash"

    if name == "grep":
        pattern = arguments.get("pattern")
        path = arguments.get("path")
        parts = ["grep"]
        if isinstance(pattern, str) and pattern:
            parts.append(f'"{pattern}"')
        if isinstance(path, str) and path:
            parts.append(path)
        return " ".join(parts)

    if name == "read":
        path = arguments.get("path")
        return f"read {path}" if isinstance(path, str) and path else "read"

    if name == "write":
        path = arguments.get("path")
        return f"write {path}" if isinstance(path, str) and path else "write"

    if name == "edit":
        path = arguments.get("path")
        return f"edit {path}" if isinstance(path, str) and path else "edit"

    parts = [name]
    for key in sorted(arguments.keys()):
        value = arguments.get(key)
        if isinstance(value, str) and value:
            parts.append(value)
        else:
            parts.append(f"{key}={value}")
    return " ".join(parts)


def render_tool_result(content: object) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    parts.append(str(item.get("text", "")))
                else:
                    parts.append(render_tool_result(item))
            elif isinstance(item, str):
                parts.append(item)
        return "".join(parts)
    if isinstance(content, dict):
        if content.get("type") == "text":
            return str(content.get("text", ""))
        if "content" in content:
            return render_tool_result(content.get("content"))
        if "text" in content:
            return str(content.get("text", ""))
    return str(content) if content is not None else ""


def _upsert_block(items: list[DiagnosticConversationBlock], next_item: DiagnosticConversationBlock) -> DiagnosticConversationBlock:
    for index, item in enumerate(items):
        if item.id == next_item.id:
            items[index] = next_item
            return next_item
    items.append(next_item)
    return next_item


def _block_timestamps(
    current: DiagnosticConversationBlock | None,
    *,
    created_at: datetime,
    updated_at: datetime | None = None,
) -> tuple[datetime, datetime | None]:
    return (
        current.created_at if current is not None else created_at,
        updated_at if updated_at is not None else (current.updated_at if current is not None else None),
    )


class PiConversationRenderer:
    def __init__(self, *, assistant_message_id: int | None = None, run_id: int | None = None, created_at: datetime | None = None) -> None:
        self.assistant_message_id = assistant_message_id
        self.run_id = run_id
        self.created_at = created_at or datetime.now(timezone.utc)
        self.blocks: list[DiagnosticConversationBlock] = []
        self.thinking_item_id: str | None = None
        self.text_item_id: str | None = None
        self.thinking_seq = 0
        self.text_seq = 0

    def _emit_block(self, block: DiagnosticConversationBlock) -> DiagnosticConversationBlock:
        return _upsert_block(self.blocks, block)

    def apply_event(self, pi_event: dict[str, Any], *, event_at: datetime | None = None) -> list[DiagnosticConversationBlock]:
        changed: list[DiagnosticConversationBlock] = []
        event_type = str(pi_event.get("type") or "")
        message = pi_event.get("message")
        block_at = event_at or self.created_at
        if event_type in {"message_start", "message_end"} and isinstance(message, dict):
            role = str(message.get("role") or "")
            if role == "toolResult":
                tool_call_id = str(message.get("toolCallId") or "")
                if tool_call_id:
                    block_id = f"tool-result-{tool_call_id}"
                    current = next((item for item in self.blocks if item.id == block_id), None)
                    created_at, updated_at = _block_timestamps(current, created_at=block_at, updated_at=block_at)
                    next_block = DiagnosticConversationBlock(
                        id=block_id,
                        message_id=self.assistant_message_id,
                        run_id=self.run_id,
                        kind="tool_result",
                        title=str(message.get("toolName") or "unknown"),
                        body=render_tool_result(message.get("content")),
                        created_at=created_at,
                        updated_at=updated_at,
                        running=event_type == "message_start",
                    )
                    changed.append(self._emit_block(next_block))
                return changed
        assistant_event = pi_event.get("assistantMessageEvent")
        if isinstance(assistant_event, dict):
            assistant_event_type = str(assistant_event.get("type") or "")
            partial_content_item = _extract_partial_content_item(assistant_event)
            if assistant_event_type == "thinking_start":
                self.thinking_seq += 1
                self.thinking_item_id = f"thinking-{self.run_id}-{self.thinking_seq}"
                changed.append(self._emit_block(
                    DiagnosticConversationBlock(
                        id=self.thinking_item_id,
                        message_id=self.assistant_message_id,
                        run_id=self.run_id,
                        kind="thinking",
                        title="thinking",
                        body="",
                        created_at=block_at,
                        updated_at=block_at,
                        running=True,
                    )
                ))
                return changed
            if assistant_event_type == "thinking_delta" and self.thinking_item_id:
                delta = str(assistant_event.get("delta") or "")
                current = next((item for item in self.blocks if item.id == self.thinking_item_id), None)
                created_at, updated_at = _block_timestamps(current, created_at=block_at, updated_at=block_at)
                next_block = DiagnosticConversationBlock(
                    id=self.thinking_item_id,
                    message_id=self.assistant_message_id,
                    run_id=self.run_id,
                    kind="thinking",
                    title="thinking",
                    body=_merge_stream_text(current.body if current is not None else "", delta),
                    created_at=created_at,
                    updated_at=updated_at,
                    running=True,
                )
                changed.append(self._emit_block(next_block))
                return changed
            if assistant_event_type == "thinking_end" and self.thinking_item_id:
                content = str(assistant_event.get("content") or "")
                current = next((item for item in self.blocks if item.id == self.thinking_item_id), None)
                created_at, updated_at = _block_timestamps(current, created_at=block_at, updated_at=block_at)
                next_block = DiagnosticConversationBlock(
                    id=self.thinking_item_id,
                    message_id=self.assistant_message_id,
                    run_id=self.run_id,
                    kind="thinking",
                    title="thinking",
                    body=content or (current.body if current is not None else ""),
                    created_at=created_at,
                    updated_at=updated_at,
                    running=False,
                )
                changed.append(self._emit_block(next_block))
                self.thinking_item_id = None
                return changed
            if assistant_event_type == "text_start":
                self.text_seq += 1
                self.text_item_id = f"text-{self.run_id}-{self.text_seq}"
                changed.append(self._emit_block(
                    DiagnosticConversationBlock(
                        id=self.text_item_id,
                        message_id=self.assistant_message_id,
                        run_id=self.run_id,
                        kind="text",
                        title="response",
                        body="",
                        created_at=block_at,
                        updated_at=block_at,
                        running=True,
                    )
                ))
                return changed
            if assistant_event_type == "text_delta" and self.text_item_id:
                delta = str(assistant_event.get("delta") or "")
                current = next((item for item in self.blocks if item.id == self.text_item_id), None)
                created_at, updated_at = _block_timestamps(current, created_at=block_at, updated_at=block_at)
                next_block = DiagnosticConversationBlock(
                    id=self.text_item_id,
                    message_id=self.assistant_message_id,
                    run_id=self.run_id,
                    kind="text",
                    title="response",
                    body=_merge_stream_text(current.body if current is not None else "", delta),
                    created_at=created_at,
                    updated_at=updated_at,
                    running=True,
                )
                changed.append(self._emit_block(next_block))
                return changed
            if assistant_event_type == "text_end" and self.text_item_id:
                content = str(assistant_event.get("content") or "")
                current = next((item for item in self.blocks if item.id == self.text_item_id), None)
                created_at, updated_at = _block_timestamps(current, created_at=block_at, updated_at=block_at)
                next_block = DiagnosticConversationBlock(
                    id=self.text_item_id,
                    message_id=self.assistant_message_id,
                    run_id=self.run_id,
                    kind="text",
                    title="response",
                    body=_merge_stream_text(current.body if current is not None else "", content),
                    created_at=created_at,
                    updated_at=updated_at,
                    running=False,
                )
                changed.append(self._emit_block(next_block))
                self.text_item_id = None
                return changed
            if assistant_event_type in {"toolcall_start", "toolcall_delta", "toolcall_end"}:
                tool_call = assistant_event.get("toolCall") if assistant_event_type == "toolcall_end" else partial_content_item
                if isinstance(tool_call, dict):
                    tool_call_id = str(tool_call.get("id") or "")
                    tool_name = str(tool_call.get("name") or "unknown")
                    body = render_tool_command(tool_name, tool_call.get("arguments")) if assistant_event_type == "toolcall_end" else ""
                    if tool_call_id:
                        block_id = f"toolcall-{tool_call_id}"
                        current = next((item for item in self.blocks if item.id == block_id), None)
                        created_at, updated_at = _block_timestamps(current, created_at=block_at, updated_at=block_at)
                        next_block = DiagnosticConversationBlock(
                            id=block_id,
                            message_id=self.assistant_message_id,
                            run_id=self.run_id,
                            kind="tool_call",
                            title=tool_name,
                            body=_merge_stream_text(current.body if current is not None else "", body),
                            created_at=created_at,
                            updated_at=updated_at,
                            running=assistant_event_type != "toolcall_end",
                        )
                        changed.append(self._emit_block(next_block))
                return changed

        if event_type == "tool_execution_start":
            tool_id = str(pi_event.get("toolCallId") or "")
            if tool_id:
                changed.append(self._emit_block(
                    DiagnosticConversationBlock(
                        id=f"tool-result-{tool_id}",
                        message_id=self.assistant_message_id,
                        run_id=self.run_id,
                        kind="tool_result",
                        title=str(pi_event.get("toolName") or "unknown"),
                        body="",
                        created_at=block_at,
                        updated_at=block_at,
                        running=True,
                    )
                ))
            return changed
        if event_type == "tool_execution_update":
            tool_id = str(pi_event.get("toolCallId") or "")
            if tool_id:
                body = "\n\n".join(_extract_text_parts(pi_event.get("partialResult"))) or ""
                current = next((item for item in self.blocks if item.id == f"tool-result-{tool_id}"), None)
                created_at, updated_at = _block_timestamps(current, created_at=block_at, updated_at=block_at)
                next_block = DiagnosticConversationBlock(
                    id=f"tool-result-{tool_id}",
                    message_id=self.assistant_message_id,
                    run_id=self.run_id,
                    kind="tool_result",
                    title=str(pi_event.get("toolName") or "unknown"),
                    body=_merge_stream_text(current.body if current is not None else "", body),
                    created_at=created_at,
                    updated_at=updated_at,
                    running=True,
                )
                changed.append(self._emit_block(next_block))
            return changed
        if event_type == "tool_execution_end":
            tool_id = str(pi_event.get("toolCallId") or "")
            if tool_id:
                body = "\n\n".join(_extract_text_parts(pi_event.get("result"))) or "tool finished"
                current = next((item for item in self.blocks if item.id == f"tool-result-{tool_id}"), None)
                created_at, updated_at = _block_timestamps(current, created_at=block_at, updated_at=block_at)
                next_block = DiagnosticConversationBlock(
                    id=f"tool-result-{tool_id}",
                    message_id=self.assistant_message_id,
                    run_id=self.run_id,
                    kind="tool_result",
                    title=str(pi_event.get("toolName") or "unknown"),
                    body=_merge_stream_text(current.body if current is not None else "", body),
                    created_at=created_at,
                    updated_at=updated_at,
                    running=False,
                )
                changed.append(self._emit_block(next_block))
            return changed
        if event_type == "message":
            if isinstance(message, dict) and message.get("role") == "assistant":
                content = message.get("content")
                if isinstance(content, list):
                    for item in content:
                        if not isinstance(item, dict):
                            continue
                        item_type = str(item.get("type") or "")
                        if item_type == "thinking":
                            text = str(item.get("thinking") or "")
                            if text.strip():
                                changed.append(self._emit_block(
                                    DiagnosticConversationBlock(
                                        id=f"thinking-fallback-{self.run_id}-{len(self.blocks) + 1}",
                                        message_id=self.assistant_message_id,
                                        run_id=self.run_id,
                                        kind="thinking",
                                        title="thinking",
                                        body=text,
                                        created_at=block_at,
                                        updated_at=block_at,
                                        running=False,
                                    )
                                ))
                        elif item_type == "text":
                            text = str(item.get("text") or "")
                            if text.strip():
                                if any(block.kind == "text" and block.body.strip() == text for block in self.blocks):
                                    continue
                                changed.append(self._emit_block(
                                    DiagnosticConversationBlock(
                                        id=f"text-fallback-{self.run_id}-{len(self.blocks) + 1}",
                                        message_id=self.assistant_message_id,
                                        run_id=self.run_id,
                                        kind="text",
                                        title="response",
                                        body=text,
                                        created_at=block_at,
                                        updated_at=block_at,
                                        running=False,
                                    )
                                ))
                        elif item_type == "toolCall":
                            tool_name = str(item.get("name") or "unknown")
                            tool_id = str(item.get("id") or f"fallback-{self.run_id}-{len(self.blocks) + 1}")
                            if any(block.kind == "tool_call" and block.title == tool_name and block.body.strip() for block in self.blocks):
                                continue
                            changed.append(self._emit_block(
                                DiagnosticConversationBlock(
                                    id=f"toolcall-{tool_id}",
                                    message_id=self.assistant_message_id,
                                    run_id=self.run_id,
                                    kind="tool_call",
                                    title=tool_name,
                                    body=render_tool_command(tool_name, item.get("arguments")),
                                    created_at=block_at,
                                    updated_at=block_at,
                                    running=False,
                                )
                            ))
            elif isinstance(message, dict) and message.get("role") == "toolResult":
                tool_id = str(message.get("toolCallId") or "")
                if tool_id:
                    changed.append(self._emit_block(
                        DiagnosticConversationBlock(
                            id=f"tool-result-{tool_id}",
                            message_id=self.assistant_message_id,
                            run_id=self.run_id,
                            kind="tool_result",
                            title=str(message.get("toolName") or "unknown"),
                            body=render_tool_result(message.get("content")),
                            created_at=block_at,
                            updated_at=block_at,
                            running=False,
                        )
                    ))
            return changed

        return changed


def render_conversation_blocks_from_events(
    events: list[Any],
    *,
    assistant_message_id: int | None,
    run_id: int,
    created_at: datetime,
) -> list[DiagnosticConversationBlock]:
    renderer = PiConversationRenderer(
        assistant_message_id=assistant_message_id,
        run_id=run_id,
        created_at=created_at,
    )
    for event in events:
        if getattr(event, "event_type", "") != "pi_event." and not str(getattr(event, "event_type", "")).startswith("pi_event."):
            continue
        payload = getattr(event, "payload", None)
        if not isinstance(payload, dict):
            continue
        pi_event = payload.get("pi_event")
        if isinstance(pi_event, dict):
            renderer.apply_event(pi_event, event_at=getattr(event, "created_at", None))
    return [block for block in renderer.blocks if block.kind != "text" or block.body.strip()]


def render_assistant_artifacts_from_events(events: list[Any]) -> DiagnosticAssistantArtifacts:
    reasoning = ""
    result_text = ""
    timeline_items: list[DiagnosticReadableItem] = []
    thinking_item_id: str | None = None
    thinking_seq = 0
    for event in events:
        if getattr(event, "event_type", "") != "pi_event." and not str(getattr(event, "event_type", "")).startswith("pi_event."):
            continue
        payload = getattr(event, "payload", None)
        if not isinstance(payload, dict):
            continue
        pi_event = payload.get("pi_event")
        if not isinstance(pi_event, dict):
            continue
        assistant_event = pi_event.get("assistantMessageEvent")
        if isinstance(assistant_event, dict):
            assistant_event_type = str(assistant_event.get("type") or "")
            if assistant_event_type == "thinking_start":
                thinking_seq += 1
                thinking_item_id = f"thinking-{thinking_seq}"
                timeline_items.append(DiagnosticReadableItem(id=thinking_item_id, title="thinking", body=""))
            elif assistant_event_type == "thinking_delta" and thinking_item_id:
                delta = str(assistant_event.get("delta") or "")
                current = next((item for item in timeline_items if item.id == thinking_item_id), None)
                if current is not None:
                    next_body = f"{current.body}{delta}"
                    reasoning = next_body
                    current.body = next_body
            elif assistant_event_type == "thinking_end" and thinking_item_id:
                content = str(assistant_event.get("content") or "")
                current = next((item for item in timeline_items if item.id == thinking_item_id), None)
                next_body = content or (current.body if current is not None else "")
                reasoning = next_body
                if current is not None:
                    current.body = next_body
                thinking_item_id = None
            elif assistant_event_type == "text_delta":
                result_text = _merge_stream_text(result_text, str(assistant_event.get("delta") or ""))
            elif assistant_event_type == "text_end":
                result_text = _merge_stream_text(result_text, str(assistant_event.get("content") or ""))

        pi_event_type = str(pi_event.get("type") or "")
        if pi_event_type == "tool_execution_update":
            body = "\n\n".join(_extract_text_parts(pi_event.get("partialResult"))) or "running..."
            tool_id = str(pi_event.get("toolCallId") or "")
            if tool_id:
                current = next((item for item in timeline_items if item.id == f"tool-result-{tool_id}"), None)
                next_body = _merge_stream_text(current.body if current is not None else "", body)
                if current is not None:
                    current.body = next_body
                else:
                    timeline_items.append(DiagnosticReadableItem(id=f"tool-result-{tool_id}", title=f"tool result: {str(pi_event.get('toolName') or 'unknown')}", body=next_body))
        elif pi_event_type == "tool_execution_end":
            body = "\n\n".join(_extract_text_parts(pi_event.get("result"))) or "tool finished"
            tool_id = str(pi_event.get("toolCallId") or "")
            if tool_id:
                current = next((item for item in timeline_items if item.id == f"tool-result-{tool_id}"), None)
                next_body = _merge_stream_text(current.body if current is not None else "", body)
                if current is not None:
                    current.body = next_body
                else:
                    timeline_items.append(DiagnosticReadableItem(id=f"tool-result-{tool_id}", title=f"tool result: {str(pi_event.get('toolName') or 'unknown')}", body=next_body))
        elif pi_event_type == "message":
            message = pi_event.get("message")
            if isinstance(message, dict) and message.get("role") == "assistant":
                content = message.get("content")
                if isinstance(content, list):
                    if not reasoning:
                        reasoning = "\n\n".join(
                            str(item.get("thinking") or "")
                            for item in content
                            if isinstance(item, dict) and item.get("type") == "thinking" and str(item.get("thinking") or "").strip()
                        ).strip()
                    if not result_text:
                        result_text = "".join(
                            str(item.get("text") or "")
                            for item in content
                            if isinstance(item, dict) and item.get("type") == "text" and str(item.get("text") or "")
                        )

    if result_text.strip():
        timeline_items.append(DiagnosticReadableItem(id="result-panel", title="result", body=result_text))
    return DiagnosticAssistantArtifacts(reasoning=reasoning, items=timeline_items)
