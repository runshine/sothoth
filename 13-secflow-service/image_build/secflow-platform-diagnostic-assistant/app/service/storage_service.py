from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Iterable

from app.db import get_conn
from app.models import (
    DiagnosticAssistantArtifacts,
    DiagnosticAgentEventRecord,
    DiagnosticAgentRunRecord,
    DiagnosticAuditRecord,
    DiagnosticConversationBlock,
    DiagnosticExecutionRecord,
    DiagnosticMessageRecord,
    DiagnosticReadableItem,
    DiagnosticSessionDetail,
    DiagnosticSessionSummary,
)
from app.service.conversation_render_service import (
    render_assistant_artifacts_from_events,
    render_conversation_blocks_from_events,
    render_tool_command,
)
from app.service.session_log_service import append_event_log, append_message_log, read_event_log, read_message_log
from app.service.session_log_service import delete_run_log, delete_session_log


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _session_from_row(row) -> DiagnosticSessionSummary:
    return DiagnosticSessionSummary.model_validate(dict(row))


def _message_from_row(row) -> DiagnosticMessageRecord:
    return DiagnosticMessageRecord.model_validate(dict(row))


def _execution_from_row(row) -> DiagnosticExecutionRecord:
    return DiagnosticExecutionRecord.model_validate(dict(row))


def _audit_from_row(row) -> DiagnosticAuditRecord:
    return DiagnosticAuditRecord.model_validate(dict(row))


def _run_from_row(row) -> DiagnosticAgentRunRecord:
    return DiagnosticAgentRunRecord.model_validate(dict(row))


def _event_from_row(row) -> DiagnosticAgentEventRecord:
    return DiagnosticAgentEventRecord.model_validate(dict(row))


def create_session(created_by: str, title: str) -> DiagnosticSessionSummary:
    now = _utc_now()
    with get_conn() as conn:
        cursor = conn.execute(
            "INSERT INTO diagnostic_session (title, created_by, created_at, updated_at, agent_session_id, agent_id, session_mode) VALUES (?, ?, ?, ?, NULL, NULL, NULL)",
            (title, created_by, now, now),
        )
        row = conn.execute("SELECT * FROM diagnostic_session WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _session_from_row(row)


def update_session_timestamp(session_id: int) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE diagnostic_session SET updated_at = ? WHERE id = ?",
            (_utc_now(), session_id),
        )


def list_sessions(limit: int = 100) -> list[DiagnosticSessionSummary]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM diagnostic_session ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_session_from_row(row) for row in rows]


def get_session(session_id: int) -> DiagnosticSessionSummary | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM diagnostic_session WHERE id = ?", (session_id,)).fetchone()
    return _session_from_row(row) if row else None


def delete_session(session_id: int) -> bool:
    with get_conn() as conn:
        session = conn.execute("SELECT id FROM diagnostic_session WHERE id = ?", (session_id,)).fetchone()
        if session is None:
            return False
        run_rows = conn.execute(
            "SELECT id FROM diagnostic_agent_run WHERE session_id = ?",
            (session_id,),
        ).fetchall()
        run_ids = [int(row["id"]) for row in run_rows]
        conn.execute(
            "DELETE FROM diagnostic_agent_event WHERE run_id IN (SELECT id FROM diagnostic_agent_run WHERE session_id = ?)",
            (session_id,),
        )
        conn.execute("DELETE FROM diagnostic_agent_run WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM diagnostic_execution WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM diagnostic_message WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM diagnostic_audit_log WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM diagnostic_session WHERE id = ?", (session_id,))
    delete_session_log(session_id)
    for run_id in run_ids:
        delete_run_log(run_id)
    return True


def bind_agent_session(
    session_id: int,
    *,
    agent_session_id: str,
    agent_id: str | None = None,
    session_mode: str | None = None,
) -> DiagnosticSessionSummary:
    with get_conn() as conn:
        current = conn.execute("SELECT * FROM diagnostic_session WHERE id = ?", (session_id,)).fetchone()
        if current is None:
            raise ValueError(f"session {session_id} not found")
        next_agent_id = agent_id if agent_id is not None else current["agent_id"]
        next_session_mode = session_mode if session_mode is not None else current["session_mode"]
        conn.execute(
            "UPDATE diagnostic_session SET agent_session_id = ?, agent_id = ?, session_mode = ?, updated_at = ? WHERE id = ?",
            (agent_session_id, next_agent_id, next_session_mode, _utc_now(), session_id),
        )
        row = conn.execute("SELECT * FROM diagnostic_session WHERE id = ?", (session_id,)).fetchone()
    return _session_from_row(row)


def add_message(session_id: int, role: str, content: str) -> DiagnosticMessageRecord:
    now = _utc_now()
    with get_conn() as conn:
        cursor = conn.execute(
            "INSERT INTO diagnostic_message (session_id, role, content, created_at) VALUES (?, ?, ?, ?)",
            (session_id, role, content, now),
        )
        row = conn.execute("SELECT * FROM diagnostic_message WHERE id = ?", (cursor.lastrowid,)).fetchone()
    update_session_timestamp(session_id)
    record = _message_from_row(row)
    append_message_log(record)
    return record


def list_messages(session_id: int, limit: int | None = None) -> list[DiagnosticMessageRecord]:
    sql = "SELECT * FROM diagnostic_message WHERE session_id = ? ORDER BY id ASC"
    params: list[object] = [session_id]
    if limit is not None:
        sql = (
            "SELECT * FROM (SELECT * FROM diagnostic_message WHERE session_id = ? ORDER BY id DESC LIMIT ?) "
            "ORDER BY id ASC"
        )
        params.append(limit)
    with get_conn() as conn:
        rows = conn.execute(sql, tuple(params)).fetchall()
    return [_message_from_row(row) for row in rows]


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


def _upsert_timeline_item(items: list[DiagnosticReadableItem], next_item: DiagnosticReadableItem) -> None:
    for index, item in enumerate(items):
        if item.id == next_item.id:
            items[index] = next_item
            return
    items.append(next_item)


def _upsert_block(items: list[DiagnosticConversationBlock], next_item: DiagnosticConversationBlock) -> None:
    for index, item in enumerate(items):
        if item.id == next_item.id:
            items[index] = next_item
            return
    items.append(next_item)


def _with_block_time(
    current: DiagnosticConversationBlock | None,
    *,
    created_at: datetime,
    updated_at: datetime | None = None,
) -> tuple[datetime, datetime | None]:
    return (
        current.created_at if current is not None else created_at,
        updated_at if updated_at is not None else (current.updated_at if current is not None else None),
    )


def _block_title_for_tool(tool_name: str) -> str:
    return tool_name or "unknown"


def _conversation_blocks_from_events(
    events: list[DiagnosticAgentEventRecord],
    *,
    assistant_message_id: int | None,
    run_id: int,
    created_at: datetime,
) -> list[DiagnosticConversationBlock]:
    blocks: list[DiagnosticConversationBlock] = []
    thinking_item_id: str | None = None
    text_item_id: str | None = None
    thinking_seq = 0
    text_seq = 0
    for event in events:
        if not event.event_type.startswith("pi_event."):
            continue
        payload = event.payload
        pi_event = payload.get("pi_event")
        if not isinstance(pi_event, dict):
            continue
        etype = str(pi_event.get("type") or "")
        assistant_event = pi_event.get("assistantMessageEvent")
        if isinstance(assistant_event, dict):
            assistant_event_type = str(assistant_event.get("type") or "")
            partial_content_item = _extract_partial_content_item(assistant_event)
            if assistant_event_type == "thinking_start":
                thinking_seq += 1
                thinking_item_id = f"thinking-{run_id}-{thinking_seq}"
                _upsert_block(
                    blocks,
                    DiagnosticConversationBlock(
                        id=thinking_item_id,
                        message_id=assistant_message_id,
                        run_id=run_id,
                        kind="thinking",
                        title="thinking",
                        body="",
                        created_at=created_at,
                        updated_at=event.created_at,
                    ),
                )
            elif assistant_event_type == "thinking_delta" and thinking_item_id:
                delta = str(assistant_event.get("delta") or "")
                current = next((item for item in blocks if item.id == thinking_item_id), None)
                if current is not None:
                    _upsert_block(
                        blocks,
                        DiagnosticConversationBlock(
                            id=current.id,
                            message_id=current.message_id,
                            run_id=current.run_id,
                            kind=current.kind,
                            title=current.title,
                            body=f"{current.body}{delta}",
                            created_at=current.created_at,
                            updated_at=event.created_at,
                        ),
                    )
            elif assistant_event_type == "thinking_end" and thinking_item_id:
                content = str(assistant_event.get("content") or "")
                current = next((item for item in blocks if item.id == thinking_item_id), None)
                if current is not None:
                    _upsert_block(
                        blocks,
                        DiagnosticConversationBlock(
                            id=current.id,
                            message_id=current.message_id,
                            run_id=current.run_id,
                            kind=current.kind,
                            title=current.title,
                            body=content or current.body,
                            created_at=current.created_at,
                            updated_at=event.created_at,
                        ),
                    )
                thinking_item_id = None
            elif assistant_event_type == "text_start":
                text_seq += 1
                text_item_id = f"text-{run_id}-{text_seq}"
                _upsert_block(
                    blocks,
                        DiagnosticConversationBlock(
                            id=text_item_id,
                            message_id=assistant_message_id,
                            run_id=run_id,
                            kind="text",
                            title="response",
                            body="",
                            created_at=created_at,
                            updated_at=event.created_at,
                        ),
                    )
            elif assistant_event_type == "text_delta" and text_item_id:
                delta = str(assistant_event.get("delta") or "")
                current = next((item for item in blocks if item.id == text_item_id), None)
                if current is not None:
                    _upsert_block(
                        blocks,
                        DiagnosticConversationBlock(
                            id=current.id,
                            message_id=current.message_id,
                            run_id=current.run_id,
                            kind=current.kind,
                            title=current.title,
                            body=_merge_stream_text(current.body, delta),
                            created_at=current.created_at,
                            updated_at=event.created_at,
                        ),
                    )
            elif assistant_event_type == "text_end" and text_item_id:
                content = str(assistant_event.get("content") or "")
                current = next((item for item in blocks if item.id == text_item_id), None)
                if current is not None:
                    _upsert_block(
                        blocks,
                        DiagnosticConversationBlock(
                            id=current.id,
                            message_id=current.message_id,
                            run_id=current.run_id,
                            kind=current.kind,
                            title=current.title,
                            body=_merge_stream_text(current.body, content),
                            created_at=current.created_at,
                            updated_at=event.created_at,
                        ),
                    )
                text_item_id = None
            elif assistant_event_type in {"toolcall_start", "toolcall_delta", "toolcall_end"}:
                tool_call = assistant_event.get("toolCall") if assistant_event_type == "toolcall_end" else partial_content_item
                if isinstance(tool_call, dict):
                    tool_call_id = str(tool_call.get("id") or "")
                    tool_name = str(tool_call.get("name") or "unknown")
                    body = render_tool_command(tool_name, tool_call.get("arguments")) if assistant_event_type == "toolcall_end" else ""
                    if tool_call_id:
                        block_id = f"toolcall-{tool_call_id}"
                        current = next((item for item in blocks if item.id == block_id), None)
                        _upsert_block(
                            blocks,
                        DiagnosticConversationBlock(
                            id=block_id,
                            message_id=assistant_message_id,
                            run_id=run_id,
                            kind="tool_call",
                            title=_block_title_for_tool(tool_name),
                            body=_merge_stream_text(current.body if current is not None else "", body),
                            created_at=current.created_at if current is not None else created_at,
                            updated_at=event.created_at,
                        ),
                    )
        if etype == "tool_execution_start":
            tool_id = str(pi_event.get("toolCallId") or "")
            if tool_id:
                _upsert_block(
                    blocks,
                        DiagnosticConversationBlock(
                            id=f"tool-result-{tool_id}",
                            message_id=assistant_message_id,
                            run_id=run_id,
                            kind="tool_result",
                            title=_block_title_for_tool(str(pi_event.get("toolName") or "unknown")),
                            body="",
                            created_at=created_at,
                            updated_at=event.created_at,
                        ),
                    )
        elif etype == "tool_execution_update":
            tool_id = str(pi_event.get("toolCallId") or "")
            if tool_id:
                body = "\n\n".join(_extract_text_parts(pi_event.get("partialResult"))) or ""
                current = next((item for item in blocks if item.id == f"tool-result-{tool_id}"), None)
                _upsert_block(
                    blocks,
                    DiagnosticConversationBlock(
                        id=f"tool-result-{tool_id}",
                        message_id=assistant_message_id,
                        run_id=run_id,
                        kind="tool_result",
                        title=_block_title_for_tool(str(pi_event.get("toolName") or "unknown")),
                        body=_merge_stream_text(current.body if current is not None else "", body),
                        created_at=current.created_at if current is not None else created_at,
                        updated_at=event.created_at,
                    ),
                )
        elif etype == "tool_execution_end":
            tool_id = str(pi_event.get("toolCallId") or "")
            if tool_id:
                body = "\n\n".join(_extract_text_parts(pi_event.get("result"))) or "tool finished"
                current = next((item for item in blocks if item.id == f"tool-result-{tool_id}"), None)
                _upsert_block(
                    blocks,
                    DiagnosticConversationBlock(
                        id=f"tool-result-{tool_id}",
                        message_id=assistant_message_id,
                        run_id=run_id,
                        kind="tool_result",
                        title=_block_title_for_tool(str(pi_event.get("toolName") or "unknown")),
                        body=_merge_stream_text(current.body if current is not None else "", body),
                        created_at=current.created_at if current is not None else created_at,
                        updated_at=event.created_at,
                    ),
                )
        elif etype == "message_end":
            message = pi_event.get("message")
            if isinstance(message, dict) and message.get("role") == "assistant":
                content = message.get("content")
                if isinstance(content, list):
                    fallback_index = 0
                    for item in content:
                        if not isinstance(item, dict):
                            continue
                        item_type = str(item.get("type") or "")
                        if item_type == "thinking":
                            text = str(item.get("thinking") or "")
                            if text.strip():
                                fallback_index += 1
                                block_id = f"thinking-fallback-{run_id}-{fallback_index}"
                                if not any(block.kind == "thinking" and block.body == text for block in blocks):
                                    blocks.append(DiagnosticConversationBlock(
                                        id=block_id,
                                        message_id=assistant_message_id,
                                        run_id=run_id,
                                        kind="thinking",
                                        title="thinking",
                                        body=text,
                                        created_at=created_at,
                                        updated_at=event.created_at,
                                    ))
                        elif item_type == "text":
                            text = str(item.get("text") or "")
                            if text.strip():
                                if any(block.kind == "text" and block.body.strip() == text for block in blocks):
                                    continue
                                fallback_index += 1
                                block_id = f"text-fallback-{run_id}-{fallback_index}"
                                if not any(block.kind == "text" and block.body == text for block in blocks):
                                    blocks.append(DiagnosticConversationBlock(
                                        id=block_id,
                                        message_id=assistant_message_id,
                                        run_id=run_id,
                                        kind="text",
                                        title="response",
                                        body=text,
                                        created_at=created_at,
                                        updated_at=event.created_at,
                                    ))
                        elif item_type == "toolCall":
                            tool_name = str(item.get("name") or "unknown")
                            tool_id = str(item.get("id") or f"fallback-{run_id}-{fallback_index}")
                            body = render_tool_command(tool_name, item.get("arguments"))
                            block_id = f"toolcall-{tool_id}"
                            if not any(block.id == block_id for block in blocks):
                                blocks.append(DiagnosticConversationBlock(
                                    id=block_id,
                                    message_id=assistant_message_id,
                                    run_id=run_id,
                                    kind="tool_call",
                                    title=_block_title_for_tool(tool_name),
                                    body=body,
                                    created_at=created_at,
                                    updated_at=event.created_at,
                                ))
    return [
        block for block in blocks
        if block.kind != "text" or block.body.strip()
    ]


def _assistant_artifacts_from_events(events: list[DiagnosticAgentEventRecord]) -> DiagnosticAssistantArtifacts:
    reasoning = ""
    result_text = ""
    timeline_items: list[DiagnosticReadableItem] = []
    thinking_item_id: str | None = None
    thinking_seq = 0
    for event in events:
        if not event.event_type.startswith("pi_event."):
            continue
        payload = event.payload
        pi_event = payload.get("pi_event")
        if not isinstance(pi_event, dict):
            continue
        etype = str(pi_event.get("type") or "")
        assistant_event = pi_event.get("assistantMessageEvent")
        if isinstance(assistant_event, dict):
            assistant_event_type = str(assistant_event.get("type") or "")
            partial_content_item = _extract_partial_content_item(assistant_event)
            if assistant_event_type == "thinking_start":
                thinking_seq += 1
                thinking_item_id = f"thinking-{thinking_seq}"
                _upsert_timeline_item(
                    timeline_items,
                    DiagnosticReadableItem(id=thinking_item_id, title="thinking", body=""),
                )
            elif assistant_event_type == "thinking_delta" and thinking_item_id:
                delta = str(assistant_event.get("delta") or "")
                current = next((item for item in timeline_items if item.id == thinking_item_id), None)
                if current is not None:
                    next_body = f"{current.body}{delta}"
                    reasoning = next_body
                    _upsert_timeline_item(
                        timeline_items,
                        DiagnosticReadableItem(id=thinking_item_id, title="thinking", body=next_body),
                    )
            elif assistant_event_type == "thinking_end" and thinking_item_id:
                content = str(assistant_event.get("content") or "")
                current = next((item for item in timeline_items if item.id == thinking_item_id), None)
                next_body = content or (current.body if current is not None else "")
                reasoning = next_body
                _upsert_timeline_item(
                    timeline_items,
                    DiagnosticReadableItem(id=thinking_item_id, title="thinking", body=next_body),
                )
                thinking_item_id = None
            elif assistant_event_type in {"toolcall_start", "toolcall_delta", "toolcall_end"}:
                tool_call = assistant_event.get("toolCall") if assistant_event_type == "toolcall_end" else partial_content_item
                if isinstance(tool_call, dict):
                    tool_call_id = str(tool_call.get("id") or "")
                    tool_name = str(tool_call.get("name") or "unknown")
                    body = render_tool_command(tool_name, tool_call.get("arguments")) if assistant_event_type == "toolcall_end" else ""
                    if tool_call_id:
                        current = next((item for item in timeline_items if item.id == f"toolcall-{tool_call_id}"), None)
                        next_body = _merge_stream_text(current.body if current is not None else "", body)
                        _upsert_timeline_item(
                            timeline_items,
                            DiagnosticReadableItem(
                                id=f"toolcall-{tool_call_id}",
                                title=f"toolcall: {tool_name}",
                                body=next_body,
                            ),
                        )
            elif assistant_event_type == "text_delta":
                result_text = _merge_stream_text(result_text, str(assistant_event.get("delta") or ""))
            elif assistant_event_type == "text_end":
                result_text = _merge_stream_text(result_text, str(assistant_event.get("content") or ""))

        if etype == "tool_execution_start":
            tool_id = str(pi_event.get("toolCallId") or "")
            if tool_id:
                _upsert_timeline_item(
                    timeline_items,
                    DiagnosticReadableItem(
                        id=f"tool-result-{tool_id}",
                        title=f"tool result: {str(pi_event.get('toolName') or 'unknown')}",
                        body="",
                    ),
                )
        elif etype == "tool_execution_update":
            tool_id = str(pi_event.get("toolCallId") or "")
            if tool_id:
                body = "\n\n".join(_extract_text_parts(pi_event.get("partialResult"))) or "running..."
                current = next((item for item in timeline_items if item.id == f"tool-result-{tool_id}"), None)
                next_body = _merge_stream_text(current.body if current is not None else "", body)
                _upsert_timeline_item(
                    timeline_items,
                    DiagnosticReadableItem(
                        id=f"tool-result-{tool_id}",
                        title=f"tool result: {str(pi_event.get('toolName') or 'unknown')}",
                        body=next_body,
                    ),
                )
        elif etype == "tool_execution_end":
            tool_id = str(pi_event.get("toolCallId") or "")
            if tool_id:
                body = "\n\n".join(_extract_text_parts(pi_event.get("result"))) or "tool finished"
                current = next((item for item in timeline_items if item.id == f"tool-result-{tool_id}"), None)
                next_body = _merge_stream_text(current.body if current is not None else "", body)
                _upsert_timeline_item(
                    timeline_items,
                    DiagnosticReadableItem(
                        id=f"tool-result-{tool_id}",
                        title=f"tool result: {str(pi_event.get('toolName') or 'unknown')}",
                        body=next_body,
                    ),
                )
        elif etype in {"message_start", "message_update", "message_end"}:
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


def get_session_detail(session_id: int) -> DiagnosticSessionDetail | None:
    session = get_session(session_id)
    if session is None:
        return None
    file_messages = read_message_log(session_id)
    messages = file_messages or list_messages(session_id)
    artifacts: dict[int, DiagnosticAssistantArtifacts] = {}
    blocks: list[DiagnosticConversationBlock] = []
    runs_by_assistant_message_id: dict[int, DiagnosticAgentRunRecord] = {}
    runs_by_user_message_id: dict[int, DiagnosticAgentRunRecord] = {}
    for run in list_agent_runs(session_id):
        if run.user_message_id is not None:
            runs_by_user_message_id[int(run.user_message_id)] = run
        if run.assistant_message_id is not None:
            runs_by_assistant_message_id[int(run.assistant_message_id)] = run
        if run.status != "completed" or run.assistant_message_id is None:
            continue
        snapshot = render_assistant_artifacts_from_events(list_agent_events(run.id))
        if snapshot.reasoning or snapshot.items:
            artifacts[int(run.assistant_message_id)] = snapshot
    for message in messages:
        if message.role == "user":
            blocks.append(
                DiagnosticConversationBlock(
                    id=f"user-{message.id}",
                    message_id=message.id,
                    run_id=None,
                    kind="user",
                    title="user",
                    body=message.content,
                    created_at=message.created_at,
                )
            )
            run = runs_by_user_message_id.get(int(message.id))
            if run is not None and run.assistant_message_id is None:
                blocks.extend(
                    render_conversation_blocks_from_events(
                        list_agent_events(run.id),
                        assistant_message_id=None,
                        run_id=run.id,
                        created_at=message.created_at,
                    )
                )
            continue
        if message.role != "assistant":
            continue
        run = runs_by_assistant_message_id.get(int(message.id))
        if run is None:
            blocks.append(
                DiagnosticConversationBlock(
                    id=f"text-{message.id}",
                    message_id=message.id,
                    run_id=None,
                    kind="text",
                    title="response",
                    body=message.content,
                    created_at=message.created_at,
                )
            )
            continue
        blocks.extend(
            render_conversation_blocks_from_events(
                list_agent_events(run.id),
                assistant_message_id=message.id,
                run_id=run.id,
                created_at=message.created_at,
            )
        )
    return DiagnosticSessionDetail(session=session, messages=messages, assistant_artifacts=artifacts, conversation_blocks=blocks)


def add_execution(record: DiagnosticExecutionRecord) -> DiagnosticExecutionRecord:
    with get_conn() as conn:
        cursor = conn.execute(
            """
            INSERT INTO diagnostic_execution (
                session_id, message_id, command_text, stdout, stderr, exit_code, status, started_at, finished_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.session_id,
                record.message_id,
                record.command_text,
                record.stdout,
                record.stderr,
                record.exit_code,
                record.status,
                record.started_at.isoformat(),
                record.finished_at.isoformat() if record.finished_at else None,
            ),
        )
        row = conn.execute("SELECT * FROM diagnostic_execution WHERE id = ?", (cursor.lastrowid,)).fetchone()
    update_session_timestamp(record.session_id)
    return _execution_from_row(row)


def list_executions(session_id: int) -> list[DiagnosticExecutionRecord]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM diagnostic_execution WHERE session_id = ? ORDER BY id DESC",
            (session_id,),
        ).fetchall()
    return [_execution_from_row(row) for row in rows]


def add_audit(user_id: str, action_type: str, request_text: str, session_id: int | None = None, command_text: str | None = None, result_summary: str | None = None) -> DiagnosticAuditRecord:
    with get_conn() as conn:
        cursor = conn.execute(
            """
            INSERT INTO diagnostic_audit_log (user_id, session_id, action_type, request_text, command_text, result_summary, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, session_id, action_type, request_text, command_text, result_summary, _utc_now()),
        )
        row = conn.execute("SELECT * FROM diagnostic_audit_log WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _audit_from_row(row)


def list_audits(limit: int = 200) -> list[DiagnosticAuditRecord]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM diagnostic_audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_audit_from_row(row) for row in rows]


def create_agent_run(
    session_id: int,
    user_message_id: int | None,
    agent_id: str,
    agent_session_id: str | None,
    task_text: str,
) -> DiagnosticAgentRunRecord:
    now = _utc_now()
    with get_conn() as conn:
        cursor = conn.execute(
            """
            INSERT INTO diagnostic_agent_run (
                session_id, user_message_id, assistant_message_id, agent_id, agent_session_id, upstream_response_id,
                task_text, final_text, status, created_at, finished_at
            ) VALUES (?, ?, NULL, ?, ?, NULL, ?, '', 'running', ?, NULL)
            """,
            (session_id, user_message_id, agent_id, agent_session_id, task_text, now),
        )
        row = conn.execute("SELECT * FROM diagnostic_agent_run WHERE id = ?", (cursor.lastrowid,)).fetchone()
    update_session_timestamp(session_id)
    return _run_from_row(row)


def update_agent_run(
    run_id: int,
    *,
    status: str | None = None,
    final_text: str | None = None,
    assistant_message_id: int | None = None,
    upstream_response_id: str | None = None,
    finished_at: str | None = None,
) -> DiagnosticAgentRunRecord:
    with get_conn() as conn:
        current = conn.execute("SELECT * FROM diagnostic_agent_run WHERE id = ?", (run_id,)).fetchone()
        if current is None:
            raise KeyError(f"run {run_id} not found")
        payload = dict(current)
        next_status = status if status is not None else payload.get("status")
        next_final_text = final_text if final_text is not None else payload.get("final_text")
        next_assistant_message_id = assistant_message_id if assistant_message_id is not None else payload.get("assistant_message_id")
        next_upstream_response_id = upstream_response_id if upstream_response_id is not None else payload.get("upstream_response_id")
        next_finished_at = finished_at if finished_at is not None else payload.get("finished_at")
        conn.execute(
            """
            UPDATE diagnostic_agent_run
            SET status = ?, final_text = ?, assistant_message_id = ?, upstream_response_id = ?, finished_at = ?
            WHERE id = ?
            """,
            (next_status, next_final_text, next_assistant_message_id, next_upstream_response_id, next_finished_at, run_id),
        )
        row = conn.execute("SELECT * FROM diagnostic_agent_run WHERE id = ?", (run_id,)).fetchone()
    update_session_timestamp(int(row["session_id"]))
    return _run_from_row(row)


def list_agent_runs(session_id: int) -> list[DiagnosticAgentRunRecord]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM diagnostic_agent_run WHERE session_id = ? ORDER BY id DESC",
            (session_id,),
        ).fetchall()
    return [_run_from_row(row) for row in rows]


def get_agent_run(run_id: int) -> DiagnosticAgentRunRecord | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM diagnostic_agent_run WHERE id = ?", (run_id,)).fetchone()
    return _run_from_row(row) if row else None


def add_agent_event(run_id: int, event_type: str, payload: dict) -> DiagnosticAgentEventRecord:
    now = _utc_now()
    with get_conn() as conn:
        cursor = conn.execute(
            "INSERT INTO diagnostic_agent_event (run_id, event_type, payload_json, created_at) VALUES (?, ?, ?, ?)",
            (run_id, event_type, json.dumps(payload, ensure_ascii=False), now),
        )
        row = conn.execute("SELECT * FROM diagnostic_agent_event WHERE id = ?", (cursor.lastrowid,)).fetchone()
    record = _event_from_row(row)
    append_event_log(record)
    return record


def list_agent_events(run_id: int, limit: int | None = None) -> list[DiagnosticAgentEventRecord]:
    file_rows = read_event_log(run_id)
    if file_rows:
        return file_rows[-limit:] if limit is not None else file_rows
    with get_conn() as conn:
        if limit is not None:
            rows = conn.execute(
                """
                SELECT * FROM (
                    SELECT * FROM diagnostic_agent_event WHERE run_id = ? ORDER BY id DESC LIMIT ?
                ) ORDER BY id ASC
                """,
                (run_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM diagnostic_agent_event WHERE run_id = ? ORDER BY id ASC",
                (run_id,),
            ).fetchall()
    return [_event_from_row(row) for row in rows]
