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
    DiagnosticExecutionRecord,
    DiagnosticMessageRecord,
    DiagnosticReadableItem,
    DiagnosticSessionDetail,
    DiagnosticSessionSummary,
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


def bind_agent_session(session_id: int, *, agent_session_id: str, agent_id: str, session_mode: str) -> DiagnosticSessionSummary:
    with get_conn() as conn:
        conn.execute(
            "UPDATE diagnostic_session SET agent_session_id = ?, agent_id = ?, session_mode = ?, updated_at = ? WHERE id = ?",
            (agent_session_id, agent_id, session_mode, _utc_now(), session_id),
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


def _assistant_artifacts_from_events(events: list[DiagnosticAgentEventRecord]) -> DiagnosticAssistantArtifacts:
    reasoning = ""
    tool_calls: list[DiagnosticReadableItem] = []
    tool_state: dict[str, DiagnosticReadableItem] = {}
    tool_order: list[str] = []
    for event in events:
        if not event.event_type.startswith("pi_event."):
            continue
        payload = event.payload
        pi_event = payload.get("pi_event")
        if not isinstance(pi_event, dict):
            continue
        etype = str(pi_event.get("type") or "")
        if etype in {"message_start", "message_update", "message_end"}:
            message = pi_event.get("message")
            if isinstance(message, dict) and message.get("role") == "assistant":
                content = message.get("content")
                if isinstance(content, list):
                    reasoning = "\n\n".join(
                        str(item.get("thinking") or "")
                        for item in content
                        if isinstance(item, dict) and item.get("type") == "thinking" and str(item.get("thinking") or "").strip()
                    ).strip()
                    tool_calls = [
                        DiagnosticReadableItem(
                            id=str(item.get("id") or f"tool-call-{idx}"),
                            title=f"tool call: {str(item.get('name') or 'unknown')}",
                            body=_stringify_tool_args(item.get("arguments")),
                        )
                        for idx, item in enumerate(content)
                        if isinstance(item, dict) and item.get("type") == "toolCall"
                    ]
        elif etype == "tool_execution_start":
            tool_id = str(pi_event.get("toolCallId") or "")
            if tool_id:
                tool_state[tool_id] = DiagnosticReadableItem(
                    id=tool_id,
                    title=f"tool start: {str(pi_event.get('toolName') or 'unknown')}",
                    body=_stringify_tool_args(pi_event.get("args")),
                )
                if tool_id not in tool_order:
                    tool_order.append(tool_id)
        elif etype == "tool_execution_update":
            tool_id = str(pi_event.get("toolCallId") or "")
            if tool_id:
                body = "\n\n".join(_extract_text_parts(pi_event.get("partialResult"))) or "running..."
                tool_state[tool_id] = DiagnosticReadableItem(
                    id=tool_id,
                    title=f"tool output: {str(pi_event.get('toolName') or 'unknown')}",
                    body=body,
                )
                if tool_id not in tool_order:
                    tool_order.append(tool_id)
        elif etype == "tool_execution_end":
            tool_id = str(pi_event.get("toolCallId") or "")
            if tool_id:
                body = "\n\n".join(_extract_text_parts(pi_event.get("result"))) or "tool finished"
                tool_state[tool_id] = DiagnosticReadableItem(
                    id=tool_id,
                    title=f"tool end: {str(pi_event.get('toolName') or 'unknown')}",
                    body=body,
                )
                if tool_id not in tool_order:
                    tool_order.append(tool_id)
    items = [*tool_calls, *(tool_state[tool_id] for tool_id in tool_order if tool_id in tool_state)]
    return DiagnosticAssistantArtifacts(reasoning=reasoning, items=items)


def get_session_detail(session_id: int) -> DiagnosticSessionDetail | None:
    session = get_session(session_id)
    if session is None:
        return None
    file_messages = read_message_log(session_id)
    messages = file_messages or list_messages(session_id)
    artifacts: dict[int, DiagnosticAssistantArtifacts] = {}
    for run in list_agent_runs(session_id):
        if run.status != "completed" or run.assistant_message_id is None:
            continue
        snapshot = _assistant_artifacts_from_events(list_agent_events(run.id))
        if snapshot.reasoning or snapshot.items:
            artifacts[int(run.assistant_message_id)] = snapshot
    return DiagnosticSessionDetail(session=session, messages=messages, assistant_artifacts=artifacts)


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
