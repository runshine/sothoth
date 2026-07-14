from __future__ import annotations

import asyncio
import json
import threading
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sse_starlette.sse import EventSourceResponse

from app.api.deps import ensure_admin_user, get_current_user
from app.models import (
    AgentRunRequest,
    CreateSessionRequest,
    DiagnosticAgentEventRecord,
    DiagnosticAgentRunRecord,
    DiagnosticSessionDetail,
    DiagnosticSessionSummary,
)
from app.service.configcenter_service import ConfigCenterError, list_llm_providers
from app.service.conversation_render_service import PiConversationRenderer
from app.service.pi_agent_service import PiAgentError, stream_pi_agent
from app.service.pi_runtime_service import prepare_pi_runtime
from app.service.run_registry_service import bind_process, register_run, unregister_run
from app.service.storage_service import (
    add_agent_event,
    add_message,
    bind_agent_session,
    create_agent_run,
    create_session,
    delete_session,
    get_agent_run,
    get_session,
    get_session_detail,
    list_agent_events,
    list_agent_runs,
    list_sessions,
    update_agent_run,
)

router = APIRouter(prefix="/api/diagnostic-assistant", tags=["diagnostic-assistant"])


def _user_name(user: dict[str, Any]) -> str:
    return str(user.get("username") or user.get("user_name") or user.get("id") or "unknown")


def _ensure_session(session_id: int | None, user_name: str, title_seed: str) -> DiagnosticSessionSummary:
    if session_id is not None:
        existing = get_session(session_id)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"session {session_id} not found")
        return existing
    title = title_seed[:80] if title_seed else "诊断会话"
    return create_session(created_by=user_name, title=title)


def _serialize_event(record: DiagnosticAgentEventRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "run_id": record.run_id,
        "event_type": record.event_type,
        "payload": record.payload,
        "created_at": record.created_at.isoformat(),
    }


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "secflow-platform-diagnostic-assistant"}


@router.post("/sessions", response_model=DiagnosticSessionSummary)
def create_session_endpoint(
    payload: CreateSessionRequest,
    user_and_token: tuple[dict[str, Any], str] = Depends(get_current_user),
) -> DiagnosticSessionSummary:
    user, _ = user_and_token
    ensure_admin_user(user)
    return create_session(created_by=_user_name(user), title=(payload.title or "诊断会话")[:80])


@router.get("/sessions", response_model=list[DiagnosticSessionSummary])
def list_sessions_endpoint(
    user_and_token: tuple[dict[str, Any], str] = Depends(get_current_user),
) -> list[DiagnosticSessionSummary]:
    user, _ = user_and_token
    ensure_admin_user(user)
    return list_sessions()


@router.get("/sessions/{session_id}", response_model=DiagnosticSessionDetail)
def get_session_endpoint(
    session_id: int,
    user_and_token: tuple[dict[str, Any], str] = Depends(get_current_user),
) -> DiagnosticSessionDetail:
    user, _ = user_and_token
    ensure_admin_user(user)
    detail = get_session_detail(session_id)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"session {session_id} not found")
    return detail


@router.delete("/sessions/{session_id}")
def delete_session_endpoint(
    session_id: int,
    user_and_token: tuple[dict[str, Any], str] = Depends(get_current_user),
) -> dict[str, Any]:
    user, _ = user_and_token
    ensure_admin_user(user)
    deleted = delete_session(session_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"session {session_id} not found")
    return {"ok": True, "session_id": session_id}


@router.get("/sessions/{session_id}/runs", response_model=list[DiagnosticAgentRunRecord])
def list_runs_endpoint(
    session_id: int,
    user_and_token: tuple[dict[str, Any], str] = Depends(get_current_user),
) -> list[DiagnosticAgentRunRecord]:
    user, _ = user_and_token
    ensure_admin_user(user)
    session = get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"session {session_id} not found")
    return list_agent_runs(session_id)


@router.get("/runs/{run_id}/events", response_model=list[DiagnosticAgentEventRecord])
def list_run_events_endpoint(
    run_id: int,
    limit: int = 200,
    user_and_token: tuple[dict[str, Any], str] = Depends(get_current_user),
) -> list[DiagnosticAgentEventRecord]:
    user, _ = user_and_token
    ensure_admin_user(user)
    run = get_agent_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"run {run_id} not found")
    safe_limit = max(1, min(limit, 5000))
    return list_agent_events(run_id, safe_limit)


@router.post("/runs/stream")
async def run_stream_endpoint(
    payload: AgentRunRequest,
    user_and_token: tuple[dict[str, Any], str] = Depends(get_current_user),
):
    user, token = user_and_token
    ensure_admin_user(user)
    user_name = _user_name(user)
    session = _ensure_session(payload.session_id, user_name, payload.message)
    user_message = add_message(session.id, "user", payload.message)
    requested_agent_id = "pi"
    session_mode = "invoke"
    try:
        providers = list_llm_providers(token_override=token)
        pi_runtime = prepare_pi_runtime(
            session.id,
            providers,
            selected_provider_key=payload.provider_key,
            agent_task_key_secret=payload.agent_task_key_secret,
        )
        session = bind_agent_session(
            session.id,
            agent_session_id=str(pi_runtime["session_path"]),
            agent_id=requested_agent_id,
            session_mode=session_mode,
        )
    except ConfigCenterError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    run = create_agent_run(
        session_id=session.id,
        user_message_id=user_message.id,
        agent_id=requested_agent_id,
        agent_session_id=session.agent_session_id,
        task_text=payload.message,
    )
    cancel_event = register_run(run.id)

    async def event_generator():
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        done_marker = {"type": "__done__"}
        render_state = PiConversationRenderer(run_id=run.id)

        def push(item: dict[str, Any]) -> None:
            loop.call_soon_threadsafe(queue.put_nowait, item)

        def stream_worker() -> None:
            try:
                upstream_stream = stream_pi_agent(
                    prompt=payload.message,
                    model_ref=str(pi_runtime["model_ref"]),
                    session_path=str(pi_runtime["session_path"]),
                    runtime_dir=str(pi_runtime["runtime_dir"]),
                    env=pi_runtime["env"],
                    cancel_event=cancel_event,
                    on_process_started=lambda proc: bind_process(run.id, proc),
                )
                for upstream_event in upstream_stream:
                    push(upstream_event)
            except PiAgentError as exc:
                push({"type": "__exception__", "message": str(exc)})
            except Exception as exc:
                push({"type": "__exception__", "message": str(exc)})
            finally:
                push(done_marker)

        worker = threading.Thread(target=stream_worker, daemon=True, name=f"diagnostic-pi-run-{run.id}")
        worker.start()

        yield {
            "event": "session",
            "data": json.dumps(
                {
                    "session_id": session.id,
                    "run_id": run.id,
                    "agent_id": requested_agent_id,
                    "agent_session_id": session.agent_session_id or "",
                    "session_mode": session_mode,
                },
                ensure_ascii=False,
            ),
        }
        final_text_parts: list[str] = []
        upstream_response_id: str | None = None
        last_error = ""
        while True:
            upstream_event = await queue.get()
            if upstream_event is done_marker or upstream_event.get("type") == "__done__":
                break
            if upstream_event.get("type") == "__exception__":
                last_error = str(upstream_event.get("message") or "agent 执行失败")
                break

            event_type = str(upstream_event.get("type") or "").strip()
            if event_type == "response.created":
                response = upstream_event.get("response") or {}
                upstream_response_id = str(response.get("id") or "") or None
                update_agent_run(run.id, upstream_response_id=upstream_response_id)
                add_agent_event(run.id, event_type, upstream_event)
                yield {"event": "run_started", "data": json.dumps({"run_id": run.id, "response_id": upstream_response_id}, ensure_ascii=False)}
                continue
            if event_type == "response.output_text.delta":
                delta = str(upstream_event.get("delta") or "")
                if delta:
                    final_text_parts.append(delta)
                    yield {"event": "answer_delta", "data": json.dumps({"text": delta}, ensure_ascii=False)}
                continue
            if event_type == "response.reasoning.delta":
                add_agent_event(run.id, event_type, upstream_event)
                yield {"event": "reasoning_delta", "data": json.dumps({"text": str(upstream_event.get('delta') or '')}, ensure_ascii=False)}
                continue
            if event_type == "response.pi.event":
                pi_event = upstream_event.get("pi_event")
                if isinstance(pi_event, dict):
                    pi_event_type = str(pi_event.get("type") or "unknown")
                    add_agent_event(run.id, f"pi_event.{pi_event_type}", upstream_event)
                    yield {"event": "pi_event", "data": json.dumps(pi_event, ensure_ascii=False)}
                    for block in render_state.apply_event(pi_event):
                        yield {
                            "event": "conversation_block",
                            "data": json.dumps({"block": block.model_dump()}, ensure_ascii=False),
                        }
                continue
            if event_type == "response.trace.item":
                stored = add_agent_event(run.id, event_type, upstream_event)
                yield {"event": "trace_item", "data": json.dumps(_serialize_event(stored), ensure_ascii=False)}
                continue
            if event_type == "response.completed":
                add_agent_event(run.id, event_type, upstream_event)
                response = upstream_event.get("response") or {}
                final_text = str(response.get("output_text") or "".join(final_text_parts)).strip()
                assistant_message = add_message(session.id, "assistant", final_text or "本轮 agent 未返回可展示文本。")
                update_agent_run(
                    run.id,
                    status="completed",
                    final_text=final_text,
                    assistant_message_id=assistant_message.id,
                    upstream_response_id=str(response.get("id") or upstream_response_id or ""),
                    finished_at=datetime.now(timezone.utc).isoformat(),
                )
                yield {
                    "event": "done",
                    "data": json.dumps(
                        {
                            "run_id": run.id,
                            "session_id": session.id,
                            "assistant_message_id": assistant_message.id,
                        },
                        ensure_ascii=False,
                    ),
                }
                return
            if event_type == "response.failed":
                add_agent_event(run.id, event_type, upstream_event)
                last_error = str(upstream_event.get("error_message") or "agent 执行失败")
                break

        update_agent_run(
            run.id,
            status="cancelled" if last_error == "agent run cancelled" else "failed",
            final_text="".join(final_text_parts).strip(),
            upstream_response_id=upstream_response_id,
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        yield {"event": "error", "data": json.dumps({"message": last_error or "agent 执行失败", "run_id": run.id}, ensure_ascii=False)}
        unregister_run(run.id)
        return
    async def wrapped_generator():
        try:
            async for item in event_generator():
                yield item
        finally:
            unregister_run(run.id)

    return EventSourceResponse(wrapped_generator())
