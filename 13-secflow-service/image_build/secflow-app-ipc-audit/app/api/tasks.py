from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from app.core.auth import Subject, get_current_subject
from app.schemas import (
    ArtifactListResponse,
    AttemptDetailResponse,
    EventPageResponse,
    PagedTaskResponse,
    StageLogResponse,
    SuccessResponse,
    TaskCreateRequest,
    TaskDetailResponse,
    TaskRetryRequest,
    TaskSummaryResponse,
)
from app.services.task_service import get_task_service

router = APIRouter()


@router.post("/tasks", response_model=TaskSummaryResponse, status_code=201)
def create_task(payload: TaskCreateRequest, subject: Subject = Depends(get_current_subject)) -> TaskSummaryResponse:
    return get_task_service().create_task(payload, subject)


@router.get("/tasks", response_model=PagedTaskResponse)
def list_tasks(
    project_id: str | None = Query(default=None),
    workspace_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    stage: str | None = Query(default=None),
    keyword: str | None = Query(default=None),
    created_by: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=200),
) -> PagedTaskResponse:
    return get_task_service().list_tasks(
        project_id=project_id,
        workspace_id=workspace_id,
        status_filter=status,
        stage=stage,
        keyword=keyword,
        created_by=created_by,
        page=page,
        per_page=per_page,
    )


@router.get("/tasks/{task_id}", response_model=TaskDetailResponse)
def get_task(task_id: str) -> TaskDetailResponse:
    return get_task_service().get_task(task_id)


@router.get("/tasks/{task_id}/attempts", response_model=list[AttemptDetailResponse])
def list_task_attempts(task_id: str) -> list[AttemptDetailResponse]:
    return get_task_service().list_attempts(task_id)


@router.get("/tasks/{task_id}/attempts/{attempt_id}", response_model=AttemptDetailResponse)
def get_task_attempt(task_id: str, attempt_id: str) -> AttemptDetailResponse:
    return get_task_service().get_attempt(task_id, attempt_id)


@router.get("/tasks/{task_id}/events", response_model=EventPageResponse)
def list_task_events(
    task_id: str,
    attempt_id: str | None = Query(default=None),
    cursor: int | None = Query(default=None, ge=0),
    limit: int = Query(default=200, ge=1, le=1000),
) -> EventPageResponse:
    return get_task_service().list_events(task_id, attempt_id=attempt_id, cursor=cursor, limit=limit)


@router.get("/tasks/{task_id}/attempts/{attempt_id}/stages/{stage_name}/log", response_model=StageLogResponse)
def get_stage_log(
    task_id: str,
    attempt_id: str,
    stage_name: str,
    lines: int = Query(default=300, ge=1, le=4000),
    cursor: int | None = Query(default=None, ge=0),
) -> StageLogResponse:
    return get_task_service().get_stage_log(task_id, attempt_id, stage_name, lines=lines, cursor=cursor)


@router.get("/tasks/{task_id}/attempts/{attempt_id}/stages/{stage_name}/sessions", response_model=list[dict])
def list_stage_sessions(task_id: str, attempt_id: str, stage_name: str) -> list[dict]:
    return get_task_service().list_stage_sessions(task_id, attempt_id, stage_name)


@router.get("/tasks/{task_id}/attempts/{attempt_id}/stages/{stage_name}/session-file", response_model=dict)
def get_stage_session_file(task_id: str, attempt_id: str, stage_name: str, path: str = Query(...)) -> dict:
    return get_task_service().get_stage_session_file(task_id, attempt_id, stage_name, path)


@router.get("/tasks/{task_id}/attempts/{attempt_id}/stages/{stage_name}/session-file/stream")
async def stream_stage_session_file(
    request: Request,
    task_id: str,
    attempt_id: str,
    stage_name: str,
    path: str = Query(...),
    cursor: int = Query(default=0, ge=0),
    poll_ms: int = Query(default=1000, ge=200, le=5000),
) -> StreamingResponse:
    normalized, candidate = get_task_service().resolve_stage_session_file_path(task_id, attempt_id, stage_name, path)
    interval = poll_ms / 1000.0

    async def event_stream():
        position = cursor
        pending = b""
        heartbeat_count = 0
        yield _sse(
            "snapshot",
            {
                "path": normalized.as_posix(),
                "exists": candidate.exists(),
                "cursor": candidate.stat().st_size if candidate.exists() and candidate.is_file() else 0,
            },
        )
        while True:
            if await request.is_disconnected():
                break
            if candidate.exists() and candidate.is_file():
                size = candidate.stat().st_size
                if size < position:
                    position = 0
                    pending = b""
                    yield _sse("file_event", {"path": normalized.as_posix(), "event": "truncated", "cursor": 0})
                if size > position:
                    with candidate.open("rb") as handle:
                        handle.seek(position)
                        chunk = handle.read(size - position)
                    from_cursor = position
                    position += len(chunk)
                    if normalized.name.endswith(".jsonl"):
                        pending += chunk
                        lines, pending = _extract_complete_lines(pending)
                        if lines:
                            yield _sse(
                                "delta",
                                {
                                    "path": normalized.as_posix(),
                                    "from_cursor": from_cursor,
                                    "cursor": position - len(pending),
                                    "lines": lines,
                                },
                            )
                    else:
                        yield _sse(
                            "delta",
                            {
                                "path": normalized.as_posix(),
                                "from_cursor": from_cursor,
                                "cursor": position,
                                "text": chunk.decode("utf-8", errors="replace"),
                            },
                        )
            heartbeat_count += 1
            if heartbeat_count >= max(1, int(5000 / poll_ms)):
                heartbeat_count = 0
                yield _sse("heartbeat", {"path": normalized.as_posix(), "cursor": position})
            await asyncio.sleep(interval)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/tasks/{task_id}/attempts/{attempt_id}/artifacts", response_model=ArtifactListResponse)
def list_task_artifacts(task_id: str, attempt_id: str) -> ArtifactListResponse:
    return get_task_service().list_artifacts(task_id, attempt_id)


@router.post("/tasks/{task_id}/cancel", response_model=TaskSummaryResponse)
def cancel_task(task_id: str) -> TaskSummaryResponse:
    return get_task_service().cancel_task(task_id)


@router.post("/tasks/{task_id}/retry", response_model=TaskSummaryResponse)
def retry_task(
    task_id: str,
    payload: TaskRetryRequest,
    subject: Subject = Depends(get_current_subject),
) -> TaskSummaryResponse:
    return get_task_service().retry_task(task_id, payload, subject)


@router.delete("/tasks/{task_id}", response_model=SuccessResponse)
def delete_task(task_id: str, delete_artifacts: bool = Query(default=False)) -> SuccessResponse:
    return get_task_service().delete_task(task_id, delete_artifacts=delete_artifacts)


def _sse(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


def _extract_complete_lines(buffer: bytes) -> tuple[list[str], bytes]:
    if not buffer:
        return [], b""
    parts = buffer.splitlines(keepends=True)
    if parts and not parts[-1].endswith((b"\n", b"\r")):
        pending = parts.pop()
    else:
        pending = b""
    lines = [part.decode("utf-8", errors="replace").rstrip("\r\n") for part in parts if part.strip()]
    return lines, pending
