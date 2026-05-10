from __future__ import annotations

from uuid import uuid4


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


def new_task_id() -> str:
    return _new_id("ipc-audit-task")


def new_attempt_id() -> str:
    return _new_id("attempt")


def new_event_id() -> str:
    return _new_id("evt")


def new_artifact_id() -> str:
    return _new_id("artifact")


def new_refresh_job_id() -> str:
    return _new_id("catalog-refresh")

