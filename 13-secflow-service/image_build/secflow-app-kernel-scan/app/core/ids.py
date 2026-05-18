from __future__ import annotations

import uuid


def new_task_id() -> str:
    return f"kscan-task-{uuid.uuid4().hex[:12]}"


def new_attempt_id() -> str:
    return f"kscan-att-{uuid.uuid4().hex[:12]}"


def new_stage_run_id() -> str:
    return f"kscan-sr-{uuid.uuid4().hex[:12]}"


def new_event_id() -> str:
    return f"kscan-evt-{uuid.uuid4().hex[:12]}"


def new_artifact_id() -> str:
    return f"kscan-art-{uuid.uuid4().hex[:12]}"
