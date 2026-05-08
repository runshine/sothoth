"""In-memory task manager for heavy filesystem operations."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable
from uuid import uuid4


TaskRunner = Callable[[], Awaitable[dict[str, Any]]]


@dataclass
class TaskState:
    task_id: str
    status: str = "queued"
    progress: float = 0.0
    accepted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    result: dict[str, Any] | None = None
    error: str | None = None


class TaskManager:
    def __init__(self):
        self._tasks: dict[str, TaskState] = {}
        self._lock = asyncio.Lock()

    async def submit(self, runner: TaskRunner) -> TaskState:
        task_id = uuid4().hex
        state = TaskState(task_id=task_id)
        async with self._lock:
            self._tasks[task_id] = state
        asyncio.create_task(self._run(state, runner))
        return state

    async def _run(self, state: TaskState, runner: TaskRunner) -> None:
        state.status = "running"
        try:
            state.result = await runner()
            state.progress = 1.0
            state.status = "succeeded"
        except Exception as exc:
            state.status = "failed"
            state.error = str(exc)
        finally:
            state.finished_at = datetime.now(timezone.utc)

    async def get(self, task_id: str) -> TaskState | None:
        return self._tasks.get(task_id)


_task_manager: TaskManager | None = None


def get_task_manager() -> TaskManager:
    global _task_manager
    if _task_manager is None:
        _task_manager = TaskManager()
    return _task_manager
