from __future__ import annotations

from typing import Any


class ExecutionCancelledError(Exception):
    pass


class ExecutionObserver:
    async def check_cancel(self, checkpoint: str, **payload: Any) -> None:
        return None

    async def on_stage_started(self, **payload: Any) -> None:
        return None

    async def on_stage_completed(self, **payload: Any) -> None:
        return None

    async def on_stage_failed(self, **payload: Any) -> None:
        return None

    async def on_cycle_started(self, **payload: Any) -> None:
        return None

    async def on_cycle_completed(self, **payload: Any) -> None:
        return None

    async def on_summary_completed(self, **payload: Any) -> None:
        return None

    async def on_workflow_abnormal_exit(self, **payload: Any) -> None:
        return None


class NullExecutionObserver(ExecutionObserver):
    pass
