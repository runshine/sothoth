from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx

from app.model import EvolutionTask
from app.service.task_service import TaskService


class _FakeQuery:
    def __init__(self, task: EvolutionTask) -> None:
        self._task = task

    def filter(self, *args, **kwargs):
        del args, kwargs
        return self

    def order_by(self, *args, **kwargs):
        del args, kwargs
        return self

    def all(self):
        return []

    def first(self):
        return self._task


class _FakeDb:
    def __init__(self, task: EvolutionTask) -> None:
        self.task = task
        self.added = []
        self.commit_calls = 0

    def query(self, model):
        del model
        return _FakeQuery(self.task)

    def add(self, row):
        self.added.append(row)

    def commit(self):
        self.commit_calls += 1


def test_run_task_defers_on_downstream_transport_error():
    task = EvolutionTask(
        id="evo-1",
        project_id="p1",
        title="demo",
        status="pending",
        created_by="tester",
        preview_payload_json={"project_id": "p1", "requested_case_ids": [], "effective_case_ids": [], "can_create": True, "blocked_reasons": [], "sources": []},
        config_json={"min_rounds": 1, "max_rounds": 1},
    )
    db = _FakeDb(task)
    service = TaskService()
    request = httpx.Request("GET", "http://downstream/tasks/demo")

    with (
        patch.object(service, "_service_authorization", return_value="Bearer token"),
        patch("app.service.task_service.EvolutionPreviewResponse.model_validate", return_value=SimpleNamespace(sources=[])),
        patch.object(service, "_run_round", side_effect=httpx.ConnectError("boom", request=request)),
        patch("app.service.task_service.get_observability"),
    ):
        asyncio.run(service.run_task(db, task.id))

    assert task.status == "pending"
    assert task.last_error is not None
    assert "boom" in task.last_error
    assert "等待调度器自动重试" in str(task.message or "")
