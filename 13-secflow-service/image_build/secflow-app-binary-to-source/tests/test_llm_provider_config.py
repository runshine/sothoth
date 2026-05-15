from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from app.api import tasks as tasks_api
from app.model import B2SProjectConfig, B2STask, B2STaskItem
from app.schemas import ElfTaskInput, TaskCreate
from app.service import task_service
from app.service.config_service import ConfigService


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *args, **kwargs):
        return self

    def filter_by(self, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def first(self):
        return self._rows[0] if self._rows else None

    def all(self):
        return list(self._rows)


class _FakeDb:
    def __init__(self, *, project_configs=None, tasks=None, task_items=None):
        self.project_configs = list(project_configs or [])
        self.tasks = list(tasks or [])
        self.task_items = list(task_items or [])

    def query(self, model, *args, **kwargs):
        del args, kwargs
        model_name = getattr(model, "__name__", "")
        if model_name == "B2SProjectConfig":
            return _FakeQuery(self.project_configs)
        if model_name == "B2STask":
            return _FakeQuery(self.tasks)
        if model_name == "B2STaskItem":
            return _FakeQuery(self.task_items)
        return _FakeQuery([])

    def add(self, obj):
        if isinstance(obj, B2SProjectConfig):
            self.project_configs.append(obj)
        elif isinstance(obj, B2STask):
            self.tasks.append(obj)
        elif isinstance(obj, B2STaskItem):
            self.task_items.append(obj)

    def flush(self):
        pass

    def commit(self):
        pass

    def refresh(self, obj):
        del obj


class _FakePiClient:
    def __init__(self):
        self.payloads = []

    async def create_job(self, payload):
        self.payloads.append(payload)
        return {"id": "job-1", "status": "queued", "phase": "queued", "progress": {}}


class ConfigServiceTests(unittest.TestCase):
    def test_get_config_roundtrip_preserves_llm_provider_key(self):
        service = ConfigService()
        row = B2SProjectConfig(project_id="p1")
        row.config = {
            "budget_exhausted_action": "treat_as_failed",
            "llm_provider_key": "team_codex",
        }
        db = _FakeDb(project_configs=[row])

        result = service.get_config(db, "p1")

        self.assertEqual("team_codex", result["llm_provider_key"])
        self.assertEqual("treat_as_failed", result["budget_exhausted_action"])

    def test_effective_provider_summary_prefers_selected_provider(self):
        async def _run():
            with mock.patch.object(tasks_api, "get_configcenter_client") as mocked_client:
                mocked_client.return_value.list_llm_providers = mock.AsyncMock(return_value={
                    "default_provider_key": "platform_default",
                    "items": [
                        {
                            "provider_key": "platform_default",
                            "display_name": "Platform Default",
                            "provider_type": "openai",
                            "enabled": True,
                            "is_default": True,
                            "model": "gpt-5.4",
                        },
                        {
                            "provider_key": "team_codex",
                            "display_name": "Team Codex",
                            "provider_type": "openai",
                            "enabled": True,
                            "is_default": False,
                            "model": "gpt-5.5",
                        },
                    ],
                })
                return await tasks_api._effective_llm_provider_summary("team_codex")

        summary = asyncio.run(_run())

        self.assertEqual("team_codex", summary["provider_key"])
        self.assertEqual("gpt-5.5", summary["model"])


class TaskProviderResolutionTests(unittest.TestCase):
    def test_create_task_uses_project_default_provider_and_freezes_metadata(self):
        db = _FakeDb()
        fake_pi = _FakePiClient()
        req = TaskCreate(
            task_id="task1",
            name="demo",
            elf_tasks=[ElfTaskInput(elf_path="/tmp/demo.elf")],
        )

        with (
            mock.patch.object(task_service, "ensure_path_in_project", return_value=Path("/tmp/demo.elf")),
            mock.patch.object(task_service, "prepare_input_file", return_value=Path("/tmp/input/demo.elf")),
            mock.patch.object(task_service, "safe_output_dir", return_value=Path("/tmp/output")),
            mock.patch.object(task_service, "choose_pi_worker", return_value="http://pi-worker"),
            mock.patch.object(task_service, "get_pi_client", return_value=fake_pi),
            mock.patch.object(task_service, "_project_default_llm_provider_key", return_value="team_codex"),
            mock.patch.object(
                task_service,
                "get_config",
                return_value=SimpleNamespace(
                    pi_re_agent=SimpleNamespace(
                        batch_size=8192,
                        max_retries=3,
                        concurrency=4,
                        agent_run_timeout_seconds=3600,
                        agent_timeout_retry_enabled=True,
                        agent_timeout_max_retries=3,
                        engine="hybrid",
                        model=None,
                    ),
                    configcenter_service=SimpleNamespace(enabled=True),
                ),
            ),
            mock.patch.object(
                task_service,
                "materialize_llm_provider",
                return_value={
                    "provider_key": "team_codex",
                    "display_name": "Team Codex",
                    "provider_type": "openai",
                    "model": "gpt-5.4",
                },
            ),
        ):
            response = asyncio.run(task_service.create_task(db, "p1", req, "tester"))

        self.assertEqual("task1", response.id)
        self.assertEqual("team_codex/gpt-5.4", fake_pi.payloads[0]["model"])
        self.assertEqual("team_codex", db.task_items[0].extra_metadata["llm_provider_key"])
        self.assertEqual("gpt-5.4", db.task_items[0].extra_metadata["llm_provider_model"])

    def test_retry_task_backfills_project_default_provider_when_metadata_missing(self):
        task = B2STask(
            id="task1",
            project_id="p1",
            task_origin_type="manual",
            name="demo",
            status="failed",
        )
        item = B2STaskItem(
            id="item1",
            task_id="task1",
            project_id="p1",
            sequence_no=1,
            elf_path="/tmp/demo.elf",
            output_dir="/tmp/output",
            status="failed",
        )
        item.extra_metadata = {"concurrency": 2}
        db = _FakeDb(tasks=[task], task_items=[item])
        fake_pi = _FakePiClient()

        with (
            mock.patch.object(task_service, "choose_pi_worker", return_value="http://pi-worker"),
            mock.patch.object(task_service, "get_pi_client", return_value=fake_pi),
            mock.patch.object(task_service, "_project_default_llm_provider_key", return_value="team_codex"),
            mock.patch.object(
                task_service,
                "get_config",
                return_value=SimpleNamespace(
                    pi_re_agent=SimpleNamespace(
                        batch_size=8192,
                        max_retries=3,
                        concurrency=4,
                        agent_run_timeout_seconds=3600,
                        agent_timeout_retry_enabled=True,
                        agent_timeout_max_retries=3,
                        engine="hybrid",
                        model=None,
                    ),
                    configcenter_service=SimpleNamespace(enabled=True),
                ),
            ),
            mock.patch.object(
                task_service,
                "materialize_llm_provider",
                return_value={
                    "provider_key": "team_codex",
                    "display_name": "Team Codex",
                    "provider_type": "openai",
                    "model": "gpt-5.4",
                },
            ),
        ):
            asyncio.run(task_service.retry_task(db, task, ["item1"]))

        self.assertEqual("team_codex/gpt-5.4", fake_pi.payloads[0]["model"])
        self.assertEqual("team_codex", item.extra_metadata["llm_provider_key"])
        self.assertEqual("gpt-5.4", item.extra_metadata["llm_provider_model"])


if __name__ == "__main__":
    unittest.main()
