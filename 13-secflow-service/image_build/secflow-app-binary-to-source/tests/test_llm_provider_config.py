from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from app.api import tasks as tasks_api
from app.model import B2SProjectConfig, B2STask, B2STaskItem
from app.schemas import ElfTaskInput, TaskCreate
from app.service import llm_provider
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
    def __init__(self, *, project_configs=None, tasks=None, task_items=None, refresh_hook=None):
        self.project_configs = list(project_configs or [])
        self.tasks = list(tasks or [])
        self.task_items = list(task_items or [])
        self.refresh_hook = refresh_hook

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
        if self.refresh_hook is not None:
            self.refresh_hook(obj)


class _FakePiClient:
    def __init__(self, response=None):
        self.payloads = []
        self.response = response

    async def create_job(self, payload):
        self.payloads.append(payload)
        if self.response is not None:
            return self.response
        return {"id": "job-1", "status": "queued", "phase": "queued", "progress": {}}


class ConfigServiceTests(unittest.TestCase):
    def test_get_config_roundtrip_preserves_llm_provider_key(self):
        service = ConfigService()
        row = B2SProjectConfig(project_id="p1")
        row.config = {
            "budget_exhausted_action": "treat_as_failed",
            "concurrency": 12,
            "llm_provider_key": "team_codex",
        }
        db = _FakeDb(project_configs=[row])

        result = service.get_config(db, "p1")

        self.assertEqual(12, result["concurrency"])
        self.assertEqual("team_codex", result["llm_provider_key"])
        self.assertEqual("treat_as_failed", result["budget_exhausted_action"])

    def test_get_config_defaults_concurrency_to_eight(self):
        service = ConfigService()
        db = _FakeDb()

        result = service.get_config(db, "p1")

        self.assertEqual(8, result["concurrency"])
        self.assertEqual("turbo", result["default_mode"])

    def test_save_config_normalizes_default_mode(self):
        service = ConfigService()
        db = _FakeDb()

        saved = service.save_config(db, "p1", {"default_mode": "agent"})

        self.assertEqual("deep", saved["default_mode"])

    def test_save_config_normalizes_concurrency_range(self):
        service = ConfigService()
        db = _FakeDb()

        saved = service.save_config(db, "p1", {"concurrency": 99})

        self.assertEqual(16, saved["concurrency"])

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
        row = B2SProjectConfig(project_id="p1")
        row.config = {"default_mode": "fast"}
        db = _FakeDb(project_configs=[row])
        fake_pi = _FakePiClient()
        cache_service = SimpleNamespace(
            try_apply_cache_hit=mock.Mock(return_value=SimpleNamespace(hit=False)),
            prepare_cache_metadata=mock.Mock(),
            store_success_cache=mock.Mock(return_value=False),
            delete_caches_for_source_task=mock.Mock(),
        )
        req = TaskCreate(
            task_id="task1",
            name="demo",
            elf_tasks=[ElfTaskInput(elf_path="/tmp/demo.elf")],
        )

        with (
            mock.patch.object(task_service, "ensure_path_in_project", return_value=Path("/tmp/demo.elf")),
            mock.patch.object(task_service, "prepare_input_file", return_value=Path("/tmp/input/demo.elf")),
            mock.patch.object(task_service, "is_ida_supported_input", return_value=True),
            mock.patch.object(task_service, "safe_output_dir", return_value=Path("/tmp/output")),
            mock.patch.object(task_service, "_project_default_llm_provider_key", return_value="team_codex"),
            mock.patch.object(
                task_service,
                "get_cache_service",
                return_value=cache_service,
            ),
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
        self.assertEqual([], fake_pi.payloads)
        self.assertEqual("pending", db.task_items[0].status)
        self.assertEqual("pending", db.task_items[0].dispatch_status)
        self.assertTrue(db.task_items[0].extra_metadata["pi_idempotency_key"].startswith("b2s:task1:"))
        self.assertTrue(db.task_items[0].extra_metadata["pi_idempotency_key"].endswith(":/tmp/input/demo.elf"))
        self.assertEqual("team_codex", db.task_items[0].extra_metadata["llm_provider_key"])
        self.assertEqual("gpt-5.4", db.task_items[0].extra_metadata["llm_provider_model"])
        self.assertEqual(8, db.task_items[0].extra_metadata["concurrency"])
        self.assertTrue(db.task_items[0].extra_metadata["reuse_cache"])
        cache_service.try_apply_cache_hit.assert_called_once()
        cache_service.prepare_cache_metadata.assert_not_called()

    def test_create_task_uses_project_default_mode_when_request_missing(self):
        row = B2SProjectConfig(project_id="p1")
        row.config = {"default_mode": "turbo"}
        db = _FakeDb(project_configs=[row])
        cache_service = SimpleNamespace(
            try_apply_cache_hit=mock.Mock(return_value=SimpleNamespace(hit=False)),
            prepare_cache_metadata=mock.Mock(),
            store_success_cache=mock.Mock(return_value=False),
            delete_caches_for_source_task=mock.Mock(),
        )
        req = TaskCreate(
            task_id="task-project-mode",
            name="demo-project-mode",
            elf_tasks=[ElfTaskInput(elf_path="/tmp/demo.elf")],
        )

        with (
            mock.patch.object(task_service, "ensure_path_in_project", return_value=Path("/tmp/demo.elf")),
            mock.patch.object(task_service, "prepare_input_file", return_value=Path("/tmp/input/demo.elf")),
            mock.patch.object(task_service, "is_ida_supported_input", return_value=True),
            mock.patch.object(task_service, "safe_output_dir", return_value=Path("/tmp/output")),
            mock.patch.object(task_service, "_project_default_llm_provider_key", return_value=None),
            mock.patch.object(task_service, "get_cache_service", return_value=cache_service),
            mock.patch.object(
                task_service,
                "get_config",
                return_value=SimpleNamespace(
                    pi_re_agent=SimpleNamespace(
                        batch_size=8192,
                        max_retries=3,
                        concurrency=8,
                        agent_run_timeout_seconds=3600,
                        agent_timeout_retry_enabled=True,
                        agent_timeout_max_retries=3,
                        engine="hybrid",
                        model=None,
                    ),
                    configcenter_service=SimpleNamespace(enabled=False),
                ),
            ),
        ):
            asyncio.run(task_service.create_task(db, "p1", req, "tester"))

        self.assertEqual("turbo", db.task_items[0].extra_metadata["mode"])
        self.assertEqual("turbo", db.task_items[0].extra_metadata["engine"])
        self.assertFalse(db.task_items[0].extra_metadata["llm_used"])

    def test_create_task_request_mode_overrides_project_default_mode(self):
        row = B2SProjectConfig(project_id="p1")
        row.config = {"default_mode": "turbo"}
        db = _FakeDb(project_configs=[row])
        cache_service = SimpleNamespace(
            try_apply_cache_hit=mock.Mock(return_value=SimpleNamespace(hit=False)),
            prepare_cache_metadata=mock.Mock(),
            store_success_cache=mock.Mock(return_value=False),
            delete_caches_for_source_task=mock.Mock(),
        )
        req = TaskCreate(
            task_id="task-request-mode",
            name="demo-request-mode",
            mode="deep",
            elf_tasks=[ElfTaskInput(elf_path="/tmp/demo.elf")],
        )

        with (
            mock.patch.object(task_service, "ensure_path_in_project", return_value=Path("/tmp/demo.elf")),
            mock.patch.object(task_service, "prepare_input_file", return_value=Path("/tmp/input/demo.elf")),
            mock.patch.object(task_service, "is_ida_supported_input", return_value=True),
            mock.patch.object(task_service, "safe_output_dir", return_value=Path("/tmp/output")),
            mock.patch.object(task_service, "_project_default_llm_provider_key", return_value="team_codex"),
            mock.patch.object(task_service, "get_cache_service", return_value=cache_service),
            mock.patch.object(
                task_service,
                "get_config",
                return_value=SimpleNamespace(
                    pi_re_agent=SimpleNamespace(
                        batch_size=8192,
                        max_retries=3,
                        concurrency=8,
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
                return_value={"provider_key": "team_codex", "model": "gpt-5.4"},
            ),
        ):
            asyncio.run(task_service.create_task(db, "p1", req, "tester"))

        self.assertEqual("deep", db.task_items[0].extra_metadata["mode"])
        self.assertEqual("agent", db.task_items[0].extra_metadata["engine"])
        self.assertTrue(db.task_items[0].extra_metadata["llm_used"])

    def test_create_task_uses_project_default_concurrency_when_request_missing(self):
        row = B2SProjectConfig(project_id="p1")
        row.config = {"concurrency": 10}
        db = _FakeDb(project_configs=[row])
        cache_service = SimpleNamespace(
            try_apply_cache_hit=mock.Mock(return_value=SimpleNamespace(hit=False)),
            prepare_cache_metadata=mock.Mock(),
            store_success_cache=mock.Mock(return_value=False),
            delete_caches_for_source_task=mock.Mock(),
        )
        req = TaskCreate(
            task_id="task-project-concurrency",
            name="demo-project-concurrency",
            elf_tasks=[ElfTaskInput(elf_path="/tmp/demo.elf")],
        )

        with (
            mock.patch.object(task_service, "ensure_path_in_project", return_value=Path("/tmp/demo.elf")),
            mock.patch.object(task_service, "prepare_input_file", return_value=Path("/tmp/input/demo.elf")),
            mock.patch.object(task_service, "is_ida_supported_input", return_value=True),
            mock.patch.object(task_service, "safe_output_dir", return_value=Path("/tmp/output")),
            mock.patch.object(task_service, "_project_default_llm_provider_key", return_value="team_codex"),
            mock.patch.object(task_service, "get_cache_service", return_value=cache_service),
            mock.patch.object(
                task_service,
                "get_config",
                return_value=SimpleNamespace(
                    pi_re_agent=SimpleNamespace(
                        batch_size=8192,
                        max_retries=3,
                        concurrency=8,
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
            asyncio.run(task_service.create_task(db, "p1", req, "tester"))

        self.assertEqual(10, db.task_items[0].extra_metadata["concurrency"])

    def test_create_task_request_concurrency_overrides_project_default(self):
        row = B2SProjectConfig(project_id="p1")
        row.config = {"concurrency": 10}
        db = _FakeDb(project_configs=[row])
        cache_service = SimpleNamespace(
            try_apply_cache_hit=mock.Mock(return_value=SimpleNamespace(hit=False)),
            prepare_cache_metadata=mock.Mock(),
            store_success_cache=mock.Mock(return_value=False),
            delete_caches_for_source_task=mock.Mock(),
        )
        req = TaskCreate(
            task_id="task-request-concurrency",
            name="demo-request-concurrency",
            concurrency=12,
            elf_tasks=[ElfTaskInput(elf_path="/tmp/demo.elf")],
        )

        with (
            mock.patch.object(task_service, "ensure_path_in_project", return_value=Path("/tmp/demo.elf")),
            mock.patch.object(task_service, "prepare_input_file", return_value=Path("/tmp/input/demo.elf")),
            mock.patch.object(task_service, "is_ida_supported_input", return_value=True),
            mock.patch.object(task_service, "safe_output_dir", return_value=Path("/tmp/output")),
            mock.patch.object(task_service, "_project_default_llm_provider_key", return_value="team_codex"),
            mock.patch.object(task_service, "get_cache_service", return_value=cache_service),
            mock.patch.object(
                task_service,
                "get_config",
                return_value=SimpleNamespace(
                    pi_re_agent=SimpleNamespace(
                        batch_size=8192,
                        max_retries=3,
                        concurrency=8,
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
            asyncio.run(task_service.create_task(db, "p1", req, "tester"))

        self.assertEqual(12, db.task_items[0].extra_metadata["concurrency"])

    def test_create_task_without_reuse_cache_skips_hit_lookup_and_freezes_flag(self):
        db = _FakeDb()
        cache_service = SimpleNamespace(
            try_apply_cache_hit=mock.Mock(return_value=SimpleNamespace(hit=False)),
            prepare_cache_metadata=mock.Mock(),
            store_success_cache=mock.Mock(return_value=False),
            delete_caches_for_source_task=mock.Mock(),
        )
        req = TaskCreate(
            task_id="task2",
            name="demo-no-cache",
            reuse_cache=False,
            elf_tasks=[ElfTaskInput(elf_path="/tmp/demo.elf")],
        )

        with (
            mock.patch.object(task_service, "ensure_path_in_project", return_value=Path("/tmp/demo.elf")),
            mock.patch.object(task_service, "prepare_input_file", return_value=Path("/tmp/input/demo.elf")),
            mock.patch.object(task_service, "is_ida_supported_input", return_value=True),
            mock.patch.object(task_service, "safe_output_dir", return_value=Path("/tmp/output")),
            mock.patch.object(task_service, "_project_default_llm_provider_key", return_value="team_codex"),
            mock.patch.object(task_service, "get_cache_service", return_value=cache_service),
            mock.patch.object(task_service, "get_observability", return_value=SimpleNamespace(
                record_cache_request=mock.Mock(),
                record_cache_bypassed=mock.Mock(),
                record_task_created=mock.Mock(),
            )),
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
                    configcenter_service=SimpleNamespace(enabled=False),
                ),
            ),
        ):
            response = asyncio.run(task_service.create_task(db, "p1", req, "tester"))

        self.assertEqual("task2", response.id)
        self.assertFalse(db.task_items[0].extra_metadata["reuse_cache"])
        cache_service.try_apply_cache_hit.assert_not_called()
        cache_service.prepare_cache_metadata.assert_called_once()

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

        self.assertEqual([], fake_pi.payloads)
        self.assertEqual("pending", item.status)
        self.assertEqual("pending", item.dispatch_status)
        self.assertRegex(item.extra_metadata["pi_idempotency_key"], r"^b2s:task1:item1:/tmp/demo\.elf:attempt:[0-9a-f]{8}$")
        self.assertTrue(item.extra_metadata["dispatch_clean"])
        self.assertEqual("team_codex", item.extra_metadata["llm_provider_key"])
        self.assertEqual("gpt-5.4", item.extra_metadata["llm_provider_model"])


class SyncTaskStaleObservationTests(unittest.TestCase):
    def test_sync_task_does_not_overwrite_item_reset_by_rerun(self):
        task = B2STask(
            id="task1",
            project_id="p1",
            task_origin_type="manual",
            name="demo",
            status="running",
        )
        item = B2STaskItem(
            id="item1",
            task_id="task1",
            project_id="p1",
            sequence_no=1,
            elf_path="/tmp/demo.elf",
            output_dir="/tmp/output",
            status="running",
        )
        item.pi_job_id = "job-old"
        item.phase = "header"
        item.extra_metadata = {
            "pi_worker_url": "http://pi",
            "pi_endpoint_url": "http://pi",
            "pi_last_seen_status": "running",
        }

        def _refresh(obj):
            if obj is item:
                obj.pi_job_id = None
                obj.status = "pending"
                obj.dispatch_status = "pending"
                obj.phase = "queued"
                obj.failure_type = None
                obj.error_reason = None
                obj.extra_metadata = {"dispatch_clean": True}

        db = _FakeDb(tasks=[task], task_items=[item], refresh_hook=_refresh)
        fake_pi_client = SimpleNamespace(
            get_job=mock.AsyncMock(return_value={
                "id": "job-old",
                "status": "failed",
                "phase": "header_synthesis",
                "error": "stale failure should be ignored",
                "progress": {},
            })
        )

        with mock.patch.object(task_service, "get_pi_client", return_value=fake_pi_client):
            asyncio.run(task_service.sync_task(db, task))

        self.assertIsNone(item.pi_job_id)
        self.assertEqual("pending", item.status)
        self.assertEqual("queued", item.phase)
        self.assertIsNone(item.failure_type)
        self.assertIsNone(item.error_reason)
        fake_pi_client.get_job.assert_awaited_once_with("job-old")

    def test_sync_task_requeues_stale_cancelling_pi_job_with_fresh_idempotency_key(self):
        task = B2STask(
            id="task1",
            project_id="p1",
            task_origin_type="manual",
            name="demo",
            status="running",
        )
        item = B2STaskItem(
            id="item1",
            task_id="task1",
            project_id="p1",
            sequence_no=1,
            elf_path="/tmp/demo.elf",
            output_dir="/tmp/output",
            status="running",
        )
        item.pi_job_id = "job-stuck"
        item.phase = "body"
        item.extra_metadata = {"pi_worker_url": "http://pi"}
        db = _FakeDb(tasks=[task], task_items=[item])
        fake_pi_client = SimpleNamespace(
            get_job=mock.AsyncMock(return_value={
                "id": "job-stuck",
                "status": "cancelling",
                "cancel_requested_at": "2026-05-18T07:00:00Z",
                "updated_at": "2026-05-18T07:00:00Z",
                "progress": {},
            }),
            cancel_job=mock.AsyncMock(return_value={"status": "ok"}),
        )

        with (
            mock.patch.object(task_service, "get_pi_client", return_value=fake_pi_client),
            mock.patch.object(task_service, "now_local", return_value=task_service.datetime(2026, 5, 18, 15, 10, 0)),
            mock.patch.object(
                task_service,
                "get_config",
                return_value=SimpleNamespace(pi_re_agent=SimpleNamespace(cancelling_stale_after_seconds=300, queued_stale_after_seconds=1800)),
            ),
        ):
            asyncio.run(task_service.sync_task(db, task))

        self.assertIsNone(item.pi_job_id)
        self.assertEqual("pending", item.status)
        self.assertEqual("pending", item.dispatch_status)
        self.assertEqual("queued", item.phase)
        self.assertRegex(item.extra_metadata["pi_idempotency_key"], r"^b2s:task1:item1:/tmp/demo\.elf:attempt:[0-9a-f]{8}$")
        self.assertEqual("stale_cancelling_requeued", item.extra_metadata["pi_recover_reason"])
        fake_pi_client.cancel_job.assert_awaited_once_with("job-stuck")

    def test_retry_stopped_task_uses_latest_project_provider_not_frozen_provider(self):
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
        item.extra_metadata = {
            "concurrency": 2,
            "llm_provider_key": "old_provider",
            "llm_provider_model": "old-model",
        }
        db = _FakeDb(tasks=[task], task_items=[item])

        with (
            mock.patch.object(task_service, "_project_default_llm_provider_key", return_value="new_provider"),
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
                    "provider_key": "new_provider",
                    "display_name": "New Provider",
                    "provider_type": "openai",
                    "model": "new-model",
                },
            ) as mocked_materialize,
        ):
            asyncio.run(task_service.retry_task(db, task, ["item1"]))

        mocked_materialize.assert_awaited_once_with("new_provider")
        self.assertEqual("new_provider", item.extra_metadata["llm_provider_key"])
        self.assertEqual("new-model", item.extra_metadata["llm_provider_model"])

    def test_retry_running_task_keeps_frozen_provider(self):
        task = B2STask(
            id="task1",
            project_id="p1",
            task_origin_type="manual",
            name="demo",
            status="running",
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
        item.extra_metadata = {
            "concurrency": 2,
            "llm_provider_key": "old_provider",
            "llm_provider_model": "old-model",
        }
        db = _FakeDb(tasks=[task], task_items=[item])

        with (
            mock.patch.object(task_service, "_project_default_llm_provider_key", return_value="new_provider"),
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
                    "provider_key": "old_provider",
                    "display_name": "Old Provider",
                    "provider_type": "openai",
                    "model": "old-model",
                },
            ) as mocked_materialize,
        ):
            asyncio.run(task_service.retry_task(db, task, ["item1"]))

        mocked_materialize.assert_awaited_once_with("old_provider")
        self.assertEqual("old_provider", item.extra_metadata["llm_provider_key"])
        self.assertEqual("old-model", item.extra_metadata["llm_provider_model"])

    def test_dispatch_item_reuses_existing_pi_job_conflict(self):
        db = _FakeDb()
        fake_pi = _FakePiClient(response={
            "_conflict": True,
            "existing_job": {
                "id": "job-existing",
                "target": "/tmp/input/demo.elf",
                "status": "running",
                "phase": "processing",
                "progress": {},
            },
        })
        item = B2STaskItem(
            id="item1",
            task_id="task1",
            project_id="p1",
            sequence_no=1,
            elf_path="/tmp/input/demo.elf",
            output_dir="/tmp/output",
            status="pending",
        )
        item.extra_metadata = {"concurrency": 4, "engine": "hybrid", "llm_provider_model": "team_codex/gpt-5.4"}
        db.task_items.append(item)

        with (
            mock.patch.object(task_service, "choose_pi_worker", return_value="http://pi-worker"),
            mock.patch.object(task_service, "get_pi_client", return_value=fake_pi),
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
                    configcenter_service=SimpleNamespace(enabled=False),
                ),
            ),
        ):
            asyncio.run(task_service.dispatch_item_to_pi(db, item, owner_id="test-owner"))

        self.assertEqual("job-existing", item.pi_job_id)
        self.assertEqual("running", item.status)
        self.assertEqual("reuse_active_target_job", item.extra_metadata["pi_recover_reason"])
        self.assertEqual("dispatched", item.dispatch_status)
        self.assertEqual("team_codex/gpt-5.4", fake_pi.payloads[0]["model"])
        self.assertEqual("b2s:task1:item1:/tmp/input/demo.elf", fake_pi.payloads[0]["idempotency_key"])
        self.assertEqual(4, fake_pi.payloads[0]["concurrency"])

    def test_dispatch_item_always_qualifies_provider_model_with_slashes(self):
        db = _FakeDb()
        fake_pi = _FakePiClient()
        item = B2STaskItem(
            id="item1",
            task_id="task1",
            project_id="p1",
            sequence_no=1,
            elf_path="/tmp/input/demo.elf",
            output_dir="/tmp/output",
            status="pending",
        )
        item.extra_metadata = {
            "concurrency": 4,
            "engine": "hybrid",
            "llm_provider_key": "local_minimax",
            "llm_provider_model": "MiniMax/MiniMax-M2.5",
        }
        db.task_items.append(item)

        with (
            mock.patch.object(task_service, "choose_pi_worker", return_value="http://pi-worker"),
            mock.patch.object(task_service, "get_pi_client", return_value=fake_pi),
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
                    configcenter_service=SimpleNamespace(enabled=False),
                ),
            ),
        ):
            asyncio.run(task_service.dispatch_item_to_pi(db, item, owner_id="test-owner"))

        self.assertEqual("local_minimax/MiniMax/MiniMax-M2.5", fake_pi.payloads[0]["model"])


class LlmProviderFileWriteTests(unittest.TestCase):
    def test_write_json_uses_unique_temp_files_under_concurrent_writes(self):
        target = Path(self._testMethodName).with_suffix(".json")
        try:
            with ThreadPoolExecutor(max_workers=8) as executor:
                list(executor.map(lambda index: llm_provider._write_json(target, {"index": index}), range(40)))

            self.assertTrue(target.exists())
            self.assertIsInstance(target.read_text(encoding="utf-8"), str)
            self.assertEqual([], list(target.parent.glob(f".{target.name}.*.tmp")))
        finally:
            target.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
