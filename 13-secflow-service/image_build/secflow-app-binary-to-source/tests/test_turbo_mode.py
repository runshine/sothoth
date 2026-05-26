from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from app.model import B2STask, B2STaskItem
from app.schemas import ElfTaskInput, TaskCreate
from app.service import task_service
from app.service.cache_service import B2SCacheService


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
    def __init__(self):
        self.tasks = []
        self.task_items = []

    def query(self, model, *args, **kwargs):
        del args, kwargs
        if getattr(model, "__name__", "") == "B2STask":
            return _FakeQuery(self.tasks)
        if getattr(model, "__name__", "") == "B2STaskItem":
            return _FakeQuery(self.task_items)
        return _FakeQuery([])

    def add(self, obj):
        if isinstance(obj, B2STask):
            self.tasks.append(obj)
        elif isinstance(obj, B2STaskItem):
            self.task_items.append(obj)

    def flush(self):
        pass

    def commit(self):
        pass

    def refresh(self, obj):
        del obj


class TurboModeTests(unittest.TestCase):
    def test_create_task_turbo_skips_llm_provider_and_freezes_turbo_engine(self):
        db = _FakeDb()
        cache_service = SimpleNamespace(
            try_apply_cache_hit=mock.Mock(return_value=SimpleNamespace(hit=False)),
            prepare_cache_metadata=mock.Mock(),
            store_success_cache=mock.Mock(return_value=False),
            delete_caches_for_source_task=mock.Mock(),
        )
        req = TaskCreate(
            task_id="turbo-task",
            name="turbo-demo",
            mode="turbo",
            elf_tasks=[ElfTaskInput(elf_path="/tmp/demo.elf")],
        )

        with (
            mock.patch.object(task_service, "ensure_path_in_project", return_value=Path("/tmp/demo.elf")),
            mock.patch.object(task_service, "prepare_input_file", return_value=Path("/tmp/input/demo.elf")),
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
            mock.patch.object(task_service, "materialize_llm_provider", new=mock.AsyncMock()) as materialize,
        ):
            response = asyncio.run(task_service.create_task(db, "p1", req, "tester"))

        self.assertEqual("turbo-task", response.id)
        self.assertEqual("turbo", response.mode)
        self.assertEqual("极速模式", response.mode_label)
        self.assertEqual("turbo", db.task_items[0].extra_metadata["engine"])
        self.assertEqual("turbo", db.task_items[0].extra_metadata["mode"])
        self.assertFalse(db.task_items[0].extra_metadata["llm_used"])
        self.assertIsNone(db.task_items[0].extra_metadata["llm_provider_key"])
        materialize.assert_not_called()

    def test_task_mode_summary_returns_turbo_label(self):
        item = B2STaskItem(id="i1", task_id="t1", project_id="p1", sequence_no=1, elf_path="/tmp/a", output_dir="/tmp/o", status="pending")
        item.extra_metadata = {"engine": "turbo"}
        self.assertEqual(("turbo", "极速模式"), task_service.task_mode_summary([item]))

    def test_item_engine_accepts_turbo(self):
        item = B2STaskItem(id="i1", task_id="t1", project_id="p1", sequence_no=1, elf_path="/tmp/in", output_dir="/tmp/out", status="pending")
        item.extra_metadata = {"engine": "turbo", "mode": "turbo", "reuse_cache": True}
        self.assertEqual("turbo", task_service._item_engine(item))

    def test_cache_service_supports_turbo_keys(self):
        service = B2SCacheService()
        digest = "a" * 64
        self.assertEqual(f"{digest}_turbo", service.build_cache_key(digest, "turbo"))
        self.assertEqual("turbo", service.cache_mode_from_key(f"{digest}_turbo"))
        self.assertEqual("turbo", service.normalize_cache_mode({"mode": "turbo"}))


if __name__ == "__main__":
    unittest.main()
