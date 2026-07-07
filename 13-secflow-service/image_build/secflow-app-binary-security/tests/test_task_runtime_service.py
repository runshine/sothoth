import asyncio
import json
import inspect
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app.model import (
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    BinarySecurityTaskRuntimeLease,
    TASK_TYPE_BINARY,
    TASK_TYPE_BINARY_MODULE,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager
from app.service.task_runtime_service import TaskRuntimeServiceMixin
from test_task_manager import _ModelAwareDb, _now


class TaskRuntimeServiceStructureTests(unittest.TestCase):
    def test_runtime_mixin_methods_remain_task_manager_entrypoints(self):
        self.assertIs(TaskManager._dispatch_loop, TaskRuntimeServiceMixin._dispatch_loop)
        self.assertIs(TaskManager._active_dispatch_count, TaskRuntimeServiceMixin._active_dispatch_count)
        self.assertIs(TaskManager._reconcile_work_queues, TaskRuntimeServiceMixin._reconcile_work_queues)
        self.assertIs(TaskManager._dispatch_once, TaskRuntimeServiceMixin._dispatch_once)
        self.assertIs(TaskManager._dispatch_task_by_id, TaskRuntimeServiceMixin._dispatch_task_by_id)
        self.assertIs(TaskManager._run_task, TaskRuntimeServiceMixin._run_task)
        self.assertIs(TaskManager._run_stage_item_by_id, TaskRuntimeServiceMixin._run_stage_item_by_id)
        self.assertIs(TaskManager._dispatch_token, TaskRuntimeServiceMixin._dispatch_token)
        self.assertIs(TaskManager._stage_item_dispatch_loop, TaskRuntimeServiceMixin._stage_item_dispatch_loop)
        self.assertIs(TaskManager._claim_streaming_stage_items, TaskRuntimeServiceMixin._claim_streaming_stage_items)
        self.assertIs(TaskManager._run_stage_pool, TaskRuntimeServiceMixin._run_stage_pool)
        self.assertIs(TaskManager._run_entry_item, TaskRuntimeServiceMixin._run_entry_item)
        self.assertIs(TaskManager._run_dataflow_item, TaskRuntimeServiceMixin._run_dataflow_item)
        self.assertIs(TaskManager._run_vuln_item, TaskRuntimeServiceMixin._run_vuln_item)

    def test_runtime_legacy_registry_removed(self):
        self.assertFalse(hasattr(task_manager_module, "_TASK_MANAGER_LEGACY_IMPLS"))

    def test_runtime_entry_item_no_longer_uses_removed_legacy_helper(self):
        source = inspect.getsource(TaskRuntimeServiceMixin)
        self.assertIn("async def _run_entry_item", source)
        self.assertNotIn("_legacy_run_entry_item_impl", source)
        self.assertFalse(hasattr(TaskManager, "_legacy_run_entry_item_impl"))

    def test_runtime_dataflow_item_no_longer_uses_removed_legacy_helper(self):
        source = inspect.getsource(TaskRuntimeServiceMixin)
        self.assertIn("async def _run_dataflow_item", source)
        self.assertNotIn("_legacy_run_dataflow_item_impl", source)
        self.assertFalse(hasattr(TaskManager, "_legacy_run_dataflow_item_impl"))

    def test_runtime_vuln_item_no_longer_uses_removed_legacy_helper(self):
        source = inspect.getsource(TaskRuntimeServiceMixin)
        self.assertIn("async def _run_vuln_item", source)
        self.assertNotIn("_legacy_run_vuln_item_impl", source)
        self.assertFalse(hasattr(TaskManager, "_legacy_run_vuln_item_impl"))

    def test_runtime_b2s_item_no_longer_uses_removed_legacy_helper(self):
        source = inspect.getsource(TaskRuntimeServiceMixin)
        self.assertIn("async def _run_b2s_item", source)
        self.assertNotIn("_legacy_run_b2s_item_impl", source)
        self.assertFalse(hasattr(TaskManager, "_legacy_run_b2s_item_impl"))

    def test_runtime_system_analysis_item_no_longer_uses_removed_legacy_helper(self):
        source = inspect.getsource(TaskRuntimeServiceMixin)
        self.assertIn("async def _run_system_analysis_item", source)
        self.assertNotIn("_legacy_run_system_analysis_item_impl", source)
        self.assertFalse(hasattr(TaskManager, "_legacy_run_system_analysis_item_impl"))

    def test_runtime_firmware_item_no_longer_uses_removed_legacy_helper(self):
        source = inspect.getsource(TaskRuntimeServiceMixin)
        self.assertIn("async def _run_firmware_item", source)
        self.assertNotIn("_legacy_run_firmware_item_impl", source)
        self.assertFalse(hasattr(TaskManager, "_legacy_run_firmware_item_impl"))

    def test_runtime_removed_compatibility_facade_is_not_exposed(self):
        self.assertFalse(hasattr(TaskManager, "_reconcile_stage_and_task_state_after_item_update"))

    def test_runtime_stage_item_dispatch_loop_no_longer_has_task_manager_body_copy(self):
        source = inspect.getsource(TaskRuntimeServiceMixin)
        self.assertIn("async def _stage_item_dispatch_loop", source)


class TaskRuntimeServiceBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_query_with_fast_task_row_lock_falls_back_when_skip_locked_not_supported(self):
        calls = []

        class _FakeQuery:
            def with_for_update(self, **kwargs):
                calls.append(dict(kwargs))
                if kwargs:
                    raise TypeError("unexpected kwargs")
                return "locked-query"

        result = self.manager._query_with_fast_task_row_lock(_FakeQuery())

        self.assertEqual("locked-query", result)
        self.assertEqual([{"skip_locked": True}, {"nowait": True}, {}], calls)

    def _task(self, *, task_type=TASK_TYPE_BINARY, name="task"):
        return BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name=name,
            status="running",
            task_type=task_type,
            current_stage="binary_to_source",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw.bin",
        )

    def _stage_run(self, stage_name: str):
        return BinarySecurityStageRun(
            id=f"sr-{stage_name}",
            task_id="task-1",
            project_id="project-1",
            stage_name=stage_name,
            sequence_no=1,
            status="running",
        )

    def test_claim_streaming_stage_items_marks_pending_item_dispatching(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        now = _now()
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="demo",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="entry_analysis",
            runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/tmp/ws",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming", "stage_parallelism": {"entry_analysis": 1}}),
        )
        item = BinarySecurityStageItem(
            id="si-entry",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr-entry",
            stage_name="entry_analysis",
            item_key="module-1",
            item_name="mod.so",
            parent_key="fw-1",
            item_identity_key="module-1::fw-1",
            status="pending",
            downstream_service="entry_analyse",
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=int(getattr(task, "execution_epoch", 0) or 0),
            owner_instance_id=self.manager.instance_id,
            owner_started_at=now,
            heartbeat_at=now,
            lease_expires_at=now + timedelta(seconds=300),
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[item], runtime_leases=[runtime_lease])

        claimed = self.manager._claim_streaming_stage_items(db)

        self.assertEqual({"t1": ["si-entry"]}, claimed)
        self.assertEqual("dispatching", item.status)

    def test_run_b2s_item_success_keeps_entry_descriptor_contract_compatible(self):
        task = self._task(task_type=TASK_TYPE_BINARY_MODULE, name="b2s-task")
        stage_run = self._stage_run("binary_to_source")
        item = BinarySecurityStageItem(
            id="item-b2s",
            task_id=task.id,
            project_id=task.project_id,
            stage_name=stage_run.stage_name,
            item_key="module-1",
            item_name="security_policy",
            parent_key="fw-1",
            status="queued",
            downstream_service="binary_to_source",
        )
        fake_session = _ModelAwareDb(stage_items=[item])
        with tempfile.TemporaryDirectory() as tmpdir:
            descriptor_root = Path(tmpdir)
            module_dir = descriptor_root / "modules" / "security_policy"
            module_dir.mkdir(parents=True, exist_ok=True)
            files_list = module_dir / "files.list"
            source_file = descriptor_root / "policy.c"
            source_file.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            files_list.write_text("policy.c\n", encoding="utf-8")

            module = {
                "module_key": "module-1",
                "module_name": "security_policy",
                "firmware_key": "fw-1",
                "entry_module_name": "security_policy",
                "entry_descriptor_root": str(descriptor_root),
                "entry_files_list": str(files_list),
                "entry_descriptor_ready": True,
                "source_dir": str(descriptor_root),
                "source_root": str(descriptor_root),
                "module_dir": str(module_dir),
                "files_list": str(files_list),
                "files_list_path": str(files_list),
            }

            with (
                patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
                patch.object(self.manager, "_upsert_stage_item", return_value=item),
                patch.object(
                    self.manager,
                    "_build_module_elf_tasks",
                    return_value=[{"path": "/tmp/bin/module.elf"}],
                    create=True,
                ),
                patch.object(self.manager, "_active_downstream_payload", new=AsyncMock(return_value=None)),
                patch.object(self.manager, "_b2s_execution_mode", return_value=("default", "ghidra")),
                patch.object(
                    self.manager,
                    "_defer_item_to_sync_maintenance_child_create",
                    new=AsyncMock(
                        return_value={
                            "status": "queued",
                            "item": dict(module),
                            "deferred_mode": "sync_maintenance_create",
                        }
                    ),
                ),
            ):
                result = asyncio.run(self.manager._run_b2s_item(task, stage_run, module, token="tok"))

        self.assertEqual("queued", result["status"])
        self.assertEqual("sync_maintenance_create", result["deferred_mode"])
        self.assertEqual(str(descriptor_root), result["item"]["entry_descriptor_root"])
        self.assertEqual(str(files_list), result["item"]["entry_files_list"])
        self.assertEqual(str(files_list), result["item"]["files_list_path"])
        self.assertEqual(str(descriptor_root), result["item"]["source_root"])
        self.assertEqual(str(module_dir), result["item"]["module_dir"])

    def test_run_b2s_item_returns_archive_blocked_without_reintroducing_legacy_path(self):
        task = self._task(task_type=TASK_TYPE_BINARY, name="b2s-archive")
        stage_run = self._stage_run("binary_to_source")
        item = BinarySecurityStageItem(
            id="item-b2s-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name=stage_run.stage_name,
            item_key="module-1",
            item_name="security_policy",
            parent_key="fw-1",
            status="queued",
            downstream_service="binary_to_source",
        )
        fake_session = _ModelAwareDb(stage_items=[item])
        module = {
            "module_key": "module-1",
            "module_name": "security_policy",
            "firmware_key": "fw-1",
            "source_dir": "/tmp/src",
            "source_root": "/tmp/src",
            "module_dir": "/tmp/src",
        }

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(
                self.manager,
                "_build_module_elf_tasks",
                return_value=[{"path": "/tmp/bin/module.elf"}],
                create=True,
            ),
            patch.object(self.manager, "_active_downstream_payload", new=AsyncMock(return_value=None)),
            patch.object(self.manager, "_b2s_execution_mode", return_value=("default", "ghidra")),
            patch.object(
                self.manager,
                "_defer_item_to_sync_maintenance_child_create",
                new=AsyncMock(
                    return_value={
                        "status": "queued",
                        "item": module,
                        "deferred_mode": "sync_maintenance_create",
                    }
                ),
            ),
        ):
            result = asyncio.run(self.manager._run_b2s_item(task, stage_run, module, token="tok"))

        self.assertEqual("queued", result["status"])
        self.assertEqual("sync_maintenance_create", result["deferred_mode"])

    def test_run_system_analysis_item_retry_adopts_active_child_and_persists_success_projection(self):
        task = self._task(task_type=TASK_TYPE_BINARY, name="system-task")
        task.current_stage = "system_analysis"
        stage_run = self._stage_run("system_analysis")
        item = BinarySecurityStageItem(
            id="item-system",
            task_id=task.id,
            project_id=task.project_id,
            stage_name=stage_run.stage_name,
            item_key="fw-1",
            item_name="firmware.bin",
            parent_key="fw-1",
            status="failed",
            downstream_service="system_analyse",
            downstream_task_id="sa-old",
        )
        fake_session = _ModelAwareDb(stage_items=[item])
        firmware = {
            "firmware_key": "fw-1",
            "firmware_name": "firmware",
            "filename": "firmware.bin",
            "unpacked_root": "/tmp/unpacked",
            "source_root": "/tmp/unpacked",
            "task_type": TASK_TYPE_BINARY,
        }

        async def _fake_poll(*args, **kwargs):
            del args, kwargs
            return "success", {"task_id": "sa-child", "status": "passed"}

        with tempfile.TemporaryDirectory() as tmpdir:
            archive_root = Path(tmpdir)
            with (
                patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
                patch.object(self.manager, "_upsert_stage_item", return_value=item),
                patch.object(self.manager, "_active_downstream_payload", new=AsyncMock(return_value=None)),
                patch.object(
                    self.manager,
                    "_classify_retry_downstream_strategy",
                    return_value=(task_manager_module.RETRY_CHILD_STRATEGY_ADOPT_ACTIVE, "running"),
                ),
                patch.object(
                    self.manager,
                    "_prepare_retry_child_for_reuse_or_recreate",
                    new=AsyncMock(return_value={"strategy": "adopt_active"}),
                ),
                patch.object(self.manager, "_store_retry_item_action"),
                patch.object(self.manager, "_has_retryable_downstream_task", return_value=True),
                patch.object(
                    self.manager,
                    "_downstream_control_existing_task",
                    new=AsyncMock(return_value={"outcome": "already_running", "payload": {"task_id": "sa-child", "status": "running"}}),
                ) as control_mock,
                patch.object(self.manager, "_downstream_create_task", new=AsyncMock(side_effect=AssertionError("should reuse active child"))),
                patch.object(self.manager, "_poll_until_terminal", side_effect=_fake_poll),
                patch.object(self.manager, "_downstream_fetch_item_result", new=AsyncMock(return_value={"summary": "ok"})),
                patch.object(self.manager, "_queue_archive_and_wait", new=AsyncMock(return_value=(archive_root, None))),
                patch.object(self.manager, "_parse_system_analysis_modules", return_value=[{"module_key": "m1", "risk_level": "高"}]),
            ):
                result = asyncio.run(self.manager._run_system_analysis_item(task, stage_run, firmware, retrying=True))

        self.assertEqual("running", result["status"])
        self.assertEqual("running", item.status)
        self.assertEqual("sa-old", item.downstream_task_id)
        self.assertEqual("fw-1", result["item"]["firmware_key"])
        control_mock.assert_not_awaited()

    def test_run_system_analysis_item_returns_archive_blocked_after_authoritative_success_payload(self):
        task = self._task(task_type=TASK_TYPE_BINARY, name="system-archive")
        task.current_stage = "system_analysis"
        stage_run = self._stage_run("system_analysis")
        item = BinarySecurityStageItem(
            id="item-system-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name=stage_run.stage_name,
            item_key="fw-1",
            item_name="firmware.bin",
            parent_key="fw-1",
            status="queued",
            downstream_service="system_analyse",
        )
        fake_session = _ModelAwareDb(stage_items=[item])
        firmware = {
            "firmware_key": "fw-1",
            "firmware_name": "firmware",
            "filename": "firmware.bin",
            "unpacked_root": "/tmp/unpacked",
            "source_root": "/tmp/unpacked",
            "task_type": TASK_TYPE_BINARY,
        }

        async def _fake_poll(*args, **kwargs):
            del args, kwargs
            return "success", {"task_id": "sa-child", "status": "passed"}

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(self.manager, "_active_downstream_payload", new=AsyncMock(return_value=None)),
            patch.object(self.manager, "_downstream_create_task", new=AsyncMock(return_value={"task_id": "sa-child", "status": "pending"})),
            patch.object(self.manager, "_replace_active_child_binding", new=AsyncMock(return_value=None)),
            patch.object(self.manager, "_poll_until_terminal", side_effect=_fake_poll),
            patch.object(self.manager, "_downstream_fetch_item_result", new=AsyncMock(return_value={"summary": "ok"})),
            patch.object(
                self.manager,
                "_queue_archive_and_wait",
                new=AsyncMock(return_value=(None, SimpleNamespace(error_message="archive blocked"))),
            ),
        ):
            result = asyncio.run(self.manager._run_system_analysis_item(task, stage_run, firmware))

        self.assertEqual("archive_blocked", result["status"])
        self.assertTrue(result["archive_blocked"])
        self.assertEqual("archive blocked", result["error"])
        self.assertEqual("archive blocked", item.error_message)

    def test_run_firmware_item_retry_adopts_active_child_and_preserves_downstream_input_shape(self):
        task = self._task(task_type=TASK_TYPE_BINARY, name="firmware-task")
        task.current_stage = "firmware_unpack"
        stage_run = self._stage_run("firmware_unpack")
        item = BinarySecurityStageItem(
            id="item-fw",
            task_id=task.id,
            project_id=task.project_id,
            stage_name=stage_run.stage_name,
            item_key="fw-1",
            item_name="firmware.bin",
            parent_key="fw-1",
            status="failed",
            downstream_service="firmware_unpacker",
            downstream_task_id="fw-old",
            output_ref={},
        )
        fake_session = _ModelAwareDb(stage_items=[item])
        input_file = {"firmware_key": "fw-1", "filename": "firmware.bin", "firmware_name": "firmware"}

        async def _fake_poll(*args, **kwargs):
            del args, kwargs
            return "success", {"task_id": "fw-child", "status": "success"}

        with tempfile.TemporaryDirectory() as tmpdir:
            archive_root = Path(tmpdir)
            with (
                patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
                patch.object(self.manager, "_upsert_stage_item", return_value=item),
                patch.object(self.manager, "_active_downstream_payload", new=AsyncMock(return_value=None)),
                patch.object(
                    self.manager,
                    "_classify_retry_downstream_strategy",
                    return_value=(task_manager_module.RETRY_CHILD_STRATEGY_ADOPT_ACTIVE, "running"),
                ),
                patch.object(
                    self.manager,
                    "_prepare_retry_child_for_reuse_or_recreate",
                    new=AsyncMock(return_value={"strategy": "adopt_active"}),
                ),
                patch.object(self.manager, "_store_retry_item_action"),
                patch.object(self.manager, "_has_retryable_downstream_task", return_value=True),
                patch.object(
                    self.manager,
                    "_downstream_control_existing_task",
                    new=AsyncMock(return_value={"outcome": "already_running", "payload": {"task_id": "fw-child", "status": "running"}}),
                ) as control_mock,
                patch.object(self.manager, "_downstream_create_task", new=AsyncMock(side_effect=AssertionError("should reuse active child"))),
                patch.object(self.manager, "_poll_until_terminal", side_effect=_fake_poll),
                patch.object(self.manager, "_queue_archive_and_wait", new=AsyncMock(return_value=(archive_root, None))),
            ):
                result = asyncio.run(
                    self.manager._run_firmware_item(task, stage_run, input_file, token="tok", retrying=True)
                )

        self.assertEqual("success", result["status"])
        self.assertEqual("success", item.status)
        self.assertEqual("fw-child", item.downstream_task_id)
        self.assertEqual(str(Path(task.workspace_root) / "input" / "firmware.bin"), result["item"]["input_path"])
        self.assertEqual(str(archive_root), result["item"]["unpacked_root"])
        control_mock.assert_awaited_once()

    def test_run_firmware_item_returns_failed_when_downstream_terminal_fails(self):
        task = self._task(task_type=TASK_TYPE_BINARY, name="firmware-failed")
        task.current_stage = "firmware_unpack"
        stage_run = self._stage_run("firmware_unpack")
        item = BinarySecurityStageItem(
            id="item-fw-failed",
            task_id=task.id,
            project_id=task.project_id,
            stage_name=stage_run.stage_name,
            item_key="fw-1",
            item_name="firmware.bin",
            parent_key="fw-1",
            status="queued",
            downstream_service="firmware_unpacker",
            output_ref={},
        )
        fake_session = _ModelAwareDb(stage_items=[item])
        input_file = {"firmware_key": "fw-1", "filename": "firmware.bin", "firmware_name": "firmware"}

        async def _fake_poll(*args, **kwargs):
            del args, kwargs
            return "failed", {"task_id": "fw-child", "status": "failed", "error": "unpack crashed"}

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(self.manager, "_active_downstream_payload", new=AsyncMock(return_value=None)),
            patch.object(self.manager, "_downstream_create_task", new=AsyncMock(return_value={"task_id": "fw-child", "status": "pending"})),
            patch.object(self.manager, "_replace_active_child_binding", new=AsyncMock(return_value=None)),
            patch.object(self.manager, "_poll_until_terminal", side_effect=_fake_poll),
            patch.object(self.manager, "_queue_archive_and_wait", new=AsyncMock(return_value=(None, None))),
        ):
            result = asyncio.run(self.manager._run_firmware_item(task, stage_run, input_file, token="tok"))

        self.assertEqual("failed", result["status"])
        self.assertEqual("unpack crashed", result["error"])
        self.assertEqual("failed", item.status)
        self.assertEqual("unpack crashed", item.error_message)


if __name__ == "__main__":
    unittest.main()
