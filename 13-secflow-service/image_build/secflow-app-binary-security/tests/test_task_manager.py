import asyncio
import json
import tempfile
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import operators

from app.model import (
    Base,
    BinarySecurityArchiveJob,
    BinarySecurityEvent,
    BinarySecurityProjectConfig,
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityStateEvent,
    BinarySecurityTask,
    BinarySecurityTaskStateLease,
    TASK_TYPE_BINARY,
    TASK_TYPE_BINARY_MODULE,
    TASK_TYPE_SOURCE,
)
from app.exception import NotFoundError, UpstreamError, ValidationError
from app.schemas import BinarySecurityServiceConfigPayload
from app.schemas import (
    BinarySecurityInputFile,
    BinarySecurityProjectConfigPayload,
    BinarySecurityArchiveJobResponse,
    BinarySecurityStageSummary,
    BinarySecurityTaskCreate,
    BinarySecurityTaskConcurrencyUpdatePayload,
    BinarySecurityTaskPolicyUpdatePayload,
    BinarySecurityUploadCompletePayload,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, _deduplicate_entry_keys, _now, _seconds_until


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows
        self._offset = 0
        self._limit = None

    def filter(self, *args, **kwargs):
        del kwargs
        rows = list(self._rows)
        for criterion in args:
            left = getattr(criterion, "left", None)
            operator = getattr(criterion, "operator", None)
            right = getattr(criterion, "right", None)
            field_name = getattr(left, "name", None)
            if not field_name or operator is None:
                continue
            if operator is operators.eq:
                expected = getattr(right, "value", None)
                rows = [row for row in rows if getattr(row, field_name, None) == expected]
                continue
            if operator is operators.in_op:
                values = getattr(right, "value", None)
                if values is None:
                    continue
                allowed = set(values)
                rows = [row for row in rows if getattr(row, field_name, None) in allowed]
                continue
        return _FakeQuery(rows)

    def order_by(self, *args, **kwargs):
        return self

    def group_by(self, *args, **kwargs):
        return self

    def join(self, *args, **kwargs):
        return self

    def distinct(self, *args, **kwargs):
        return self

    def options(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        self._limit = args[0] if args else None
        del kwargs
        return self

    def offset(self, *args, **kwargs):
        self._offset = args[0] if args else 0
        del kwargs
        return self

    def count(self):
        return len(self._rows)

    def all(self):
        rows = list(self._rows)
        if self._offset:
            rows = rows[self._offset :]
        if self._limit is not None:
            rows = rows[: self._limit]
        return rows

    def first(self):
        rows = self.all()
        return rows[0] if rows else None

    def scalar(self):
        row = self.first()
        if isinstance(row, (list, tuple)):
            return row[0] if row else None
        return row

    def delete(self, synchronize_session=False):
        count = len(self._rows)
        self._rows.clear()
        return count

    def update(self, values, synchronize_session=False):
        for row in self._rows:
            for key, value in (values or {}).items():
                name = getattr(key, "name", None)
                if name and hasattr(row, name):
                    setattr(row, name, value)
        return len(self._rows)


class _FakeDb:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.added = []
        self.commits = 0

    def query(self, model=None, *args, **kwargs):
        del args, kwargs
        if model is None:
            return _FakeQuery(self.rows)
        model_name = getattr(model, "__name__", "")
        if not self.rows:
            return _FakeQuery([])
        first_name = getattr(self.rows[0].__class__, "__name__", "")
        if first_name == "_StageRun" and model_name == "BinarySecurityStageRun":
            return _FakeQuery(self.rows)
        return _FakeQuery(self.rows if not model_name or model_name == first_name else [])

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        self.commits += 1

    def flush(self):
        pass


class _ModelAwareDb:
    def __init__(
        self,
        *,
        tasks=None,
        stage_runs=None,
        stage_items=None,
        archive_jobs=None,
        events=None,
        state_events=None,
        state_leases=None,
        project_configs=None,
        service_configs=None,
    ):
        self.tasks = list(tasks or [])
        self.stage_runs = list(stage_runs or [])
        self.stage_items = list(stage_items or [])
        self.archive_jobs = list(archive_jobs or [])
        self.events = list(events or [])
        self.state_events = list(state_events or [])
        self.state_leases = list(state_leases or [])
        self.project_configs = list(project_configs or [])
        self.service_configs = list(service_configs or [])
        self.added = []

    def query(self, model, *args, **kwargs):
        model_name = getattr(model, "__name__", "")
        if model_name == "BinarySecurityTask":
            return _FakeQuery(self.tasks)
        if model_name == "BinarySecurityStageRun":
            return _FakeQuery(self.stage_runs)
        if model_name == "BinarySecurityStageItem":
            return _FakeQuery(self.stage_items)
        if model_name == "BinarySecurityArchiveJob":
            return _FakeQuery(self.archive_jobs)
        if model_name == "BinarySecurityEvent":
            return _FakeQuery(self.events)
        if model_name == "BinarySecurityStateEvent":
            return _FakeQuery(self.state_events)
        if model_name == "BinarySecurityTaskStateLease":
            return _FakeQuery(self.state_leases)
        if model_name == "BinarySecurityProjectConfig":
            return _FakeQuery(self.project_configs)
        if model_name == "BinarySecurityServiceConfig":
            return _FakeQuery(self.service_configs)
        return _FakeQuery([])

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        pass

    def flush(self):
        pass

    def refresh(self, obj):
        return obj

    def rollback(self):
        pass

    def close(self):
        pass


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar(self):
        return self._value


class _FakeConnection:
    def __init__(self, lock_result=True):
        self.lock_result = lock_result
        self.calls = []
        self.closed = False

    def execute(self, statement, params=None):
        self.calls.append((str(statement), dict(params or {})))
        sql = str(statement)
        if "GET_LOCK" in sql:
            return _ScalarResult(1 if self.lock_result else 0)
        return _ScalarResult(1)

    def close(self):
        self.closed = True


class _LockingDb(_ModelAwareDb):
    def __init__(self, connection):
        super().__init__()
        self._connection = connection

    def connection(self):
        return self._connection

    def execute(self, statement, params=None):
        return self._connection.execute(statement, params)


class _AppendingModelAwareDb(_ModelAwareDb):
    def add(self, obj):
        super().add(obj)
        model_name = obj.__class__.__name__
        if model_name == "BinarySecurityStageItem":
            self.stage_items.append(obj)
        elif model_name == "BinarySecurityStageRun":
            self.stage_runs.append(obj)
        elif model_name == "BinarySecurityArchiveJob":
            self.archive_jobs.append(obj)
        elif model_name == "BinarySecurityEvent":
            self.events.append(obj)
        elif model_name == "BinarySecurityTask":
            self.tasks.append(obj)
        elif model_name == "BinarySecurityProjectConfig":
            self.project_configs.append(obj)
        elif model_name == "BinarySecurityServiceConfig":
            self.service_configs.append(obj)


class _FlakyCommitDb(_AppendingModelAwareDb):
    def __init__(self, *, fail_commits=0, fail_flushes=0, error_factory=None, **kwargs):
        super().__init__(**kwargs)
        self.fail_commits = fail_commits
        self.fail_flushes = fail_flushes
        self.error_factory = error_factory or (lambda: None)
        self.commit_calls = 0
        self.flush_calls = 0
        self.rollback_calls = 0

    def commit(self):
        self.commit_calls += 1
        if self.fail_commits > 0:
            self.fail_commits -= 1
            raise self.error_factory()

    def flush(self):
        self.flush_calls += 1
        if self.fail_flushes > 0:
            self.fail_flushes -= 1
            raise self.error_factory()

    def rollback(self):
        self.rollback_calls += 1


def _deadlock_operational_error():
    return task_manager_module.OperationalError(
        "INSERT INTO secflow_binary_security_stage_item ...",
        {},
        Exception(1213, "Deadlock found when trying to get lock; try restarting transaction"),
    )


class _FlakyArchiveJobDb(_LockingDb):
    def __init__(self, connection, *, fail_flushes=0, fail_commits=0, **kwargs):
        super().__init__(connection)
        self.tasks = list(kwargs.get("tasks") or [])
        self.stage_items = list(kwargs.get("stage_items") or [])
        self.archive_jobs = list(kwargs.get("archive_jobs") or [])
        self.fail_flushes = fail_flushes
        self.fail_commits = fail_commits
        self.flush_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0

    def flush(self):
        self.flush_calls += 1
        if self.fail_flushes > 0:
            self.fail_flushes -= 1
            raise _deadlock_operational_error()

    def commit(self):
        self.commit_calls += 1
        if self.fail_commits > 0:
            self.fail_commits -= 1
            raise _deadlock_operational_error()

    def rollback(self):
        self.rollback_calls += 1

    def rollback(self):
        self.rollback_calls += 1


class _StageRun:
    def __init__(self, stage_name, status):
        self.stage_name = stage_name
        self.status = status


class _AsyncDataflowClientStub:
    def __init__(self, *, listed=None, fetched=None, fail_on_create=False):
        self.listed = listed or {"items": []}
        self.fetched = fetched or {}
        self.fail_on_create = fail_on_create
        self.created = 0

    async def list_tasks(self, *args, **kwargs):
        del args, kwargs
        return self.listed

    async def get_task(self, task_id):
        return dict(self.fetched.get(task_id) or {"task_id": task_id, "status": "passed"})

    async def create_task(self, *args, **kwargs):
        del args, kwargs
        self.created += 1
        if self.fail_on_create:
            raise AssertionError("create_task should not be called")
        return {"task_id": "dfa-created"}


class _AsyncSystemAnalyseClientStub:
    def __init__(self, *, listed=None, fetched=None, fail_on_create=False):
        self.listed = listed or {"items": []}
        self.fetched = fetched or {}
        self.fail_on_create = fail_on_create
        self.created = 0

    async def list_tasks(self, *args, **kwargs):
        del args, kwargs
        return self.listed

    async def get_task(self, task_id):
        return dict(self.fetched.get(task_id) or {"task_id": task_id, "status": "passed"})

    async def create_task(self, *args, **kwargs):
        del args, kwargs
        self.created += 1
        if self.fail_on_create:
            raise AssertionError("create_task should not be called")
        return {"task_id": "sat-created"}

    async def get_task_result(self, task_id):
        return {"task_id": task_id}


class _AsyncBinaryToSourceClientStub:
    def __init__(self, *, listed=None, fetched=None, fail_on_create=False):
        self.listed = listed or {"items": []}
        self.fetched = fetched or {}
        self.fail_on_create = fail_on_create
        self.created = 0

    async def list_tasks(self, *args, **kwargs):
        del args, kwargs
        return self.listed

    async def get_task(self, project_id, task_id, token):
        del project_id, token
        return dict(self.fetched.get(task_id) or {"id": task_id, "status": "success", "items": []})

    async def create_task(self, *args, **kwargs):
        del args, kwargs
        self.created += 1
        if self.fail_on_create:
            raise AssertionError("create_task should not be called")
        return {"id": "b2s-created"}


class _AsyncEntryAnalyseClientStub:
    def __init__(self, *, listed=None, fetched=None, fail_on_create=False):
        self.listed = listed or {"items": []}
        self.fetched = fetched or {}
        self.fail_on_create = fail_on_create
        self.created = 0

    async def list_tasks(self, *args, **kwargs):
        del args, kwargs
        return self.listed

    async def get_task(self, task_id, token=None):
        del token
        return dict(self.fetched.get(task_id) or {"task_id": task_id, "status": "passed"})

    async def create_task(self, *args, **kwargs):
        del args, kwargs
        self.created += 1
        if self.fail_on_create:
            raise AssertionError("create_task should not be called")
        return {"task_id": "eat-created"}


class _AsyncFirmwareUnpackerClientStub:
    def __init__(self, *, listed=None, fetched=None, fail_on_create=False):
        self.listed = listed or {"items": []}
        self.fetched = fetched or {}
        self.fail_on_create = fail_on_create
        self.created = 0

    async def list_tasks(self, *args, **kwargs):
        del args, kwargs
        return self.listed

    async def get_task(self, project_id, task_id, token):
        del project_id, token
        return dict(self.fetched.get(task_id) or {"task_id": task_id, "status": "success"})

    async def create_task(self, *args, **kwargs):
        del args, kwargs
        self.created += 1
        if self.fail_on_create:
            raise AssertionError("create_task should not be called")
        return {"task_id": "fu-created"}


class _AsyncDataflowVulnScannerClientStub:
    def __init__(self, *, listed=None, fetched=None, artifacts=None, fail_on_create=False):
        self.listed = listed or []
        self.fetched = fetched or {}
        self.artifacts = artifacts or {"workspace_root": "/tmp"}
        self.fail_on_create = fail_on_create
        self.created = 0

    async def list_tasks(self, *args, **kwargs):
        del args, kwargs
        return self.listed

    async def get_task(self, task_id, token):
        del token
        return dict(self.fetched.get(task_id) or {"task_id": task_id, "status": "completed"})

    async def get_artifacts(self, task_id, token):
        del task_id, token
        return dict(self.artifacts)

    async def create_task(self, *args, **kwargs):
        del args, kwargs
        self.created += 1
        if self.fail_on_create:
            raise AssertionError("create_task should not be called")
        return {"task_id": "dfvs-created"}


class TaskManagerTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def _finish_continue_prepare(self, db, task, target_stage: str) -> None:
        asyncio.run(self.manager._prepare_continue_task(db, task, target_stage))
        task.status = "pending"
        task.current_stage = target_stage
        task.execution_mode = "task_retry"
        task.target_stage_name = target_stage
        task.pending_action = None

    def _finish_retry_prepare(self, db, task) -> None:
        stage_sequence = asyncio.run(self.manager._prepare_retry_task(db, task))
        task.status = "pending"
        task.current_stage = stage_sequence[0]
        task.execution_mode = None
        task.target_stage_name = None
        task.pending_action = None

    def test_task_summary_is_written_to_task_workspace_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="n",
                status="pending",
                task_type=TASK_TYPE_BINARY,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root="/o",
                workspace_root=tmp,
            )

            task.summary = {"selected_modules": [{"module_key": "m1"}]}

            summary_path = Path(tmp) / BinarySecurityTask.SUMMARY_FILENAME
            self.assertTrue(summary_path.is_file())
            self.assertIsNone(task.summary_json)
            self.assertEqual({"selected_modules": [{"module_key": "m1"}]}, task.summary)

    def test_task_summary_concurrent_file_writes_use_unique_temp_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            tasks = [
                BinarySecurityTask(
                    id=f"t{index}",
                    project_id="p1",
                    name="n",
                    status="pending",
                    task_type=TASK_TYPE_BINARY,
                    firmware_source="project_filesystem",
                    firmware_path="/fw",
                    output_root="/o",
                    workspace_root=tmp,
                )
                for index in range(24)
            ]

            def write_summary(index: int) -> None:
                tasks[index].summary = {"writer": index, "items": list(range(index))}

            with ThreadPoolExecutor(max_workers=8) as executor:
                list(executor.map(write_summary, range(len(tasks))))

            summary_path = Path(tmp) / BinarySecurityTask.SUMMARY_FILENAME
            payload = json.loads(summary_path.read_text("utf-8"))
            self.assertIn("writer", payload)
            self.assertFalse(list(Path(tmp).glob(f".{BinarySecurityTask.SUMMARY_FILENAME}.*.tmp")))

    def test_deduplicate_entry_keys_handles_long_duplicate_suffixes(self):
        long_signature = (
            "VeryLongNamespace::VeryLongClassName::VeryLongMethodNameWithExtremelyLongSuffix("
            "const std::string& request, const std::string& response, const std::string& context)"
        )
        entries = [
            {
                "entry_key": "source_project-image-PullImage-1",
                "raw_function_name": long_signature,
                "function_name": "PullImage",
                "file_name": "image.cc",
            },
            {
                "entry_key": "source_project-image-PullImage-1",
                "raw_function_name": long_signature,
                "function_name": "PullImage",
                "file_name": "image.cc",
            },
            {
                "entry_key": "source_project-image-PullImage-1",
                "raw_function_name": long_signature,
                "function_name": "PullImage",
                "file_name": "image.cc",
            },
        ]

        deduped = _deduplicate_entry_keys(entries)

        self.assertEqual(3, len(deduped))
        self.assertEqual(3, len({row["entry_key"] for row in deduped}))

    def test_resolve_entry_source_dir_prefers_source_root_for_source_tasks(self):
        resolved = self.manager._resolve_entry_source_dir(
            {
                "task_type": TASK_TYPE_SOURCE,
                "source_dir": "/task/output/system-analyse/modules/cri",
                "source_root": "/task/input",
                "unpacked_root": "/task/input",
                "module_dir": "/task/output/system-analyse/modules/cri",
            }
        )

        self.assertEqual("/task/input", resolved)

    def test_resolve_entry_source_dir_keeps_module_dir_for_binary_module_tasks(self):
        resolved = self.manager._resolve_entry_source_dir(
            {
                "task_type": TASK_TYPE_BINARY_MODULE,
                "source_dir": "/task/output/b2s/module-a",
                "source_root": "/task/output/b2s",
                "unpacked_root": "/task/input",
                "module_dir": "/task/output/b2s/module-a",
            }
        )

        self.assertEqual("/task/output/b2s/module-a", resolved)

    def test_normalize_dfa_source_file_returns_relative_path_under_source_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src"
            target = root / "pkg" / "main.c"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("int main(void) { return 0; }\n", encoding="utf-8")

            normalized = self.manager._normalize_dfa_source_file(
                str(root),
                {"definition_file": str(target)},
            )

        self.assertEqual("pkg/main.c", normalized)

    def test_trigger_entry_items_from_b2s_result_creates_pending_entry_item_in_streaming_mode(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="demo",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/tmp/ws",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        upstream_item = BinarySecurityStageItem(
            id="si-b2s",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr-b2s",
            stage_name="binary_to_source",
            item_key="module-1",
            item_name="mod.so",
            parent_key="fw-1",
            item_identity_key="module-1::fw-1",
            status="success",
            downstream_service="binary_to_source",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[])

        seeded = self.manager._trigger_entry_items_from_b2s_result(
            db,
            task,
            {
                "module_key": "module-1",
                "module_name": "mod.so",
                "firmware_key": "fw-1",
                "source_dir": "/tmp/source/module-1",
                "source_root": "/tmp/source/module-1",
            },
            upstream_item=upstream_item,
        )

        self.assertIsNotNone(seeded)
        self.assertEqual("entry_analysis", seeded.stage_name)
        self.assertEqual("pending", seeded.status)
        self.assertIsNone(seeded.started_at)
        self.assertEqual("entry_analyse", seeded.downstream_service)
        self.assertEqual("si-b2s", seeded.input_ref["upstream_item_id"])
        self.assertEqual("binary_to_source", seeded.input_ref["triggered_by_stage"])
        self.assertTrue(any(run.stage_name == "entry_analysis" for run in db.stage_runs))
        self.assertTrue(any(event.event_type == "streaming_entry_item_seeded" for event in db.events))

    def test_trigger_entry_items_from_b2s_result_rebuilds_descriptor_for_binary_task(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        with tempfile.TemporaryDirectory() as tmp:
            artifact_root = Path(tmp)
            (artifact_root / "libvnfcadapt_ppc_rtos.c").write_text("int a(void) { return 0; }\n", encoding="utf-8")
            (artifact_root / "libvnfcadapt_ppc_rtos.h").write_text("#pragma once\n", encoding="utf-8")
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="demo",
                status="running",
                task_type=TASK_TYPE_BINARY,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root="/o",
                workspace_root="/tmp/ws",
                policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
            )
            upstream_item = BinarySecurityStageItem(
                id="si-b2s",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr-b2s",
                stage_name="binary_to_source",
                item_key="module-1",
                item_name="sdn_nfv",
                parent_key="fw-1",
                item_identity_key="module-1::fw-1",
                status="success",
                downstream_service="binary_to_source",
            )
            db = _AppendingModelAwareDb(tasks=[task], stage_items=[])

            seeded = self.manager._trigger_entry_items_from_b2s_result(
                db,
                task,
                {
                    "module_key": "module-1",
                    "module_name": "sdn_nfv",
                    "firmware_key": "fw-1",
                    "source_dir": str(artifact_root),
                    "source_root": str(artifact_root),
                    "files_list": "/tmp/original-module/files.list",
                },
                upstream_item=upstream_item,
            )

            self.assertIsNotNone(seeded)
            self.assertEqual(str(artifact_root), seeded.input_ref["source_dir"])
            self.assertEqual(str(artifact_root), seeded.input_ref["source_root"])
            files_list = Path(seeded.input_ref["entry_files_list"])
            self.assertTrue(files_list.is_file())
            self.assertEqual(
                ["libvnfcadapt_ppc_rtos.c", "libvnfcadapt_ppc_rtos.h"],
                files_list.read_text(encoding="utf-8").splitlines(),
            )

    def test_trigger_dataflow_items_from_entry_result_creates_pending_dataflow_items_in_streaming_mode(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="demo",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/tmp/ws",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        upstream_item = BinarySecurityStageItem(
            id="si-entry",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr-entry",
            stage_name="entry_analysis",
            item_key="module-1",
            item_name="mod.so",
            parent_key="fw-1",
            item_identity_key="module-1::fw-1",
            status="success",
            downstream_service="entry_analyse",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[])

        seeded = self.manager._trigger_dataflow_items_from_entry_result(
            db,
            task,
            {
                "entries": [
                    {
                        "entry_key": "entry-1",
                        "module_key": "module-1",
                        "function_name": "handle_req",
                        "file_name": "main.c",
                    },
                    {
                        "entry_key": "entry-2",
                        "module_key": "module-1",
                        "function_name": "handle_rsp",
                        "file_name": "main.c",
                    },
                ]
            },
            upstream_item=upstream_item,
        )

        self.assertEqual(2, len(seeded))
        self.assertEqual({"entry-1", "entry-2"}, {item.item_key for item in seeded})
        self.assertTrue(all(item.stage_name == "dataflow_analysis" for item in seeded))
        self.assertTrue(all(item.status == "pending" for item in seeded))
        self.assertTrue(all(item.input_ref["upstream_item_id"] == "si-entry" for item in seeded))
        self.assertTrue(any(run.stage_name == "dataflow_analysis" for run in db.stage_runs))
        self.assertTrue(any(event.event_type == "streaming_dataflow_items_seeded" for event in db.events))

    def test_trigger_vuln_items_from_dataflow_result_creates_pending_vuln_item_in_streaming_mode(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="demo",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/tmp/ws",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        upstream_item = BinarySecurityStageItem(
            id="si-df",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr-df",
            stage_name="dataflow_analysis",
            item_key="entry-1",
            item_name="handle_req",
            parent_key="module-1",
            item_identity_key="entry-1::module-1",
            status="success",
            downstream_service="dataflow_analyse",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[])

        seeded = self.manager._trigger_vuln_items_from_dataflow_result(
            db,
            task,
            {
                "entry_key": "entry-1",
                "module_key": "module-1",
                "function_name": "handle_req",
                "data_flow_file": "/tmp/flow.md",
                "source_dir": "/tmp/source/module-1",
            },
            upstream_item=upstream_item,
        )

        self.assertIsNotNone(seeded)
        self.assertEqual("vuln_scan", seeded.stage_name)
        self.assertEqual("pending", seeded.status)
        self.assertEqual("dataflow_vuln_scanner", seeded.downstream_service)
        self.assertEqual("si-df", seeded.input_ref["upstream_item_id"])
        self.assertEqual("dataflow_analysis", seeded.input_ref["triggered_by_stage"])
        self.assertTrue(any(run.stage_name == "vuln_scan" for run in db.stage_runs))
        self.assertTrue(any(event.event_type == "streaming_vuln_item_seeded" for event in db.events))

    def test_task_needs_downstream_reconcile_skips_streaming_tail_task(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="demo",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/tmp/ws",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )

        self.assertFalse(self.manager._task_needs_downstream_reconcile(task))

    def test_claim_streaming_stage_items_marks_pending_item_dispatching(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="demo",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="entry_analysis",
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
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item])

        claimed = self.manager._claim_streaming_stage_items(db)

        self.assertEqual(["si-entry"], claimed)
        self.assertEqual("dispatching", item.status)
        self.assertIsNotNone(item.started_at)

    def test_write_json_concurrent_writes_use_unique_temp_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "input" / "task-metadata.json"

            def write_payload(index: int) -> None:
                task_manager_module._write_json(target, {"writer": index, "items": list(range(index))})

            with ThreadPoolExecutor(max_workers=8) as executor:
                list(executor.map(write_payload, range(24)))

            payload = json.loads(target.read_text("utf-8"))
            self.assertIn("writer", payload)
            self.assertFalse(list(target.parent.glob(".task-metadata.json.*.tmp")))

    def test_stage_worker_terminal_event_keeps_task_active_when_waiting_downstream_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="source",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(Path(tmp) / "output"),
                workspace_root=tmp,
                started_at=_now(),
                dispatcher_instance_id="pod-a",
                dispatch_started_at=_now(),
            )
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="running",
                started_at=_now(),
            )
            event = BinarySecurityStateEvent(
                id="sev-active-terminal",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                event_type="stage_worker_terminal_observed",
                idempotency_key="sev-active-terminal",
                status="processing",
                available_at=_now(),
            )
            event.payload = {
                "stage_name": "entry_analysis",
                "status": "running",
                "summary": {"running_count": 1, "failed_count": 0},
            }
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run])

            asyncio.run(self.manager._apply_stage_worker_terminal_event_locked(db, event))

            self.assertEqual("running", task.status)
            self.assertEqual("entry_analysis", task.current_stage)
            self.assertEqual("pod-a", task.dispatcher_instance_id)
            self.assertIsNotNone(task.dispatch_started_at)
            self.assertIsNone(task.finished_at)
            self.assertEqual("running", stage_run.status)
            self.assertIsNone(stage_run.finished_at)
            self.assertTrue(any(row.event_type == "stage_waiting_downstream_progress" for row in db.events))

    def test_stage_worker_terminal_failure_finalizes_streaming_tail_stage(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="source",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(Path(tmp) / "output"),
                workspace_root=tmp,
                started_at=_now(),
                policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
            )
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="running",
                started_at=_now(),
            )
            item = BinarySecurityStageItem(
                id="si1",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr1",
                stage_name="entry_analysis",
                item_key="module-1",
                item_name="module-1",
                parent_key="fw-1",
                item_identity_key="module-1::fw-1",
                status="running",
                downstream_service="entry_analyse",
            )
            event = BinarySecurityStateEvent(
                id="sev-fail-terminal",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                event_type="stage_worker_terminal_observed",
                idempotency_key="sev-fail-terminal",
                status="processing",
                available_at=_now(),
            )
            event.payload = {
                "stage_name": "entry_analysis",
                "status": "failed",
                "summary": {"failed_count": 1, "error": "entry failed"},
            }
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[item], state_events=[event])

            asyncio.run(self.manager._apply_stage_worker_terminal_event_locked(db, event))

            self.assertEqual("failed", stage_run.status)
            self.assertEqual("failed", task.status)
            self.assertEqual("entry_analysis", task.current_stage)
            self.assertIsNotNone(task.finished_at)
            self.assertEqual("failed", item.status)
            self.assertTrue(any(row.event_type == "stage_failed" for row in db.events))

    def test_streaming_lifecycle_transitions_from_stage_completion_into_tail_sync(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="source",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(Path(tmp) / "output"),
                workspace_root=tmp,
                started_at=_now(),
                policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
            )
            entry_run = BinarySecurityStageRun(
                id="sr-entry",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="running",
                started_at=_now(),
            )
            system_run = BinarySecurityStageRun(
                id="sr-system",
                task_id="t1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="success",
                started_at=_now(),
                finished_at=_now(),
            )
            dataflow_run = BinarySecurityStageRun(
                id="sr-df",
                task_id="t1",
                project_id="p1",
                stage_name="dataflow_analysis",
                sequence_no=3,
                status="pending",
            )
            dataflow_item = BinarySecurityStageItem(
                id="si-df",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr-df",
                stage_name="dataflow_analysis",
                item_key="entry-a",
                item_name="func_a",
                parent_key="mod-a",
                item_identity_key="entry-a::mod-a",
                status="pending",
                downstream_service="dataflow_analyse",
                downstream_task_id="dfa-1",
            )
            dataflow_item.input_ref = {"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a"}
            event = BinarySecurityStateEvent(
                id="sev-streaming-tail",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                event_type="stage_worker_terminal_observed",
                idempotency_key="sev-streaming-tail",
                status="processing",
                available_at=_now(),
            )
            event.payload = {
                "stage_name": "entry_analysis",
                "status": "success",
                "summary": {"success_count": 1, "failed_count": 0, "entry_count": 1},
            }
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[system_run, entry_run, dataflow_run], stage_items=[dataflow_item], events=[event])

            original_factory = task_manager_module.get_session_factory
            original_write = self.manager._write_task_metadata_async
            task_manager_module.get_session_factory = lambda: (lambda: db)

            async def fake_write(*args, **kwargs):
                del args, kwargs
                return None

            self.manager._write_task_metadata_async = fake_write
            try:
                asyncio.run(self.manager._apply_stage_worker_terminal_event_locked(db, event))
                self.assertEqual("running", task.status)
                self.assertEqual("dataflow_analysis", task.current_stage)
                self.assertTrue(any(row.event_type == "streaming_tail_activated" for row in db.events))

                asyncio.run(self.manager._sync_streaming_task_tail_state("t1"))
            finally:
                task_manager_module.get_session_factory = original_factory
                self.manager._write_task_metadata_async = original_write

            self.assertEqual("running", task.status)
            self.assertEqual("dataflow_analysis", task.current_stage)

    def test_streaming_reducer_sequence_applies_terminal_then_downstream_status(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="source",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(Path(tmp) / "output"),
                workspace_root=tmp,
                started_at=_now(),
                policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
            )
            system_run = BinarySecurityStageRun(
                id="sr-system",
                task_id="t1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="success",
                started_at=_now(),
                finished_at=_now(),
            )
            entry_run = BinarySecurityStageRun(
                id="sr-entry",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="running",
                started_at=_now(),
            )
            dataflow_run = BinarySecurityStageRun(
                id="sr-df",
                task_id="t1",
                project_id="p1",
                stage_name="dataflow_analysis",
                sequence_no=3,
                status="pending",
            )
            dataflow_item = BinarySecurityStageItem(
                id="si-df",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr-df",
                stage_name="dataflow_analysis",
                item_key="entry-a",
                item_name="func_a",
                parent_key="mod-a",
                item_identity_key="entry-a::mod-a",
                status="pending",
                downstream_service="dataflow_analyse",
                downstream_task_id="dfa-1",
            )
            dataflow_item.input_ref = {"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a"}
            terminal_event = BinarySecurityStateEvent(
                id="sev-streaming-terminal",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                event_type="stage_worker_terminal_observed",
                idempotency_key="sev-streaming-terminal",
                status="processing",
                available_at=_now(),
            )
            terminal_event.payload = {
                "stage_name": "entry_analysis",
                "status": "success",
                "summary": {"success_count": 1, "failed_count": 0, "entry_count": 1},
            }
            downstream_event = BinarySecurityStateEvent(
                id="sev-streaming-df-running",
                task_id="t1",
                project_id="p1",
                stage_name="dataflow_analysis",
                item_id="si-df",
                event_type="downstream_status_observed",
                idempotency_key="sev-streaming-df-running",
                status="processing",
                available_at=_now(),
            )
            downstream_event.payload = {
                "mapped_status": "running",
                "before_status": "pending",
                "downstream_status": "running",
                "downstream_payload": {"task_id": "dfa-1", "status": "running"},
            }
            db = _AppendingModelAwareDb(
                tasks=[task],
                stage_runs=[system_run, entry_run, dataflow_run],
                stage_items=[dataflow_item],
                events=[terminal_event, downstream_event],
            )

            original_write = self.manager._write_task_metadata_async

            async def fake_write(*args, **kwargs):
                del args, kwargs
                return None

            self.manager._write_task_metadata_async = fake_write
            try:
                asyncio.run(self.manager._apply_stage_worker_terminal_event_locked(db, terminal_event))
                self.assertEqual("running", task.status)
                self.assertEqual("dataflow_analysis", task.current_stage)
                self.assertEqual(self.manager.instance_id, task.dispatcher_instance_id)
                self.assertIsNotNone(task.dispatch_started_at)

                asyncio.run(self.manager._apply_downstream_status_event_locked(db, downstream_event))
            finally:
                self.manager._write_task_metadata_async = original_write

            self.assertEqual("running", task.status)
            self.assertEqual("dataflow_analysis", task.current_stage)
            self.assertEqual("running", dataflow_item.status)
            self.assertEqual("running", dataflow_run.status)
            self.assertEqual("running", task.stage_summary["dataflow_analysis"]["status"])

    def test_reduce_state_event_end_to_end_updates_tail_detail_and_observability(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="source",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(Path(tmp) / "output"),
                workspace_root=tmp,
                started_at=_now(),
                policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
            )
            system_run = BinarySecurityStageRun(
                id="sr-system",
                task_id="t1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="success",
                started_at=_now(),
                finished_at=_now(),
            )
            entry_run = BinarySecurityStageRun(
                id="sr-entry",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="running",
                started_at=_now(),
            )
            dataflow_run = BinarySecurityStageRun(
                id="sr-df",
                task_id="t1",
                project_id="p1",
                stage_name="dataflow_analysis",
                sequence_no=3,
                status="pending",
            )
            dataflow_item = BinarySecurityStageItem(
                id="si-df",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr-df",
                stage_name="dataflow_analysis",
                item_key="entry-a",
                item_name="func_a",
                parent_key="mod-a",
                item_identity_key="entry-a::mod-a",
                status="pending",
                downstream_service="dataflow_analyse",
                downstream_task_id="dfa-1",
            )
            dataflow_item.input_ref = {"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a"}
            terminal_event = BinarySecurityStateEvent(
                id="sev-terminal",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                event_type="stage_worker_terminal_observed",
                idempotency_key="sev-terminal",
                status="processing",
                leased_by=self.manager.instance_id,
                available_at=_now(),
                created_at=_now(),
            )
            terminal_event.payload = {
                "stage_name": "entry_analysis",
                "status": "success",
                "summary": {"success_count": 1, "failed_count": 0, "entry_count": 1},
            }
            downstream_event = BinarySecurityStateEvent(
                id="sev-downstream",
                task_id="t1",
                project_id="p1",
                stage_name="dataflow_analysis",
                item_id="si-df",
                event_type="downstream_status_observed",
                idempotency_key="sev-downstream",
                status="processing",
                leased_by=self.manager.instance_id,
                available_at=_now(),
                created_at=_now(),
            )
            downstream_event.payload = {
                "mapped_status": "running",
                "before_status": "pending",
                "downstream_status": "running",
                "downstream_payload": {"task_id": "dfa-1", "status": "running"},
            }
            db = _AppendingModelAwareDb(
                tasks=[task],
                stage_runs=[system_run, entry_run, dataflow_run],
                stage_items=[dataflow_item],
                state_events=[terminal_event, downstream_event],
            )

            original_factory = task_manager_module.get_session_factory
            original_write = self.manager._write_task_metadata_async
            original_acquire = self.manager._acquire_task_state_lease
            original_release = self.manager._release_task_state_lease
            task_manager_module.get_session_factory = lambda: (lambda: db)

            async def fake_write(*args, **kwargs):
                del args, kwargs
                return None

            self.manager._write_task_metadata_async = fake_write
            self.manager._acquire_task_state_lease = lambda _db, _task_id: "lease-1"
            self.manager._release_task_state_lease = lambda _db, _task_id, token=None, held_started=None: None
            try:
                asyncio.run(self.manager._reduce_state_event("sev-terminal"))
                asyncio.run(self.manager._reduce_state_event("sev-downstream"))
            finally:
                task_manager_module.get_session_factory = original_factory
                self.manager._write_task_metadata_async = original_write
                self.manager._acquire_task_state_lease = original_acquire
                self.manager._release_task_state_lease = original_release

            detail = self.manager.get_task_detail(db, project_id="p1", task_id="t1")
            observability = self.manager.get_orchestration_observability(db, project_id="p1", task_id="t1")

            self.assertEqual("processed", terminal_event.status)
            self.assertEqual("processed", downstream_event.status)
            self.assertEqual("dataflow_analysis", task.current_stage)
            self.assertEqual("running", dataflow_item.status)
            self.assertTrue(any(row.event_type == "streaming_tail_activated" for row in db.events))
            self.assertTrue(any(row.event_type == "downstream_status_event_applied" for row in db.events))
            self.assertEqual("running", detail.stage_summaries[2].status)
            self.assertEqual("task_running", detail.manual_operation_state["blocking_code"])
            self.assertEqual(2, observability["state_events"]["status_counts"]["processed"])
            self.assertEqual(
                {"sev-terminal", "sev-downstream"},
                {row["id"] for row in observability["state_events"]["recent"][:2]},
            )

    def test_reduce_state_event_end_to_end_surfaces_tail_downstream_missing_failure(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="source",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(Path(tmp) / "output"),
                workspace_root=tmp,
                started_at=_now(),
                policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
            )
            system_run = BinarySecurityStageRun(
                id="sr-system",
                task_id="t1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="success",
                started_at=_now(),
                finished_at=_now(),
            )
            entry_run = BinarySecurityStageRun(
                id="sr-entry",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="running",
                started_at=_now(),
            )
            dataflow_run = BinarySecurityStageRun(
                id="sr-df",
                task_id="t1",
                project_id="p1",
                stage_name="dataflow_analysis",
                sequence_no=3,
                status="pending",
            )
            dataflow_item = BinarySecurityStageItem(
                id="si-df",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr-df",
                stage_name="dataflow_analysis",
                item_key="entry-a",
                item_name="func_a",
                parent_key="mod-a",
                item_identity_key="entry-a::mod-a",
                status="pending",
                downstream_service="dataflow_analyse",
                downstream_task_id="dfa-1",
            )
            dataflow_item.input_ref = {"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a"}
            terminal_event = BinarySecurityStateEvent(
                id="sev-terminal-fail",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                event_type="stage_worker_terminal_observed",
                idempotency_key="sev-terminal-fail",
                status="processing",
                leased_by=self.manager.instance_id,
                available_at=_now(),
                created_at=_now(),
            )
            terminal_event.payload = {
                "stage_name": "entry_analysis",
                "status": "success",
                "summary": {"success_count": 1, "failed_count": 0, "entry_count": 1},
            }
            downstream_event = BinarySecurityStateEvent(
                id="sev-downstream-missing",
                task_id="t1",
                project_id="p1",
                stage_name="dataflow_analysis",
                item_id="si-df",
                event_type="downstream_status_observed",
                idempotency_key="sev-downstream-missing",
                status="processing",
                leased_by=self.manager.instance_id,
                available_at=_now(),
                created_at=_now(),
            )
            downstream_event.payload = {
                "mapped_status": "downstream_missing",
                "before_status": "pending",
                "downstream_status": "downstream_missing",
                "error_message": "downstream task not found",
                "downstream_payload": {"task_id": "dfa-1", "status": "downstream_missing", "error": "downstream task not found"},
            }
            db = _AppendingModelAwareDb(
                tasks=[task],
                stage_runs=[system_run, entry_run, dataflow_run],
                stage_items=[dataflow_item],
                state_events=[terminal_event, downstream_event],
            )

            original_factory = task_manager_module.get_session_factory
            original_write = self.manager._write_task_metadata_async
            original_acquire = self.manager._acquire_task_state_lease
            original_release = self.manager._release_task_state_lease
            task_manager_module.get_session_factory = lambda: (lambda: db)

            async def fake_write(*args, **kwargs):
                del args, kwargs
                return None

            self.manager._write_task_metadata_async = fake_write
            self.manager._acquire_task_state_lease = lambda _db, _task_id: "lease-1"
            self.manager._release_task_state_lease = lambda _db, _task_id, token=None, held_started=None: None
            try:
                asyncio.run(self.manager._reduce_state_event("sev-terminal-fail"))
                asyncio.run(self.manager._reduce_state_event("sev-downstream-missing"))
            finally:
                task_manager_module.get_session_factory = original_factory
                self.manager._write_task_metadata_async = original_write
                self.manager._acquire_task_state_lease = original_acquire
                self.manager._release_task_state_lease = original_release

            detail = self.manager.get_task_detail(db, project_id="p1", task_id="t1")
            observability = self.manager.get_orchestration_observability(db, project_id="p1", task_id="t1")
            overview_nodes = {node.node_id: node for node in detail.overview_nodes}

            self.assertEqual("failed", task.status)
            self.assertEqual("processed", terminal_event.status)
            self.assertEqual("processed", downstream_event.status)
            self.assertEqual("downstream_missing", dataflow_item.status)
            self.assertEqual("downstream_missing", detail.stage_summaries[2].status)
            self.assertEqual("downstream_missing", detail.abnormal_reason.code)
            self.assertEqual("downstream_missing", detail.stage_items[0].abnormal_reason.code)
            self.assertEqual("downstream_missing", overview_nodes["business:dataflow_analysis"].abnormal_reason.code)
            self.assertTrue(detail.manual_operation_state["can_retry"])
            self.assertFalse(detail.manual_operation_state["can_retry_failed_items"])
            self.assertTrue(detail.task_retry_failed_items_reason)
            self.assertEqual(2, observability["state_events"]["status_counts"]["processed"])
            self.assertTrue(any(row.event_type == "task_finalize_blocked_by_incomplete_stage" for row in db.events))

    def test_reduce_state_event_end_to_end_surfaces_tail_downstream_failed_failure(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="source",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(Path(tmp) / "output"),
                workspace_root=tmp,
                started_at=_now(),
                policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
            )
            system_run = BinarySecurityStageRun(id="sr-system", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=1, status="success", started_at=_now(), finished_at=_now())
            entry_run = BinarySecurityStageRun(id="sr-entry", task_id="t1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="running", started_at=_now())
            dataflow_run = BinarySecurityStageRun(id="sr-df", task_id="t1", project_id="p1", stage_name="dataflow_analysis", sequence_no=3, status="pending")
            dataflow_item = BinarySecurityStageItem(
                id="si-df",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr-df",
                stage_name="dataflow_analysis",
                item_key="entry-a",
                item_name="func_a",
                parent_key="mod-a",
                item_identity_key="entry-a::mod-a",
                status="pending",
                downstream_service="dataflow_analyse",
                downstream_task_id="dfa-1",
                error_message=None,
            )
            dataflow_item.input_ref = {"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a"}
            terminal_event = BinarySecurityStateEvent(
                id="sev-terminal-error",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                event_type="stage_worker_terminal_observed",
                idempotency_key="sev-terminal-error",
                status="processing",
                leased_by=self.manager.instance_id,
                available_at=_now(),
                created_at=_now(),
            )
            terminal_event.payload = {"stage_name": "entry_analysis", "status": "success", "summary": {"success_count": 1, "failed_count": 0, "entry_count": 1}}
            downstream_event = BinarySecurityStateEvent(
                id="sev-downstream-failed",
                task_id="t1",
                project_id="p1",
                stage_name="dataflow_analysis",
                item_id="si-df",
                event_type="downstream_status_observed",
                idempotency_key="sev-downstream-failed",
                status="processing",
                leased_by=self.manager.instance_id,
                available_at=_now(),
                created_at=_now(),
            )
            downstream_event.payload = {
                "mapped_status": "failed",
                "before_status": "pending",
                "downstream_status": "failed",
                "error_message": "worker exited with code 1",
                "downstream_payload": {"task_id": "dfa-1", "status": "failed", "error": "worker exited with code 1"},
            }
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[system_run, entry_run, dataflow_run], stage_items=[dataflow_item], state_events=[terminal_event, downstream_event])

            original_factory = task_manager_module.get_session_factory
            original_write = self.manager._write_task_metadata_async
            original_acquire = self.manager._acquire_task_state_lease
            original_release = self.manager._release_task_state_lease
            task_manager_module.get_session_factory = lambda: (lambda: db)

            async def fake_write(*args, **kwargs):
                del args, kwargs
                return None

            self.manager._write_task_metadata_async = fake_write
            self.manager._acquire_task_state_lease = lambda _db, _task_id: "lease-1"
            self.manager._release_task_state_lease = lambda _db, _task_id, token=None, held_started=None: None
            try:
                asyncio.run(self.manager._reduce_state_event("sev-terminal-error"))
                asyncio.run(self.manager._reduce_state_event("sev-downstream-failed"))
            finally:
                task_manager_module.get_session_factory = original_factory
                self.manager._write_task_metadata_async = original_write
                self.manager._acquire_task_state_lease = original_acquire
                self.manager._release_task_state_lease = original_release

            detail = self.manager.get_task_detail(db, project_id="p1", task_id="t1")
            self.assertEqual("failed", task.status)
            self.assertEqual("failed", dataflow_item.status)
            self.assertEqual("failed", detail.stage_summaries[2].status)
            self.assertEqual("downstream_failed", detail.abnormal_reason.code)
            self.assertEqual("downstream_failed", detail.stage_items[0].abnormal_reason.code)
            self.assertTrue(detail.manual_operation_state["can_retry"])
            self.assertTrue(any(row.event_type == "downstream_status_event_applied" for row in db.events))

    def test_reduce_state_event_end_to_end_finalizes_partial_success_after_vuln_success(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="source",
                status="pending",
                task_type=TASK_TYPE_SOURCE,
                current_stage="vuln_scan",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(Path(tmp) / "output"),
                workspace_root=tmp,
                started_at=_now(),
                policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
            )
            system_run = BinarySecurityStageRun(id="sr-system", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=1, status="success", started_at=_now(), finished_at=_now())
            entry_run = BinarySecurityStageRun(id="sr-entry", task_id="t1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="success", started_at=_now(), finished_at=_now())
            dataflow_run = BinarySecurityStageRun(id="sr-df", task_id="t1", project_id="p1", stage_name="dataflow_analysis", sequence_no=3, status="failed", started_at=_now(), finished_at=_now(), last_error="dfa failed")
            vuln_run = BinarySecurityStageRun(id="sr-vuln", task_id="t1", project_id="p1", stage_name="vuln_scan", sequence_no=4, status="pending", started_at=_now())
            vuln_item = BinarySecurityStageItem(
                id="si-vuln",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr-vuln",
                stage_name="vuln_scan",
                item_key="entry-a",
                item_name="func_a",
                parent_key="mod-a",
                item_identity_key="entry-a::mod-a",
                status="pending",
                downstream_service="dataflow_vuln_scanner",
                downstream_task_id="dvs-1",
            )
            vuln_item.input_ref = {"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a", "upstream_item_id": "si-df"}
            downstream_event = BinarySecurityStateEvent(
                id="sev-vuln-success",
                task_id="t1",
                project_id="p1",
                stage_name="vuln_scan",
                item_id="si-vuln",
                event_type="downstream_status_observed",
                idempotency_key="sev-vuln-success",
                status="processing",
                leased_by=self.manager.instance_id,
                available_at=_now(),
                created_at=_now(),
            )
            downstream_event.payload = {
                "mapped_status": "success",
                "before_status": "pending",
                "downstream_status": "success",
                "downstream_payload": {"task_id": "dvs-1", "status": "success"},
            }
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[system_run, entry_run, dataflow_run, vuln_run], stage_items=[vuln_item], state_events=[downstream_event])

            original_factory = task_manager_module.get_session_factory
            original_write = self.manager._write_task_metadata_async
            original_acquire = self.manager._acquire_task_state_lease
            original_release = self.manager._release_task_state_lease
            task_manager_module.get_session_factory = lambda: (lambda: db)

            async def fake_write(*args, **kwargs):
                del args, kwargs
                return None

            self.manager._write_task_metadata_async = fake_write
            self.manager._acquire_task_state_lease = lambda _db, _task_id: "lease-1"
            self.manager._release_task_state_lease = lambda _db, _task_id, token=None, held_started=None: None
            try:
                asyncio.run(self.manager._reduce_state_event("sev-vuln-success"))
            finally:
                task_manager_module.get_session_factory = original_factory
                self.manager._write_task_metadata_async = original_write
                self.manager._acquire_task_state_lease = original_acquire
                self.manager._release_task_state_lease = original_release

            detail = self.manager.get_task_detail(db, project_id="p1", task_id="t1")
            observability = self.manager.get_orchestration_observability(db, project_id="p1", task_id="t1")
            self.assertEqual("partial_success", task.status)
            self.assertEqual("success", vuln_item.status)
            self.assertEqual("success", detail.stage_summaries[3].status)
            self.assertEqual("partial_success", detail.status)
            self.assertEqual("orchestration_failed", detail.abnormal_reason.code)
            self.assertTrue(detail.manual_operation_state["can_retry"])
            self.assertEqual(1, observability["state_events"]["status_counts"]["processed"])
            self.assertTrue(any(row.event_type == "task_finished" for row in db.events))

    def test_refresh_task_status_after_sync_does_not_resurrect_cancelled_task(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="cancelled",
            task_type=TASK_TYPE_BINARY,
            current_stage="binary_to_source",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="pod-a",
            dispatch_started_at=_now(),
            lease_expires_at=_now() + timedelta(minutes=1),
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="binary_to_source",
            sequence_no=3,
            status="running",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[run])

        self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("cancelled", task.status)
        self.assertIsNone(task.dispatcher_instance_id)
        self.assertIsNotNone(task.finished_at)

    def test_refresh_task_status_after_sync_keeps_failed_task_terminal_without_active_stage(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="pod-a",
            dispatch_started_at=_now(),
            lease_expires_at=_now() + timedelta(minutes=1),
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[])

        self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("failed", task.status)
        self.assertIsNone(task.dispatcher_instance_id)
        self.assertIsNotNone(task.finished_at)

    def test_refresh_task_status_after_sync_resurrects_failed_task_when_stage_retry_is_running(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="pod-a",
            dispatch_started_at=_now(),
            lease_expires_at=_now() + timedelta(minutes=1),
            last_error="old failed snapshot",
            finished_at=_now(),
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=4,
            status="running",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[run])

        self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("running", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertIsNone(task.dispatcher_instance_id)
        self.assertIsNone(task.dispatch_started_at)
        self.assertIsNone(task.lease_expires_at)
        self.assertIsNone(task.finished_at)
        self.assertIsNone(task.last_error)

    def test_get_task_detail_keeps_read_path_side_effect_free_when_stage_is_running(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="dispatching",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=2,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="system_analysis",
            item_key="fw-1",
            item_name="fw-1",
            item_identity_key="fw-1::",
            status="running",
            downstream_service="system_analyse",
            downstream_task_id="sat-1",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[run], stage_items=[item])

        detail = self.manager.get_task_detail(db, project_id="p1", task_id="t1")

        self.assertEqual("dispatching", detail.status)
        self.assertEqual("dispatching", task.status)
        self.assertEqual("running", next(summary.status for summary in detail.stage_summaries if summary.stage_name == "system_analysis"))

    def test_list_tasks_keeps_read_path_side_effect_free_when_stage_is_running(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="dispatching",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=2,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="system_analysis",
            item_key="fw-1",
            item_name="fw-1",
            item_identity_key="fw-1::",
            status="running",
            downstream_service="system_analyse",
            downstream_task_id="sat-1",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[run], stage_items=[item])

        response = self.manager.list_tasks(db, project_id="p1")

        self.assertEqual(1, response.total)
        self.assertEqual("dispatching", response.items[0].status)
        self.assertEqual("dispatching", task.status)

    def test_stage_run_output_summary_db_payload_is_hard_capped(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/missing",
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        huge_entries = [
            {
                "entry_key": f"e{i}",
                "module_key": "m",
                "module_name": "module",
                "function_name": "func",
                "function_description": "x" * 4000,
                "entry_reason": "y" * 4000,
                "taint_details": [{"name": "z" * 1000}],
                "source_dir": "/data/source",
            }
            for i in range(20)
        ]
        summary = {
            "status": "partial_success",
            "items": [{"module_key": "m", "module_name": "module", "entries": huge_entries}],
            "failed_items": [{"error": "boom" * 1000, "item": {"module_key": "m", "source_dir": "/data/source"}} for _ in range(20)],
        }

        compact = self.manager._compact_stage_output_summary_for_db(task, stage_run, summary, summary_file="/tmp/full.json")
        encoded = json.dumps(compact, ensure_ascii=False, default=str).encode("utf-8")

        self.assertLessEqual(len(encoded), 32768)
        self.assertTrue(compact.get("items_preview_truncated_for_db") or compact.get("db_summary_truncated"))
        self.assertEqual("/tmp/full.json", compact.get("summary_file"))

    def test_task_summary_falls_back_to_db_before_workspace_is_available(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="n",
            status="pending",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="",
        )

        task.summary = {"status": "created"}

        self.assertIsNotNone(task.summary_json)
        self.assertEqual({"status": "created"}, task.summary)

    def test_parse_system_analysis_modules_from_modules_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            modules_dir = root / "modules"
            (modules_dir / "busybox").mkdir(parents=True)
            (modules_dir / "dropbear").mkdir(parents=True)
            (root / "modules.list").write_text("busybox\ndropbear\n", encoding="utf-8")

            modules = self.manager._parse_system_analysis_modules(root, {
                "firmware_key": "fw1",
                "firmware_name": "fw1",
                "filename": "fw1.bin",
                "unpacked_root": str(root),
                "task_type": TASK_TYPE_BINARY,
            })

            self.assertEqual(2, len(modules))
            self.assertEqual("busybox", modules[0]["module_name"])
            self.assertTrue((root / "high_risk_modules.json").is_file())
            self.assertEqual(str((modules_dir / "busybox")), modules[0]["source_dir"])

    def test_parse_entries_prefers_json_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "result.json").write_text(
                '{"entries":[{"file_name":"main.c","function_name":"int handle_req(int argc, char **argv)","line_no":12}]}',
                encoding="utf-8",
            )

            rows = self.manager._parse_entries(root, {"module_key": "mod", "module_name": "mod", "source_dir": "/src"})

            self.assertEqual(1, len(rows))
            self.assertEqual("handle_req", rows[0]["function_name"])
            self.assertEqual("main.c", rows[0]["file_name"])
            self.assertEqual(["argc", "argv"], rows[0]["signature_params"])
            self.assertEqual("/src", rows[0]["source_dir"])
            self.assertIn("module_input_path", rows[0])
            self.assertIn("source_root_path", rows[0])

    def test_parse_entries_falls_back_to_markdown_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "entry-list.md").write_text(
                "| idx | no | file | function | line | desc | risk |\n| --- | --- | --- | --- | --- | --- | --- |\n| 1 | 1 | app.c | parse_input | 99 | d | h |\n",
                encoding="utf-8",
            )

            rows = self.manager._parse_entries(root, {"module_key": "mod", "module_name": "mod", "source_dir": "/src"})

            self.assertEqual(1, len(rows))
            self.assertEqual("parse_input", rows[0]["function_name"])

    def test_build_stage_summaries_aggregates_downstream_statuses(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="task", firmware_path="/tmp/in", output_root="/tmp/out", workspace_root="/tmp/ws", status="running", current_stage="firmware_unpack")
        stage_run = BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="pending")
        items = [
            BinarySecurityStageItem(id="i1", task_id="t1", project_id="p1", stage_run_id="sr1", stage_name="firmware_unpack", item_key="fw1", status="success"),
            BinarySecurityStageItem(id="i2", task_id="t1", project_id="p1", stage_run_id="sr1", stage_name="firmware_unpack", item_key="fw2", status="failed"),
        ]

        summaries = self.manager._build_stage_summaries(
            _ModelAwareDb(stage_runs=[stage_run], stage_items=items),
            task,
            ["firmware_unpack"],
            [stage_run],
            items,
        )

        self.assertEqual(1, len(summaries))
        self.assertEqual("partial_success", summaries[0].status)
        self.assertEqual(2, summaries[0].total_items)
        self.assertEqual(1, summaries[0].success_items)
        self.assertEqual(1, summaries[0].failed_items)

    def test_streaming_active_item_status_helper_normalizes_queue_states(self):
        self.assertTrue(self.manager._is_streaming_active_item_status("pending"))
        self.assertTrue(self.manager._is_streaming_active_item_status("queued"))
        self.assertTrue(self.manager._is_streaming_active_item_status("dispatching"))
        self.assertTrue(self.manager._is_streaming_active_item_status("running"))
        self.assertTrue(self.manager._is_streaming_active_item_status("processing"))
        self.assertFalse(self.manager._is_streaming_active_item_status("success"))
        self.assertFalse(self.manager._is_streaming_active_item_status("failed"))

    def test_refresh_streaming_tail_stage_state_dispatches_expected_rebuilders(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        db = _ModelAwareDb(tasks=[task])
        calls = []
        original_refresh = self.manager._refresh_stage_run_from_items
        original_rebuild_entry = self.manager._rebuild_entry_results_from_stage_items
        original_rebuild_summary = self.manager._rebuild_summary_results_from_stage_items
        try:
            self.manager._refresh_stage_run_from_items = lambda _db, _task, stage_name: calls.append(("refresh", stage_name))
            self.manager._rebuild_entry_results_from_stage_items = lambda _db, _task: calls.append(("entry", "entry_analysis"))
            self.manager._rebuild_summary_results_from_stage_items = lambda _db, _task, stage_name, summary_key: calls.append((stage_name, summary_key))

            self.manager._refresh_streaming_tail_stage_state(db, task, "entry_analysis")
            self.manager._refresh_streaming_tail_stage_state(db, task, "dataflow_analysis")
            self.manager._refresh_streaming_tail_stage_state(db, task, "vuln_scan")
        finally:
            self.manager._refresh_stage_run_from_items = original_refresh
            self.manager._rebuild_entry_results_from_stage_items = original_rebuild_entry
            self.manager._rebuild_summary_results_from_stage_items = original_rebuild_summary

        self.assertEqual(
            [
                ("refresh", "entry_analysis"),
                ("entry", "entry_analysis"),
                ("refresh", "dataflow_analysis"),
                ("dataflow_analysis", "dataflow_results"),
                ("refresh", "vuln_scan"),
                ("vuln_scan", "vuln_results"),
            ],
            calls,
        )

    def test_build_stage_summaries_keeps_streaming_tail_failed_status_without_items(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="task",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/tmp/in",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            status="failed",
            current_stage="dataflow_analysis",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            sequence_no=3,
            status="failed",
        )

        summaries = self.manager._build_stage_summaries(
            _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[]),
            task,
            ["system_analysis", "entry_analysis", "dataflow_analysis", "vuln_scan"],
            [stage_run],
            [],
        )

        by_stage = {summary.stage_name: summary for summary in summaries}
        self.assertEqual("failed", by_stage["dataflow_analysis"].status)

    def test_upstream_stage_retried_detects_previous_retry(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="task",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/tmp/in",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            status="failed",
        )
        stage_runs = [
            BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="success", retry_count=1),
            BinarySecurityStageRun(id="sr2", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=2, status="failed", retry_count=0),
        ]
        stage_items = [
            BinarySecurityStageItem(id="i1", task_id="t1", project_id="p1", stage_run_id="sr2", stage_name="system_analysis", item_key="fw1", parent_key="fw1", status="failed"),
        ]

        upstream_retried, upstream_stage = self.manager._upstream_stage_retried(
            _ModelAwareDb(tasks=[task], stage_runs=stage_runs, stage_items=stage_items),
            task,
            "system_analysis",
        )

        self.assertTrue(upstream_retried)
        self.assertEqual("firmware_unpack", upstream_stage)

    def test_upstream_stage_retried_ignores_retry_before_target_items_created(self):
        upstream_finished_at = datetime(2026, 5, 15, 19, 3, 33)
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            status="partial_success",
        )
        stage_runs = [
            BinarySecurityStageRun(
                id="sr1",
                task_id="s1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="success",
                retry_count=3,
                finished_at=upstream_finished_at,
            ),
            BinarySecurityStageRun(
                id="sr2",
                task_id="s1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="partial_success",
            ),
        ]
        stage_items = [
            BinarySecurityStageItem(
                id="i1",
                task_id="s1",
                project_id="p1",
                stage_run_id="sr2",
                stage_name="entry_analysis",
                item_key="m1",
                parent_key="source_project",
                item_identity_key="source_project::m1",
                status="failed",
                downstream_service="entry_analyse",
                created_at=upstream_finished_at + timedelta(hours=1),
            ),
        ]

        upstream_retried, upstream_stage = self.manager._upstream_stage_retried(
            _ModelAwareDb(tasks=[task], stage_runs=stage_runs, stage_items=stage_items),
            task,
            "entry_analysis",
        )

        self.assertFalse(upstream_retried)
        self.assertIsNone(upstream_stage)

    def test_stage_retry_failed_items_allows_fresh_items_after_upstream_retry(self):
        upstream_finished_at = datetime(2026, 5, 15, 19, 3, 33)
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            status="partial_success",
        )
        task.summary = {"selected_modules": [{"module_key": "m1", "module_name": "module1"}]}
        stage_runs = [
            BinarySecurityStageRun(
                id="sr1",
                task_id="s1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="success",
                retry_count=3,
                finished_at=upstream_finished_at,
            ),
            BinarySecurityStageRun(
                id="sr2",
                task_id="s1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="partial_success",
            ),
        ]
        stage_items = [
            BinarySecurityStageItem(
                id="i1",
                task_id="s1",
                project_id="p1",
                stage_run_id="sr2",
                stage_name="entry_analysis",
                item_key="m1",
                item_name="module1",
                parent_key="source_project",
                item_identity_key="source_project::m1",
                status="failed",
                downstream_service="entry_analyse",
                downstream_task_id="eat_1",
                created_at=upstream_finished_at + timedelta(hours=1),
            ),
        ]

        supported, reason, items = self.manager._stage_retry_failed_items_support(
            _ModelAwareDb(tasks=[task], stage_runs=stage_runs, stage_items=stage_items),
            task,
            "entry_analysis",
        )

        self.assertTrue(supported)
        self.assertIsNone(reason)
        self.assertEqual(["m1"], [item.item_key for item in items])

    def test_stage_retry_failed_items_requires_real_downstream_task(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            status="running",
        )
        task.summary = {"selected_modules": [{"module_key": "m1", "module_name": "module1"}]}
        stage_runs = [
            BinarySecurityStageRun(
                id="sr2",
                task_id="s1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="failed",
            ),
        ]
        stage_items = [
            BinarySecurityStageItem(
                id="i1",
                task_id="s1",
                project_id="p1",
                stage_run_id="sr2",
                stage_name="entry_analysis",
                item_key="m1",
                item_name="module1",
                parent_key="source_project",
                item_identity_key="source_project::m1",
                status="failed",
                downstream_service="entry_analyse",
                downstream_task_id=None,
            ),
        ]

        supported, reason, items = self.manager._stage_retry_failed_items_support(
            _ModelAwareDb(tasks=[task], stage_runs=stage_runs, stage_items=stage_items),
            task,
            "entry_analysis",
        )

        self.assertFalse(supported)
        self.assertEqual("当前阶段没有可重试的失败项", reason)
        self.assertEqual([], items)

    def test_manual_operation_state_allows_stage_failed_item_retry_while_task_running(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        stage_run = BinarySecurityStageRun(
            id="sr-entry",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=4,
            status="failed",
        )
        failed_item = BinarySecurityStageItem(
            id="si-entry",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr-entry",
            stage_name="entry_analysis",
            item_key="module-a",
            parent_key="source_project",
            item_identity_key="source_project::module-a",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="eat-1",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[failed_item])

        state = self.manager._build_manual_operation_state(
            db,
            task,
            task_retry_supported=False,
            task_retry_reason="当前任务正在执行或排队中，不能重试: running",
            task_retry_failed_supported=False,
            task_retry_failed_reason="当前任务正在执行或排队中，不能重试失败项: running",
            task_continue_supported=False,
            task_continue_reason="当前任务正在执行或排队中，不能手动继续: running",
            stage_summaries=[
                BinarySecurityStageSummary(
                    stage_name="entry_analysis",
                    sequence_no=4,
                    status="failed",
                    retry_failed_supported=True,
                )
            ],
        )

        self.assertEqual("ready", state["overall"])
        self.assertIsNone(state["blocking_code"])
        self.assertTrue(state["can_retry_stage_failed_items"])

    def test_upstream_stage_retried_blocks_items_created_before_upstream_retry_finished(self):
        upstream_finished_at = datetime(2026, 5, 15, 19, 3, 33)
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            status="partial_success",
        )
        stage_runs = [
            BinarySecurityStageRun(
                id="sr1",
                task_id="s1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="success",
                retry_count=1,
                finished_at=upstream_finished_at,
            ),
            BinarySecurityStageRun(
                id="sr2",
                task_id="s1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="partial_success",
            ),
        ]
        stage_items = [
            BinarySecurityStageItem(
                id="i1",
                task_id="s1",
                project_id="p1",
                stage_run_id="sr2",
                stage_name="entry_analysis",
                item_key="m1",
                parent_key="source_project",
                item_identity_key="source_project::m1",
                status="failed",
                downstream_service="entry_analyse",
                created_at=upstream_finished_at - timedelta(minutes=10),
            ),
        ]

        upstream_retried, upstream_stage = self.manager._upstream_stage_retried(
            _ModelAwareDb(tasks=[task], stage_runs=stage_runs, stage_items=stage_items),
            task,
            "entry_analysis",
        )

        self.assertTrue(upstream_retried)
        self.assertEqual("system_analysis", upstream_stage)

    def test_upstream_stage_retried_honors_stale_stage_marker(self):
        upstream_finished_at = datetime(2026, 5, 15, 19, 3, 33)
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            status="partial_success",
        )
        task.summary = {
            "stale_from_stage": "system_analysis",
            "stale_stages": ["entry_analysis"],
        }
        stage_runs = [
            BinarySecurityStageRun(
                id="sr1",
                task_id="s1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="success",
                retry_count=0,
                finished_at=upstream_finished_at,
            ),
        ]
        stage_items = [
            BinarySecurityStageItem(
                id="i1",
                task_id="s1",
                project_id="p1",
                stage_run_id="sr2",
                stage_name="entry_analysis",
                item_key="m1",
                status="failed",
                created_at=upstream_finished_at + timedelta(hours=1),
            ),
        ]

        upstream_retried, upstream_stage = self.manager._upstream_stage_retried(
            _ModelAwareDb(tasks=[task], stage_runs=stage_runs, stage_items=stage_items),
            task,
            "entry_analysis",
        )

        self.assertTrue(upstream_retried)
        self.assertEqual("system_analysis", upstream_stage)

    def test_prepare_stage_items_for_execution_only_requeues_selected_failed_items(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="task",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/tmp/in",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            status="failed",
        )
        task.summary = {
            "retry_plan": {
                "target_stage": "firmware_unpack",
                "mode": "retry_stage_failed_items",
                "retry_item_keys": ["fw2::fw2"],
            }
        }
        stage_run = BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="failed")
        existing_success = BinarySecurityStageItem(
            id="i1",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="firmware_unpack",
            item_key="fw1",
            item_name="fw1.bin",
            parent_key="fw1",
            item_identity_key="fw1::fw1",
            status="success",
        )
        db = _AppendingModelAwareDb(stage_runs=[stage_run], stage_items=[existing_success])

        executable_inputs = self.manager._prepare_stage_items_for_execution(
            db,
            task=task,
            stage_run=stage_run,
            inputs=[
                {"firmware_key": "fw1", "filename": "fw1.bin"},
                {"firmware_key": "fw2", "filename": "fw2.bin"},
            ],
            downstream_service="firmware_unpacker",
            identity=lambda input_file: (
                input_file["firmware_key"],
                input_file["filename"],
                input_file["firmware_key"],
                {"filename": input_file["filename"]},
            ),
            output_ref=lambda _input_file: {"downstream_service": "firmware_unpacker"},
        )

        self.assertEqual("success", existing_success.status)
        stage_item_keys = sorted(item.item_key for item in db.stage_items)
        self.assertEqual(["fw1", "fw2"], stage_item_keys)
        retried = next(item for item in db.stage_items if item.item_key == "fw2")
        self.assertEqual("queued", retried.status)
        self.assertEqual(["fw2"], [row["firmware_key"] for row in executable_inputs])

    def test_prepare_stage_items_for_execution_retries_retryable_deadlock(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="task",
            task_type=TASK_TYPE_BINARY_MODULE,
            firmware_source="project_filesystem",
            firmware_path="/tmp/in",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            status="running",
        )
        task.policy = {"stage_item_seed_batch_size": 50}
        stage_run = BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="dataflow_analysis", sequence_no=4, status="running")
        db = _FlakyCommitDb(
            stage_runs=[stage_run],
            stage_items=[],
            fail_commits=1,
            error_factory=_deadlock_operational_error,
        )

        executable_inputs = self.manager._prepare_stage_items_for_execution(
            db,
            task=task,
            stage_run=stage_run,
            inputs=[
                {"entry_key": "e1", "function_name": "fn1", "module_key": "mod-a"},
                {"entry_key": "e2", "function_name": "fn2", "module_key": "mod-a"},
            ],
            downstream_service="dataflow_analyse",
            identity=lambda entry: (
                entry["entry_key"],
                entry["function_name"],
                entry.get("module_key"),
                entry,
            ),
            output_ref=lambda _entry: {},
        )

        self.assertEqual(2, len(executable_inputs))
        self.assertEqual(2, len(db.stage_items))
        self.assertGreaterEqual(db.rollback_calls, 1)
        self.assertGreaterEqual(db.commit_calls, 2)

    def test_stage_entry_analysis_only_runs_retry_plan_items(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            status="running",
        )
        task.policy = {}
        task.summary = {
            "selected_modules": [
                {"firmware_key": "source_project", "module_key": "m1", "module_name": "m1", "source_dir": "/src/m1"},
                {"firmware_key": "source_project", "module_key": "m2", "module_name": "m2", "source_dir": "/src/m2"},
                {"firmware_key": "source_project", "module_key": "m3", "module_name": "m3", "source_dir": "/src/m3"},
            ],
            "retry_plan": {
                "target_stage": "entry_analysis",
                "mode": "retry_stage_failed_items",
                "retry_item_keys": ["m2::source_project"],
            },
        }
        stage_run = BinarySecurityStageRun(
            id="sr-entry",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run])
        captured = {}

        async def fake_run_stage_pool(current_task, items, concurrency, runner, retries=0, initial_retry=False):
            del current_task, concurrency, runner, retries, initial_retry
            captured["items"] = items
            return [{"status": "success", "item": items[0], "entries": [{"entry_key": "e1", "function_name": "main"}]}]

        original_run_stage_pool = self.manager._run_stage_pool
        self.manager._run_stage_pool = fake_run_stage_pool
        try:
            status, summary = asyncio.run(self.manager._stage_entry_analysis(db, task, stage_run, token=None, retry_existing=True))
        finally:
            self.manager._run_stage_pool = original_run_stage_pool

        self.assertEqual("success", status)
        self.assertEqual(["m2"], [row["module_key"] for row in captured["items"]])
        self.assertEqual(["m2"], [item.item_key for item in db.stage_items])
        self.assertEqual(1, summary["success_count"])

    def test_task_operation_lock_uses_bound_text_query_and_releases_lock(self):
        connection = _FakeConnection(lock_result=True)
        db = _LockingDb(connection)
        with self.manager._task_operation_lock(db, "task-1", operation="unit_test"):
            pass

        self.assertEqual(2, len(connection.calls))
        self.assertIn("GET_LOCK", connection.calls[0][0])
        self.assertEqual("secflow_binary_security_task_lock:task-1", connection.calls[0][1]["name"])
        self.assertIn("RELEASE_LOCK", connection.calls[1][0])

    def test_task_operation_lock_rejects_when_named_lock_not_acquired(self):
        connection = _FakeConnection(lock_result=False)
        db = _LockingDb(connection)
        with self.assertRaises(ValidationError):
            with self.manager._task_operation_lock(db, "task-1", operation="unit_test"):
                pass

    def test_runtime_status_reports_dispatch_loops(self):
        self.manager._running = True

        class _Task:
            def __init__(self, done):
                self._done = done

            def done(self):
                return self._done

        self.manager._loop_task = _Task(False)
        self.manager._action_loop_task = _Task(False)
        self.manager._archive_loop_task = _Task(True)
        self.manager._stage_item_loop_task = _Task(True)
        self.manager._downstream_reconcile_task = _Task(False)

        status = self.manager.runtime_status()

        self.assertTrue(status["running"])
        self.assertEqual(
            {
                "task_dispatch": True,
                "action_dispatch": True,
                "archive_dispatch": False,
                "stage_item_dispatch": False,
                "downstream_reconcile": True,
                "state_reducer": False,
                "reducer_metrics_snapshot": False,
            },
            status["loops"],
        )

    def test_aggregate_archive_stage_status_supports_applying(self):
        self.assertEqual("pending", self.manager._aggregate_archive_stage_status([]))
        self.assertEqual("running", self.manager._aggregate_archive_stage_status(["pending", "running"]))
        self.assertEqual("applying", self.manager._aggregate_archive_stage_status(["archived"]))
        self.assertEqual("failed", self.manager._aggregate_archive_stage_status(["failed"]))
        self.assertEqual("success", self.manager._aggregate_archive_stage_status(["success", "success"]))

    def test_build_stage_overview_nodes_returns_business_then_archive(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="task", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/tmp/in", output_root="/tmp/out", workspace_root="/tmp/ws", status="running")
        summaries = [
            self.manager._build_stage_summaries(
                _ModelAwareDb(),
                task,
                ["firmware_unpack"],
                [BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="success")],
                [BinarySecurityStageItem(id="i1", task_id="t1", project_id="p1", stage_run_id="sr1", stage_name="firmware_unpack", item_key="fw1", status="success")],
            )[0]
        ]
        archive_jobs = [
            BinarySecurityArchiveJobResponse(
                id="aj1",
                stage_name="firmware_unpack",
                item_id="i1",
                item_key="fw1",
                archive_status="running",
            )
        ]

        stage_items = [
            BinarySecurityStageItem(
                id="i1",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr1",
                stage_name="firmware_unpack",
                item_key="fw1",
                status="success",
                downstream_service="firmware_unpacker",
                downstream_task_id="d1",
            )
        ]
        nodes = self.manager._build_stage_overview_nodes(_ModelAwareDb(), task, summaries, archive_jobs, stage_items)

        self.assertEqual("business:firmware_unpack", nodes[0].node_id)
        self.assertEqual("archive:firmware_unpack", nodes[1].node_id)
        self.assertEqual("success", nodes[0].status)
        self.assertEqual("running", nodes[1].status)
        self.assertEqual("fw1", nodes[0].detail.representative_item_key)
        self.assertEqual("d1", nodes[0].detail.representative_downstream_task_id)
        self.assertEqual(["firmware_unpacker"], nodes[0].detail.downstream_services)

    def test_build_stage_overview_nodes_keeps_archive_pending_when_some_items_not_terminal(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="task",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/tmp/in",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            status="running",
        )
        summaries = [
            self.manager._build_stage_summaries(
                _ModelAwareDb(),
                task,
                ["entry_analysis"],
                [BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="running")],
                [
                    BinarySecurityStageItem(id="i1", task_id="t1", project_id="p1", stage_run_id="sr1", stage_name="entry_analysis", item_key="m1", status="success"),
                    BinarySecurityStageItem(id="i2", task_id="t1", project_id="p1", stage_run_id="sr1", stage_name="entry_analysis", item_key="m2", status="running"),
                ],
            )[0]
        ]
        archive_jobs = [
            BinarySecurityArchiveJobResponse(
                id="aj1",
                stage_name="entry_analysis",
                item_id="i1",
                item_key="m1",
                archive_status="success",
            )
        ]
        stage_items = [
            BinarySecurityStageItem(
                id="i1",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr1",
                stage_name="entry_analysis",
                item_key="m1",
                status="success",
                downstream_service="entry_analyse",
                downstream_task_id="d1",
            ),
            BinarySecurityStageItem(
                id="i2",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr1",
                stage_name="entry_analysis",
                item_key="m2",
                status="running",
                downstream_service="entry_analyse",
                downstream_task_id="d2",
            ),
        ]

        nodes = self.manager._build_stage_overview_nodes(_ModelAwareDb(), task, summaries, archive_jobs, stage_items)
        by_node_id = {node.node_id: node for node in nodes}

        self.assertEqual("pending", by_node_id["archive:entry_analysis"].status)

    def test_choose_module_binary_handles_relative_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unpacked = root / "unpacked"
            module_dir = unpacked / "modules" / "openssl"
            module_dir.mkdir(parents=True)
            target = unpacked / "bin" / "openssl.elf"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"elf")
            (module_dir / "files.list").write_text("bin/openssl.elf\n", encoding="utf-8")

            path = self.manager._choose_module_binary(
                {
                    "module_name": "openssl",
                    "module_dir": str(module_dir),
                    "files_list": str(module_dir / "files.list"),
                    "unpacked_root": str(unpacked),
                }
            )

            self.assertEqual(str(target.resolve()), path)

    def test_resolve_module_binary_paths_returns_all_module_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unpacked = root / "unpacked"
            module_dir = unpacked / "modules" / "ipsec"
            module_dir.mkdir(parents=True)
            first = unpacked / "lib" / "libipsecluaext-ppc_rtos.so"
            second = unpacked / "module" / "libipsec-ppc_rtos.so"
            first.parent.mkdir(parents=True)
            second.parent.mkdir(parents=True)
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            (module_dir / "files.list").write_text(
                "lib/libipsecluaext-ppc_rtos.so\nmodule/libipsec-ppc_rtos.so\n",
                encoding="utf-8",
            )

            paths = self.manager._resolve_module_binary_paths(
                {
                    "module_name": "ipsec",
                    "module_dir": str(module_dir),
                    "files_list": str(module_dir / "files.list"),
                    "unpacked_root": str(unpacked),
                }
            )

            self.assertEqual([str(first.resolve()), str(second.resolve())], paths)

    def test_build_module_elf_tasks_creates_one_task_per_module_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unpacked = root / "unpacked"
            module_dir = unpacked / "modules" / "ipsec"
            module_dir.mkdir(parents=True)
            first = unpacked / "lib" / "libipsecluaext-ppc_rtos.so"
            second = unpacked / "module" / "libipsec-ppc_rtos.so"
            first.parent.mkdir(parents=True)
            second.parent.mkdir(parents=True)
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            (module_dir / "files.list").write_text(
                "lib/libipsecluaext-ppc_rtos.so\nmodule/libipsec-ppc_rtos.so\n",
                encoding="utf-8",
            )

            elf_tasks = self.manager._build_module_elf_tasks(
                {
                    "module_key": "fw-ipsec",
                    "module_name": "ipsec",
                    "module_dir": str(module_dir),
                    "files_list": str(module_dir / "files.list"),
                    "unpacked_root": str(unpacked),
                    "risk_level": "高",
                }
            )

            self.assertEqual(2, len(elf_tasks))
            self.assertEqual(str(first.resolve()), elf_tasks[0]["elf_path"])
            self.assertEqual(str(second.resolve()), elf_tasks[1]["elf_path"])
            self.assertEqual(1, elf_tasks[0]["metadata"]["module_file_index"])
            self.assertEqual(2, elf_tasks[1]["metadata"]["module_file_count"])
            self.assertEqual(
                [str(first.resolve()), str(second.resolve())],
                elf_tasks[0]["metadata"]["module_all_elf_paths"],
            )


class BinaryToSourceClientTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.manager = TaskManager()

    def _finish_continue_prepare(self, db, task, target_stage: str) -> None:
        asyncio.run(self.manager._prepare_continue_task(db, task, target_stage))
        task.status = "pending"
        task.current_stage = target_stage
        task.execution_mode = "task_retry"
        task.target_stage_name = target_stage
        task.pending_action = None

    def _finish_retry_prepare(self, db, task) -> None:
        stage_sequence = asyncio.run(self.manager._prepare_retry_task(db, task))
        task.status = "pending"
        task.current_stage = stage_sequence[0]
        task.execution_mode = None
        task.target_stage_name = None
        task.pending_action = None

    async def test_create_task_preserves_multiple_elf_tasks(self):
        from app.service.binary_to_source import BinaryToSourceClient

        client = BinaryToSourceClient()
        recorded = {}

        async def fake_post(path, *, token=None, json_body=None):
            recorded["path"] = path
            recorded["token"] = token
            recorded["json_body"] = json_body
            return {"id": "task1"}

        client.post = fake_post

        elf_tasks = [
            {"elf_path": "/tmp/first.so", "file_list": [], "metadata": {"module_file_index": 1}},
            {"elf_path": "/tmp/second.so", "file_list": [], "metadata": {"module_file_index": 2}},
        ]
        result = await client.create_task("p1", "ipsec", elf_tasks, "token123", {"parent_task_id": "bs1"})

        self.assertEqual({"id": "task1"}, result)
        self.assertEqual("/projects/p1/tasks", recorded["path"])
        self.assertEqual("token123", recorded["token"])
        self.assertEqual(elf_tasks, recorded["json_body"]["elf_tasks"])
        self.assertEqual("bs1", recorded["json_body"]["parent_task_id"])

    async def test_create_task_rejects_binary_module_without_module_name(self):
        payload = BinarySecurityTaskCreate(
            task_id="bm1",
            task_type=TASK_TYPE_BINARY_MODULE,
            name="binary-module-task",
            input_files=[BinarySecurityInputFile(filename="libipsec.so", size=12)],
        )

        with self.assertRaisesRegex(ValidationError, "必须填写模块名"):
            await self.manager.create_task(
                _FakeDb(),
                project_id="p1",
                payload=payload,
                created_by="tester",
                authorization_token="token",
            )

    async def test_create_task_uses_project_pipeline_mode_when_no_override(self):
        payload = BinarySecurityTaskCreate(
            task_id="t1",
            task_type=TASK_TYPE_SOURCE,
            name="source-task",
            input_files=[BinarySecurityInputFile(filename="src.zip", size=12)],
        )
        row = BinarySecurityProjectConfig(project_id="p1")
        row.config = {"pipeline_mode": "mixed_streaming"}
        db = _AppendingModelAwareDb(project_configs=[row])

        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "task-root"
            with (
                patch.object(task_manager_module, "app_task_root", return_value=workspace),
                patch.object(self.manager, "_init_workspace_async", unittest.mock.AsyncMock()),
                patch.object(self.manager, "_ensure_task_directories", unittest.mock.AsyncMock()),
                patch.object(self.manager, "_write_task_metadata_async", unittest.mock.AsyncMock()),
                patch.object(
                    self.manager,
                    "get_task_detail",
                    side_effect=lambda _db, project_id, task_id: SimpleNamespace(
                        id=task_id,
                        project_id=project_id,
                        policy=dict(_db.tasks[-1].policy or {}),
                    ),
                ),
            ):
                detail = await self.manager.create_task(
                    db,
                    project_id="p1",
                    payload=payload,
                    created_by="tester",
                    authorization_token="token",
                )

        self.assertEqual("mixed_streaming", detail.policy["pipeline_mode"])
        self.assertEqual("mixed_streaming", db.tasks[-1].policy["pipeline_mode"])

    async def test_create_task_override_pipeline_mode_wins_after_normalization(self):
        payload = BinarySecurityTaskCreate(
            task_id="t1",
            task_type=TASK_TYPE_SOURCE,
            name="source-task",
            input_files=[BinarySecurityInputFile(filename="src.zip", size=12)],
            policy_overrides={"pipeline_mode": "unexpected-mode"},
        )
        row = BinarySecurityProjectConfig(project_id="p1")
        row.config = {"pipeline_mode": "mixed_streaming"}
        db = _AppendingModelAwareDb(project_configs=[row])

        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "task-root"
            with (
                patch.object(task_manager_module, "app_task_root", return_value=workspace),
                patch.object(self.manager, "_init_workspace_async", unittest.mock.AsyncMock()),
                patch.object(self.manager, "_ensure_task_directories", unittest.mock.AsyncMock()),
                patch.object(self.manager, "_write_task_metadata_async", unittest.mock.AsyncMock()),
                patch.object(
                    self.manager,
                    "get_task_detail",
                    side_effect=lambda _db, project_id, task_id: SimpleNamespace(
                        id=task_id,
                        project_id=project_id,
                        policy=dict(_db.tasks[-1].policy or {}),
                    ),
                ),
            ):
                detail = await self.manager.create_task(
                    db,
                    project_id="p1",
                    payload=payload,
                    created_by="tester",
                    authorization_token="token",
                )

        self.assertEqual("barrier", detail.policy["pipeline_mode"])
        self.assertEqual("barrier", db.tasks[-1].policy["pipeline_mode"])

    async def test_complete_uploads_populates_binary_module_summary_and_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            input_dir = workspace / "input"
            input_dir.mkdir(parents=True)
            elf_rel = "mod/libipsec.so"
            elf_path = input_dir / elf_rel
            elf_path.parent.mkdir(parents=True, exist_ok=True)
            elf_path.write_bytes(b"\x7fELFdemo")

            task = BinarySecurityTask(
                id="bm1",
                project_id="p1",
                name="binary-module-task",
                task_type=TASK_TYPE_BINARY_MODULE,
                status="pending_upload",
                firmware_source="project_filesystem",
                firmware_path=str(input_dir),
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            task.summary = {
                "input_dir": str(input_dir),
                "input_kind": "module_elf_files",
                "module_input": {"module_name": "ipsec"},
                "input_files": [{"filename": "libipsec.so", "relative_path": elf_rel}],
            }
            task.metrics = {}
            db = _ModelAwareDb(tasks=[task], stage_runs=[], stage_items=[], archive_jobs=[])

            def _fake_start_task(_db, *, project_id, task_id):
                self.assertEqual("p1", project_id)
                self.assertEqual("bm1", task_id)
                return self.manager.get_task_detail(_db, project_id=project_id, task_id=task_id)

            original_start_task = self.manager.start_task
            original_build_queue_info = self.manager._build_queue_info
            self.manager.start_task = _fake_start_task
            self.manager._build_queue_info = lambda *_args, **_kwargs: {"pending_positions": {}, "running_count": 0, "queued_count": 0, "max_concurrent_tasks": 0}
            try:
                detail = await self.manager.complete_uploads(
                    db,
                    project_id="p1",
                    task_id="bm1",
                    payload=BinarySecurityUploadCompletePayload(
                        files=[BinarySecurityInputFile(filename="libipsec.so", relative_path=elf_rel)]
                    ),
                    updated_by="tester",
                    authorization_token="token",
                )
            finally:
                self.manager.start_task = original_start_task
                self.manager._build_queue_info = original_build_queue_info

            self.assertEqual("ready_to_start", task.status)
            self.assertTrue(task.summary["system_analysis_bypassed"])
            self.assertEqual("module_elf_files", task.summary["input_kind"])
            self.assertEqual("ipsec", task.summary["module_input"]["module_name"])
            self.assertEqual(1, len(task.summary["selected_modules"]))
            self.assertEqual(TASK_TYPE_BINARY_MODULE, task.summary["selected_modules"][0]["task_type"])
            self.assertEqual(1, task.metrics["selected_module_count"])
            self.assertEqual(1, task.metrics["candidate_module_count"])
            self.assertEqual(1, task.metrics["uploaded_file_count"])
            self.assertEqual("ready_to_start", detail.status)

    def test_build_project_stats_aggregates_task_metrics(self):
        success = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="success",
            status="success",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw1",
            output_root="/o1",
            workspace_root="/w1",
        )
        success.metrics = {
            "firmware_item_count": 2,
            "unpacked_firmware_count": 2,
            "failed_firmware_count": 0,
            "selected_module_count": 3,
            "candidate_module_count": 5,
            "high_risk_module_count": 1,
            "entry_count": 7,
            "vuln_result_count": 11,
        }
        running = BinarySecurityTask(
            id="t2",
            project_id="p1",
            name="running",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw2",
            output_root="/o2",
            workspace_root="/w2",
        )
        running.metrics = {
            "firmware_item_count": 1,
            "unpacked_firmware_count": 0,
            "failed_firmware_count": 1,
            "selected_module_count": 2,
            "candidate_module_count": 4,
            "high_risk_module_count": 2,
            "entry_count": 6,
            "vuln_result_count": 10,
        }

        stats = self.manager._build_project_stats([success, running])

        self.assertEqual(2, stats.total)
        self.assertEqual(1, stats.success)
        self.assertEqual(1, stats.running)
        self.assertEqual(3, stats.input_count)
        self.assertEqual(2, stats.unpacked_firmware_count)
        self.assertEqual(1, stats.failed_firmware_count)
        self.assertEqual(5, stats.selected_module_count)
        self.assertEqual(9, stats.candidate_module_count)
        self.assertEqual(3, stats.high_risk_module_count)
        self.assertEqual(13, stats.entry_count)
        self.assertEqual(21, stats.vuln_result_count)

    def test_build_project_stage_aggregates_includes_binary_stage_defaults(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[
                SimpleNamespace(task_id="t1", stage_name="firmware_unpack"),
                SimpleNamespace(task_id="t1", stage_name="system_analysis"),
            ],
            stage_items=[
                SimpleNamespace(task_id="t1", stage_name="firmware_unpack", status="success"),
                SimpleNamespace(task_id="t1", stage_name="system_analysis", status="failed"),
                SimpleNamespace(task_id="t1", stage_name="system_analysis", status="running"),
                SimpleNamespace(task_id="t1", stage_name="system_analysis", status="cancelled"),
            ],
            archive_jobs=[
                SimpleNamespace(task_id="t1", stage_name="firmware_unpack", archive_status="success"),
                SimpleNamespace(task_id="t1", stage_name="system_analysis", archive_status="applying"),
                SimpleNamespace(task_id="t1", stage_name="system_analysis", archive_status="pending"),
                SimpleNamespace(task_id="t1", stage_name="system_analysis", archive_status="failed"),
            ],
        )

        aggregates = self.manager._build_project_stage_aggregates(db, [task], TASK_TYPE_BINARY)
        by_stage = {item.stage_name: item for item in aggregates}

        self.assertEqual(
            ["firmware_unpack", "system_analysis", "binary_to_source", "entry_analysis", "dataflow_analysis", "vuln_scan"],
            [item.stage_name for item in aggregates],
        )
        self.assertEqual(1, by_stage["system_analysis"].business.task_count)
        self.assertEqual(3, by_stage["system_analysis"].business.total_items)
        self.assertEqual(1, by_stage["system_analysis"].business.failed_items)
        self.assertEqual(1, by_stage["system_analysis"].business.running_items)
        self.assertEqual(1, by_stage["system_analysis"].business.cancelled_items)
        self.assertEqual({"failed": 1, "running": 1, "cancelled": 1}, by_stage["system_analysis"].business.status_counts)
        self.assertEqual(3, by_stage["system_analysis"].archive.job_count)
        self.assertEqual(1, by_stage["system_analysis"].archive.failed_count)
        self.assertEqual(1, by_stage["system_analysis"].archive.applying_count)
        self.assertEqual(1, by_stage["system_analysis"].archive.pending_count)
        self.assertEqual(0, by_stage["binary_to_source"].business.total_items)
        self.assertEqual(0, by_stage["binary_to_source"].archive.job_count)

    def test_build_project_stage_aggregates_uses_source_stage_sequence(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src.zip",
            output_root="/o",
            workspace_root="/w",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[SimpleNamespace(task_id="t1", stage_name="system_analysis")],
            stage_items=[SimpleNamespace(task_id="t1", stage_name="system_analysis", status="success")],
            archive_jobs=[SimpleNamespace(task_id="t1", stage_name="system_analysis", archive_status="success")],
        )

        aggregates = self.manager._build_project_stage_aggregates(db, [task], TASK_TYPE_SOURCE)

        self.assertEqual(
            ["system_analysis", "entry_analysis", "dataflow_analysis", "vuln_scan"],
            [item.stage_name for item in aggregates],
        )
        self.assertNotIn("firmware_unpack", [item.stage_name for item in aggregates])
        self.assertEqual(1, aggregates[0].business.success_items)
        self.assertEqual(1, aggregates[0].archive.success_count)

    def test_aggregate_stage_items_marks_partial_success(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.summary = {}
        db = _FakeDb()

        status, summary = self.manager._aggregate_stage_items(
            db,
            task,
            results=[
                {
                    "status": "success",
                    "item": {
                        "firmware_key": "fw1",
                        "firmware_name": "fw.bin",
                        "filename": "fw.bin",
                        "unpacked_root": "/tmp/unpacked",
                        "source_root": "/tmp/unpacked",
                        "module_key": "m1",
                        "module_name": "openssl",
                        "module_dir": "/tmp/unpacked/modules/openssl",
                        "source_dir": "/tmp/archive/openssl",
                    },
                },
                {"status": "failed", "item": {"id": "b"}, "error": "boom"},
            ],
            summary_key="b2s_results",
        )

        self.assertEqual("partial_success", status)
        self.assertEqual(1, summary["success_count"])
        self.assertEqual(1, summary["failed_count"])
        self.assertEqual(
            [
                {
                    "firmware_key": "fw1",
                    "firmware_name": "fw.bin",
                    "filename": "fw.bin",
                    "unpacked_root": "/tmp/unpacked",
                    "source_root": "/tmp/unpacked",
                    "task_type": None,
                    "module_key": "m1",
                    "module_name": "openssl",
                    "module_dir": "/tmp/unpacked/modules/openssl",
                    "source_dir": "/tmp/archive/openssl",
                    "module_report": None,
                    "files_list": None,
                    "entry_module_name": None,
                    "entry_descriptor_root": None,
                    "entry_files_list": None,
                    "entry_source_file_count": None,
                    "entry_source_files_preview": None,
                    "entry_descriptor_ready": False,
                    "primary_result_kind": None,
                    "result_kinds": [],
                    "artifact_kind_summary": {},
                    "result_kind_summary": {},
                    "artifact_index_path": None,
                    "result_summary_version": 1,
                }
            ],
            task.summary["b2s_results"],
        )
        self.assertEqual(1, db.commits)

    def test_aggregate_stage_items_marks_downstream_missing_as_failed(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.summary = {}
        db = _FakeDb()

        status, summary = self.manager._aggregate_stage_items(
            db,
            task,
            results=[
                {"status": "downstream_missing", "item": {"id": "a"}, "error": "missing"},
            ],
            summary_key="b2s_results",
        )

        self.assertEqual("failed", status)
        self.assertEqual(1, summary["failed_count"])
        self.assertEqual(1, summary["downstream_missing_count"])
        self.assertEqual("missing", summary["error"])

    def test_aggregate_stage_items_marks_partial_success_with_success_and_downstream_missing(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.summary = {}
        db = _FakeDb()

        status, summary = self.manager._aggregate_stage_items(
            db,
            task,
            results=[
                {
                    "status": "success",
                    "item": {
                        "firmware_key": "fw1",
                        "firmware_name": "fw.bin",
                        "filename": "fw.bin",
                        "unpacked_root": "/tmp/unpacked",
                        "source_root": "/tmp/unpacked",
                        "module_key": "m1",
                        "module_name": "openssl",
                        "module_dir": "/tmp/unpacked/modules/openssl",
                        "source_dir": "/tmp/archive/openssl",
                    },
                },
                {"status": "downstream_missing", "item": {"id": "b"}, "error": "missing"},
            ],
            summary_key="b2s_results",
        )

        self.assertEqual("partial_success", status)
        self.assertEqual(1, summary["success_count"])
        self.assertEqual(1, summary["failed_count"])
        self.assertEqual(1, summary["downstream_missing_count"])

    def test_aggregate_stage_items_compacts_b2s_results_for_summary_storage(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.summary = {}
        db = _FakeDb()

        status, summary = self.manager._aggregate_stage_items(
            db,
            task,
            results=[
                {
                    "status": "success",
                    "item": {
                        "firmware_key": "fw1",
                        "firmware_name": "fw.bin",
                        "filename": "fw.bin",
                        "unpacked_root": "/tmp/unpacked",
                        "source_root": "/tmp/unpacked",
                        "module_key": "m1",
                        "module_name": "openssl",
                        "module_dir": "/tmp/unpacked/modules/openssl",
                        "source_dir": "/tmp/archive/openssl",
                        "module_report": "/tmp/archive/openssl/report.md",
                        "files_list": "/tmp/archive/openssl/files.list",
                        "primary_result_kind": "recovered_source",
                        "result_kinds": ["recovered_source", "recovered_header"],
                        "artifact_kind_summary": {"source": 10, "header": 2},
                        "result_kind_summary": {"recovered_source": 10, "recovered_header": 2},
                        "artifact_index_path": "/tmp/archive/openssl/artifacts/index.json",
                        "result_summary_version": 1,
                        "generated_files": [f"/tmp/archive/openssl/{idx}.c" for idx in range(100)],
                        "downstream": {"items": [{"huge": "x" * 1000} for _ in range(100)]},
                    },
                }
            ],
            summary_key="b2s_results",
        )

        self.assertEqual("success", status)
        stored = task.summary["b2s_results"][0]
        self.assertEqual("m1", stored["module_key"])
        self.assertEqual("/tmp/archive/openssl", stored["source_dir"])
        self.assertEqual("recovered_source", stored["primary_result_kind"])
        self.assertEqual(["recovered_source", "recovered_header"], stored["result_kinds"])
        self.assertEqual({"source": 10, "header": 2}, stored["artifact_kind_summary"])
        self.assertEqual("/tmp/archive/openssl/artifacts/index.json", stored["artifact_index_path"])
        self.assertNotIn("generated_files", stored)
        self.assertNotIn("downstream", stored)
        self.assertEqual(stored, summary["items"][0])

    def test_entry_results_keep_entries_but_drop_downstream_payload(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.summary = {}
        db = _FakeDb()

        _, summary = self.manager._aggregate_stage_items(
            db,
            task,
            results=[
                {
                    "status": "success",
                    "item": {
                        "module_key": "m1",
                        "module_name": "openssl",
                        "source_dir": "/tmp/archive/openssl",
                        "artifact_root": "/tmp/archive/openssl/entry",
                        "entries": [
                            {
                                "entry_key": "e1",
                                "module_key": "m1",
                                "module_name": "openssl",
                                "file_name": "main.c",
                                "function_name": "main",
                                "raw_function_name": "main",
                                "line_no": "10",
                                "definition_file": "src/main.c",
                                "definition_line": "42",
                                "is_definition_found": True,
                                "taint_params": ["argv", ""],
                                "signature_params": ["argc", "argv"],
                                "source_dir": "/tmp/archive/openssl",
                                "extra_blob": "x" * 4000,
                            }
                        ],
                        "downstream": {"result": {"entries": [{"blob": "y" * 4000}]}},
                    },
                }
            ],
            summary_key="entry_results",
        )

        stored = task.summary["entry_results"][0]
        self.assertEqual("e1", stored["entries"][0]["entry_key"])
        self.assertEqual("src/main.c", stored["entries"][0]["definition_file"])
        self.assertEqual("42", stored["entries"][0]["definition_line"])
        self.assertTrue(stored["entries"][0]["is_definition_found"])
        self.assertEqual(["argv"], stored["entries"][0]["taint_params"])
        self.assertEqual(["argc", "argv"], stored["entries"][0]["signature_params"])
        self.assertNotIn("extra_blob", stored["entries"][0])
        self.assertNotIn("downstream", stored)
        self.assertEqual(1, summary["entry_count"])
        self.assertNotIn("entries", summary["items"][0])
        self.assertEqual("e1", summary["items"][0]["entries_preview"][0]["entry_key"])
        self.assertEqual(["argv"], summary["items"][0]["entries_preview"][0]["taint_params"])

    def test_entry_results_default_missing_taints_to_all_signature_params(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.summary = {}
        db = _FakeDb()

        self.manager._aggregate_stage_items(
            db,
            task,
            results=[
                {
                    "status": "success",
                    "item": {
                        "module_key": "m1",
                        "module_name": "openssl",
                        "source_dir": "/tmp/archive/openssl",
                        "entries": [
                            {
                                "entry_key": "e1",
                                "module_key": "m1",
                                "module_name": "openssl",
                                "file_name": "main.c",
                                "function_name": "main",
                                "raw_function_name": "int main(int argc, char **argv)",
                                "line_no": "10",
                                "signature_params": ["argc", "argv"],
                                "source_dir": "/tmp/archive/openssl",
                            }
                        ],
                    },
                }
            ],
            summary_key="entry_results",
        )

        stored = task.summary["entry_results"][0]["entries"][0]
        self.assertEqual(["argc", "argv"], stored["signature_params"])
        self.assertEqual(["argc", "argv"], stored["taint_params"])

    def test_rebuild_entry_results_from_synced_stage_items_uses_archive_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            artifact = workspace / "output" / "entry"
            artifact.mkdir(parents=True)
            (artifact / "functions.list").write_text(
                """[
  {"file": "main.c", "line": 10, "function": "main(int argc, char **argv)", "taints": ["argv"]}
]""",
                encoding="utf-8",
            )
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            task.summary = {}
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="success",
            )
            stage_run.counts = {"total_items": 1, "success_items": 1, "failed_items": 0, "cancelled_items": 0}
            item = BinarySecurityStageItem(
                id="i1",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr1",
                stage_name="entry_analysis",
                item_key="mod1",
                item_name="mod",
                status="success",
            )
            item.input_ref = {"module_key": "mod1", "module_name": "mod", "source_dir": "/src/mod", "task_type": TASK_TYPE_SOURCE}
            item.output_ref = {"artifact_root": str(artifact)}
            db = _ModelAwareDb(stage_runs=[stage_run], stage_items=[item])

            rebuilt = self.manager._rebuild_entry_results_from_stage_items(db, task, stage_run)

            self.assertEqual(1, len(rebuilt))
            self.assertEqual(1, len(task.summary["entry_results"][0]["entries"]))
            self.assertEqual("main", task.summary["entry_results"][0]["entries"][0]["function_name"])
            self.assertEqual(1, task.metrics["entry_count"])
            self.assertEqual(1, stage_run.output_summary["entry_count"])

    def test_dataflow_stage_backfills_missing_entry_results_before_failing_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            artifact = workspace / "output" / "entry"
            artifact.mkdir(parents=True)
            (artifact / "functions.list").write_text(
                '[{"file":"main.c","line":10,"function":"main(int argc, char **argv)","taints":["argv"]}]',
                encoding="utf-8",
            )
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            task.summary = {}
            entry_run = BinarySecurityStageRun(id="sr-entry", task_id="t1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="success")
            dataflow_run = BinarySecurityStageRun(id="sr-df", task_id="t1", project_id="p1", stage_name="dataflow_analysis", sequence_no=3, status="running")
            item = BinarySecurityStageItem(
                id="i1",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr-entry",
                stage_name="entry_analysis",
                item_key="mod1",
                item_name="mod",
                status="success",
            )
            item.input_ref = {"module_key": "mod1", "module_name": "mod", "source_dir": "/src/mod", "task_type": TASK_TYPE_SOURCE}
            item.output_ref = {"artifact_root": str(artifact)}
            db = _AppendingModelAwareDb(stage_runs=[entry_run, dataflow_run], stage_items=[item])
            captured = {}

            def fake_prepare(*args, **kwargs):
                return None

            async def fake_run_stage_pool(task_arg, entries, parallelism, runner, retries=0, initial_retry=False):
                captured["entries"] = entries
                return [{"status": "success", "item": {**entries[0], "data_flow_file": "/tmp/df.md"}}]

            self.manager._prepare_stage_items_for_execution = fake_prepare
            self.manager._run_stage_pool = fake_run_stage_pool

            status, summary = asyncio.run(self.manager._stage_dataflow_analysis(db, task, dataflow_run, token=None))

            self.assertEqual("success", status)
            self.assertEqual("main", captured["entries"][0]["function_name"])
            self.assertEqual(1, summary["success_count"])

    def test_dataflow_results_keep_vuln_inputs_but_drop_downstream_payload(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.summary = {}
        db = _FakeDb()

        self.manager._aggregate_stage_items(
            db,
            task,
            results=[
                {
                    "status": "success",
                    "item": {
                        "entry_key": "e1",
                        "module_key": "m1",
                        "module_name": "openssl",
                        "file_name": "main.c",
                        "function_name": "main",
                        "line_no": "10",
                        "source_dir": "/tmp/archive/openssl",
                        "data_flow_file": "/tmp/archive/openssl/dataflow.md",
                        "artifact_root": "/tmp/archive/openssl/dataflow",
                        "downstream": {"items": [{"blob": "z" * 4000}]},
                    },
                }
            ],
            summary_key="dataflow_results",
        )

        stored = task.summary["dataflow_results"][0]
        self.assertEqual("/tmp/archive/openssl/dataflow.md", stored["data_flow_file"])
        self.assertEqual("/tmp/archive/openssl", stored["source_dir"])
        self.assertNotIn("downstream", stored)

    def test_vuln_results_store_only_archive_summary(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.summary = {}
        db = _FakeDb()

        self.manager._aggregate_stage_items(
            db,
            task,
            results=[
                {
                    "status": "success",
                    "item": {
                        "entry_key": "e1",
                        "module_key": "m1",
                        "module_name": "openssl",
                        "function_name": "main",
                        "source_dir": "/tmp/archive/openssl",
                        "data_flow_file": "/tmp/archive/openssl/dataflow.md",
                        "workspace_root": "/tmp/workspace",
                        "archive_root": "/tmp/archive/scan",
                        "artifact_files": [f"/tmp/archive/scan/{idx}.json" for idx in range(50)],
                        "artifacts": {"files": [{"blob": "x" * 4000}]},
                        "downstream": {"result": {"blob": "y" * 4000}},
                    },
                }
            ],
            summary_key="vuln_results",
        )

        stored = task.summary["vuln_results"][0]
        self.assertEqual(50, stored["artifact_file_count"])
        self.assertEqual("/tmp/archive/scan", stored["archive_root"])
        self.assertNotIn("artifact_files", stored)
        self.assertNotIn("artifacts", stored)
        self.assertNotIn("downstream", stored)

    def test_finalize_task_prefers_partial_success_after_vuln_stage(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[
                BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="binary_to_source", sequence_no=3, status="failed"),
                BinarySecurityStageRun(id="sr2", task_id="t1", project_id="p1", stage_name="vuln_scan", sequence_no=6, status="partial_success"),
            ],
        )

        self.manager._finalize_task(db, task)

        self.assertEqual("partial_success", task.status)
        self.assertIsNotNone(task.finished_at)
        self.assertTrue(any(isinstance(obj, BinarySecurityEvent) for obj in db.added))

    def test_finalize_task_defers_failure_when_streaming_upstream_still_active(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[
                BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr2", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=2, status="success"),
                BinarySecurityStageRun(id="sr3", task_id="t1", project_id="p1", stage_name="binary_to_source", sequence_no=3, status="running"),
                BinarySecurityStageRun(id="sr4", task_id="t1", project_id="p1", stage_name="entry_analysis", sequence_no=4, status="failed"),
            ],
        )

        self.manager._finalize_task(db, task)

        self.assertEqual("running", task.status)
        self.assertEqual("binary_to_source", task.current_stage)
        self.assertIsNone(task.finished_at)
        self.assertIsNone(task.latest_abnormal_reason)
        self.assertTrue(
            any(
                isinstance(obj, BinarySecurityEvent) and obj.event_type == "task_finalize_deferred_for_streaming_upstream"
                for obj in db.added
            )
        )

    def test_finalize_task_defers_failure_when_any_enabled_stage_is_still_active(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[
                BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr2", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=2, status="success"),
                BinarySecurityStageRun(id="sr3", task_id="t1", project_id="p1", stage_name="binary_to_source", sequence_no=3, status="running"),
                BinarySecurityStageRun(id="sr4", task_id="t1", project_id="p1", stage_name="entry_analysis", sequence_no=4, status="failed"),
            ],
            stage_items=[
                BinarySecurityStageItem(
                    id="si1",
                    task_id="t1",
                    project_id="p1",
                    stage_run_id="sr4",
                    stage_name="entry_analysis",
                    item_key="m1",
                    status="failed",
                    downstream_service="entry_analyse",
                    downstream_task_id="eat-1",
                )
            ],
            events=[],
        )

        self.manager._finalize_task(db, task)

        self.assertEqual("running", task.status)
        self.assertEqual("binary_to_source", task.current_stage)
        self.assertIsNone(task.finished_at)
        self.assertTrue(
            any(
                isinstance(obj, BinarySecurityEvent) and obj.event_type == "task_finalize_deferred_for_active_stage"
                for obj in db.added
            )
        )

    def test_finalize_task_does_not_mark_success_when_enabled_stage_missing(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "stage_options": {
                "firmware_unpack": {"enabled": True},
                "system_analysis": {"enabled": True},
                "binary_to_source": {"enabled": True},
                "entry_analysis": {"enabled": True},
                "dataflow_analysis": {"enabled": True},
                "vuln_scan": {"enabled": True},
            }
        }
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[
                BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr2", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=2, status="success"),
            ],
        )

        self.manager._finalize_task(db, task)

        self.assertEqual("failed", task.status)
        self.assertEqual("binary_to_source", task.current_stage)
        self.assertEqual("stage_incomplete_terminated", task.latest_abnormal_reason["code"])

    def test_finalize_task_clears_latest_abnormal_reason_after_success(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="vuln_scan",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.latest_abnormal_reason = {
            "is_abnormal": True,
            "category": "downstream",
            "code": "downstream_failed",
            "title": "旧异常",
            "message": "旧异常",
            "terminal": True,
            "source_layer": "task",
            "status": "failed",
            "service": "binary-security",
            "evidence": [],
            "related_event_ids": [],
        }
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[
                BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr2", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=2, status="success"),
                BinarySecurityStageRun(id="sr3", task_id="t1", project_id="p1", stage_name="binary_to_source", sequence_no=3, status="success"),
                BinarySecurityStageRun(id="sr4", task_id="t1", project_id="p1", stage_name="entry_analysis", sequence_no=4, status="success"),
                BinarySecurityStageRun(id="sr5", task_id="t1", project_id="p1", stage_name="dataflow_analysis", sequence_no=5, status="success"),
                BinarySecurityStageRun(id="sr6", task_id="t1", project_id="p1", stage_name="vuln_scan", sequence_no=6, status="success"),
            ],
        )

        self.manager._finalize_task(db, task)

        self.assertEqual("success", task.status)
        self.assertIsNone(task.latest_abnormal_reason)

    def test_finalize_task_preserves_retry_preparing_when_pending_action_exists(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="n",
            status="partial_success",
            pending_action="retry",
            current_stage="binary_to_source",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        db = _FakeDb()

        self.manager._finalize_task(db, task)

        self.assertEqual("retry_preparing", task.status)
        self.assertEqual("retry", task.pending_action)
        self.assertIsNone(task.finished_at)
        self.assertIsNone(task.dispatcher_instance_id)

    def test_next_incomplete_stage_skips_disabled_stages(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "stage_options": {
                "firmware_unpack": {"enabled": True},
                "system_analysis": {"enabled": True},
                "binary_to_source": {"enabled": False},
                "entry_analysis": {"enabled": False},
                "dataflow_analysis": {"enabled": False},
                "vuln_scan": {"enabled": False},
            }
        }
        db = _ModelAwareDb(
            stage_runs=[
                BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr2", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=2, status="success"),
            ],
        )

        self.assertIsNone(self.manager._next_incomplete_stage(db, task))

    def test_next_incomplete_stage_treats_partial_success_as_completed(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        db = _ModelAwareDb(
            stage_runs=[
                BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr2", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=2, status="success"),
                BinarySecurityStageRun(id="sr3", task_id="t1", project_id="p1", stage_name="binary_to_source", sequence_no=3, status="partial_success"),
            ],
        )

        self.assertEqual("binary_to_source", self.manager._next_incomplete_stage(db, task))

    def test_next_incomplete_stage_blocks_partial_success_when_stage_advancement_disabled(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "partial_success_stage_advancement": {
                "binary_to_source": False,
                "entry_analysis": True,
                "dataflow_analysis": True,
            }
        }
        db = _ModelAwareDb(
            stage_runs=[
                BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr2", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=2, status="success"),
                BinarySecurityStageRun(id="sr3", task_id="t1", project_id="p1", stage_name="binary_to_source", sequence_no=3, status="partial_success"),
            ],
        )

        self.assertEqual("binary_to_source", self.manager._next_incomplete_stage(db, task))

    def test_task_continue_support_targets_current_stage_when_partial_success_advancement_disabled(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="n",
            status="partial_success",
            task_type=TASK_TYPE_BINARY,
            current_stage="binary_to_source",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.summary = {
            "selected_modules": [{"module_key": "m1", "module_name": "m1", "firmware_key": "fw1"}],
        }
        task.policy = {
            "partial_success_stage_advancement": {
                "binary_to_source": False,
                "entry_analysis": True,
                "dataflow_analysis": True,
            }
        }
        db = _ModelAwareDb(
            stage_runs=[
                BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr2", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=2, status="success"),
                BinarySecurityStageRun(id="sr3", task_id="t1", project_id="p1", stage_name="binary_to_source", sequence_no=3, status="partial_success"),
            ],
        )

        supported, reason, target_stage = self.manager._task_continue_support(db, task)

        self.assertTrue(supported)
        self.assertIsNone(reason)
        self.assertEqual("binary_to_source", target_stage)

    def test_refresh_task_status_after_sync_requeues_next_stage(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
        )
        db = _ModelAwareDb(stage_runs=[run])

        self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("pending", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertIsNone(task.dispatcher_instance_id)
        self.assertIsNone(task.dispatch_started_at)

    def test_refresh_task_status_after_sync_clears_latest_abnormal_reason_when_stage_is_running(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="binary_to_source",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.latest_abnormal_reason = {
            "is_abnormal": True,
            "category": "downstream",
            "code": "downstream_cancelled",
            "title": "旧异常",
            "message": "旧异常",
            "terminal": True,
            "source_layer": "task",
            "status": "failed",
            "service": "binary_to_source",
            "stage_name": "binary_to_source",
            "evidence": [],
            "related_event_ids": [],
        }
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[
                BinarySecurityStageRun(
                    id="sr1",
                    task_id="t1",
                    project_id="p1",
                    stage_name="binary_to_source",
                    sequence_no=1,
                    status="running",
                ),
            ],
        )

        self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("running", task.status)
        self.assertIsNone(task.last_error)
        self.assertIsNone(task.latest_abnormal_reason)

    def test_refresh_task_status_after_sync_requeues_next_stage_for_task_retry_mode(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            execution_mode="task_retry",
            target_stage_name="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        runs = [
            BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="firmware_unpack",
                sequence_no=1,
                status="success",
            ),
            BinarySecurityStageRun(
                id="sr2",
                task_id="t1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=2,
                status="success",
            ),
        ]
        db = _ModelAwareDb(tasks=[task], stage_runs=runs)

        self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("pending", task.status)
        self.assertEqual("binary_to_source", task.current_stage)
        self.assertIsNone(task.execution_mode)
        self.assertIsNone(task.target_stage_name)
        self.assertIsNone(task.dispatcher_instance_id)
        self.assertIsNone(task.dispatch_started_at)

    def test_refresh_task_status_after_sync_does_not_auto_retry_failed_stage(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        runs = [
            BinarySecurityStageRun(
                id="sr1",
                task_id="s1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="success",
            ),
            BinarySecurityStageRun(
                id="sr2",
                task_id="s1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="failed",
            ),
            BinarySecurityStageRun(
                id="sr3",
                task_id="s1",
                project_id="p1",
                stage_name="dataflow_analysis",
                sequence_no=3,
                status="pending",
            ),
        ]
        db = _ModelAwareDb(stage_runs=runs)

        self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("failed", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertIsNotNone(task.finished_at)

    def test_refresh_task_status_after_sync_preserves_retry_preparing_when_pending_action_exists(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="partial_success",
            pending_action="retry",
            current_stage="firmware_unpack",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        db = _ModelAwareDb(tasks=[task])

        self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("retry_preparing", task.status)
        self.assertEqual("retry", task.pending_action)
        self.assertIsNone(task.finished_at)

    def test_refresh_task_status_after_sync_keeps_preparing_dispatch_ownership(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="retry_preparing",
            pending_action="retry_stage_full",
            current_stage="entry_analysis",
            dispatcher_instance_id="worker-a",
            dispatch_started_at=_now(),
            lease_expires_at=_now() + timedelta(seconds=30),
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        db = _ModelAwareDb(tasks=[task])

        self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("retry_preparing", task.status)
        self.assertEqual("worker-a", task.dispatcher_instance_id)
        self.assertIsNotNone(task.dispatch_started_at)
        self.assertIsNotNone(task.lease_expires_at)

    def test_mark_task_waiting_for_archive_retry_clears_latest_abnormal_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="binary",
                status="failed",
                current_stage="binary_to_source",
                task_type=TASK_TYPE_BINARY,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(Path(tmp) / "output"),
                workspace_root=tmp,
            )
            task.latest_abnormal_reason = {
                "is_abnormal": True,
                "category": "archive",
                "code": "archive_failed",
                "title": "归档失败",
                "message": "归档失败",
                "terminal": True,
                "source_layer": "task",
                "status": "failed",
                "service": "binary-security",
                "stage_name": "binary_to_source",
                "evidence": [],
                "related_event_ids": [],
            }
            db = _ModelAwareDb(tasks=[task])

            self.manager._mark_task_waiting_for_archive_retry(db, task, "binary_to_source")

            self.assertEqual("running", task.status)
            self.assertEqual("binary_to_source", task.current_stage)
            self.assertIsNone(task.latest_abnormal_reason)

    def test_continue_task_starts_after_last_successful_stage(self):
        workspace = Path(tempfile.mkdtemp())
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="partial_success",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root=str(workspace / "output"),
            workspace_root=str(workspace),
        )
        task.summary = {
            "selected_modules": [{"module_key": "m1"}],
            "entry_results": [{"entry_key": "e1"}],
            "stale_stages": ["entry_analysis"],
        }
        task.metrics = {"entry_count": 1, "vuln_result_count": 1}
        task.stage_summary = {"system_analysis": {"status": "success"}, "entry_analysis": {"status": "failed"}}
        runs = [
            BinarySecurityStageRun(
                id="sr1",
                task_id="s1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="success",
            ),
            BinarySecurityStageRun(
                id="sr2",
                task_id="s1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="failed",
                last_error="boom",
            ),
            BinarySecurityStageRun(
                id="sr3",
                task_id="s1",
                project_id="p1",
                stage_name="dataflow_analysis",
                sequence_no=3,
                status="pending",
            ),
        ]
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=runs,
            stage_items=[BinarySecurityStageItem(id="i1", task_id="s1", project_id="p1", stage_name="entry_analysis", item_key="m1")],
        )

        async def fake_delete_downstream_refs(*args, **kwargs):
            return 0

        self.manager._delete_downstream_refs = fake_delete_downstream_refs

        target_stage = asyncio.run(self.manager.continue_task(db, project_id="p1", task_id="s1"))

        self.assertEqual("entry_analysis", target_stage)
        self._finish_continue_prepare(db, task, target_stage)
        self.assertEqual("pending", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertIsNone(task.finished_at)
        self.assertNotIn("entry_results", task.summary)
        self.assertNotIn("stale_stages", task.summary)
        self.assertEqual("pending", runs[1].status)
        self.assertEqual({}, runs[1].output_summary)

    def test_continue_task_clears_archive_jobs_for_affected_stages(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="s1",
                project_id="p1",
                name="source",
                status="partial_success",
                task_type=TASK_TYPE_SOURCE,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            task.summary = {"selected_modules": [{"module_key": "m1", "source_dir": "/src/m1"}]}
            runs = [
                BinarySecurityStageRun(id="sr1", task_id="s1", project_id="p1", stage_name="system_analysis", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr2", task_id="s1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="failed"),
            ]
            archive_jobs = [
                BinarySecurityArchiveJob(
                    id="aj1",
                    task_id="s1",
                    project_id="p1",
                    stage_name="entry_analysis",
                    item_id="i1",
                    archive_status="success",
                )
            ]
            db = _ModelAwareDb(tasks=[task], stage_runs=runs, archive_jobs=archive_jobs)

            async def fake_cleanup_downstream_refs(*args, **kwargs):
                return 0

            self.manager._cleanup_downstream_refs = fake_cleanup_downstream_refs

            target_stage = asyncio.run(self.manager.continue_task(db, project_id="p1", task_id="s1"))
            self._finish_continue_prepare(db, task, target_stage)

            self.assertEqual("pending", task.status)
            self.assertEqual("entry_analysis", task.current_stage)

    def test_persist_stage_run_output_summary_externalizes_full_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="demo",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="running",
            )
            full_summary = {
                "items": [
                    {
                        "module_key": "m1",
                        "module_name": "module-1",
                        "source_dir": "/src/module-1",
                        "artifact_root": "/out/module-1",
                        "entries": [
                            {"entry_key": f"e{i}", "function_name": f"fn{i}", "file_name": "a.c", "line_no": i}
                            for i in range(20)
                        ],
                    }
                ],
                "success_count": 1,
                "failed_count": 0,
                "entry_count": 20,
            }

            compact = self.manager._persist_stage_run_output_summary(task, stage_run, full_summary)

            summary_file = workspace / "run" / "stage-summaries" / "02_entry_analysis.json"
            self.assertTrue(summary_file.is_file())
            self.assertEqual(full_summary["entry_count"], compact["entry_count"])
            self.assertTrue(compact["summary_externalized"])
            self.assertEqual(str(summary_file), compact["summary_file"])
            self.assertEqual(1, compact["item_count"])
            self.assertEqual(20, compact["items_preview"][0]["entry_count"])
            self.assertLessEqual(len(compact["items_preview"][0]["entries_preview"]), 5)

    def test_enqueue_state_event_externalizes_large_stage_terminal_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="demo",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="running",
            )
            payload = {
                "stage_name": "entry_analysis",
                "status": "running",
                "summary": {
                    "items": [
                        {
                            "module_key": "m1",
                            "module_name": "module-1",
                            "source_dir": "/src/module-1",
                            "artifact_root": "/out/module-1",
                            "entries": [
                                {
                                    "entry_key": f"e{i}",
                                    "function_name": f"fn{i}",
                                    "file_name": "a.c",
                                    "line_no": i,
                                    "function_description": f"desc-{i}" * 8,
                                    "entry_reason": f"reason-{i}" * 8,
                                }
                                for i in range(240)
                            ],
                        }
                    ],
                    "success_count": 1,
                    "failed_count": 0,
                    "entry_count": 240,
                },
                "stage_retry_mode": False,
                "task_retry_mode": False,
                "target_stage_name": None,
            }
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run])

            event = self.manager._enqueue_state_event(
                db,
                task=task,
                task_id=task.id,
                project_id=task.project_id,
                stage_name="entry_analysis",
                event_type="stage_worker_terminal_observed",
                idempotency_key="terminal:t1:entry_analysis:running",
                payload=payload,
            )

            self.assertIsNotNone(event)
            payload_file = workspace / "run" / "state-event-payloads" / f"{event.id}_stage_worker_terminal_observed.json"
            self.assertTrue(payload_file.is_file())
            self.assertTrue(event.payload["payload_externalized"])
            self.assertEqual(str(payload_file), event.payload["payload_file"])
            self.assertEqual(240, event.payload["summary"]["entry_count"])
            self.assertLessEqual(self.manager._json_payload_size_bytes(event.payload), task_manager_module.DB_EVENT_PAYLOAD_LIMIT_BYTES)

    def test_apply_stage_worker_terminal_event_loads_externalized_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="demo",
                status="running",
                current_stage="entry_analysis",
                task_type=TASK_TYPE_SOURCE,
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
                started_at=_now(),
            )
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="running",
                started_at=_now(),
            )
            payload = {
                "stage_name": "entry_analysis",
                "status": "running",
                "summary": {
                    "items": [
                        {
                            "module_key": "m1",
                            "module_name": "module-1",
                            "source_dir": "/src/module-1",
                            "artifact_root": "/out/module-1",
                            "entries": [
                                {
                                    "entry_key": f"e{i}",
                                    "function_name": f"fn{i}",
                                    "file_name": "a.c",
                                    "line_no": i,
                                    "function_description": f"desc-{i}" * 12,
                                    "entry_reason": f"reason-{i}" * 12,
                                }
                                for i in range(240)
                            ],
                        }
                    ],
                    "success_count": 1,
                    "failed_count": 0,
                    "entry_count": 240,
                },
            }
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], events=[])
            event = self.manager._enqueue_state_event(
                db,
                task=task,
                task_id=task.id,
                project_id=task.project_id,
                stage_name="entry_analysis",
                event_type="stage_worker_terminal_observed",
                idempotency_key="terminal:t1:entry_analysis:running",
                payload=payload,
            )

            asyncio.run(self.manager._apply_stage_worker_terminal_event_locked(db, event))

            summary_file = workspace / "run" / "stage-summaries" / "02_entry_analysis.json"
            self.assertTrue(summary_file.is_file())
            stored = json.loads(summary_file.read_text(encoding="utf-8"))
            self.assertEqual(240, len(stored["items"][0]["entries"]))
            self.assertEqual(240, task.metrics["entry_count"])
            self.assertEqual("running", task.status)

    def test_apply_stage_worker_terminal_event_uses_entry_items_as_authoritative_status(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="demo",
            status="running",
            current_stage="entry_analysis",
            task_type=TASK_TYPE_BINARY_MODULE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            started_at=_now(),
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        stage_run = BinarySecurityStageRun(
            id="sr-entry",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
            started_at=_now(),
        )
        failed_item = BinarySecurityStageItem(
            id="si-entry",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr-entry",
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="module-input",
            item_identity_key="IPSEC::module-input",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="eat-1",
            error_message="maximum recursion depth exceeded while calling a Python object",
        )
        failed_item.input_ref = {"module_key": "IPSEC", "module_name": "IPSEC", "source_dir": "/src/IPSEC"}
        failed_item.result = {}
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[failed_item], events=[])
        event = self.manager._enqueue_state_event(
            db,
            task=task,
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            event_type="stage_worker_terminal_observed",
            idempotency_key="terminal:t1:entry_analysis:success",
            payload={
                "stage_name": "entry_analysis",
                "status": "success",
                "summary": {"success_count": 1, "failed_count": 0, "entry_count": 12},
            },
        )

        asyncio.run(self.manager._apply_stage_worker_terminal_event_locked(db, event))

        self.assertEqual("failed", stage_run.status)
        self.assertEqual("failed", task.status)
        self.assertEqual("maximum recursion depth exceeded while calling a Python object", task.last_error)
        self.assertEqual("failed", dict(stage_run.output_summary or {}).get("sync_status"))

    def test_update_task_concurrency_updates_binary_stage_parallelism(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="success",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "max_stage_parallelism": 4,
            "max_retries_per_item": 3,
            "continue_on_item_failure": False,
            "stage_parallelism": {
                "firmware_unpack": 4,
                "system_analysis": 4,
                "binary_to_source": 4,
                "entry_analysis": 4,
                "dataflow_analysis": 4,
                "vuln_scan": 4,
            },
        }
        db = _ModelAwareDb(tasks=[task])

        detail = self.manager.update_task_concurrency(
            db,
            project_id="p1",
            task_id="t1",
            payload=BinarySecurityTaskConcurrencyUpdatePayload(
                stage_parallelism={"firmware_unpack": 2, "vuln_scan": 8}
            ),
        )

        self.assertIn("manual_policy_update_requested", [getattr(event, "event_type", "") for event in db.added])
        self.manager._apply_manual_policy_update_requested_locked(db, db.added[-1])
        detail = self.manager.get_task_detail(db, project_id="p1", task_id="t1")

        self.assertEqual(8, detail.policy["max_stage_parallelism"])
        self.assertEqual(2, detail.policy["stage_parallelism"]["firmware_unpack"])
        self.assertEqual(8, detail.policy["stage_parallelism"]["vuln_scan"])
        self.assertEqual(4, detail.policy["stage_parallelism"]["system_analysis"])
        self.assertEqual(3, detail.policy["max_retries_per_item"])
        self.assertFalse(detail.policy["continue_on_item_failure"])

    def test_update_task_concurrency_rejects_stages_outside_source_flow(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {"stage_parallelism": {"system_analysis": 4, "entry_analysis": 4, "dataflow_analysis": 4, "vuln_scan": 4}}
        db = _ModelAwareDb(tasks=[task])

        with self.assertRaisesRegex(Exception, "阶段不属于当前任务流程"):
            self.manager.update_task_concurrency(
                db,
                project_id="p1",
                task_id="t1",
                payload=BinarySecurityTaskConcurrencyUpdatePayload(stage_parallelism={"firmware_unpack": 2}),
            )

    def test_update_task_concurrency_rejects_invalid_parallelism_value(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {"stage_parallelism": {"system_analysis": 4, "entry_analysis": 4, "dataflow_analysis": 4, "vuln_scan": 4}}
        db = _ModelAwareDb(tasks=[task])

        with self.assertRaisesRegex(Exception, "并发必须是 1 到 32 之间的整数"):
            self.manager.update_task_concurrency(
                db,
                project_id="p1",
                task_id="t1",
                payload=BinarySecurityTaskConcurrencyUpdatePayload(stage_parallelism={"system_analysis": 33}),
            )

    def test_update_task_policy_merges_fields_and_records_event(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "max_stage_parallelism": 4,
            "max_retries_per_item": 2,
            "continue_on_item_failure": True,
            "partial_success_stage_advancement": {
                "binary_to_source": True,
                "entry_analysis": True,
                "dataflow_analysis": True,
            },
            "stage_parallelism": {
                "firmware_unpack": 4,
                "system_analysis": 4,
                "binary_to_source": 4,
                "entry_analysis": 4,
                "dataflow_analysis": 4,
                "vuln_scan": 4,
            },
            "stage_options": {
                "binary_to_source": {"enabled": True},
            },
            "module_selection_mode": "auto",
            "module_risk_levels": ["高"],
        }
        db = _ModelAwareDb(tasks=[task])

        detail = self.manager.update_task_policy(
            db,
            project_id="p1",
            task_id="t1",
            payload=BinarySecurityTaskPolicyUpdatePayload(
                stage_options={"binary_to_source": {"enabled": False}},
                max_retries_per_item=5,
                continue_on_item_failure=False,
                partial_success_stage_advancement={"binary_to_source": False, "entry_analysis": True},
                stage_parallelism={"vuln_scan": 8},
                module_selection_mode="manual_confirm",
                module_risk_levels=["高", "中"],
            ),
        )

        self.assertIn("manual_policy_update_requested", [getattr(event, "event_type", "") for event in db.added])
        self.manager._apply_manual_policy_update_requested_locked(db, db.added[-1])
        detail = self.manager.get_task_detail(db, project_id="p1", task_id="t1")

        self.assertEqual(8, detail.policy["max_stage_parallelism"])
        self.assertEqual(5, detail.policy["max_retries_per_item"])
        self.assertFalse(detail.policy["continue_on_item_failure"])
        self.assertFalse(detail.policy["partial_success_stage_advancement"]["binary_to_source"])
        self.assertTrue(detail.policy["partial_success_stage_advancement"]["entry_analysis"])
        self.assertEqual(8, detail.policy["stage_parallelism"]["vuln_scan"])
        self.assertEqual(4, detail.policy["stage_parallelism"]["firmware_unpack"])
        self.assertFalse(detail.policy["stage_options"]["binary_to_source"]["enabled"])
        self.assertEqual("manual_confirm", detail.policy["module_selection_mode"])
        self.assertEqual(["高", "中"], detail.policy["module_risk_levels"])
        self.assertTrue(any(isinstance(obj, BinarySecurityEvent) and obj.event_type == "task_policy_updated" for obj in db.added))

    def test_update_task_policy_normalizes_pipeline_mode_to_mixed_streaming(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "pipeline_mode": "barrier",
            "max_stage_parallelism": 4,
            "stage_parallelism": {
                "system_analysis": 4,
                "entry_analysis": 4,
                "dataflow_analysis": 4,
                "vuln_scan": 4,
            },
        }
        db = _ModelAwareDb(tasks=[task])

        self.manager.update_task_policy(
            db,
            project_id="p1",
            task_id="t1",
            payload=BinarySecurityTaskPolicyUpdatePayload(pipeline_mode=" Mixed_Streaming "),
        )

        event = db.added[-1]
        self.assertEqual("manual_policy_update_requested", getattr(event, "event_type", ""))
        self.assertEqual("mixed_streaming", event.payload["after"]["pipeline_mode"])

        self.manager._apply_manual_policy_update_requested_locked(db, event)
        detail = self.manager.get_task_detail(db, project_id="p1", task_id="t1")
        self.assertEqual("mixed_streaming", detail.policy["pipeline_mode"])

    def test_update_task_policy_normalizes_unknown_pipeline_mode_to_barrier(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "pipeline_mode": "mixed_streaming",
            "max_stage_parallelism": 4,
            "stage_parallelism": {
                "system_analysis": 4,
                "entry_analysis": 4,
                "dataflow_analysis": 4,
                "vuln_scan": 4,
            },
        }
        db = _ModelAwareDb(tasks=[task])

        self.manager.update_task_policy(
            db,
            project_id="p1",
            task_id="t1",
            payload=BinarySecurityTaskPolicyUpdatePayload(pipeline_mode="unexpected-mode"),
        )

        event = db.added[-1]
        self.assertEqual("barrier", event.payload["after"]["pipeline_mode"])
        self.manager._apply_manual_policy_update_requested_locked(db, event)
        detail = self.manager.get_task_detail(db, project_id="p1", task_id="t1")
        self.assertEqual("barrier", detail.policy["pipeline_mode"])

    def test_update_task_policy_rejects_stage_outside_source_flow(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "stage_parallelism": {
                "system_analysis": 4,
                "entry_analysis": 4,
                "dataflow_analysis": 4,
                "vuln_scan": 4,
            }
        }
        db = _ModelAwareDb(tasks=[task])

        with self.assertRaisesRegex(Exception, "阶段不属于当前任务流程"):
            self.manager.update_task_policy(
                db,
                project_id="p1",
                task_id="t1",
                payload=BinarySecurityTaskPolicyUpdatePayload(stage_options={"firmware_unpack": {"enabled": False}}),
            )

    def test_update_task_policy_rejects_partial_success_stage_outside_source_flow(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {}
        db = _ModelAwareDb(tasks=[task])

        with self.assertRaisesRegex(Exception, "阶段不属于当前任务流程: binary_to_source"):
            self.manager.update_task_policy(
                db,
                project_id="p1",
                task_id="t1",
                payload=BinarySecurityTaskPolicyUpdatePayload(
                    partial_success_stage_advancement={"binary_to_source": False}
                ),
            )

    def test_get_task_detail_returns_structured_abnormal_reason_for_failed_task(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            current_stage="binary_to_source",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
            last_error="下游任务执行失败",
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="binary_to_source",
            sequence_no=3,
            status="failed",
            last_error="逆向服务失败",
        )
        item = BinarySecurityStageItem(
            id="i1",
            task_id="t1",
            project_id="p1",
            stage_name="binary_to_source",
            item_key="module:openssl",
            status="failed",
            downstream_service="binary-to-source",
            downstream_task_id="b2s-1",
            error_message="worker exited with code 1",
        )
        archive_job = BinarySecurityArchiveJob(
            id="a1",
            task_id="t1",
            project_id="p1",
            stage_name="binary_to_source",
            item_id="i1",
            item_key="module:openssl",
            archive_status="failed",
            error_message="copy failed",
        )
        event = BinarySecurityEvent(
            id="e1",
            task_id="t1",
            project_id="p1",
            event_type="abnormal_reason_recorded",
            message="下游任务失败",
            level="error",
            created_at=_now(),
        )
        event.payload = {
            "reason": {
                "is_abnormal": True,
                "category": "downstream",
                "code": "downstream_failed",
                "title": "下游任务失败",
                "message": "worker exited with code 1",
                "terminal": True,
                "source_layer": "task",
                "status": "failed",
                "service": "binary-security",
                "stage_name": "binary_to_source",
                "item_key": "module:openssl",
                "downstream_task_id": "b2s-1",
                "downstream_service": "binary-to-source",
                "evidence": [
                    {"key": "downstream_task_id", "label": "下游任务 ID", "value": "b2s-1"},
                    {"key": "error_message", "label": "原始错误", "value": "worker exited with code 1"},
                ],
                "related_event_ids": [],
            }
        }
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[item], archive_jobs=[archive_job], events=[event])

        detail = self.manager.get_task_detail(db, project_id="p1", task_id="t1")

        self.assertEqual("archive_failed", detail.abnormal_reason.code)
        self.assertEqual("archive_failed", detail.archive_jobs[0].abnormal_reason.code)
        self.assertEqual("downstream_failed", detail.stage_items[0].abnormal_reason.code)
        self.assertEqual("downstream_failed", detail.stage_summaries[2].abnormal_reason.code)
        self.assertEqual(1, len(detail.abnormal_reason_history))

    def test_get_task_detail_streaming_tail_snapshot_stays_consistent(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="pending",
            task_type=TASK_TYPE_SOURCE,
            current_stage="dataflow_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.summary = {}
        task.metrics = {}
        entry_run = BinarySecurityStageRun(
            id="sr-entry",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-df",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            sequence_no=3,
            status="failed",
            last_error="dfa failed",
        )
        vuln_run = BinarySecurityStageRun(
            id="sr-vuln",
            task_id="t1",
            project_id="p1",
            stage_name="vuln_scan",
            sequence_no=4,
            status="pending",
        )
        entry_item = BinarySecurityStageItem(
            id="i-entry",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr-entry",
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            item_identity_key="mod-a::source_project",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-1",
        )
        entry_item.input_ref = {"module_key": "mod-a", "module_name": "mod-a", "source_dir": "/src/mod-a"}
        entry_item.result = {
            "module_key": "mod-a",
            "module_name": "mod-a",
            "source_dir": "/src/mod-a",
            "entries_preview": [{"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a"}],
        }
        dataflow_item = BinarySecurityStageItem(
            id="i-df",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr-df",
            stage_name="dataflow_analysis",
            item_key="entry-a",
            item_name="func_a",
            parent_key="mod-a",
            item_identity_key="entry-a::mod-a",
            status="pending",
            downstream_service="dataflow_analyse",
            downstream_task_id="dfa-1",
        )
        dataflow_item.input_ref = {"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a", "upstream_item_id": "i-entry"}
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run, dataflow_run, vuln_run],
            stage_items=[entry_item, dataflow_item],
            archive_jobs=[],
            events=[],
        )

        detail = self.manager.get_task_detail(db, project_id="p1", task_id="t1")

        by_stage = {summary.stage_name: summary for summary in detail.stage_summaries}
        by_node = {node.node_id: node for node in detail.overview_nodes}
        self.assertEqual("blocked", detail.manual_operation_state["overall"])
        self.assertEqual("task_running", detail.manual_operation_state["blocking_code"])
        self.assertFalse(detail.manual_operation_state["can_continue"])
        self.assertFalse(detail.manual_operation_state["can_retry"])
        self.assertEqual("running", by_stage["dataflow_analysis"].status)
        self.assertEqual("running", by_node["business:dataflow_analysis"].status)
        self.assertEqual("dfa-1", by_node["business:dataflow_analysis"].detail.representative_downstream_task_id)

    def test_task_response_exposes_abnormal_reason_summary_fields(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            current_stage="binary_to_source",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        item = BinarySecurityStageItem(
            id="i1",
            task_id="t1",
            project_id="p1",
            stage_name="binary_to_source",
            item_key="module:openssl",
            status="downstream_missing",
            downstream_service="binary-to-source",
            downstream_task_id="b2s-1",
            error_message="downstream task not found",
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[item])

        response = self.manager._task_response(db, task)

        self.assertEqual("downstream_missing", response.abnormal_reason_code)
        self.assertEqual("downstream", response.abnormal_reason_category)
        self.assertTrue(response.abnormal_reason_title)

    def test_task_response_streaming_tail_snapshot_stays_consistent_for_list_view(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="pending",
            task_type=TASK_TYPE_SOURCE,
            current_stage="dataflow_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.summary = {}
        task.metrics = {}
        entry_run = BinarySecurityStageRun(
            id="sr-entry",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-df",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            sequence_no=3,
            status="failed",
            last_error="dfa failed",
        )
        vuln_run = BinarySecurityStageRun(
            id="sr-vuln",
            task_id="t1",
            project_id="p1",
            stage_name="vuln_scan",
            sequence_no=4,
            status="pending",
        )
        entry_item = BinarySecurityStageItem(
            id="i-entry",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr-entry",
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            item_identity_key="mod-a::source_project",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-1",
        )
        entry_item.input_ref = {"module_key": "mod-a", "module_name": "mod-a", "source_dir": "/src/mod-a"}
        entry_item.result = {
            "module_key": "mod-a",
            "module_name": "mod-a",
            "source_dir": "/src/mod-a",
            "entries_preview": [{"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a"}],
        }
        dataflow_item = BinarySecurityStageItem(
            id="i-df",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr-df",
            stage_name="dataflow_analysis",
            item_key="entry-a",
            item_name="func_a",
            parent_key="mod-a",
            item_identity_key="entry-a::mod-a",
            status="dispatching",
            downstream_service="dataflow_analyse",
            downstream_task_id="dfa-1",
        )
        dataflow_item.input_ref = {"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a", "upstream_item_id": "i-entry"}
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run, dataflow_run, vuln_run],
            stage_items=[entry_item, dataflow_item],
            archive_jobs=[],
            events=[],
        )

        response = self.manager._task_response(db, task)

        by_stage = {summary.stage_name: summary for summary in response.stage_summaries}
        self.assertEqual("blocked", response.manual_operation_state["overall"])
        self.assertEqual("task_running", response.manual_operation_state["blocking_code"])
        self.assertFalse(response.manual_operation_state["can_continue"])
        self.assertFalse(response.manual_operation_state["can_retry"])
        self.assertFalse(response.manual_operation_state["can_retry_failed_items"])
        self.assertEqual("running", by_stage["dataflow_analysis"].status)
        self.assertEqual(1, by_stage["dataflow_analysis"].running_items)
        self.assertEqual("pending", response.status)
        self.assertEqual("dataflow_analysis", response.current_stage)

    def test_get_task_detail_streaming_tail_queued_item_is_exposed_as_running(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="pending",
            task_type=TASK_TYPE_SOURCE,
            current_stage="vuln_scan",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.summary = {}
        task.metrics = {}
        vuln_run = BinarySecurityStageRun(
            id="sr-vuln",
            task_id="t1",
            project_id="p1",
            stage_name="vuln_scan",
            sequence_no=4,
            status="pending",
        )
        vuln_item = BinarySecurityStageItem(
            id="i-vuln",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr-vuln",
            stage_name="vuln_scan",
            item_key="entry-a",
            item_name="func_a",
            parent_key="mod-a",
            item_identity_key="entry-a::mod-a",
            status="queued",
            downstream_service="dataflow_vuln_scanner",
            downstream_task_id="dvs-1",
        )
        vuln_item.input_ref = {"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a", "upstream_item_id": "i-df"}
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[vuln_run],
            stage_items=[vuln_item],
            archive_jobs=[],
            events=[],
        )

        detail = self.manager.get_task_detail(db, project_id="p1", task_id="t1")

        by_stage = {summary.stage_name: summary for summary in detail.stage_summaries}
        by_node = {node.node_id: node for node in detail.overview_nodes}
        self.assertEqual("running", by_stage["vuln_scan"].status)
        self.assertEqual(1, by_stage["vuln_scan"].running_items)
        self.assertEqual("running", by_node["business:vuln_scan"].status)
        self.assertEqual("dvs-1", by_node["business:vuln_scan"].detail.representative_downstream_task_id)
        self.assertEqual("blocked", detail.manual_operation_state["overall"])
        self.assertEqual("task_running", detail.manual_operation_state["blocking_code"])

    def test_get_task_stage_items_page_preserves_streaming_tail_lineage(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="pending",
            task_type=TASK_TYPE_SOURCE,
            current_stage="dataflow_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        item_1 = BinarySecurityStageItem(
            id="i-df-1",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            item_key="entry-a",
            item_name="func_a",
            parent_key="mod-a",
            item_identity_key="entry-a::mod-a",
            status="queued",
            downstream_service="dataflow_analyse",
            downstream_task_id="dfa-1",
            created_at=_now() - timedelta(minutes=2),
        )
        item_1.input_ref = {"entry_key": "entry-a", "module_key": "mod-a", "upstream_item_id": "i-entry-1"}
        item_2 = BinarySecurityStageItem(
            id="i-df-2",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            item_key="entry-b",
            item_name="func_b",
            parent_key="mod-b",
            item_identity_key="entry-b::mod-b",
            status="dispatching",
            downstream_service="dataflow_analyse",
            downstream_task_id="dfa-2",
            created_at=_now() - timedelta(minutes=1),
        )
        item_2.input_ref = {"entry_key": "entry-b", "module_key": "mod-b", "upstream_item_id": "i-entry-2"}
        db = _ModelAwareDb(tasks=[task], stage_items=[item_1, item_2])

        page = self.manager.get_task_stage_items_page(
            db,
            project_id="p1",
            task_id="t1",
            stage_name="dataflow_analysis",
            page=1,
            per_page=1,
        )

        self.assertEqual(2, page.total)
        self.assertEqual(1, len(page.items))
        self.assertEqual("i-df-1", page.items[0].id)
        self.assertEqual("queued", page.items[0].status)
        self.assertEqual("i-entry-1", page.items[0].input_ref["upstream_item_id"])

    def test_get_orchestration_observability_summarizes_streaming_tail_activity(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="pending",
            task_type=TASK_TYPE_SOURCE,
            current_stage="dataflow_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        now_value = _now()
        processing_event = BinarySecurityStateEvent(
            id="se-processing",
            task_id="t1",
            project_id="p1",
            event_type="stage_worker_start_requested",
            status="processing",
            stage_name="dataflow_analysis",
            item_id="i-df-1",
            attempts=1,
            leased_by="worker-a",
            lease_expires_at=now_value + timedelta(minutes=1),
            created_at=now_value - timedelta(minutes=3),
        )
        retryable_event = BinarySecurityStateEvent(
            id="se-retryable",
            task_id="t1",
            project_id="p1",
            event_type="downstream_status_sync_requested",
            status="retryable",
            stage_name="vuln_scan",
            item_id="i-vuln-1",
            attempts=2,
            created_at=now_value - timedelta(minutes=5),
            error_message="temporary downstream timeout",
        )
        latest_reconcile = BinarySecurityEvent(
            id="evt-reconcile",
            task_id="t1",
            project_id="p1",
            event_type="downstream_status_synced",
            message="streaming tail synced",
            level="info",
            created_at=now_value - timedelta(seconds=30),
        )
        lease = BinarySecurityTaskStateLease(
            task_id="t1",
            owner_id="reducer-1",
            lease_token="lease-1",
            operation="reduce",
            lease_expires_at=now_value + timedelta(minutes=2),
            heartbeat_at=now_value - timedelta(seconds=5),
        )
        archive_job = BinarySecurityArchiveJob(
            id="aj-1",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            item_id="i-df-1",
            item_key="entry-a",
            archive_status="success",
        )

        class _ObservabilityDb(_ModelAwareDb):
            def query(self, model, *args, **kwargs):
                model_name = getattr(model, "__name__", "")
                if model_name:
                    return super().query(model, *args, **kwargs)
                if model is BinarySecurityArchiveJob.stage_name:
                    class _AggregateQuery(_FakeQuery):
                        def filter(self, *args, **kwargs):
                            del args, kwargs
                            return self

                    rows = [
                        (job.stage_name, job.archive_status, 1)
                        for job in self.archive_jobs
                    ]
                    return _AggregateQuery(rows)
                return _FakeQuery([])

        db = _ObservabilityDb(
            tasks=[task],
            archive_jobs=[archive_job],
            events=[latest_reconcile],
            state_events=[processing_event, retryable_event],
            state_leases=[lease],
        )

        observability = self.manager.get_orchestration_observability(db, project_id="p1", task_id="t1")

        self.assertEqual(1, observability["state_events"]["status_counts"]["processing"])
        self.assertEqual(1, observability["state_events"]["status_counts"]["retryable"])
        self.assertEqual("se-processing", observability["state_events"]["processing"][0]["id"])
        self.assertGreater(observability["state_events"]["oldest_active_age_seconds"], 0.0)
        self.assertTrue(observability["task_state_lock"]["active"])
        self.assertEqual("reducer-1", observability["task_state_lock"]["owner_id"])
        self.assertEqual(1, observability["archive"]["by_stage"]["dataflow_analysis"]["success"])
        self.assertEqual("downstream_status_synced", observability["reconcile"]["latest_event_type"])
        self.assertEqual(
            "/w/input/task-metadata.json",
            observability["files"]["metadata_path"],
        )

    def test_sync_task_abnormal_reason_snapshot_records_history_on_change(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        db = _ModelAwareDb(tasks=[task])
        first = self.manager._build_abnormal_reason(
            category="downstream",
            code="downstream_failed",
            title="下游任务失败",
            message="worker failed",
            source_layer="task",
            status="failed",
            service="binary-security",
            evidence=[],
        )
        second = self.manager._build_abnormal_reason(
            category="archive",
            code="archive_failed",
            title="归档任务失败",
            message="archive failed",
            source_layer="task",
            status="failed",
            service="binary-security",
            evidence=[],
        )

        self.manager._sync_task_abnormal_reason_snapshot(db, task, first)
        self.manager._sync_task_abnormal_reason_snapshot(db, task, second)

        abnormal_events = [obj for obj in db.added if isinstance(obj, BinarySecurityEvent) and obj.event_type == "abnormal_reason_recorded"]
        self.assertEqual(2, len(abnormal_events))
        self.assertEqual("archive_failed", task.latest_abnormal_reason["code"])

    def test_update_task_policy_rejects_running_task(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "stage_parallelism": {
                "firmware_unpack": 4,
                "system_analysis": 4,
                "binary_to_source": 4,
                "entry_analysis": 4,
                "dataflow_analysis": 4,
                "vuln_scan": 4,
            }
        }
        db = _ModelAwareDb(tasks=[task])

        with self.assertRaisesRegex(Exception, "不允许修改任务策略"):
            self.manager.update_task_policy(
                db,
                project_id="p1",
                task_id="t1",
                payload=BinarySecurityTaskPolicyUpdatePayload(stage_parallelism={"vuln_scan": 8}),
            )

    def test_continue_task_deletes_archive_child_outputs_for_affected_stages(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            output_root = workspace / "output"
            system_output = output_root / "system-analyse"
            entry_output = output_root / "entry-analyse"
            system_output.mkdir(parents=True)
            entry_output.mkdir(parents=True)
            (system_output / "kept.txt").write_text("old", encoding="utf-8")
            (entry_output / "stale.txt").write_text("old", encoding="utf-8")
            task = BinarySecurityTask(
                id="s1",
                project_id="p1",
                name="source",
                status="partial_success",
                task_type=TASK_TYPE_SOURCE,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(output_root),
                workspace_root=str(workspace),
            )
            task.summary = {"selected_modules": [{"module_key": "m1", "source_dir": "/src/m1"}]}
            runs = [
                BinarySecurityStageRun(id="sr1", task_id="s1", project_id="p1", stage_name="system_analysis", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr2", task_id="s1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="failed"),
            ]
            db = _ModelAwareDb(tasks=[task], stage_runs=runs)

            async def fake_cleanup_downstream_refs(*args, **kwargs):
                return 0

            self.manager._cleanup_downstream_refs = fake_cleanup_downstream_refs

            target_stage = asyncio.run(self.manager.continue_task(db, project_id="p1", task_id="s1"))
            self._finish_continue_prepare(db, task, target_stage)

            self.assertTrue(system_output.exists())
            self.assertFalse(entry_output.exists())

    def test_continue_task_deletes_affected_downstream_tasks_before_requeue(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "input").mkdir(parents=True)
            task = BinarySecurityTask(
                id="s1",
                project_id="p1",
                name="source",
                status="failed",
                task_type=TASK_TYPE_SOURCE,
                current_stage="system_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            runs = [
                BinarySecurityStageRun(id="sr1", task_id="s1", project_id="p1", stage_name="system_analysis", sequence_no=1, status="failed"),
                BinarySecurityStageRun(id="sr2", task_id="s1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="pending"),
            ]
            items = [
                BinarySecurityStageItem(
                    id="i1",
                    task_id="s1",
                    project_id="p1",
                    stage_run_id="sr1",
                    stage_name="system_analysis",
                    item_key="m1",
                    parent_key="m1",
                    downstream_service="system_analyse",
                    downstream_task_id="sat_1",
                    status="failed",
                ),
                BinarySecurityStageItem(
                    id="i2",
                    task_id="s1",
                    project_id="p1",
                    stage_run_id="sr2",
                    stage_name="entry_analysis",
                    item_key="m1",
                    parent_key="m1",
                    downstream_service="entry_analyse",
                    downstream_task_id="eat_1",
                    status="pending",
                ),
            ]
            db = _ModelAwareDb(tasks=[task], stage_runs=runs, stage_items=items)
            cleaned_refs: list[dict[str, str]] = []

            async def fake_cleanup_downstream_refs(_db, _task, refs, _token):
                cleaned_refs.extend(refs)
                return len(refs)

            self.manager._cleanup_downstream_refs = fake_cleanup_downstream_refs

            target_stage = asyncio.run(self.manager.continue_task(db, project_id="p1", task_id="s1"))

            self.assertEqual("system_analysis", target_stage)
            self._finish_continue_prepare(db, task, target_stage)
            self.assertEqual("pending", task.status)
            self.assertEqual("system_analysis", task.current_stage)

    def test_cancel_task_cancels_local_worker(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        item = BinarySecurityStageItem(
            id="i1",
            task_id="t1",
            project_id="p1",
            stage_name="system_analysis",
            item_key="m1",
            status="running",
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=1,
            status="running",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[item])
        cancelled: list[str] = []

        async def fake_write_task_metadata_async(*args, **kwargs):
            return None

        async def fake_cancel_local_worker(task_id: str):
            cancelled.append(task_id)

        self.manager._write_task_metadata_async = fake_write_task_metadata_async
        self.manager._cancel_local_worker = fake_cancel_local_worker

        asyncio.run(self.manager.cancel_task(db, project_id="p1", task_id="t1"))

        self.assertEqual([], cancelled)
        self.assertEqual("running", task.status)
        event_types = [getattr(event, "event_type", "") for event in db.added]
        self.assertIn("manual_cancel_requested", event_types)
        asyncio.run(self.manager._apply_manual_cancel_request_locked(db, db.added[-1]))

        self.assertEqual(["t1"], cancelled)
        self.assertEqual("cancelled", task.status)
        self.assertEqual("cancelled", stage_run.status)
        self.assertEqual("cancelled", item.status)

    def test_cancel_task_holds_lock_during_async_cleanup(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        item = BinarySecurityStageItem(
            id="i1",
            task_id="t1",
            project_id="p1",
            stage_name="system_analysis",
            item_key="m1",
            status="running",
            downstream_service="system_analyse",
            downstream_task_id="sat_1",
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[item])
        order: list[str] = []

        async def fake_write_task_metadata_async(*args, **kwargs):
            del args, kwargs
            order.append("write_metadata")

        async def fake_cancel_local_worker(task_id: str):
            self.assertEqual("t1", task_id)
            order.append("cancel_worker")

        async def fake_cancel_downstream(downstream_item, token):
            del token
            self.assertEqual("sat_1", downstream_item.downstream_task_id)
            order.append("cancel_downstream")

        self.manager._write_task_metadata_async = fake_write_task_metadata_async
        self.manager._cancel_local_worker = fake_cancel_local_worker
        self.manager._cancel_downstream = fake_cancel_downstream

        asyncio.run(self.manager.cancel_task(db, project_id="p1", task_id="t1"))
        self.assertEqual([], order)
        asyncio.run(self.manager._apply_manual_cancel_request_locked(db, db.added[-1]))

        self.assertEqual(
            ["write_metadata", "cancel_worker", "cancel_downstream"],
            order,
        )

    def test_retry_task_clears_archive_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="binary",
                status="failed",
                task_type=TASK_TYPE_BINARY,
                current_stage="vuln_scan",
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            archive_jobs = [
                BinarySecurityArchiveJob(
                    id="aj1",
                    task_id="t1",
                    project_id="p1",
                    stage_name="vuln_scan",
                    item_id="i1",
                    archive_status="success",
                )
            ]
            db = _AppendingModelAwareDb(tasks=[task], archive_jobs=archive_jobs)

            self.manager.retry_task(db, project_id="p1", task_id="t1")
            self.assertEqual("failed", task.status)
            self.assertIsNone(task.pending_action)
            self.assertIn("manual_blocking_action_requested", [getattr(event, "event_type", "") for event in db.added])
            self.manager._apply_blocking_action_request_locked(db, db.added[-1])
            self.assertEqual("retry_preparing", task.status)
            self.assertEqual("retry", task.pending_action)

            original_delete_items = self.manager._delete_stage_items_for_stages
            original_delete_archive = self.manager._delete_archive_children_for_stages
            try:
                self.manager._delete_stage_items_for_stages = lambda db_arg, task_id, stages: db_arg.stage_items.clear()
                self.manager._delete_archive_children_for_stages = lambda db_arg, task_arg, stages: db_arg.archive_jobs.clear()
                stage_sequence = asyncio.run(self.manager._prepare_retry_task(db, task))
                task.status = "pending"
                task.current_stage = stage_sequence[0]
                task.execution_mode = None
                task.target_stage_name = None
                task.pending_action = None
                self.manager._clear_task_abnormal_reason_snapshot(db, task)
            finally:
                self.manager._delete_stage_items_for_stages = original_delete_items
                self.manager._delete_archive_children_for_stages = original_delete_archive

            self.assertEqual("pending", task.status)
            self.assertEqual([], db.archive_jobs)

    def test_retry_task_end_to_end_requeues_streaming_tail_failed_task(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="source",
                status="failed",
                task_type=TASK_TYPE_SOURCE,
                current_stage="dataflow_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
                policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
            )
            task.latest_abnormal_reason = {
                "is_abnormal": True,
                "category": "downstream",
                "code": "downstream_failed",
                "title": "下游任务失败",
                "message": "worker exited",
                "source_layer": "task",
                "status": "failed",
                "service": "binary-security",
            }
            stage_runs = [
                BinarySecurityStageRun(id="sr-system", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr-entry", task_id="t1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="success"),
                BinarySecurityStageRun(id="sr-df", task_id="t1", project_id="p1", stage_name="dataflow_analysis", sequence_no=3, status="failed"),
                BinarySecurityStageRun(id="sr-vuln", task_id="t1", project_id="p1", stage_name="vuln_scan", sequence_no=4, status="pending"),
            ]
            stage_items = [
                BinarySecurityStageItem(
                    id="si-df",
                    task_id="t1",
                    project_id="p1",
                    stage_run_id="sr-df",
                    stage_name="dataflow_analysis",
                    item_key="entry-a",
                    parent_key="mod-a",
                    item_identity_key="entry-a::mod-a",
                    status="failed",
                    downstream_service="dataflow_analyse",
                    downstream_task_id="dfa-1",
                    error_message="worker exited",
                )
            ]
            archive_jobs = [
                BinarySecurityArchiveJob(
                    id="aj-df",
                    task_id="t1",
                    project_id="p1",
                    stage_name="dataflow_analysis",
                    item_id="si-df",
                    archive_status="failed",
                )
            ]
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=stage_runs, stage_items=stage_items, archive_jobs=archive_jobs)

            self.manager.retry_task(db, project_id="p1", task_id="t1")
            self.assertIn("manual_blocking_action_requested", [getattr(event, "event_type", "") for event in db.added])

            self.manager._apply_blocking_action_request_locked(db, db.added[-1])
            self.assertEqual("retry_preparing", task.status)
            self.assertEqual("retry", task.pending_action)

            original_delete_items = self.manager._delete_stage_items_for_stages
            original_delete_archive = self.manager._delete_archive_children_for_stages
            try:
                self.manager._delete_stage_items_for_stages = lambda db_arg, task_id, stages: db_arg.stage_items.clear()
                self.manager._delete_archive_children_for_stages = lambda db_arg, task_arg, stages: db_arg.archive_jobs.clear()
                stage_sequence = asyncio.run(self.manager._prepare_retry_task(db, task))
                task.status = "pending"
                task.current_stage = stage_sequence[0]
                task.execution_mode = None
                task.target_stage_name = None
                task.pending_action = None
                self.manager._clear_task_abnormal_reason_snapshot(db, task)
            finally:
                self.manager._delete_stage_items_for_stages = original_delete_items
                self.manager._delete_archive_children_for_stages = original_delete_archive

            self.assertEqual("pending", task.status)
            self.assertEqual("system_analysis", task.current_stage)
            self.assertEqual([], db.stage_items)
            self.assertEqual([], db.archive_jobs)
            self.assertIsNone(task.latest_abnormal_reason)

    def test_prepare_retry_task_hard_restart_resets_epoch_and_local_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "input").mkdir(parents=True)
            (workspace / "output" / "entry-analyse").mkdir(parents=True)
            (workspace / "run" / "upload-tmp").mkdir(parents=True)
            (workspace / "state-event-payloads").mkdir(parents=True)
            (workspace / "timeline-event-payloads").mkdir(parents=True)
            (workspace / "task-summary.json").write_text("{}", encoding="utf-8")
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="binary",
                status="failed",
                task_type=TASK_TYPE_BINARY,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
                execution_epoch=2,
            )
            task.summary = {
                "input_files": [{"filename": "fw.bin", "size": 12}],
                "selected_modules": [{"module_key": "m1"}],
                "entry_results": [{"entry_key": "e1"}],
                "stale_reason": "old",
            }
            task.metrics = {"entry_count": 4, "input_total_bytes": 12}
            task.stage_summary = {"entry_analysis": {"status": "failed"}}
            stage_runs = [
                BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr2", task_id="t1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="failed"),
            ]
            stage_items = [
                BinarySecurityStageItem(
                    id="i1",
                    task_id="t1",
                    project_id="p1",
                    stage_run_id="sr2",
                    stage_name="entry_analysis",
                    item_key="m1",
                    status="failed",
                )
            ]
            archive_jobs = [
                BinarySecurityArchiveJob(
                    id="aj1",
                    task_id="t1",
                    project_id="p1",
                    stage_name="entry_analysis",
                    item_id="i1",
                    archive_status="failed",
                )
            ]
            timeline_events = [
                BinarySecurityEvent(
                    id="ev1",
                    task_id="t1",
                    project_id="p1",
                    event_type="task_failed",
                    message="failed",
                )
            ]
            db = _AppendingModelAwareDb(
                tasks=[task],
                stage_runs=stage_runs,
                stage_items=stage_items,
                archive_jobs=archive_jobs,
                events=timeline_events,
                state_events=[],
            )

            async def fake_cleanup_downstream_refs(_db, _task, refs, _token):
                self.assertEqual([], refs)

            self.manager._cleanup_downstream_refs = fake_cleanup_downstream_refs

            stage_sequence = asyncio.run(self.manager._prepare_retry_task(db, task))

            self.assertEqual(self.manager._stage_sequence_for_task(task), stage_sequence)
            self.assertEqual(3, task.execution_epoch)
            self.assertEqual(task.current_stage, stage_sequence[0])
            self.assertEqual([], db.stage_runs)
            self.assertEqual([], db.stage_items)
            self.assertEqual([], db.archive_jobs)
            self.assertEqual([], db.events)
            self.assertEqual([], db.state_events)
            self.assertEqual({}, task.stage_summary)
            self.assertEqual({}, task.cleanup_snapshot)
            self.assertEqual([], task.summary.get("selected_modules") or [])
            self.assertEqual([], task.summary.get("entry_results") or [])
            self.assertTrue((workspace / "task-summary.json").exists())
            self.assertEqual(3, json.loads((workspace / "task-summary.json").read_text(encoding="utf-8")).get("execution_epoch"))
            self.assertFalse((workspace / "output" / "entry-analyse").exists())

    def test_prepare_retry_task_rejects_when_cleanup_leaves_state_event_residue(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "input").mkdir(parents=True)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="source",
                status="failed",
                task_type=TASK_TYPE_SOURCE,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
                execution_epoch=0,
            )
            task.summary = {"input_files": [{"filename": "src.tar.gz", "size": 8}]}
            state_event = BinarySecurityStateEvent(
                id="sev1",
                task_id="t1",
                project_id="p1",
                event_type="downstream_terminal_observed",
                idempotency_key="sev1",
                status="pending",
                available_at=_now(),
            )
            db = _AppendingModelAwareDb(tasks=[task], state_events=[state_event])

            async def fake_cleanup_downstream_refs(_db, _task, refs, _token):
                self.assertEqual([], refs)

            self.manager._cleanup_downstream_refs = fake_cleanup_downstream_refs
            original_delete_state_events = self.manager._delete_task_state_event_rows
            try:
                def fake_delete_state_events(_db, _task_id):
                    return 0

                self.manager._delete_task_state_event_rows = fake_delete_state_events
                with self.assertRaises(ValidationError):
                    asyncio.run(self.manager._prepare_retry_task(db, task))
                self.assertEqual(1, len(db.state_events))
            finally:
                self.manager._delete_task_state_event_rows = original_delete_state_events

    def test_retry_failed_items_end_to_end_requeues_target_stage_for_streaming_tail_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="source",
                status="failed",
                task_type=TASK_TYPE_SOURCE,
                current_stage="dataflow_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
                policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
            )
            task.summary = {
                "entry_results": [
                    {
                        "module_key": "mod-a",
                        "entries": [{"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a"}],
                    },
                    {
                        "module_key": "mod-b",
                        "entries": [{"entry_key": "entry-b", "function_name": "func_b", "module_key": "mod-b"}],
                    },
                ],
                "vuln_results": [{"entry_key": "entry-a"}, {"entry_key": "entry-b"}],
            }
            stage_runs = [
                BinarySecurityStageRun(id="sr-system", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr-entry", task_id="t1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="success"),
                BinarySecurityStageRun(id="sr-df", task_id="t1", project_id="p1", stage_name="dataflow_analysis", sequence_no=3, status="failed"),
                BinarySecurityStageRun(id="sr-vuln", task_id="t1", project_id="p1", stage_name="vuln_scan", sequence_no=4, status="success"),
            ]
            df_failed = BinarySecurityStageItem(
                id="si-df-a",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr-df",
                stage_name="dataflow_analysis",
                item_key="entry-a",
                parent_key="mod-a",
                item_identity_key="entry-a::mod-a",
                status="failed",
                downstream_service="dataflow_analyse",
                downstream_task_id="dfa-a",
                error_message="dfa failed",
            )
            df_failed.input_ref = {"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a"}
            df_success = BinarySecurityStageItem(
                id="si-df-b",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr-df",
                stage_name="dataflow_analysis",
                item_key="entry-b",
                parent_key="mod-b",
                item_identity_key="entry-b::mod-b",
                status="success",
                downstream_service="dataflow_analyse",
                downstream_task_id="dfa-b",
            )
            df_success.input_ref = {"entry_key": "entry-b", "function_name": "func_b", "module_key": "mod-b"}
            vuln_failed = BinarySecurityStageItem(
                id="si-vuln-a",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr-vuln",
                stage_name="vuln_scan",
                item_key="entry-a",
                parent_key="mod-a",
                item_identity_key="entry-a::mod-a",
                status="success",
                downstream_service="dataflow_vuln_scanner",
                downstream_task_id="dvs-a",
            )
            vuln_failed.input_ref = {"entry_key": "entry-a", "module_key": "mod-a", "upstream_item_id": "si-df-a"}
            vuln_success = BinarySecurityStageItem(
                id="si-vuln-b",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr-vuln",
                stage_name="vuln_scan",
                item_key="entry-b",
                parent_key="mod-b",
                item_identity_key="entry-b::mod-b",
                status="success",
                downstream_service="dataflow_vuln_scanner",
                downstream_task_id="dvs-b",
            )
            vuln_success.input_ref = {"entry_key": "entry-b", "module_key": "mod-b", "upstream_item_id": "si-df-b"}
            archive_jobs = [
                BinarySecurityArchiveJob(id="aj-vuln-a", task_id="t1", project_id="p1", stage_name="vuln_scan", item_id="si-vuln-a", archive_status="success"),
                BinarySecurityArchiveJob(id="aj-vuln-b", task_id="t1", project_id="p1", stage_name="vuln_scan", item_id="si-vuln-b", archive_status="success"),
            ]
            db = _AppendingModelAwareDb(
                tasks=[task],
                stage_runs=stage_runs,
                stage_items=[df_failed, df_success, vuln_failed, vuln_success],
                archive_jobs=archive_jobs,
            )

            self.manager.retry_failed_items(db, project_id="p1", task_id="t1")
            self.assertIn("manual_blocking_action_requested", [getattr(event, "event_type", "") for event in db.added])
            self.manager._apply_blocking_action_request_locked(db, db.added[-1])

            self.assertEqual("retry_preparing", task.status)
            self.assertEqual("retry_failed_items", task.pending_action)
            self.assertEqual("dataflow_analysis", task.current_stage)

            original_delete_by_ids = self.manager._delete_stage_items_by_ids
            original_clear_archive = self.manager._clear_archive_jobs_for_stage_items
            original_cleanup_refs = self.manager._cleanup_downstream_refs
            try:
                self.manager._delete_stage_items_by_ids = lambda db_arg, item_ids: (
                    setattr(db_arg, "stage_items", [item for item in db_arg.stage_items if item.id not in set(item_ids)]) or len(item_ids)
                )
                self.manager._clear_archive_jobs_for_stage_items = lambda db_arg, task_id, stage_name, item_ids: (
                    setattr(db_arg, "archive_jobs", [job for job in db_arg.archive_jobs if job.item_id not in set(item_ids)]) or len(item_ids)
                )
                async def _noop_cleanup(db_arg, task_arg, refs_arg, token_arg):
                    del db_arg, task_arg, refs_arg, token_arg
                    return None
                self.manager._cleanup_downstream_refs = _noop_cleanup
                affected = asyncio.run(self.manager._prepare_retry_failed_items(db, task, "dataflow_analysis"))
                task.status = "pending"
                task.pending_action = None
                task.execution_mode = "task_retry_failed_items"
                task.target_stage_name = "dataflow_analysis"
            finally:
                self.manager._delete_stage_items_by_ids = original_delete_by_ids
                self.manager._clear_archive_jobs_for_stage_items = original_clear_archive
                self.manager._cleanup_downstream_refs = original_cleanup_refs

            self.assertEqual(["dataflow_analysis", "vuln_scan"], affected)
            self.assertEqual("pending", task.status)
            self.assertEqual("dataflow_analysis", task.current_stage)
            self.assertEqual({"si-df-a", "si-df-b", "si-vuln-b"}, {item.id for item in db.stage_items})
            self.assertEqual(["aj-vuln-b"], [job.id for job in db.archive_jobs])
            self.assertEqual(["entry-b"], [row.get("entry_key") for row in task.summary.get("vuln_results") or []])
            self.assertEqual("task_retry_failed_items", task.execution_mode)

    def test_apply_blocking_action_request_does_not_enqueue_action_directly(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="binary",
                status="failed",
                task_type=TASK_TYPE_BINARY,
                current_stage="binary_to_source",
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
                operation_lock_token="op-1",
            )
            event = BinarySecurityStateEvent(
                id="evt1",
                task_id="t1",
                project_id="p1",
                stage_name="binary_to_source",
                event_type="manual_blocking_action_requested",
                status="leased",
                payload={
                    "action": "retry_stage_full",
                    "preparing_status": "retry_preparing",
                    "target_stage": "binary_to_source",
                    "message": "accepted",
                    "operation_token": "op-1",
                },
            )
            db = _ModelAwareDb(tasks=[task])

            with patch.object(self.manager, "_enqueue_action") as enqueue_action:
                self.manager._apply_blocking_action_request_locked(db, event)

            self.assertEqual("retry_preparing", task.status)
            self.assertEqual("retry_stage_full", task.pending_action)
            enqueue_action.assert_not_called()

    def test_retry_task_clears_stage_output_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            output_root = workspace / "output"
            system_output = output_root / "system-analyse"
            entry_output = output_root / "entry-analyse"
            system_output.mkdir(parents=True)
            entry_output.mkdir(parents=True)
            (system_output / "stale.txt").write_text("old", encoding="utf-8")
            (entry_output / "stale.txt").write_text("old", encoding="utf-8")
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="binary",
                status="failed",
                task_type=TASK_TYPE_BINARY,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(output_root),
                workspace_root=str(workspace),
            )
            db = _ModelAwareDb(tasks=[task])

            self.manager.retry_task(db, project_id="p1", task_id="t1")
            self._finish_retry_prepare(db, task)

            self.assertFalse(system_output.exists())
            self.assertFalse(entry_output.exists())

    def test_binary_to_source_existing_retry_uses_rerun_api(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        item = BinarySecurityStageItem(
            id="item1",
            task_id="task1",
            project_id="p1",
            stage_name="binary_to_source",
            item_key="module1",
            item_name="mod.so",
            parent_key="fw1",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-1",
            status="failed",
        )

        class _FakeB2SClient:
            def __init__(self):
                self.calls = []

            async def rerun_task(self, project_id, task_id, token, *, clean_output=True, cancel_running=True):
                self.calls.append(
                    {
                        "project_id": project_id,
                        "task_id": task_id,
                        "token": token,
                        "clean_output": clean_output,
                        "cancel_running": cancel_running,
                    }
                )
                return {"status": "ok"}

        fake_client = _FakeB2SClient()
        original = task_manager_module.get_binary_to_source_client
        task_manager_module.get_binary_to_source_client = lambda: fake_client
        try:
            result = asyncio.run(
                self.manager._invoke_existing_downstream_retry(
                    "binary_to_source",
                    task=task,
                    item=item,
                    token="tok",
                )
            )
        finally:
            task_manager_module.get_binary_to_source_client = original

        self.assertEqual({"status": "ok"}, result)
        self.assertEqual(
            [
                {
                    "project_id": "p1",
                    "task_id": "b2s-1",
                    "token": "tok",
                    "clean_output": True,
                    "cancel_running": True,
                }
            ],
            fake_client.calls,
        )

    def test_control_existing_downstream_task_marks_running_conflict_as_already_running(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        item = BinarySecurityStageItem(
            id="item1",
            task_id="task1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="module1",
            item_name="mod",
            parent_key="fw1",
            downstream_service="entry_analyse",
            downstream_task_id="ea-1",
            status="failed",
        )

        async def fake_retry(*args, **kwargs):
            del args, kwargs
            raise ValidationError('{"detail":"任务仍在运行中，请先取消后再重启"}')

        async def fake_fetch(*args, **kwargs):
            del args, kwargs
            return {"task_id": "ea-1", "status": "running"}

        with (
            patch.object(self.manager, "_invoke_existing_downstream_retry", side_effect=fake_retry),
            patch.object(self.manager, "_fetch_downstream_task_payload", side_effect=fake_fetch),
        ):
            result = asyncio.run(
                self.manager._control_existing_downstream_task(
                    "entry_analysis",
                    task=task,
                    item=item,
                    token="tok",
                )
            )

        self.assertEqual("already_running", result["outcome"])
        self.assertEqual("ea-1", result["payload"]["task_id"])
        self.assertEqual("running", result["payload"]["status"])

    def test_control_existing_dataflow_task_reuses_running_downstream(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            current_stage="dataflow_analysis",
            task_type=TASK_TYPE_BINARY_MODULE,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        item = BinarySecurityStageItem(
            id="item1",
            task_id="task1",
            project_id="p1",
            stage_name="dataflow_analysis",
            item_key="entry1",
            item_name="entry1",
            parent_key="mod1",
            downstream_service="dataflow_analyse",
            downstream_task_id="dfa-1",
            status="running",
        )

        async def fake_fetch(*args, **kwargs):
            del args, kwargs
            return {"task_id": "dfa-1", "status": "running"}

        with patch.object(self.manager, "_fetch_downstream_task_payload", side_effect=fake_fetch):
            result = asyncio.run(
                self.manager._control_existing_downstream_task(
                    "dataflow_analysis",
                    task=task,
                    item=item,
                    token=None,
                )
            )

        self.assertEqual("already_running", result["outcome"])
        self.assertEqual("dfa-1", result["payload"]["task_id"])
        self.assertEqual("running", result["payload"]["status"])

    def test_control_existing_dataflow_running_task_reuses_without_restart(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            current_stage="dataflow_analysis",
            task_type=TASK_TYPE_BINARY_MODULE,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        item = BinarySecurityStageItem(
            id="item1",
            task_id="task1",
            project_id="p1",
            stage_name="dataflow_analysis",
            item_key="entry-1",
            item_name="entry",
            parent_key="mod-1",
            downstream_service="dataflow_analyse",
            downstream_task_id="dfa-1",
            status="running",
        )

        async def fake_fetch(*args, **kwargs):
            del args, kwargs
            return {"task_id": "dfa-1", "status": "running"}

        with patch.object(self.manager, "_fetch_downstream_task_payload", side_effect=fake_fetch):
            result = asyncio.run(
                self.manager._control_existing_downstream_task(
                    "dataflow_analysis",
                    task=task,
                    item=item,
                    token=None,
                )
            )

        self.assertEqual("already_running", result["outcome"])
        self.assertEqual("dfa-1", result["payload"]["task_id"])
        self.assertEqual("running", result["payload"]["status"])

    def test_control_existing_downstream_task_marks_transport_error_as_deferred(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        item = BinarySecurityStageItem(
            id="item1",
            task_id="task1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="module1",
            item_name="mod",
            parent_key="fw1",
            downstream_service="entry_analyse",
            downstream_task_id="ea-1",
            status="failed",
        )

        async def fake_retry(*args, **kwargs):
            del args, kwargs
            raise UpstreamError("无法连接下游服务: All connection attempts failed")

        with patch.object(self.manager, "_invoke_existing_downstream_retry", side_effect=fake_retry):
            result = asyncio.run(
                self.manager._control_existing_downstream_task(
                    "entry_analysis",
                    task=task,
                    item=item,
                    token="tok",
                )
            )

        self.assertEqual("transport_error", result["outcome"])
        self.assertIn("All connection attempts failed", result["error_message"])

    def test_retry_task_full_restart_cleans_existing_downstream_refs(self):
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="failed",
                task_type=TASK_TYPE_BINARY,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(Path(tmp) / "output"),
                workspace_root=tmp,
            )
            items = [
                BinarySecurityStageItem(
                    id="item1",
                    task_id="task1",
                    project_id="p1",
                    stage_name="system_analysis",
                    item_key="fw1",
                    item_name="fw1",
                    parent_key="fw1",
                    downstream_service="system_analyse",
                    downstream_task_id="sa-1",
                    status="failed",
                )
            ]
            db = _ModelAwareDb(tasks=[task], stage_items=items)
            calls = []

            async def fake_cleanup(db_arg, task_arg, refs_arg, token_arg):
                calls.append(
                    {
                        "db": db_arg,
                        "task_id": task_arg.id,
                        "refs": refs_arg,
                        "token": token_arg,
                    }
                )

            original_cleanup = self.manager._cleanup_downstream_refs
            original_discover = self.manager._discover_parent_linked_downstream_refs
            self.manager._cleanup_downstream_refs = fake_cleanup
            self.manager._discover_parent_linked_downstream_refs = lambda _db, _task: [
                {"service": "system_analyse", "task_id": "sa-1", "project_id": "p1", "stage_name": "system_analysis"},
                {"service": "system_analyse", "task_id": "sa-orphan", "project_id": "p1", "stage_name": "system_analysis"},
                {"service": "dataflow_analyse", "task_id": "dfa-other", "project_id": "p1", "stage_name": "dataflow_analysis"},
            ]
            try:
                self.manager.retry_task(db, project_id="p1", task_id="task1")
                self._finish_retry_prepare(db, task)
            finally:
                self.manager._cleanup_downstream_refs = original_cleanup
                self.manager._discover_parent_linked_downstream_refs = original_discover

            self.assertEqual(1, len(calls))
            self.assertEqual("task1", calls[0]["task_id"])
            self.assertEqual(["sa-1", "sa-orphan", "dfa-other"], [ref["task_id"] for ref in calls[0]["refs"]])

    def test_cleanup_downstream_refs_waits_for_system_analyse_to_stop_before_delete(self):
        refs = [{"service": "system_analyse", "task_id": "sat-1", "project_id": "p1", "stage_name": "system_analysis"}]
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/tmp/ws",
        )
        db = _ModelAwareDb(tasks=[task])
        calls = []
        responses = iter([
            {"status": "running"},
            {"status": "cancelled"},
        ])

        async def fake_cancel(*args, **kwargs):
            calls.append("cancel")
            return 1

        async def fake_delete(*args, **kwargs):
            calls.append("delete")
            return 1

        async def fake_fetch(*args, **kwargs):
            calls.append("fetch")
            return next(responses)

        async def fake_sleep(*args, **kwargs):
            return None

        original_cancel = self.manager._cancel_downstream_refs
        original_delete = self.manager._delete_downstream_refs
        original_fetch = self.manager._fetch_downstream_ref_payload
        original_sleep = task_manager_module.asyncio.sleep
        self.manager._cancel_downstream_refs = fake_cancel
        self.manager._delete_downstream_refs = fake_delete
        self.manager._fetch_downstream_ref_payload = fake_fetch
        task_manager_module.asyncio.sleep = fake_sleep
        try:
            asyncio.run(self.manager._cleanup_downstream_refs(db, task, refs, None))
        finally:
            self.manager._cancel_downstream_refs = original_cancel
            self.manager._delete_downstream_refs = original_delete
            self.manager._fetch_downstream_ref_payload = original_fetch
            task_manager_module.asyncio.sleep = original_sleep

        self.assertEqual(["cancel", "fetch", "fetch", "delete"], calls)

    def test_cleanup_downstream_refs_raises_when_system_analyse_stays_running(self):
        refs = [{"service": "system_analyse", "task_id": "sat-1", "project_id": "p1", "stage_name": "system_analysis"}]
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/tmp/ws",
        )
        db = _ModelAwareDb(tasks=[task])

        async def fake_cancel(*args, **kwargs):
            return 1

        async def fake_fetch(*args, **kwargs):
            return {"status": "running"}

        async def fake_sleep(*args, **kwargs):
            return None

        original_cancel = self.manager._cancel_downstream_refs
        original_fetch = self.manager._fetch_downstream_ref_payload
        original_sleep = task_manager_module.asyncio.sleep
        self.manager._cancel_downstream_refs = fake_cancel
        self.manager._fetch_downstream_ref_payload = fake_fetch
        task_manager_module.asyncio.sleep = fake_sleep
        self.manager.cfg.scheduler.downstream_request_timeout_seconds = 0
        self.manager.cfg.scheduler.stage_poll_interval_seconds = 0
        try:
            with self.assertRaises(ValidationError):
                asyncio.run(self.manager._cleanup_downstream_refs(db, task, refs, None))
        finally:
            self.manager._cancel_downstream_refs = original_cancel
            self.manager._fetch_downstream_ref_payload = original_fetch
            task_manager_module.asyncio.sleep = original_sleep

    def test_continue_task_prefers_existing_downstream_tasks(self):
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="failed",
                task_type=TASK_TYPE_BINARY,
                current_stage="system_analysis",
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root="/o",
                workspace_root=tmp,
            )
            task.summary = {
                "firmware_unpack_results": [{"firmware_key": "fw1"}],
                "selected_modules": [{"module_key": "m1"}],
                "entry_results": [{"entry_key": "e1"}],
            }
            stage_runs = [
                SimpleNamespace(task_id="task1", stage_name="firmware_unpack", status="success"),
                BinarySecurityStageRun(id="sr1", task_id="task1", stage_name="system_analysis", status="failed"),
                BinarySecurityStageRun(id="sr2", task_id="task1", stage_name="binary_to_source", status="pending"),
            ]
            item = BinarySecurityStageItem(
                id="item1",
                task_id="task1",
                project_id="p1",
                stage_name="system_analysis",
                item_key="fw1",
                item_name="fw1",
                parent_key="fw1",
                downstream_service="system_analyse",
                downstream_task_id="sa-1",
                status="failed",
            )
            db = _ModelAwareDb(tasks=[task], stage_runs=stage_runs, stage_items=[item])

            stage = asyncio.run(self.manager.continue_task(db, project_id="p1", task_id="task1"))

            self.assertEqual("system_analysis", stage)
            self._finish_continue_prepare(db, task, stage)
            self.assertEqual("task_retry", task.execution_mode)
            self.assertEqual("system_analysis", task.target_stage_name)
            self.assertEqual(1, len(db.stage_items))

    def test_retry_stage_requeues_failed_archive_job_and_marks_task_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="binary",
                status="failed",
                task_type=TASK_TYPE_BINARY,
                current_stage="firmware_unpack",
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
                last_error="归档失败",
                finished_at=_now(),
            )
            run = BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="firmware_unpack",
                sequence_no=1,
                status="failed",
                last_error="归档失败",
            )
            item = BinarySecurityStageItem(
                id="i1",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr1",
                stage_name="firmware_unpack",
                item_key="fw1",
                item_name="fw.bin",
                status="failed",
                downstream_service="firmware_unpacker",
                downstream_task_id="ut1",
                error_message="归档失败",
            )
            item.input_ref = {"filename": "fw.bin", "path": "/input/fw.bin"}
            job = BinarySecurityArchiveJob(
                id="aj1",
                task_id="t1",
                project_id="p1",
                stage_name="firmware_unpack",
                item_id="i1",
                item_key="fw1",
                downstream_service="firmware_unpacker",
                downstream_task_id="ut1",
                archive_status="failed",
                owner_id="old-worker",
                archive_root=str(workspace / "old-archive"),
                error_message="copy failed",
            )
            job.payload = {"mapped_status": "success"}
            db = _ModelAwareDb(tasks=[task], stage_runs=[run], stage_items=[item], archive_jobs=[job])

            self.manager.retry_stage(db, project_id="p1", task_id="t1", stage_name="firmware_unpack")

            self.assertEqual("failed", task.status)
            self.assertEqual("firmware_unpack", task.current_stage)
            self.assertEqual("归档失败", task.last_error)
            self.assertIsNotNone(task.finished_at)
            self.assertEqual("failed", job.archive_status)
            self.assertEqual("old-worker", job.owner_id)
            self.assertEqual(str(workspace / "old-archive"), job.archive_root)
            self.assertEqual("failed", item.status)
            event_types = [getattr(event, "event_type", "") for event in db.added]
            self.assertIn("manual_blocking_action_requested", event_types)

    def test_retry_stage_archive_requeues_only_target_stage_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="binary",
                status="failed",
                task_type=TASK_TYPE_BINARY,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
                finished_at=_now(),
            )
            entry_item = BinarySecurityStageItem(
                id="i1",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                item_key="m1",
                status="failed",
                downstream_service="entry_analyse",
                downstream_task_id="eat1",
            )
            dataflow_item = BinarySecurityStageItem(
                id="i2",
                task_id="t1",
                project_id="p1",
                stage_name="dataflow_analysis",
                item_key="m1-entry",
                status="failed",
                downstream_service="dataflow_analyse",
                downstream_task_id="dat1",
            )
            entry_job = BinarySecurityArchiveJob(
                id="aj1",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                item_id="i1",
                item_key="m1",
                archive_status="failed",
                archive_root=str(workspace / "entry-archive"),
                error_message="copy failed",
            )
            entry_job.payload = {"mapped_status": "partial_success"}
            dataflow_job = BinarySecurityArchiveJob(
                id="aj2",
                task_id="t1",
                project_id="p1",
                stage_name="dataflow_analysis",
                item_id="i2",
                item_key="m1-entry",
                archive_status="failed",
                archive_root=str(workspace / "dataflow-archive"),
                error_message="copy failed",
            )
            dataflow_job.payload = {"mapped_status": "success"}
            db = _ModelAwareDb(tasks=[task], stage_items=[entry_item, dataflow_item], archive_jobs=[entry_job, dataflow_job])

            self.manager.retry_stage_archive(db, project_id="p1", task_id="t1", stage_name="entry_analysis")
            event_types = [getattr(event, "event_type", "") for event in db.added]
            self.assertIn("manual_archive_retry_requested", event_types)
            self.manager._apply_manual_archive_retry_request_locked(db, db.added[-1])

            self.assertEqual("pending", entry_job.archive_status)
            self.assertEqual("failed", dataflow_job.archive_status)
            self.assertEqual("running", task.status)
            self.assertEqual("entry_analysis", task.current_stage)
            self.assertIsNone(task.finished_at)
            event_types = [getattr(event, "event_type", "") for event in db.added]
            self.assertIn("archive_stage_retry_requested", event_types)
            self.assertIn("task_archive_retry_requeued", event_types)

    def test_retry_archive_job_requeues_single_failed_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="binary",
                status="partial_success",
                task_type=TASK_TYPE_BINARY,
                current_stage="system_analysis",
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
                finished_at=_now(),
            )
            item = BinarySecurityStageItem(
                id="i1",
                task_id="t1",
                project_id="p1",
                stage_name="system_analysis",
                item_key="fw1",
                status="failed",
                downstream_service="system_analyse",
                downstream_task_id="sat1",
            )
            retryable_job = BinarySecurityArchiveJob(
                id="aj1",
                task_id="t1",
                project_id="p1",
                stage_name="system_analysis",
                item_id="i1",
                item_key="fw1",
                archive_status="failed",
                archive_root=str(workspace / "old-archive"),
                error_message="copy failed",
                owner_id="worker1",
            )
            retryable_job.payload = {"mapped_status": "success", "downstream_payload": {"task_id": "sat1"}}
            other_job = BinarySecurityArchiveJob(
                id="aj2",
                task_id="t1",
                project_id="p1",
                stage_name="system_analysis",
                item_id="i1",
                item_key="fw1",
                archive_status="failed",
                archive_root=str(workspace / "old-archive-2"),
                error_message="copy failed",
                owner_id="worker2",
            )
            other_job.payload = {"mapped_status": "failed", "downstream_payload": {"task_id": "sat1"}}
            db = _ModelAwareDb(tasks=[task], stage_items=[item], archive_jobs=[retryable_job, other_job])

            stage_name = self.manager.retry_archive_job(db, project_id="p1", task_id="t1", archive_job_id="aj1")

            self.assertEqual("system_analysis", stage_name)
            event_types = [getattr(event, "event_type", "") for event in db.added]
            self.assertIn("manual_archive_retry_requested", event_types)
            self.manager._apply_manual_archive_retry_request_locked(db, db.added[-1])
            self.assertEqual("pending", retryable_job.archive_status)
            self.assertIsNone(retryable_job.archive_root)
            self.assertIsNone(retryable_job.error_message)
            self.assertIsNone(retryable_job.owner_id)
            self.assertEqual("failed", other_job.archive_status)
            event_types = [getattr(event, "event_type", "") for event in db.added]
            self.assertIn("archive_job_retry_requested", event_types)
            self.assertIn("task_archive_retry_requeued", event_types)

    def test_archive_job_retry_support_rejects_non_success_like_target_status(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        job = BinarySecurityArchiveJob(
            id="aj1",
            task_id="t1",
            project_id="p1",
            stage_name="system_analysis",
            item_id="i1",
            archive_status="failed",
        )
        job.payload = {"mapped_status": "failed"}

        supported, reason = self.manager._archive_job_retry_support(_ModelAwareDb(), task, job)

        self.assertFalse(supported)
        self.assertIn("目标状态", reason or "")

    def test_build_stage_overview_nodes_sets_archive_retry_support(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="task",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/tmp/in",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            status="failed",
        )
        item = BinarySecurityStageItem(
            id="i1",
            task_id="t1",
            project_id="p1",
            stage_name="firmware_unpack",
            item_key="fw1",
            status="failed",
            downstream_service="firmware_unpacker",
            downstream_task_id="d1",
        )
        summaries = [
            BinarySecurityStageSummary(
                stage_name="firmware_unpack",
                sequence_no=1,
                status="failed",
                retry_supported=True,
                failed_items=1,
                total_items=1,
            )
        ]
        archive_jobs = [
            BinarySecurityArchiveJobResponse(
                id="aj1",
                stage_name="firmware_unpack",
                item_id="i1",
                item_key="fw1",
                archive_status="failed",
                retry_supported=True,
            )
        ]
        db = _ModelAwareDb(
            tasks=[task],
            stage_items=[item],
            archive_jobs=[
                BinarySecurityArchiveJob(
                    id="aj1",
                    task_id="t1",
                    project_id="p1",
                    stage_name="firmware_unpack",
                    item_id="i1",
                    item_key="fw1",
                    archive_status="failed",
                )
            ],
        )
        db.archive_jobs[0].payload = {"mapped_status": "success"}

        nodes = self.manager._build_stage_overview_nodes(db, task, summaries, archive_jobs, [item])
        by_node_id = {node.node_id: node for node in nodes}

        self.assertTrue(by_node_id["archive:firmware_unpack"].retry_supported)

    def test_build_manual_operation_state_exposes_can_retry_archive(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="task",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/tmp/in",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            status="failed",
        )
        item = BinarySecurityStageItem(
            id="i1",
            task_id="t1",
            project_id="p1",
            stage_name="firmware_unpack",
            item_key="fw1",
            status="failed",
        )
        job = BinarySecurityArchiveJob(
            id="aj1",
            task_id="t1",
            project_id="p1",
            stage_name="firmware_unpack",
            item_id="i1",
            archive_status="failed",
        )
        job.payload = {"mapped_status": "success"}
        db = _ModelAwareDb(tasks=[task], stage_items=[item], archive_jobs=[job])

        state = self.manager._build_manual_operation_state(
            db,
            task,
            task_retry_supported=False,
            task_retry_reason=None,
            task_retry_failed_supported=False,
            task_retry_failed_reason=None,
            task_continue_supported=False,
            task_continue_reason=None,
            stage_summaries=[BinarySecurityStageSummary(stage_name="firmware_unpack", sequence_no=1, status="failed")],
        )

        self.assertTrue(state["can_retry_archive"])

    def test_build_manual_operation_state_blocks_streaming_tail_pending_auto_progress(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="task",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/tmp/in",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            status="pending",
            current_stage="dataflow_analysis",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        item = BinarySecurityStageItem(
            id="i1",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            item_key="entry-1",
            status="pending",
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[item])

        state = self.manager._build_manual_operation_state(
            db,
            task,
            task_retry_supported=False,
            task_retry_reason="当前任务处于 streaming tail 自动推进中，暂不支持任务重试",
            task_retry_failed_supported=False,
            task_retry_failed_reason="当前任务处于 streaming tail 自动推进中，暂不支持失败项重试",
            task_continue_supported=False,
            task_continue_reason="当前任务处于 streaming tail 自动推进中，无需手动继续",
            stage_summaries=[BinarySecurityStageSummary(stage_name="dataflow_analysis", sequence_no=3, status="pending")],
        )

        self.assertEqual("blocked", state["overall"])
        self.assertEqual("task_running", state["blocking_code"])
        self.assertFalse(state["can_continue"])
        self.assertFalse(state["can_retry"])
        self.assertFalse(state["can_retry_failed_items"])

    def test_retry_stage_clears_archive_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="s1",
                project_id="p1",
                name="source",
                status="failed",
                task_type=TASK_TYPE_SOURCE,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            run = BinarySecurityStageRun(
                id="sr1",
                task_id="s1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="failed",
            )
            archive_jobs = [
                BinarySecurityArchiveJob(
                    id="aj1",
                    task_id="s1",
                    project_id="p1",
                    stage_name="entry_analysis",
                    item_id="i1",
                    archive_status="failed",
                )
            ]
            stage_items = [
                BinarySecurityStageItem(
                    id="i1",
                    task_id="s1",
                    project_id="p1",
                    stage_run_id="sr1",
                    stage_name="entry_analysis",
                    item_key="module-1",
                    status="failed",
                )
            ]
            db = _ModelAwareDb(tasks=[task], stage_runs=[run], stage_items=stage_items, archive_jobs=archive_jobs)

            self.manager.retry_stage(db, project_id="p1", task_id="s1", stage_name="entry_analysis")

            self.assertEqual("failed", task.status)
            self.assertIn("manual_blocking_action_requested", [getattr(event, "event_type", "") for event in db.added])
            self.assertEqual(1, len(db.archive_jobs))

    def test_retry_stage_deletes_affected_downstream_tasks_before_requeue(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="s1",
                project_id="p1",
                name="source",
                status="failed",
                task_type=TASK_TYPE_SOURCE,
                current_stage="system_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            runs = [
                BinarySecurityStageRun(id="sr1", task_id="s1", project_id="p1", stage_name="system_analysis", sequence_no=1, status="failed"),
                BinarySecurityStageRun(id="sr2", task_id="s1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="pending"),
            ]
            items = [
                BinarySecurityStageItem(
                    id="i1",
                    task_id="s1",
                    project_id="p1",
                    stage_run_id="sr1",
                    stage_name="system_analysis",
                    item_key="source_project",
                    parent_key="source_project",
                    downstream_service="system_analyse",
                    downstream_task_id="sat_1",
                    status="running",
                ),
                BinarySecurityStageItem(
                    id="i2",
                    task_id="s1",
                    project_id="p1",
                    stage_run_id="sr2",
                    stage_name="entry_analysis",
                    item_key="m1",
                    parent_key="m1",
                    downstream_service="entry_analyse",
                    downstream_task_id="eat_1",
                    status="queued",
                ),
            ]
            db = _ModelAwareDb(tasks=[task], stage_runs=runs, stage_items=items)
            deleted_refs: list[dict[str, str]] = []
            cancelled_refs: list[dict[str, str]] = []

            async def fake_cancel_downstream_refs(_db, _task, refs, _token):
                cancelled_refs.extend(refs)
                return len(refs)

            async def fake_delete_downstream_refs(_db, _task, refs, _token):
                deleted_refs.extend(refs)
                return len(refs)

            original_cancel = self.manager._cancel_downstream_refs
            original_delete = self.manager._delete_downstream_refs
            original_retry_support = self.manager._stage_retry_support
            original_discover = self.manager._discover_parent_linked_downstream_refs
            try:
                self.manager._cancel_downstream_refs = fake_cancel_downstream_refs
                self.manager._delete_downstream_refs = fake_delete_downstream_refs
                self.manager._stage_retry_support = lambda _db, _task, _stage_name: (True, None)
                self.manager._discover_parent_linked_downstream_refs = lambda _db, _task: [
                    {"service": "system_analyse", "task_id": "sat_1", "project_id": "p1", "stage_name": "system_analysis"},
                    {"service": "system_analyse", "task_id": "sat_orphan", "project_id": "p1", "stage_name": "system_analysis"},
                    {"service": "entry_analyse", "task_id": "eat_1", "project_id": "p1", "stage_name": "entry_analysis"},
                    {"service": "firmware_unpacker", "task_id": "fw_ignored", "project_id": "p1", "stage_name": "firmware_unpack"},
                ]
                self.manager.retry_stage(db, project_id="p1", task_id="s1", stage_name="system_analysis")
            finally:
                self.manager._cancel_downstream_refs = original_cancel
                self.manager._delete_downstream_refs = original_delete
                self.manager._stage_retry_support = original_retry_support
                self.manager._discover_parent_linked_downstream_refs = original_discover

            self.assertEqual([], cancelled_refs)
            self.assertEqual([], deleted_refs)
            self.assertEqual("failed", task.status)

    def test_retry_failed_items_cleanup_includes_orphaned_downstream_refs_in_affected_stages(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.summary = {
            "retry_plan": {
                "target_stage": "system_analysis",
                "mode": "retry_stage_failed_items",
                "retry_item_keys": ["fw1::fw1"],
            }
        }
        runs = [
            BinarySecurityStageRun(id="sr1", task_id="task1", project_id="p1", stage_name="system_analysis", sequence_no=1, status="failed"),
            BinarySecurityStageRun(id="sr2", task_id="task1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="failed"),
        ]
        items = [
            BinarySecurityStageItem(
                id="item1",
                task_id="task1",
                project_id="p1",
                stage_run_id="sr1",
                stage_name="system_analysis",
                item_key="fw1",
                item_name="fw1",
                parent_key="fw1",
                item_identity_key="fw1::fw1",
                downstream_service="system_analyse",
                downstream_task_id="sa-1",
                status="failed",
            ),
            BinarySecurityStageItem(
                id="item2",
                task_id="task1",
                project_id="p1",
                stage_run_id="sr2",
                stage_name="entry_analysis",
                item_key="mod1",
                item_name="mod1",
                parent_key="fw1",
                downstream_service="entry_analyse",
                downstream_task_id="ea-1",
                status="failed",
            ),
        ]
        db = _ModelAwareDb(tasks=[task], stage_runs=runs, stage_items=items)
        calls = []

        async def fake_cleanup(db_arg, task_arg, refs_arg, token_arg):
            calls.append({"db": db_arg, "task_id": task_arg.id, "refs": refs_arg, "token": token_arg})

        async def fake_sync(*args, **kwargs):
            del args, kwargs
            return None

        original_cleanup = self.manager._cleanup_downstream_refs
        original_sync = self.manager.sync_downstream_status
        original_discover = self.manager._discover_parent_linked_downstream_refs
        try:
            self.manager._cleanup_downstream_refs = fake_cleanup
            self.manager.sync_downstream_status = fake_sync
            self.manager._discover_parent_linked_downstream_refs = lambda _db, _task: [
                {"service": "system_analyse", "task_id": "sa-orphan", "project_id": "p1", "stage_name": "system_analysis"},
                {"service": "entry_analyse", "task_id": "ea-orphan", "project_id": "p1", "stage_name": "entry_analysis"},
                {"service": "firmware_unpacker", "task_id": "fw-ignored", "project_id": "p1", "stage_name": "firmware_unpack"},
            ]
            affected = asyncio.run(self.manager._prepare_retry_failed_items(db, task, "system_analysis"))
        finally:
            self.manager._cleanup_downstream_refs = original_cleanup
            self.manager.sync_downstream_status = original_sync
            self.manager._discover_parent_linked_downstream_refs = original_discover

        self.assertEqual(
            ["system_analysis", "binary_to_source", "entry_analysis", "dataflow_analysis", "vuln_scan"],
            affected,
        )
        self.assertEqual(1, len(calls))
        self.assertEqual(["ea-orphan"], [ref["task_id"] for ref in calls[0]["refs"]])

    def test_prepare_retry_failed_items_streaming_entry_retry_clears_only_linked_descendants(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="failed",
                task_type=TASK_TYPE_SOURCE,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(Path(tmp) / "output"),
                workspace_root=tmp,
                policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
            )
            task.summary = {
                "retry_plan": {
                    "target_stage": "entry_analysis",
                    "mode": "retry_stage_failed_items",
                    "retry_item_keys": ["mod-a::source_project"],
                },
                "dataflow_results": [
                    {"entry_key": "entry-a", "module_key": "mod-a", "function_name": "func_a"},
                    {"entry_key": "entry-b", "module_key": "mod-b", "function_name": "func_b"},
                ],
                "vuln_results": [
                    {"entry_key": "entry-a", "module_key": "mod-a", "function_name": "func_a"},
                    {"entry_key": "entry-b", "module_key": "mod-b", "function_name": "func_b"},
                ],
            }
            stage_runs = [
                BinarySecurityStageRun(id="sr-entry", task_id="task1", project_id="p1", stage_name="entry_analysis", sequence_no=1, status="failed"),
                BinarySecurityStageRun(id="sr-df", task_id="task1", project_id="p1", stage_name="dataflow_analysis", sequence_no=2, status="success"),
                BinarySecurityStageRun(id="sr-vuln", task_id="task1", project_id="p1", stage_name="vuln_scan", sequence_no=3, status="success"),
            ]

            entry_a = BinarySecurityStageItem(
                id="si-entry-a",
                task_id="task1",
                project_id="p1",
                stage_run_id="sr-entry",
                stage_name="entry_analysis",
                item_key="mod-a",
                item_name="mod-a",
                parent_key="source_project",
                item_identity_key="source_project::mod-a",
                status="failed",
                downstream_service="entry_analyse",
                downstream_task_id="ea-a",
            )
            entry_a.input_ref = {"module_key": "mod-a", "module_name": "mod-a", "source_dir": "/src/a"}
            entry_b = BinarySecurityStageItem(
                id="si-entry-b",
                task_id="task1",
                project_id="p1",
                stage_run_id="sr-entry",
                stage_name="entry_analysis",
                item_key="mod-b",
                item_name="mod-b",
                parent_key="source_project",
                item_identity_key="source_project::mod-b",
                status="success",
                downstream_service="entry_analyse",
                downstream_task_id="ea-b",
            )
            entry_b.input_ref = {"module_key": "mod-b", "module_name": "mod-b", "source_dir": "/src/b"}
            entry_b.result = {"entries_preview": [{"entry_key": "entry-b", "function_name": "func_b", "module_key": "mod-b"}]}

            df_a = BinarySecurityStageItem(
                id="si-df-a",
                task_id="task1",
                project_id="p1",
                stage_run_id="sr-df",
                stage_name="dataflow_analysis",
                item_key="entry-a",
                item_name="func_a",
                parent_key="mod-a",
                item_identity_key="mod-a::entry-a",
                status="success",
                downstream_service="dataflow_analyse",
                downstream_task_id="dfa-a",
            )
            df_a.input_ref = {"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a", "upstream_item_id": "si-entry-a"}
            df_a.result = {"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a"}
            df_b = BinarySecurityStageItem(
                id="si-df-b",
                task_id="task1",
                project_id="p1",
                stage_run_id="sr-df",
                stage_name="dataflow_analysis",
                item_key="entry-b",
                item_name="func_b",
                parent_key="mod-b",
                item_identity_key="mod-b::entry-b",
                status="success",
                downstream_service="dataflow_analyse",
                downstream_task_id="dfa-b",
            )
            df_b.input_ref = {"entry_key": "entry-b", "function_name": "func_b", "module_key": "mod-b", "upstream_item_id": "si-entry-b"}
            df_b.result = {"entry_key": "entry-b", "function_name": "func_b", "module_key": "mod-b"}

            vuln_a = BinarySecurityStageItem(
                id="si-vuln-a",
                task_id="task1",
                project_id="p1",
                stage_run_id="sr-vuln",
                stage_name="vuln_scan",
                item_key="entry-a",
                item_name="func_a",
                parent_key="mod-a",
                item_identity_key="mod-a::entry-a",
                status="success",
                downstream_service="dataflow_vuln_scanner",
                downstream_task_id="dfvs-a",
            )
            vuln_a.input_ref = {"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a", "upstream_item_id": "si-df-a"}
            vuln_a.result = {"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a"}
            vuln_b = BinarySecurityStageItem(
                id="si-vuln-b",
                task_id="task1",
                project_id="p1",
                stage_run_id="sr-vuln",
                stage_name="vuln_scan",
                item_key="entry-b",
                item_name="func_b",
                parent_key="mod-b",
                item_identity_key="mod-b::entry-b",
                status="success",
                downstream_service="dataflow_vuln_scanner",
                downstream_task_id="dfvs-b",
            )
            vuln_b.input_ref = {"entry_key": "entry-b", "function_name": "func_b", "module_key": "mod-b", "upstream_item_id": "si-df-b"}
            vuln_b.result = {"entry_key": "entry-b", "function_name": "func_b", "module_key": "mod-b"}

            archive_jobs = [
                BinarySecurityArchiveJob(id="aj-df-a", task_id="task1", project_id="p1", stage_name="dataflow_analysis", item_id="si-df-a", archive_status="success"),
                BinarySecurityArchiveJob(id="aj-df-b", task_id="task1", project_id="p1", stage_name="dataflow_analysis", item_id="si-df-b", archive_status="success"),
                BinarySecurityArchiveJob(id="aj-vuln-a", task_id="task1", project_id="p1", stage_name="vuln_scan", item_id="si-vuln-a", archive_status="success"),
                BinarySecurityArchiveJob(id="aj-vuln-b", task_id="task1", project_id="p1", stage_name="vuln_scan", item_id="si-vuln-b", archive_status="success"),
            ]
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=stage_runs, stage_items=[entry_a, entry_b, df_a, df_b, vuln_a, vuln_b], archive_jobs=archive_jobs)
            cleanup_refs = []

            async def fake_sync(*args, **kwargs):
                del args, kwargs
                return None

            async def fake_cleanup(db_arg, task_arg, refs_arg, token_arg):
                del db_arg, task_arg, token_arg
                cleanup_refs.extend(refs_arg)
                return len(refs_arg)

            def fake_delete_items(db_arg, item_ids):
                db_arg.stage_items = [item for item in db_arg.stage_items if item.id not in set(item_ids)]
                return len(item_ids)

            def fake_clear_archive(db_arg, task_id, stage_name, item_ids):
                del task_id, stage_name
                db_arg.archive_jobs = [job for job in db_arg.archive_jobs if job.item_id not in set(item_ids)]
                return len(item_ids)

            original_sync = self.manager.sync_downstream_status
            original_cleanup = self.manager._cleanup_downstream_refs
            original_delete_items = self.manager._delete_stage_items_by_ids
            original_clear_archive = self.manager._clear_archive_jobs_for_stage_items
            try:
                self.manager.sync_downstream_status = fake_sync
                self.manager._cleanup_downstream_refs = fake_cleanup
                self.manager._delete_stage_items_by_ids = fake_delete_items
                self.manager._clear_archive_jobs_for_stage_items = fake_clear_archive
                affected = asyncio.run(self.manager._prepare_retry_failed_items(db, task, "entry_analysis"))
            finally:
                self.manager.sync_downstream_status = original_sync
                self.manager._cleanup_downstream_refs = original_cleanup
                self.manager._delete_stage_items_by_ids = original_delete_items
                self.manager._clear_archive_jobs_for_stage_items = original_clear_archive

            self.assertEqual(["entry_analysis", "dataflow_analysis", "vuln_scan"], affected)
            self.assertEqual({"si-entry-a", "si-entry-b", "si-df-b", "si-vuln-b"}, {row.id for row in db.stage_items})
            self.assertEqual({"aj-df-b", "aj-vuln-b"}, {row.id for row in db.archive_jobs})
            self.assertEqual(["dfa-a", "dfvs-a"], [ref["task_id"] for ref in cleanup_refs])
            self.assertEqual(["dataflow_analysis", "vuln_scan"], task.summary["retry_plan"]["cleared_business_stages"])
            self.assertEqual(["entry-b"], [row.get("entry_key") for row in task.summary.get("dataflow_results") or []])
            self.assertEqual(["entry-b"], [row.get("entry_key") for row in task.summary.get("vuln_results") or []])
            self.assertEqual([], [row.id for row in db.state_events if row.stage_name in {"dataflow_analysis", "vuln_scan"}])
            self.assertEqual([], [row.id for row in db.events if row.stage_name in {"dataflow_analysis", "vuln_scan"}])

    def test_prepare_retry_failed_items_streaming_dataflow_retry_clears_vuln_summary_when_last_descendant_removed(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="failed",
                task_type=TASK_TYPE_SOURCE,
                current_stage="dataflow_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(Path(tmp) / "output"),
                workspace_root=tmp,
                policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
            )
            task.summary = {
                "retry_plan": {
                    "target_stage": "dataflow_analysis",
                    "mode": "retry_stage_failed_items",
                    "retry_item_keys": ["entry-a::mod-a"],
                },
                "vuln_results": [{"entry_key": "entry-a", "module_key": "mod-a", "function_name": "func_a"}],
            }
            stage_runs = [
                BinarySecurityStageRun(id="sr-df", task_id="task1", project_id="p1", stage_name="dataflow_analysis", sequence_no=1, status="failed"),
                BinarySecurityStageRun(id="sr-vuln", task_id="task1", project_id="p1", stage_name="vuln_scan", sequence_no=2, status="success"),
            ]

            df_a = BinarySecurityStageItem(
                id="si-df-a",
                task_id="task1",
                project_id="p1",
                stage_run_id="sr-df",
                stage_name="dataflow_analysis",
                item_key="entry-a",
                item_name="func_a",
                parent_key="mod-a",
                item_identity_key="mod-a::entry-a",
                status="failed",
                downstream_service="dataflow_analyse",
                downstream_task_id="dfa-a",
            )
            df_a.input_ref = {"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a"}
            vuln_a = BinarySecurityStageItem(
                id="si-vuln-a",
                task_id="task1",
                project_id="p1",
                stage_run_id="sr-vuln",
                stage_name="vuln_scan",
                item_key="entry-a",
                item_name="func_a",
                parent_key="mod-a",
                item_identity_key="mod-a::entry-a",
                status="success",
                downstream_service="dataflow_vuln_scanner",
                downstream_task_id="dfvs-a",
            )
            vuln_a.input_ref = {"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a", "upstream_item_id": "si-df-a"}
            vuln_a.result = {"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a"}
            archive_jobs = [
                BinarySecurityArchiveJob(id="aj-vuln-a", task_id="task1", project_id="p1", stage_name="vuln_scan", item_id="si-vuln-a", archive_status="success"),
            ]
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=stage_runs, stage_items=[df_a, vuln_a], archive_jobs=archive_jobs)
            cleanup_refs = []

            async def fake_sync(*args, **kwargs):
                del args, kwargs
                return None

            async def fake_cleanup(db_arg, task_arg, refs_arg, token_arg):
                del db_arg, task_arg, token_arg
                cleanup_refs.extend(refs_arg)
                return len(refs_arg)

            def fake_delete_items(db_arg, item_ids):
                db_arg.stage_items = [item for item in db_arg.stage_items if item.id not in set(item_ids)]
                return len(item_ids)

            def fake_clear_archive(db_arg, task_id, stage_name, item_ids):
                del task_id, stage_name
                db_arg.archive_jobs = [job for job in db_arg.archive_jobs if job.item_id not in set(item_ids)]
                return len(item_ids)

            original_sync = self.manager.sync_downstream_status
            original_cleanup = self.manager._cleanup_downstream_refs
            original_delete_items = self.manager._delete_stage_items_by_ids
            original_clear_archive = self.manager._clear_archive_jobs_for_stage_items
            try:
                self.manager.sync_downstream_status = fake_sync
                self.manager._cleanup_downstream_refs = fake_cleanup
                self.manager._delete_stage_items_by_ids = fake_delete_items
                self.manager._clear_archive_jobs_for_stage_items = fake_clear_archive
                affected = asyncio.run(self.manager._prepare_retry_failed_items(db, task, "dataflow_analysis"))
            finally:
                self.manager.sync_downstream_status = original_sync
                self.manager._cleanup_downstream_refs = original_cleanup
                self.manager._delete_stage_items_by_ids = original_delete_items
                self.manager._clear_archive_jobs_for_stage_items = original_clear_archive

            self.assertEqual(["dataflow_analysis", "vuln_scan"], affected)
            self.assertEqual({"si-df-a"}, {row.id for row in db.stage_items})
            self.assertEqual([], db.archive_jobs)
            self.assertEqual(["dfvs-a"], [ref["task_id"] for ref in cleanup_refs])
            self.assertEqual([], task.summary.get("vuln_results"))
            self.assertEqual(0, int((task.metrics or {}).get("vuln_result_count", 0)))

    def test_prepare_retry_stage_full_clears_downstream_stage_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="failed",
                task_type=TASK_TYPE_SOURCE,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(Path(tmp) / "output"),
                workspace_root=tmp,
            )
            task.summary = {
                "entry_results": [{"entry_key": "entry-a"}],
                "dataflow_results": [{"entry_key": "entry-a"}],
                "vuln_results": [{"entry_key": "entry-a"}],
            }
            stage_runs = [
                BinarySecurityStageRun(id="sr-entry", task_id="task1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="partial_success"),
                BinarySecurityStageRun(id="sr-df", task_id="task1", project_id="p1", stage_name="dataflow_analysis", sequence_no=3, status="failed"),
                BinarySecurityStageRun(id="sr-vuln", task_id="task1", project_id="p1", stage_name="vuln_scan", sequence_no=4, status="success"),
            ]
            stage_items = [
                BinarySecurityStageItem(id="si-entry", task_id="task1", project_id="p1", stage_name="entry_analysis", item_key="entry-a", parent_key="mod-a", downstream_service="entry_analyse", downstream_task_id="ea-1", status="success"),
                BinarySecurityStageItem(id="si-df", task_id="task1", project_id="p1", stage_name="dataflow_analysis", item_key="entry-a", parent_key="mod-a", downstream_service="dataflow_analyse", downstream_task_id="dfa-1", status="failed"),
                BinarySecurityStageItem(id="si-vuln", task_id="task1", project_id="p1", stage_name="vuln_scan", item_key="entry-a", parent_key="mod-a", downstream_service="dataflow_vuln_scanner", downstream_task_id="dfvs-1", status="success"),
            ]
            archive_jobs = [
                BinarySecurityArchiveJob(id="aj-entry", task_id="task1", project_id="p1", stage_name="entry_analysis", item_id="si-entry", archive_status="success"),
                BinarySecurityArchiveJob(id="aj-df", task_id="task1", project_id="p1", stage_name="dataflow_analysis", item_id="si-df", archive_status="failed"),
                BinarySecurityArchiveJob(id="aj-vuln", task_id="task1", project_id="p1", stage_name="vuln_scan", item_id="si-vuln", archive_status="success"),
            ]
            state_events = [
                BinarySecurityStateEvent(id="sev-entry", task_id="task1", project_id="p1", stage_name="entry_analysis", event_type="stage_worker_terminal_observed"),
                BinarySecurityStateEvent(id="sev-df", task_id="task1", project_id="p1", stage_name="dataflow_analysis", event_type="stage_worker_terminal_observed"),
                BinarySecurityStateEvent(id="sev-vuln", task_id="task1", project_id="p1", stage_name="vuln_scan", event_type="archive_job_copied"),
            ]
            events = [
                BinarySecurityEvent(id="ev-entry", task_id="task1", project_id="p1", stage_name="entry_analysis", event_type="stage_finished"),
                BinarySecurityEvent(id="ev-df", task_id="task1", project_id="p1", stage_name="dataflow_analysis", event_type="stage_failed"),
                BinarySecurityEvent(id="ev-vuln", task_id="task1", project_id="p1", stage_name="vuln_scan", event_type="archive_finished"),
            ]
            db = _ModelAwareDb(
                tasks=[task],
                stage_runs=stage_runs,
                stage_items=stage_items,
                archive_jobs=archive_jobs,
                state_events=state_events,
                events=events,
            )

            async def _noop_cleanup(*args, **kwargs):
                del args, kwargs
                return None

            original_cleanup = self.manager._cleanup_downstream_refs
            try:
                self.manager._cleanup_downstream_refs = _noop_cleanup
                affected = asyncio.run(self.manager._prepare_retry_stage_full(db, task, "entry_analysis"))
            finally:
                self.manager._cleanup_downstream_refs = original_cleanup

            self.assertEqual(["entry_analysis", "dataflow_analysis", "vuln_scan"], affected)
            self.assertEqual([], db.stage_items)
            self.assertEqual([], db.archive_jobs)
            self.assertEqual([], db.state_events)
            self.assertEqual([], db.events)
            self.assertEqual([], task.summary.get("entry_results") or [])
            self.assertEqual([], task.summary.get("dataflow_results") or [])
            self.assertEqual([], task.summary.get("vuln_results") or [])

    def test_sync_streaming_task_tail_state_rebuilds_entry_results(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(Path(tmp) / "output"),
                workspace_root=tmp,
                policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
            )
            task.summary = {}
            runs = [
                BinarySecurityStageRun(id="sr-entry", task_id="task1", project_id="p1", stage_name="entry_analysis", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr-df", task_id="task1", project_id="p1", stage_name="dataflow_analysis", sequence_no=2, status="pending"),
                BinarySecurityStageRun(id="sr-vuln", task_id="task1", project_id="p1", stage_name="vuln_scan", sequence_no=3, status="pending"),
            ]
            entry_item = BinarySecurityStageItem(
                id="si-entry",
                task_id="task1",
                project_id="p1",
                stage_run_id="sr-entry",
                stage_name="entry_analysis",
                item_key="mod-a",
                item_name="mod-a",
                parent_key="source_project",
                item_identity_key="mod-a::source_project",
                status="success",
                downstream_service="entry_analyse",
            )
            entry_item.input_ref = {"module_key": "mod-a", "module_name": "mod-a", "source_dir": "/src/mod-a"}
            entry_item.result = {
                "module_key": "mod-a",
                "module_name": "mod-a",
                "source_dir": "/src/mod-a",
                "entries_preview": [{"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a"}],
            }
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=runs, stage_items=[entry_item])

            original_factory = task_manager_module.get_session_factory
            original_write = self.manager._write_task_metadata_async
            task_manager_module.get_session_factory = lambda: (lambda: db)

            async def fake_write(*args, **kwargs):
                del args, kwargs
                return None

            self.manager._write_task_metadata_async = fake_write
            try:
                asyncio.run(self.manager._sync_streaming_task_tail_state("task1"))
            finally:
                task_manager_module.get_session_factory = original_factory
                self.manager._write_task_metadata_async = original_write

            self.assertEqual(["entry-a"], [row.get("entries", [{}])[0].get("entry_key") for row in task.summary.get("entry_results") or []])
            self.assertEqual("dataflow_analysis", task.current_stage)
            self.assertEqual("pending", task.status)

    def test_sync_streaming_task_tail_state_keeps_current_stage_on_earliest_incomplete_tail_before_finalize(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                current_stage="vuln_scan",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(Path(tmp) / "output"),
                workspace_root=tmp,
                policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
            )
            runs = [
                BinarySecurityStageRun(id="sr-entry", task_id="task1", project_id="p1", stage_name="entry_analysis", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr-df", task_id="task1", project_id="p1", stage_name="dataflow_analysis", sequence_no=2, status="failed"),
                BinarySecurityStageRun(id="sr-vuln", task_id="task1", project_id="p1", stage_name="vuln_scan", sequence_no=3, status="pending"),
            ]
            entry_item = BinarySecurityStageItem(
                id="si-entry",
                task_id="task1",
                project_id="p1",
                stage_run_id="sr-entry",
                stage_name="entry_analysis",
                item_key="mod-a",
                item_name="mod-a",
                parent_key="source_project",
                item_identity_key="mod-a::source_project",
                status="success",
                downstream_service="entry_analyse",
            )
            entry_item.input_ref = {"module_key": "mod-a", "module_name": "mod-a", "source_dir": "/src/mod-a"}
            entry_item.result = {
                "module_key": "mod-a",
                "module_name": "mod-a",
                "source_dir": "/src/mod-a",
                "entries_preview": [{"entry_key": "entry-a", "function_name": "func_a", "module_key": "mod-a"}],
            }
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=runs, stage_items=[entry_item])

            original_factory = task_manager_module.get_session_factory
            original_write = self.manager._write_task_metadata_async
            task_manager_module.get_session_factory = lambda: (lambda: db)

            async def fake_write(*args, **kwargs):
                del args, kwargs
                return None

            self.manager._write_task_metadata_async = fake_write
            try:
                asyncio.run(self.manager._sync_streaming_task_tail_state("task1"))
            finally:
                task_manager_module.get_session_factory = original_factory
                self.manager._write_task_metadata_async = original_write

            self.assertEqual("dataflow_analysis", task.current_stage)
            self.assertEqual("failed", task.status)

    def test_refresh_stage_run_from_items_preserves_streaming_tail_failed_status_without_items(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="dataflow_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        run = BinarySecurityStageRun(
            id="sr-df",
            task_id="task1",
            project_id="p1",
            stage_name="dataflow_analysis",
            sequence_no=2,
            status="failed",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[run], stage_items=[])

        self.manager._refresh_stage_run_from_items(db, task, "dataflow_analysis")

        self.assertEqual("failed", run.status)

    def test_refresh_stage_run_from_items_keeps_non_streaming_empty_stage_pending(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        run = BinarySecurityStageRun(
            id="sr-system",
            task_id="task1",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=1,
            status="failed",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[run], stage_items=[])

        self.manager._refresh_stage_run_from_items(db, task, "system_analysis")

        self.assertEqual("pending", run.status)

    def test_refresh_stage_run_from_items_updates_task_stage_summary_for_streaming_tail(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="dataflow_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        run = BinarySecurityStageRun(
            id="sr-df",
            task_id="task1",
            project_id="p1",
            stage_name="dataflow_analysis",
            sequence_no=2,
            status="failed",
        )
        run.counts = {"failed_items": 0, "running_items": 0}
        run.last_error = "dfa failed"
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[run], stage_items=[])

        self.manager._refresh_stage_run_from_items(db, task, "dataflow_analysis")

        self.assertEqual("failed", task.stage_summary["dataflow_analysis"]["status"])
        self.assertEqual("dfa failed", task.stage_summary["dataflow_analysis"]["last_error"])

    def test_refresh_task_status_after_stage_retry_requeues_downstream_stage(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            execution_mode="stage_retry",
            target_stage_name="system_analysis",
        )
        task.summary = {"stale_stages": ["entry_analysis"], "stage_retry_context": {"system_analysis": {}}}
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
        )
        db = _ModelAwareDb(stage_runs=[run])

        self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("pending", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertIsNone(task.execution_mode)
        self.assertIsNone(task.target_stage_name)
        self.assertNotIn("stage_retry_context", task.summary)

    def test_stage_retry_support_allows_missing_downstream_task_id(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="partial_success",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="m1",
            parent_key="source_project",
            downstream_service="entry_analyse",
            downstream_task_id=None,
        )
        db = _ModelAwareDb(stage_runs=[run], stage_items=[item])

        supported, reason = self.manager._stage_retry_support(db, task, "entry_analysis")

        self.assertTrue(supported)
        self.assertIsNone(reason)
        self.assertFalse(self.manager._has_retryable_downstream_task(item))

    def test_stage_item_with_missing_downstream_task_is_not_retryable(self):
        item = BinarySecurityStageItem(
            id="si1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="m1",
            parent_key="source_project",
            status="downstream_missing",
            downstream_service="entry_analyse",
            downstream_task_id="eat_missing_1",
        )

        self.assertFalse(self.manager._has_retryable_downstream_task(item))

    def test_aggregate_item_statuses_keeps_downstream_missing_distinct(self):
        self.assertEqual("downstream_missing", self.manager._aggregate_item_statuses(["downstream_missing"]))
        self.assertEqual("partial_success", self.manager._aggregate_item_statuses(["success", "downstream_missing"]))

    def test_acquire_task_state_lease_retries_retryable_deadlock(self):
        db = _FlakyCommitDb(
            state_leases=[],
            fail_flushes=1,
            error_factory=_deadlock_operational_error,
        )

        token = self.manager._acquire_task_state_lease(db, "task-1")

        self.assertIsNotNone(token)
        self.assertGreaterEqual(db.flush_calls, 2)
        self.assertGreaterEqual(db.rollback_calls, 1)

    def test_sync_downstream_status_marks_missing_child_task(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="s1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="entry_analysis",
            item_key="m1",
            parent_key="source_project",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat_missing_1",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[run], stage_items=[item])

        original_fetch = self.manager._fetch_downstream_task_payload
        original_write = self.manager._write_task_metadata_async
        original_enqueue = self.manager._enqueue_task
        async def _raise_missing(*_args, **_kwargs):
            raise NotFoundError("Task not found")

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._fetch_downstream_task_payload = _raise_missing
        self.manager._write_task_metadata_async = _noop_write
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            resp = asyncio.run(self.manager.sync_downstream_status(
                db,
                project_id="p1",
                task_id="s1",
                stage_name="entry_analysis",
            ))
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch
            self.manager._write_task_metadata_async = original_write
            self.manager._enqueue_task = original_enqueue

        self.assertEqual("downstream_missing", item.status)
        self.assertEqual("下游子任务不存在", item.error_message)
        self.assertEqual(1, resp.synced_downstream_count)

    def test_sync_downstream_status_keeps_all_missing_children_after_multiple_404s(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        item1 = BinarySecurityStageItem(
            id="si1",
            task_id="s1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="entry_analysis",
            item_key="m1",
            parent_key="source_project",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat_missing_1",
        )
        item2 = BinarySecurityStageItem(
            id="si2",
            task_id="s1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="entry_analysis",
            item_key="m2",
            parent_key="source_project",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat_missing_2",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[run], stage_items=[item1, item2])

        original_fetch = self.manager._fetch_downstream_task_payload
        original_write = self.manager._write_task_metadata_async
        original_enqueue = self.manager._enqueue_task

        async def _raise_missing(*_args, **_kwargs):
            raise NotFoundError("Task not found")

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._fetch_downstream_task_payload = _raise_missing
        self.manager._write_task_metadata_async = _noop_write
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            resp = asyncio.run(
                self.manager.sync_downstream_status(
                    db,
                    project_id="p1",
                    task_id="s1",
                    stage_name="entry_analysis",
                )
            )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch
            self.manager._write_task_metadata_async = original_write
            self.manager._enqueue_task = original_enqueue

        self.assertEqual("downstream_missing", item1.status)
        self.assertEqual("下游子任务不存在", item1.error_message)
        self.assertEqual("downstream_missing", item2.status)
        self.assertEqual("下游子任务不存在", item2.error_message)
        self.assertEqual(2, resp.synced_downstream_count)

    def test_sync_downstream_status_processes_items_in_batches(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        items = [
            BinarySecurityStageItem(
                id=f"si{index}",
                task_id="s1",
                project_id="p1",
                stage_run_id="sr1",
                stage_name="entry_analysis",
                item_key=f"m{index}",
                parent_key="source_project",
                status="queued",
                downstream_service="entry_analyse",
                downstream_task_id=f"eat_{index}",
            )
            for index in range(3)
        ]
        db = _ModelAwareDb(tasks=[task], stage_runs=[run], stage_items=items)
        self.manager.cfg.scheduler.downstream_sync_batch_size = 2

        fetched_ids = []
        original_fetch = self.manager._fetch_downstream_task_payload
        original_write = self.manager._write_task_metadata_async
        original_enqueue = self.manager._enqueue_task

        async def _fetch(_task, item, _token):
            fetched_ids.append(item.id)
            return {"status": "running"}

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._fetch_downstream_task_payload = _fetch
        self.manager._write_task_metadata_async = _noop_write
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            resp = asyncio.run(
                self.manager.sync_downstream_status(
                    db,
                    project_id="p1",
                    task_id="s1",
                    stage_name="entry_analysis",
                )
            )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch
            self.manager._write_task_metadata_async = original_write
            self.manager._enqueue_task = original_enqueue

        self.assertEqual(["si0", "si1"], fetched_ids)
        self.assertEqual(2, resp.synced_downstream_count)

    def test_sync_downstream_status_http_500_keeps_item_running(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="s1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="entry_analysis",
            item_key="m1",
            parent_key="source_project",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat_1",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[run], stage_items=[item])

        original_fetch = self.manager._fetch_downstream_task_payload
        async def _raise_500(*_args, **_kwargs):
            raise UpstreamError("下游服务返回异常状态码: 500, body=boom")

        self.manager._fetch_downstream_task_payload = _raise_500
        try:
            resp = asyncio.run(
                self.manager.sync_downstream_status(
                    db,
                    project_id="p1",
                    task_id="s1",
                    stage_name="entry_analysis",
                )
            )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch

        failed_events = [event for event in db.events if event.event_type == "downstream_status_sync_failed"]
        self.assertEqual("running", item.status)
        self.assertEqual("running", run.status)
        self.assertEqual("running", task.status)
        self.assertEqual(1, resp.failed_downstream_count)
        self.assertTrue(failed_events)
        self.assertEqual(500, failed_events[-1].payload.get("http_status"))
        self.assertEqual("http_5xx", failed_events[-1].payload.get("error_type"))
        self.assertFalse(bool(failed_events[-1].payload.get("state_applied")))
        self.assertFalse(any(event.event_type == "downstream_status_event_applied" for event in db.events))
        self.assertEqual("transport_error", item.result.get("sync_status"))
        self.assertIsNotNone(item.result.get("downstream_status_synced_at"))

    def test_sync_downstream_status_timeout_keeps_item_running(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="s1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="entry_analysis",
            item_key="m1",
            parent_key="source_project",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat_1",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[run], stage_items=[item])

        original_fetch = self.manager._fetch_downstream_task_payload
        async def _raise_timeout(*_args, **_kwargs):
            raise UpstreamError("下游服务 GET 超时: http://entry/tasks/eat_1")

        self.manager._fetch_downstream_task_payload = _raise_timeout
        try:
            resp = asyncio.run(
                self.manager.sync_downstream_status(
                    db,
                    project_id="p1",
                    task_id="s1",
                    stage_name="entry_analysis",
                )
            )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch

        failed_events = [event for event in db.events if event.event_type == "downstream_status_sync_failed"]
        self.assertEqual("running", item.status)
        self.assertEqual("running", run.status)
        self.assertEqual("running", task.status)
        self.assertEqual(1, resp.failed_downstream_count)
        self.assertTrue(failed_events)
        self.assertEqual("timeout", failed_events[-1].payload.get("error_type"))
        self.assertFalse(bool(failed_events[-1].payload.get("state_applied")))

    def test_sync_downstream_status_prioritizes_failed_items_with_downstream_refs(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        failed_item = BinarySecurityStageItem(
            id="si_failed",
            task_id="s1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="entry_analysis",
            item_key="m_failed",
            parent_key="source_project",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="eat_failed",
        )
        queued_items = [
            BinarySecurityStageItem(
                id=f"si_q{index}",
                task_id="s1",
                project_id="p1",
                stage_run_id="sr1",
                stage_name="entry_analysis",
                item_key=f"m_q{index}",
                parent_key="source_project",
                status="queued",
                downstream_service="entry_analyse",
                downstream_task_id=f"eat_q{index}",
            )
            for index in range(2)
        ]
        db = _ModelAwareDb(tasks=[task], stage_runs=[run], stage_items=[queued_items[0], failed_item, queued_items[1]])
        self.manager.cfg.scheduler.downstream_sync_batch_size = 2

        fetched_ids = []
        original_fetch = self.manager._fetch_downstream_task_payload
        original_write = self.manager._write_task_metadata_async
        original_enqueue = self.manager._enqueue_task

        async def _fetch(_task, item, _token):
            fetched_ids.append(item.id)
            return {"status": "running"}

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._fetch_downstream_task_payload = _fetch
        self.manager._write_task_metadata_async = _noop_write
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            resp = asyncio.run(
                self.manager.sync_downstream_status(
                    db,
                    project_id="p1",
                    task_id="s1",
                    stage_name="entry_analysis",
                )
            )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch
            self.manager._write_task_metadata_async = original_write
            self.manager._enqueue_task = original_enqueue

        self.assertEqual(["si_failed", "si_q0"], fetched_ids)
        self.assertEqual(2, resp.synced_downstream_count)

    def test_sync_downstream_status_unknown_status_is_skipped(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="s1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="entry_analysis",
            item_key="m1",
            parent_key="source_project",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat_1",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[run], stage_items=[item])

        original_fetch = self.manager._fetch_downstream_task_payload
        async def _fetch(_task, _item, _token):
            return {"status": "mystery_state"}

        self.manager._fetch_downstream_task_payload = _fetch
        try:
            resp = asyncio.run(
                self.manager.sync_downstream_status(
                    db,
                    project_id="p1",
                    task_id="s1",
                    stage_name="entry_analysis",
                )
            )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch

        skipped_events = [event for event in db.events if event.event_type == "downstream_status_sync_skipped"]
        self.assertEqual("running", item.status)
        self.assertEqual("running", run.status)
        self.assertEqual("running", task.status)
        self.assertEqual(1, resp.skipped_downstream_count)
        self.assertTrue(skipped_events)
        self.assertEqual("mystery_state", skipped_events[-1].payload.get("status_raw"))
        self.assertIsNone(skipped_events[-1].payload.get("mapped_status"))
        self.assertFalse(bool(skipped_events[-1].payload.get("state_applied")))

    def test_sync_downstream_status_running_revives_failed_active_stage_task(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=1,
            status="failed",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="s1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="system_analysis",
            item_key="fw1",
            parent_key="fw1",
            status="failed",
            downstream_service="system_analyse",
            downstream_task_id="sat_1",
            error_message="old failure",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[run], stage_items=[item])

        original_fetch = self.manager._fetch_downstream_task_payload
        original_write = self.manager._write_task_metadata_async
        original_enqueue = self.manager._enqueue_task

        async def _fetch(_task, _item, _token):
            return {"status": "running"}

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._fetch_downstream_task_payload = _fetch
        self.manager._write_task_metadata_async = _noop_write
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            resp = asyncio.run(
                self.manager.sync_downstream_status(
                    db,
                    project_id="p1",
                    task_id="s1",
                    stage_name="system_analysis",
                )
            )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch
            self.manager._write_task_metadata_async = original_write
            self.manager._enqueue_task = original_enqueue

        self.assertEqual("running", item.status)
        self.assertEqual("running", run.status)
        self.assertEqual("running", task.status)
        self.assertEqual(1, resp.synced_downstream_count)

    def test_sync_downstream_status_refreshes_parent_state_when_item_status_changes(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="s1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="entry_analysis",
            item_key="m1",
            parent_key="source_project",
            status="queued",
            downstream_service="entry_analyse",
            downstream_task_id="eat_1",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[run], stage_items=[item])

        original_fetch = self.manager._fetch_downstream_task_payload
        original_write = self.manager._write_task_metadata_async
        original_enqueue = self.manager._enqueue_task
        original_refresh_stage = self.manager._refresh_stage_run_from_items
        original_refresh_task = self.manager._refresh_task_status_after_sync

        refreshed_stages = []
        refreshed_tasks = []

        async def _fetch(_task, _item, _token):
            return {"status": "running"}

        async def _noop_write(*_args, **_kwargs):
            return None

        def _capture_stage(_db, _task, current_stage):
            refreshed_stages.append(current_stage)

        def _capture_task(_db, current_task):
            refreshed_tasks.append(current_task.id)

        self.manager._fetch_downstream_task_payload = _fetch
        self.manager._write_task_metadata_async = _noop_write
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        self.manager._refresh_stage_run_from_items = _capture_stage
        self.manager._refresh_task_status_after_sync = _capture_task
        try:
            asyncio.run(
                self.manager.sync_downstream_status(
                    db,
                    project_id="p1",
                    task_id="s1",
                    stage_name="entry_analysis",
                )
            )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch
            self.manager._write_task_metadata_async = original_write
            self.manager._enqueue_task = original_enqueue
            self.manager._refresh_stage_run_from_items = original_refresh_stage
            self.manager._refresh_task_status_after_sync = original_refresh_task

        self.assertEqual(["entry_analysis"], refreshed_stages)
        self.assertEqual(["s1"], refreshed_tasks)

    def test_business_stage_status_prefers_stage_run_success_over_stale_item_status(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="system_analysis",
            item_key="source_project",
            status="running",
            downstream_service="system_analyse",
            downstream_task_id="sat1",
        )

        status = self.manager._business_stage_status(task, "system_analysis", run, [item])

        self.assertEqual("success", status)

    def test_business_stage_status_uses_stage_run_running_for_active_stage(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )

        status = self.manager._business_stage_status(task, "entry_analysis", run, [])

        self.assertEqual("running", status)

    def test_stage_retry_support_still_rejects_downstream_service_mismatch(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="partial_success",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="m1",
            parent_key="source_project",
            downstream_service="system_analyse",
            downstream_task_id=None,
        )
        db = _ModelAwareDb(stage_runs=[run], stage_items=[item])

        supported, reason = self.manager._stage_retry_support(db, task, "entry_analysis")

        self.assertFalse(supported)
        self.assertIn("下游服务不匹配", reason or "")

    def test_stage_retry_support_allows_failed_stage_without_items_when_inputs_can_be_rebuilt(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="partial_success",
            task_type=TASK_TYPE_SOURCE,
            current_stage="dataflow_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.summary = {}
        run = BinarySecurityStageRun(
            id="sr3",
            task_id="s1",
            project_id="p1",
            stage_name="dataflow_analysis",
            sequence_no=3,
            status="failed",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="m1",
            item_name="m1",
            status="success",
        )
        entry_item.result = {
            "module_key": "m1",
            "module_name": "m1",
            "source_dir": "/src/m1",
            "entries_preview": [{"entry_key": "e1", "function_name": "main", "file_name": "main.c", "line_no": 1}],
        }
        db = _ModelAwareDb(stage_runs=[run])
        original_stage_items = self.manager._stage_items

        def fake_stage_items(_db, _task_id, stage_name):
            return [entry_item] if stage_name == "entry_analysis" else []

        self.manager._stage_items = fake_stage_items
        try:
            supported, reason = self.manager._stage_retry_support(db, task, "dataflow_analysis")
        finally:
            self.manager._stage_items = original_stage_items

        self.assertTrue(supported)
        self.assertIsNone(reason)
        self.assertEqual(1, len(task.summary["entry_results"]))

    def test_task_continue_support_blocks_streaming_tail_auto_progress(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="pending",
            task_type=TASK_TYPE_SOURCE,
            current_stage="dataflow_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        stage_item = BinarySecurityStageItem(
            id="si-df",
            task_id="s1",
            project_id="p1",
            stage_name="dataflow_analysis",
            item_key="entry-1",
            status="pending",
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[stage_item])

        supported, reason, target_stage = self.manager._task_continue_support(db, task)

        self.assertFalse(supported)
        self.assertIn("streaming tail 自动推进中", reason or "")
        self.assertIsNone(target_stage)

    def test_task_continue_support_rebuilds_dataflow_inputs_from_entry_stage_items(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="partial_success",
            task_type=TASK_TYPE_SOURCE,
            current_stage="dataflow_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.summary = {}
        runs = [
            BinarySecurityStageRun(id="sr1", task_id="s1", project_id="p1", stage_name="system_analysis", sequence_no=1, status="success"),
            BinarySecurityStageRun(id="sr2", task_id="s1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="success"),
            BinarySecurityStageRun(id="sr3", task_id="s1", project_id="p1", stage_name="dataflow_analysis", sequence_no=3, status="failed"),
            BinarySecurityStageRun(id="sr4", task_id="s1", project_id="p1", stage_name="vuln_scan", sequence_no=4, status="pending"),
        ]
        entry_item = BinarySecurityStageItem(
            id="si-entry",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="m1",
            item_name="m1",
            status="success",
        )
        entry_item.result = {
            "module_key": "m1",
            "module_name": "m1",
            "source_dir": "/src/m1",
            "entries_preview": [{"entry_key": "e1", "function_name": "main", "file_name": "main.c", "line_no": 1}],
        }
        db = _ModelAwareDb(stage_runs=runs, stage_items=[entry_item])

        supported, reason, target_stage = self.manager._task_continue_support(db, task)

        self.assertTrue(supported)
        self.assertIsNone(reason)
        self.assertEqual("dataflow_analysis", target_stage)
        self.assertEqual(1, len(task.summary["entry_results"]))

    def test_stage_retry_clears_only_target_stage_outputs(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="partial_success",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.summary = {
            "selected_modules": [{"module_key": "m1"}],
            "entry_results": [{"entry_key": "e1"}],
            "dataflow_results": [{"entry_key": "e1"}],
            "vuln_results": [{"entry_key": "e1"}],
            "stale_stages": ["dataflow_analysis"],
            "stale_from_stage": "entry_analysis",
        }
        task.metrics = {"entry_count": 1, "vuln_result_count": 1}
        task.stage_summary = {
            "system_analysis": {"status": "success"},
            "entry_analysis": {"status": "failed"},
            "dataflow_analysis": {"status": "success"},
        }

        self.manager._clear_single_stage_outputs(task, "entry_analysis")

        self.assertNotIn("entry_results", task.summary)
        self.assertIn("dataflow_results", task.summary)
        self.assertIn("vuln_results", task.summary)
        self.assertIn("stale_stages", task.summary)
        self.assertEqual(0, task.metrics["entry_count"])
        self.assertEqual(1, task.metrics["vuln_result_count"])
        self.assertNotIn("entry_analysis", task.stage_summary)
        self.assertIn("dataflow_analysis", task.stage_summary)

    def test_upsert_stage_item_creates_missing_item_during_retry(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        db = _ModelAwareDb(stage_runs=[run], stage_items=[])

        item = self.manager._upsert_stage_item(
            db,
            task=task,
            stage_run=run,
            stage_name="entry_analysis",
            item_key="m1",
            item_name="module1",
            parent_key="source_project",
            downstream_service="entry_analyse",
            input_ref={"module_key": "m1"},
            retrying=True,
        )

        self.assertEqual("m1", item.item_key)
        self.assertEqual(0, item.retry_count)
        self.assertEqual(1, item.rerun_count)
        self.assertEqual("running", item.status)
        self.assertEqual(1, len(db.added))

    def test_upsert_stage_item_increments_auto_retry_count_only_for_auto_retry(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        existing = BinarySecurityStageItem(
            id="si1",
            task_id="s1",
            project_id="p1",
            stage_run_id="sr0",
            stage_name="entry_analysis",
            item_key="m1",
            item_name="module1",
            parent_key="source_project",
            status="failed",
            retry_count=1,
            rerun_count=2,
            downstream_service="entry_analyse",
        )
        db = _ModelAwareDb(stage_runs=[run], stage_items=[existing])

        item = self.manager._upsert_stage_item(
            db,
            task=task,
            stage_run=run,
            stage_name="entry_analysis",
            item_key="m1",
            item_name="module1",
            parent_key="source_project",
            downstream_service="entry_analyse",
            input_ref={"module_key": "m1"},
            retrying=True,
            auto_retrying=True,
        )

        self.assertEqual(2, item.retry_count)
        self.assertEqual(3, item.rerun_count)

    def test_stage_enabled_uses_policy_override(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.policy = {"stage_options": {"vuln_scan": {"enabled": False}}}

        self.assertFalse(self.manager._stage_enabled(task, "vuln_scan"))
        self.assertTrue(self.manager._stage_enabled(task, "entry_analysis"))

    def test_stage_sequence_uses_task_type(self):
        binary_task = BinarySecurityTask(id="b1", project_id="p1", name="binary", task_type=TASK_TYPE_BINARY, status="pending", firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        source_task = BinarySecurityTask(id="s1", project_id="p1", name="source", task_type=TASK_TYPE_SOURCE, status="pending", firmware_source="project_filesystem", firmware_path="/src", output_root="/o", workspace_root="/w")
        module_task = BinarySecurityTask(id="m1", project_id="p1", name="module", task_type=TASK_TYPE_BINARY_MODULE, status="pending", firmware_source="project_filesystem", firmware_path="/input", output_root="/o", workspace_root="/w")

        self.assertEqual(
            ["firmware_unpack", "system_analysis", "binary_to_source", "entry_analysis", "dataflow_analysis", "vuln_scan"],
            self.manager._stage_sequence_for_task(binary_task),
        )
        self.assertEqual(
            ["system_analysis", "entry_analysis", "dataflow_analysis", "vuln_scan"],
            self.manager._stage_sequence_for_task(source_task),
        )
        self.assertEqual(
            ["binary_to_source", "entry_analysis", "dataflow_analysis", "vuln_scan"],
            self.manager._stage_sequence_for_task(module_task),
        )

    def test_normalize_binary_module_input_files_allows_same_filename_under_different_relative_paths(self):
        rows = self.manager._normalize_input_files(
            [
                {"filename": "libcrypto.so", "relative_path": "a/libcrypto.so"},
                {"filename": "libcrypto.so", "relative_path": "b/libcrypto.so"},
            ],
            task_type=TASK_TYPE_BINARY_MODULE,
        )

        self.assertEqual(["a/libcrypto.so", "b/libcrypto.so"], [row["relative_path"] for row in rows])

    def test_build_binary_module_summary_preloads_single_selected_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            input_dir = workspace / "input"
            input_dir.mkdir(parents=True)
            task = BinarySecurityTask(
                id="m1",
                project_id="p1",
                name="module-task",
                task_type=TASK_TYPE_BINARY_MODULE,
                status="pending_upload",
                firmware_source="project_filesystem",
                firmware_path=str(input_dir),
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            task.summary = {
                "input_dir": str(input_dir),
                "module_input": {
                    "module_name": "ipsec",
                },
            }

            summary = self.manager._build_binary_module_summary(
                task,
                [
                    {"filename": "ipsec_main.so", "relative_path": "core/ipsec_main.so"},
                    {"filename": "ipsec_helper.so", "relative_path": "plugins/ipsec_helper.so"},
                ],
            )

            selected = summary["selected_modules"]
            self.assertEqual(1, len(selected))
            self.assertEqual(TASK_TYPE_BINARY_MODULE, selected[0]["task_type"])
            self.assertEqual("ipsec", selected[0]["module_name"])
            self.assertEqual("高", selected[0]["risk_level"])
            self.assertEqual("manual_input", selected[0]["risk_source"])
            self.assertEqual("manual_input", selected[0]["selected_by"])
            self.assertEqual(str(input_dir / "module-files.list"), selected[0]["files_list"])
            self.assertEqual(selected, summary["high_risk_modules"])
            self.assertEqual(["core/ipsec_main.so", "plugins/ipsec_helper.so"], (input_dir / "module-files.list").read_text(encoding="utf-8").splitlines())
            self.assertTrue(summary["system_analysis_bypassed"])

    def test_entry_analysis_inputs_rebuild_from_binary_to_source_stage_items(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="module-task",
            task_type=TASK_TYPE_BINARY_MODULE,
            status="running",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.summary = {"b2s_results": []}
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="binary_to_source",
            item_key="ipsec",
            item_name="ipsec",
            status="success",
        )
        item.input_ref = {
            "firmware_key": "module-input",
            "firmware_name": "ipsec",
            "module_key": "ipsec",
            "module_name": "ipsec",
        }
        item.result = {
            "source_dir": "/archive/b2s/ipsec",
            "module_dir": "/archive/b2s/ipsec/module",
            "source_root": "/archive/b2s/ipsec",
            "files_list": "/archive/b2s/ipsec/module/files.list",
            "task_type": TASK_TYPE_BINARY_MODULE,
        }
        db = _ModelAwareDb(tasks=[task], stage_items=[item])

        rows = self.manager._entry_analysis_inputs(db, task)

        self.assertEqual(1, len(rows))
        self.assertEqual("/archive/b2s/ipsec", rows[0]["source_dir"])
        self.assertEqual("ipsec", rows[0]["module_name"])
        self.assertEqual(rows, task.summary["b2s_results"])

    def test_prepare_entry_module_descriptor_creates_files_list_for_binary_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact_root = Path(tmp)
            (artifact_root / "libipsec.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (artifact_root / "libipsec.h").write_text("#pragma once\n", encoding="utf-8")
            work_dir = artifact_root / "run" / "runs" / "run-1"
            work_dir.mkdir(parents=True)
            (work_dir / "batch_001.chat.json").write_text("{}", encoding="utf-8")
            descriptor = self.manager._prepare_entry_module_descriptor(
                artifact_root,
                {"module_name": "IPSEC"},
            )

            self.assertEqual("IPSEC", descriptor["entry_module_name"])
            self.assertTrue(descriptor["entry_descriptor_ready"])
            files_list = Path(descriptor["entry_files_list"])
            self.assertTrue(files_list.is_file())
            self.assertEqual(
                ["libipsec.c", "libipsec.h"],
                files_list.read_text(encoding="utf-8").splitlines(),
            )

    def test_prepare_entry_module_descriptor_excludes_ida_intermediate_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact_root = Path(tmp)
            (artifact_root / "libipsec.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (artifact_root / "libipsec_ida.c").write_text("int ida_main(void) { return 0; }\n", encoding="utf-8")
            (artifact_root / "libipsec_ida.h").write_text("#pragma once\n", encoding="utf-8")

            descriptor = self.manager._prepare_entry_module_descriptor(
                artifact_root,
                {"module_name": "IPSEC"},
            )

            files_list = Path(descriptor["entry_files_list"])
            self.assertEqual(
                ["libipsec.c"],
                files_list.read_text(encoding="utf-8").splitlines(),
            )

    def test_entry_analysis_inputs_normalize_binary_module_to_descriptor_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact_root = Path(tmp)
            (artifact_root / "libipsec.c").write_text("int f(void) { return 1; }\n", encoding="utf-8")
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="module-task",
                task_type=TASK_TYPE_BINARY_MODULE,
                status="failed",
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root="/o",
                workspace_root="/w",
            )
            task.summary = {
                "b2s_results": [
                    {
                        "module_key": "IPSEC",
                        "module_name": "IPSEC",
                        "firmware_key": "module-input",
                        "firmware_name": "IPSEC",
                        "source_dir": str(artifact_root),
                    }
                ]
            }
            db = _ModelAwareDb(tasks=[task])

            rows = self.manager._entry_analysis_inputs(db, task)

            self.assertEqual(1, len(rows))
            self.assertTrue(rows[0]["entry_descriptor_ready"])
            self.assertEqual("IPSEC", rows[0]["module_name"])
            self.assertEqual(str(artifact_root), rows[0]["source_dir"])
            self.assertTrue(rows[0]["entry_files_list"].endswith("modules/IPSEC/files.list"))

    def test_entry_analysis_inputs_rebuilds_invalid_input_descriptor_from_archive_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_root = root / "input"
            archive_root = root / "output" / "binary-to-source" / "IPSEC__task-1"
            (input_root / "modules" / "IPSEC").mkdir(parents=True)
            (input_root / "modules" / "IPSEC" / "files.list").write_text("", encoding="utf-8")
            archive_root.mkdir(parents=True)
            (archive_root / "libipsec.c").write_text("int g(void) { return 0; }\n", encoding="utf-8")
            (archive_root / "libipsec.h").write_text("#pragma once\n", encoding="utf-8")
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="module-task",
                task_type=TASK_TYPE_BINARY_MODULE,
                status="failed",
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root="/o",
                workspace_root="/w",
            )
            task.summary = {
                "b2s_results": [
                    {
                        "module_key": "IPSEC",
                        "module_name": "IPSEC",
                        "firmware_key": "module-input",
                        "firmware_name": "IPSEC",
                        "source_dir": str(input_root),
                        "archive_root": str(archive_root),
                        "entry_descriptor_root": str(input_root),
                        "entry_files_list": str(input_root / "modules" / "IPSEC" / "files.list"),
                        "entry_descriptor_ready": False,
                        "entry_source_file_count": 0,
                    }
                ]
            }
            db = _ModelAwareDb(tasks=[task])

            rows = self.manager._entry_analysis_inputs(db, task)

            self.assertEqual(1, len(rows))
            self.assertTrue(rows[0]["entry_descriptor_ready"])
            self.assertEqual(str(archive_root), rows[0]["source_dir"])
            self.assertEqual(str(archive_root), rows[0]["entry_descriptor_root"])
            self.assertTrue(rows[0]["entry_files_list"].endswith("output/binary-to-source/IPSEC__task-1/modules/IPSEC/files.list"))
            self.assertEqual(rows, task.summary["b2s_results"])

    def test_normalize_entry_analysis_module_input_requires_non_empty_descriptor_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            descriptor_root = root / "input"
            archive_root = root / "archive"
            (descriptor_root / "modules" / "IPSEC").mkdir(parents=True)
            empty_files_list = descriptor_root / "modules" / "IPSEC" / "files.list"
            empty_files_list.write_text("", encoding="utf-8")
            archive_root.mkdir(parents=True)
            (archive_root / "libipsec.c").write_text("int h(void) { return 0; }\n", encoding="utf-8")
            normalized = self.manager._normalize_entry_analysis_module_input(
                BinarySecurityTask(
                    id="t1",
                    project_id="p1",
                    name="module-task",
                    task_type=TASK_TYPE_BINARY_MODULE,
                    firmware_source="project_filesystem",
                    firmware_path="/fw",
                    output_root="/o",
                    workspace_root="/w",
                ),
                {
                    "module_key": "IPSEC",
                    "module_name": "IPSEC",
                    "entry_module_name": "IPSEC",
                    "entry_descriptor_root": str(descriptor_root),
                    "entry_files_list": str(empty_files_list),
                    "entry_descriptor_ready": True,
                    "archive_root": str(archive_root),
                },
            )

            self.assertEqual(str(archive_root), normalized["entry_descriptor_root"])
            self.assertEqual(str(archive_root), normalized["source_dir"])
            self.assertTrue(normalized["entry_descriptor_ready"])
            self.assertEqual(1, normalized["entry_source_file_count"])

    def test_normalize_entry_analysis_module_input_aligns_source_root_with_descriptor_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            descriptor_root = root / "archive"
            module_dir = descriptor_root / "modules" / "IPSEC"
            module_dir.mkdir(parents=True)
            source_file = descriptor_root / "src" / "ipsec.c"
            source_file.parent.mkdir(parents=True)
            source_file.write_text("int ipsec(void) { return 0; }\n", encoding="utf-8")
            files_list = module_dir / "files.list"
            files_list.write_text("src/ipsec.c\n", encoding="utf-8")

            normalized = self.manager._normalize_entry_analysis_module_input(
                BinarySecurityTask(
                    id="t1",
                    project_id="p1",
                    name="module-task",
                    task_type=TASK_TYPE_BINARY_MODULE,
                    firmware_source="project_filesystem",
                    firmware_path="/fw",
                    output_root="/o",
                    workspace_root="/w",
                ),
                {
                    "module_key": "IPSEC",
                    "module_name": "IPSEC",
                    "entry_module_name": "IPSEC",
                    "entry_descriptor_root": str(descriptor_root),
                    "entry_files_list": str(files_list),
                    "entry_descriptor_ready": True,
                    "source_root": "/wrong/upstream/source/root",
                    "archive_root": str(descriptor_root),
                },
            )

            self.assertEqual(str(descriptor_root), normalized["source_dir"])
            self.assertEqual(str(descriptor_root), normalized["source_root"])
            self.assertEqual(str(module_dir), normalized["module_dir"])
            self.assertEqual(str(files_list), normalized["files_list"])

    def test_compact_b2s_summary_item_keeps_binary_module_archive_contract(self):
        row = self.manager._compact_b2s_summary_item(
            {
                "firmware_key": "module-input",
                "firmware_name": "IPSEC",
                "task_type": TASK_TYPE_BINARY_MODULE,
                "module_key": "IPSEC",
                "module_name": "IPSEC",
                "module_dir": "/task/input",
                "source_dir": "/task/output/binary-to-source/IPSEC__task-1",
                "source_root": "/task/output/binary-to-source/IPSEC__task-1",
                "artifact_root": "/task/output/binary-to-source/IPSEC__task-1",
                "archive_root": "/task/output/binary-to-source/IPSEC__task-1",
                "descriptor_root": "/task/output/binary-to-source/IPSEC__task-1",
                "files_list_path": "/task/output/binary-to-source/IPSEC__task-1/modules/IPSEC/files.list",
                "entry_module_name": "IPSEC",
                "entry_descriptor_root": "/task/output/binary-to-source/IPSEC__task-1",
                "entry_files_list": "/task/output/binary-to-source/IPSEC__task-1/modules/IPSEC/files.list",
                "entry_descriptor_ready": True,
                "artifact_index_path": "/task/output/binary-to-source/IPSEC__task-1/artifacts/index.json",
                "result_summary_version": 1,
            }
        )

        self.assertEqual("/task/output/binary-to-source/IPSEC__task-1", row["artifact_root"])
        self.assertEqual("/task/output/binary-to-source/IPSEC__task-1", row["archive_root"])
        self.assertEqual("/task/output/binary-to-source/IPSEC__task-1", row["descriptor_root"])
        self.assertEqual(
            "/task/output/binary-to-source/IPSEC__task-1/modules/IPSEC/files.list",
            row["files_list_path"],
        )
        self.assertEqual(
            "/task/output/binary-to-source/IPSEC__task-1/modules/IPSEC/files.list",
            row["entry_files_list"],
        )

    def test_compact_b2s_summary_item_for_source_task_contract_remains_unchanged(self):
        row = self.manager._compact_b2s_summary_item(
            {
                "firmware_key": "source_project",
                "firmware_name": "source-project",
                "task_type": TASK_TYPE_SOURCE,
                "module_key": "network",
                "module_name": "network",
                "module_dir": "/task/system-analysis/modules/network",
                "source_dir": "/task/input",
                "source_root": "/task/input",
                "files_list": "/task/system-analysis/modules/network/files.list",
            }
        )

        self.assertEqual(TASK_TYPE_SOURCE, row["task_type"])
        self.assertEqual("/task/input", row["source_dir"])
        self.assertEqual("/task/input", row["source_root"])
        self.assertIsNone(row["artifact_root"])
        self.assertIsNone(row["archive_root"])
        self.assertIsNone(row["descriptor_root"])
        self.assertIsNone(row["entry_descriptor_root"])

    def test_rebuild_entry_results_restores_source_dir_from_definition_file(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="module-task",
            task_type=TASK_TYPE_BINARY_MODULE,
            status="running",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
            summary={},
        )
        stage_item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="module-1",
            item_name="IPSEC",
            status="success",
            input_ref={"module_key": "module-1", "module_name": "IPSEC", "source_dir": None},
            result={
                "module_key": "module-1",
                "module_name": "IPSEC",
                "entries_preview": [
                    {
                        "entry_key": "entry-1",
                        "module_key": "module-1",
                        "module_name": "IPSEC",
                        "function_name": "IPSEC_CFG_VRDestory",
                        "file_name": "libipsec.c",
                        "definition_file": "/tmp/repo/src/libipsec.c",
                        "definition_line": "1572",
                        "taint_params": ["argv"],
                    }
                ],
            },
            output_ref={},
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[stage_item])

        rebuilt = self.manager._rebuild_entry_results_from_stage_items(db, task)

        self.assertEqual(1, len(rebuilt))
        self.assertEqual("/tmp/repo/src", rebuilt[0]["source_dir"])
        self.assertEqual("/tmp/repo/src", rebuilt[0]["entries"][0]["source_dir"])

    def test_stage_entry_analysis_uses_binary_to_source_failure_reason_when_inputs_missing(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="module-task",
            task_type=TASK_TYPE_BINARY_MODULE,
            status="running",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.summary = {"b2s_results": []}
        stage_run = BinarySecurityStageRun(
            id="sr-entry",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=3,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si-b2s",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr-b2s",
            stage_name="binary_to_source",
            item_key="ipsec",
            item_name="ipsec",
            status="failed",
            error_message="binary-to-source failed: worker timeout",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[item])

        status, payload = asyncio.run(self.manager._stage_entry_analysis(db, task, stage_run, token=None))

        self.assertEqual("failed", status)
        self.assertEqual("binary-to-source failed: worker timeout", payload["error"])

    def test_source_system_analysis_inputs_use_workspace_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "input").mkdir()
            task = BinarySecurityTask(id="s1", project_id="p1", name="source-task", task_type=TASK_TYPE_SOURCE, status="pending", firmware_source="project_filesystem", firmware_path="/src", output_root=str(workspace / "output"), workspace_root=str(workspace))

            rows = self.manager._system_analysis_inputs(task)

            self.assertEqual(1, len(rows))
            self.assertEqual(TASK_TYPE_SOURCE, rows[0]["task_type"])
            self.assertEqual(str(workspace / "input"), rows[0]["unpacked_root"])
            self.assertEqual(str(workspace / "input"), rows[0]["source_root"])

    def test_binary_system_analysis_inputs_fallback_to_firmware_stage_items(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="binary-task", task_type=TASK_TYPE_BINARY, status="running", firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.summary = {"firmware_unpack_results": [{"firmware_key": None, "unpacked_root": None}]}
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="firmware_unpack",
            item_key="fw.bin",
            item_name="fw.bin",
            status="success",
        )
        item.input_ref = {"filename": "fw.bin", "path": "/input/fw.bin"}
        item.output_ref = {"archive_root": "/archive/fw"}
        item.result = {
            "firmware_key": "fw.bin",
            "firmware_name": "fw",
            "filename": "fw.bin",
            "input_path": "/input/fw.bin",
            "unpacked_root": "/archive/fw",
            "source_root": "/archive/fw",
        }
        db = _ModelAwareDb(stage_items=[item])

        rows = self.manager._system_analysis_inputs(task, db=db)

        self.assertEqual(1, len(rows))
        self.assertEqual("fw.bin", rows[0]["firmware_key"])
        self.assertEqual("/archive/fw", rows[0]["unpacked_root"])
        self.assertEqual("/archive/fw", rows[0]["source_root"])

    def test_prepare_stage_items_for_execution_rejects_empty_item_key(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="binary-task", task_type=TASK_TYPE_BINARY, status="running", firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        stage_run = BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=2, status="running")
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run])

        with self.assertRaises(ValidationError):
            self.manager._prepare_stage_items_for_execution(
                db,
                task=task,
                stage_run=stage_run,
                inputs=[{"firmware_key": None}],
                downstream_service="system_analyse",
                identity=lambda row: (row.get("firmware_key"), None, row.get("firmware_key"), row),
                output_ref=lambda _row: {},
            )

    def test_source_entry_analysis_inputs_come_from_high_risk_modules(self):
        task = BinarySecurityTask(id="s1", project_id="p1", name="source-task", task_type=TASK_TYPE_SOURCE, status="pending", firmware_source="project_filesystem", firmware_path="/src", output_root="/o", workspace_root="/w")
        task.summary = {
            "selected_modules": [
                {"module_key": "m1", "module_name": "module1", "source_dir": "/src/module1"},
            ],
            "b2s_results": [
                {"module_key": "legacy", "module_name": "legacy", "source_dir": "/legacy"},
            ],
        }

        rows = self.manager._entry_analysis_inputs(_ModelAwareDb(tasks=[task]), task)

        self.assertEqual(1, len(rows))
        self.assertEqual("m1", rows[0]["module_key"])

    def test_stage_entry_analysis_precreates_all_selected_modules_as_queued_items(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source-task",
            task_type=TASK_TYPE_SOURCE,
            status="pending",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.summary = {
            "selected_modules": [
                {"module_key": "m1", "module_name": "module1", "firmware_key": "source_project_1", "source_dir": "/src/module1"},
                {"module_key": "m2", "module_name": "module2", "firmware_key": "source_project_2", "source_dir": "/src/module2"},
                {"module_key": "m3", "module_name": "module3", "firmware_key": "source_project_3", "source_dir": "/src/module3"},
            ]
        }
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run])

        async def fake_run_stage_pool(current_task, items, concurrency, runner, retries=0, initial_retry=False):
            queued_items = [
                obj for obj in db.added
                if isinstance(obj, BinarySecurityStageItem) and obj.stage_name == "entry_analysis"
            ]
            self.assertEqual(task, current_task)
            self.assertEqual(3, len(items))
            self.assertEqual(3, len(queued_items))
            self.assertEqual(["m1", "m2", "m3"], [item.item_key for item in queued_items])
            self.assertTrue(all(item.status == "queued" for item in queued_items))
            self.assertTrue(all(item.started_at is None for item in queued_items))
            return [
                {"status": "cancelled", "item": module, "error": "cancelled"}
                for module in items
            ]

        self.manager._run_stage_pool = fake_run_stage_pool

        status, summary = asyncio.run(self.manager._stage_entry_analysis(db, task, stage_run, token=None, retry_existing=False))

        self.assertEqual("cancelled", status)
        self.assertEqual(3, summary["cancelled_count"])

    def test_filter_candidate_modules_by_risk_levels(self):
        modules = [
            {"module_key": "h1", "risk_level": "高"},
            {"module_key": "m1", "risk_level": "中"},
            {"module_key": "l1", "risk_level": "低"},
        ]

        rows = self.manager._filter_candidate_modules(modules, ["高", "中"])

        self.assertEqual(["h1", "m1"], [row["module_key"] for row in rows])

    def test_stage_system_analysis_marks_no_candidate_modules_as_business_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="source-task",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                current_stage="system_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            task.policy = {}
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="running",
            )
            (workspace / "input").mkdir(parents=True, exist_ok=True)
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run])

            original_prepare = self.manager._prepare_stage_items_for_execution
            original_run_stage_pool = self.manager._run_stage_pool
            self.manager._prepare_stage_items_for_execution = lambda *args, **kwargs: None

            async def fake_run_stage_pool(current_task, items, concurrency, runner, retries=0, initial_retry=False):
                del current_task, items, concurrency, runner, retries, initial_retry
                return [
                    {
                        "status": "success",
                        "item": {
                            "firmware_key": "source_project",
                            "firmware_name": "source-task",
                            "filename": "source-project",
                            "unpacked_root": str(workspace / "input"),
                            "source_root": str(workspace / "input"),
                            "task_type": TASK_TYPE_SOURCE,
                        },
                        "modules": [{"module_key": "m1", "module_name": "m1", "risk_level": "中", "risk_score": 50}],
                    }
                ]

            self.manager._run_stage_pool = fake_run_stage_pool
            try:
                status, summary = asyncio.run(
                    self.manager._stage_system_analysis(db, task, stage_run, token=None, retry_existing=False)
                )
            finally:
                self.manager._prepare_stage_items_for_execution = original_prepare
                self.manager._run_stage_pool = original_run_stage_pool

            self.assertEqual("failed", status)
            self.assertEqual("no_candidate_modules", summary["failure_code"])
            self.assertEqual("business", summary["failure_category"])
            self.assertIn("未发现匹配所选风险等级的风险模块", summary["failure_message"])
            self.assertEqual(summary["failure_message"], task.last_error)
            self.assertEqual("no_candidate_modules", task.summary["failure_code"])
            event_types = [getattr(event, "event_type", "") for event in db.added if isinstance(event, BinarySecurityEvent)]
            self.assertIn("system_analysis_no_candidate_modules", event_types)

    def test_stage_system_analysis_preserves_downstream_failure_when_no_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="binary-task",
                status="running",
                task_type=TASK_TYPE_BINARY,
                current_stage="system_analysis",
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            task.policy = {}
            task.summary = {
                "firmware_unpack_results": [
                    {
                        "firmware_key": "fw1",
                        "firmware_name": "fw1",
                        "filename": "fw1",
                        "unpacked_root": str(workspace / "fw1"),
                    }
                ]
            }
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="running",
            )
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run])

            original_prepare = self.manager._prepare_stage_items_for_execution
            original_run_stage_pool = self.manager._run_stage_pool
            self.manager._prepare_stage_items_for_execution = lambda *args, **kwargs: None

            async def fake_run_stage_pool(current_task, items, concurrency, runner, retries=0, initial_retry=False):
                del current_task, items, concurrency, runner, retries, initial_retry
                return [{"status": "failed", "item": {"firmware_key": "fw1", "filename": "fw1"}, "error": "401 Authentication Error"}]

            self.manager._run_stage_pool = fake_run_stage_pool
            try:
                status, summary = asyncio.run(
                    self.manager._stage_system_analysis(db, task, stage_run, token=None, retry_existing=False)
                )
            finally:
                self.manager._prepare_stage_items_for_execution = original_prepare
                self.manager._run_stage_pool = original_run_stage_pool

            self.assertEqual("failed", status)
            self.assertEqual("401 Authentication Error", summary["error"])
            self.assertNotIn("failure_code", summary)
            self.assertNotEqual(task_manager_module.NO_CANDIDATE_MODULES_FAILURE_MESSAGE, task.last_error)
            event_types = [getattr(event, "event_type", "") for event in db.added if isinstance(event, BinarySecurityEvent)]
            self.assertNotIn("system_analysis_no_candidate_modules", event_types)

    def test_stage_system_analysis_pending_result_does_not_close_as_success(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="task",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {}
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=1,
            status="running",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[])

        original_prepare = self.manager._prepare_stage_items_for_execution
        original_inputs = self.manager._system_analysis_inputs
        original_run = self.manager._run_stage_pool
        self.manager._system_analysis_inputs = lambda *_args, **_kwargs: [{"firmware_key": "source_project"}]
        self.manager._prepare_stage_items_for_execution = lambda *args, **kwargs: None

        async def fake_run_stage_pool(*_args, **_kwargs):
            return [{
                "status": "pending",
                "item": {
                    "firmware_key": "source_project",
                    "modules": [{"module_key": "m1", "module_name": "m1", "risk_level": "高"}],
                },
                "deferred_mode": "redispatch",
            }]

        self.manager._run_stage_pool = fake_run_stage_pool
        try:
            status, summary = asyncio.run(self.manager._stage_system_analysis(db, task, stage_run, token=None))
        finally:
            self.manager._prepare_stage_items_for_execution = original_prepare
            self.manager._system_analysis_inputs = original_inputs
            self.manager._run_stage_pool = original_run

        self.assertEqual("pending", status)
        self.assertEqual(1, summary["pending_count"])
        self.assertEqual(0, summary["success_count"])

    def test_refresh_system_analysis_stage_from_synced_items_marks_no_candidate_modules_as_business_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            output_root = workspace / "output"
            artifact_root = output_root / "system-analyse" / "source_project__sat1"
            artifact_root.mkdir(parents=True, exist_ok=True)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="source-task",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                current_stage="system_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(output_root),
                workspace_root=str(workspace),
            )
            task.policy = {}
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="running",
            )
            item = BinarySecurityStageItem(
                id="si1",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr1",
                stage_name="system_analysis",
                item_key="source_project",
                item_name="source-project",
                status="success",
                downstream_service="system_analyse",
                downstream_task_id="sat1",
            )
            item.result = {
                "firmware_key": "source_project",
                "firmware_name": "source-task",
                "filename": "source-project",
                "unpacked_root": str(workspace / "input"),
                "source_root": str(workspace / "input"),
                "task_type": TASK_TYPE_SOURCE,
                "artifact_root": str(artifact_root),
                "archive_root": str(artifact_root),
                "modules": [{"module_key": "m1", "module_name": "m1", "risk_level": "", "risk_score": 0}],
            }
            item.output_ref = {"archive_root": str(artifact_root)}
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[item])

            self.manager._refresh_system_analysis_stage_from_synced_items(db, task)

            self.assertEqual("failed", stage_run.status)
            self.assertEqual("系统分析已完成，但未发现匹配所选风险等级的风险模块", stage_run.last_error)
            self.assertEqual(stage_run.last_error, task.last_error)
            self.assertEqual("no_candidate_modules", task.summary["failure_code"])
            self.assertEqual("business", task.summary["failure_category"])
            self.assertEqual("no_candidate_modules", stage_run.output_summary["failure_code"])
            event_types = [getattr(event, "event_type", "") for event in db.added if isinstance(event, BinarySecurityEvent)]
            self.assertIn("system_analysis_no_candidate_modules", event_types)

    def test_refresh_system_analysis_stage_preserves_failed_item_reason_when_no_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            output_root = workspace / "output"
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="binary-task",
                status="running",
                task_type=TASK_TYPE_BINARY,
                current_stage="system_analysis",
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(output_root),
                workspace_root=str(workspace),
            )
            task.policy = {}
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="running",
            )
            item = BinarySecurityStageItem(
                id="si1",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr1",
                stage_name="system_analysis",
                item_key="fw1",
                item_name="fw1",
                status="failed",
                downstream_service="system_analyse",
                downstream_task_id="sat1",
                error_message="401 Authentication Error",
            )
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[item])

            self.manager._refresh_system_analysis_stage_from_synced_items(db, task)

            self.assertEqual("failed", stage_run.status)
            self.assertEqual("401 Authentication Error", stage_run.last_error)
            self.assertNotIn("failure_code", task.summary)
            self.assertNotIn("failure_code", stage_run.output_summary)
            event_types = [getattr(event, "event_type", "") for event in db.added if isinstance(event, BinarySecurityEvent)]
            self.assertNotIn("system_analysis_no_candidate_modules", event_types)

    def test_stage_item_response_exposes_sync_observation_fields(self):
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="entry_analysis",
            item_key="entry1",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat1",
        )
        item.result = {
            "sync_status": "transport_error",
            "downstream_status_synced_at": "2026-05-24T23:05:39",
        }

        response = self.manager._stage_item_response(item)

        self.assertEqual("transport_error", response.sync_status)
        self.assertIsNotNone(response.last_synced_at)

    def test_stage_item_response_exposes_retry_and_rerun_counts(self):
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="dataflow_analysis",
            item_key="entry1",
            status="failed",
            retry_count=1,
            rerun_count=11,
        )

        response = self.manager._stage_item_response(item)

        self.assertEqual(1, response.retry_count)
        self.assertEqual(11, response.rerun_count)
        self.assertEqual(1, response.auto_retry_count)

    def test_stage_worker_terminal_event_rebuilds_system_analysis_from_items(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            output_root = workspace / "output"
            artifact_root = output_root / "system-analyse" / "source_project__sat1"
            artifact_root.mkdir(parents=True, exist_ok=True)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="source-task",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                current_stage="system_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(output_root),
                workspace_root=str(workspace),
            )
            task.policy = {}
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="running",
            )
            item = BinarySecurityStageItem(
                id="si1",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr1",
                stage_name="system_analysis",
                item_key="source_project",
                item_name="source-project",
                status="success",
                downstream_service="system_analyse",
                downstream_task_id="sat1",
            )
            item.result = {
                "firmware_key": "source_project",
                "firmware_name": "source-task",
                "filename": "source-project",
                "unpacked_root": str(workspace / "input"),
                "source_root": str(workspace / "input"),
                "task_type": TASK_TYPE_SOURCE,
                "artifact_root": str(artifact_root),
                "archive_root": str(artifact_root),
                "modules": [{"module_key": "m1", "module_name": "m1", "risk_level": "高", "risk_score": 90}],
            }
            item.output_ref = {"archive_root": str(artifact_root)}
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[item], state_events=[])

            event = BinarySecurityStateEvent(
                id="sev1",
                task_id="t1",
                project_id="p1",
                stage_name="system_analysis",
                event_type="stage_worker_terminal_observed",
                status="pending",
            )
            event.payload = {
                "stage_name": "system_analysis",
                "status": "success",
                "summary": {
                    "items": [],
                    "failed_items": [],
                    "success_count": 0,
                    "failed_count": 0,
                    "module_count": 0,
                    "high_risk_module_count": 0,
                    "medium_risk_module_count": 0,
                    "low_risk_module_count": 0,
                    "candidate_module_count": 0,
                    "selected_module_count": 0,
                    "requires_confirmation": False,
                    "error": None,
                },
            }

            original_write = self.manager._write_task_metadata_async
            async def _noop_write(*_args, **_kwargs):
                return None
            self.manager._write_task_metadata_async = _noop_write
            try:
                asyncio.run(self.manager._apply_stage_worker_terminal_event_locked(db, event))
            finally:
                self.manager._write_task_metadata_async = original_write

            self.assertEqual("success", stage_run.status)
            self.assertEqual("entry_analysis", task.current_stage)
            self.assertEqual(1, int(task.metrics.get("high_risk_module_count") or 0))

    def test_stage_system_analysis_success_clears_stale_failure_fields(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="task",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {"module_risk_levels": ["高"]}
        task.summary = {
            "failure_code": "no_candidate_modules",
            "failure_category": "business",
            "failure_message": "stale",
            "error": "stale",
            "firmware_unpack_results": [{
                "firmware_key": "fw1",
                "firmware_name": "fw1",
                "filename": "fw1.bin",
                "unpacked_root": "/tmp/fw1",
                "source_root": "/tmp/fw1",
                "task_type": TASK_TYPE_BINARY,
            }],
        }
        task.last_error = "stale"
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=2,
            status="running",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run])

        original_prepare = self.manager._prepare_stage_items_for_execution
        original_run_stage_pool = self.manager._run_stage_pool
        self.manager._prepare_stage_items_for_execution = lambda *args, **kwargs: None

        async def fake_run_stage_pool(*args, **kwargs):
            return [{
                "status": "success",
                "item": {
                    "firmware_key": "fw1",
                    "firmware_name": "fw1",
                    "filename": "fw1.bin",
                    "modules": [{
                        "module_key": "m1",
                        "module_name": "m1",
                        "risk_level": "高",
                        "risk_score": 90,
                    }],
                },
            }]

        self.manager._run_stage_pool = fake_run_stage_pool
        try:
            status, summary = asyncio.run(
                self.manager._stage_system_analysis(db, task, stage_run, token=None, retry_existing=False)
            )
        finally:
            self.manager._prepare_stage_items_for_execution = original_prepare
            self.manager._run_stage_pool = original_run_stage_pool

        self.assertEqual("success", status)
        self.assertEqual(1, summary["candidate_module_count"])
        self.assertEqual(1, len(task.summary["selected_modules"]))
        self.assertNotIn("failure_code", task.summary)
        self.assertNotIn("failure_category", task.summary)
        self.assertNotIn("failure_message", task.summary)
        self.assertNotIn("error", task.summary)
        self.assertIsNone(task.last_error)

    def test_confirm_module_selection_updates_task(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="task",
            task_type=TASK_TYPE_SOURCE,
            status="pending_module_confirmation",
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.summary = {
            "candidate_modules": [
                {"module_key": "m1", "module_name": "module1", "risk_level": "高"},
                {"module_key": "m2", "module_name": "module2", "risk_level": "中"},
            ],
            "selected_modules": [],
        }
        task.policy = {"module_selection_mode": "manual_confirm", "module_risk_levels": ["高", "中"]}

        class _TaskDb(_FakeDb):
            def __init__(self, task_row):
                super().__init__([task_row])
                self.task_row = task_row

            def query(self, model, *args, **kwargs):
                class _Query(_FakeQuery):
                    def filter(self, *args, **kwargs):
                        return self
                    def order_by(self, *args, **kwargs):
                        return self
                if getattr(model, "__name__", "") == "BinarySecurityTask":
                    return _Query([self.task_row])
                if getattr(model, "__name__", "") == "BinarySecurityStageRun":
                    return _Query([])
                return _Query([])

        db = _TaskDb(task)
        self.manager._write_task_metadata = lambda *args, **kwargs: None
        detail = self.manager.confirm_module_selection(
            db,
            project_id="p1",
            task_id="t1",
            selected_module_keys=["m2"],
        )

        self.assertEqual("pending_module_confirmation", task.status)
        self.assertIn("manual_module_selection_confirmed", [getattr(event, "event_type", "") for event in db.added])
        self.manager._apply_manual_module_selection_confirmed_locked(db, db.added[-1])

        self.assertEqual("pending", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual(1, task.metrics["selected_module_count"])
        self.assertEqual(["m2"], [item["module_key"] for item in task.summary["selected_modules"]])
        self.assertEqual(0, detail.selected_module_count)

    def test_normalize_source_input_files_rejects_duplicate_relative_paths(self):
        with self.assertRaisesRegex(Exception, "重复文件名"):
            self.manager._normalize_input_files(
                [
                    {"filename": "src.zip", "relative_path": "src/a.c"},
                    {"filename": "src.zip", "relative_path": "src/b.c"},
                ],
                task_type=TASK_TYPE_SOURCE,
            )

    def test_normalize_source_input_files_rejects_non_archive(self):
        with self.assertRaisesRegex(Exception, "仅支持常见压缩文件"):
            self.manager._normalize_input_files(
                [
                    {"filename": "main.c"},
                ],
                task_type=TASK_TYPE_SOURCE,
            )

    def test_materialize_source_archives_extracts_into_input_and_cleans_temp_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            input_dir = workspace / "input"
            temp_dir = workspace / "run" / "upload-tmp"
            input_dir.mkdir(parents=True)
            temp_dir.mkdir(parents=True)
            archive_path = temp_dir / "source.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("src/main.c", "int main() { return 0; }\n")
                archive.writestr("README.md", "# demo\n")
            task = BinarySecurityTask(
                id="s1",
                project_id="p1",
                name="source-task",
                task_type=TASK_TYPE_SOURCE,
                status="pending_upload",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            task.summary = {
                "input_dir": "/app/secflow-app-binary-security/s1/input",
                "temp_upload_dir": "/app/secflow-app-binary-security/s1/run/upload-tmp",
            }

            files, total_bytes, extracted_count = asyncio.run(
                self.manager._materialize_source_archives(
                    task,
                    [{"filename": "source.zip", "relative_path": "source.zip"}],
                )
            )

            self.assertEqual(1, len(files))
            self.assertGreater(total_bytes, 0)
            self.assertEqual(2, extracted_count)
            self.assertTrue((input_dir / "src" / "main.c").is_file())
            self.assertTrue((input_dir / "README.md").is_file())
            self.assertFalse(archive_path.exists())

    def test_resolve_downstream_output_sources_prefers_output_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            output_dir = workspace / "output"
            output_dir.mkdir(parents=True)
            (output_dir / "report.md").write_text("ok", encoding="utf-8")

            rows = self.manager._resolve_downstream_output_sources(
                {"workspace_root": str(workspace)},
                downstream_task_id="t123",
            )

            self.assertEqual(output_dir, rows[0])

    def test_archive_downstream_output_copies_output_contents_without_output_layer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            output_dir = workspace / "output"
            output_dir.mkdir(parents=True)
            (output_dir / "result.json").write_text("{}", encoding="utf-8")
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_BINARY,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(root / "task-output"),
                workspace_root=str(root / "workspace-root"),
            )
            item = type("Item", (), {
                "downstream_service": "system_analyse",
                "stage_name": "system_analysis",
                "downstream_task_id": "down1",
                "item_key": "fw1",
                "id": "si1",
            })()
            db = _FakeDb()

            target = self.manager._archive_downstream_output(
                db,
                task,
                item,
                semantic_key="fw1",
                payload={"workspace_root": str(workspace)},
            )

            self.assertIsNotNone(target)
            assert target is not None
            self.assertTrue((target / "result.json").is_file())
            self.assertFalse((target / "output").exists())
            self.assertEqual("system-analyse", target.parent.name)
            self.assertEqual("fw1__down1", target.name)

    def test_resolve_downstream_output_sources_reads_nested_result_output_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_dir = root / "service" / "down1" / "output"
            output_dir.mkdir(parents=True)
            (output_dir / "report.md").write_text("ok", encoding="utf-8")

            rows = self.manager._resolve_downstream_output_sources(
                {"result": {"output_root": str(root / "service")}},
                downstream_task_id="down1",
            )

            self.assertEqual(output_dir, rows[0])

    def test_resolve_downstream_output_sources_prefers_task_scoped_output_over_service_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service_root = root / "service"
            other_output = service_root / "other-task" / "output"
            task_output = service_root / "down1" / "output"
            other_output.mkdir(parents=True)
            task_output.mkdir(parents=True)
            (other_output / "other.md").write_text("other", encoding="utf-8")
            (task_output / "report.md").write_text("ok", encoding="utf-8")

            rows = self.manager._resolve_downstream_output_sources(
                {"output_path": str(service_root)},
                downstream_task_id="down1",
            )

            self.assertEqual(task_output, rows[0])
            self.assertIn(service_root, rows)

    def test_archive_downstream_output_uses_standard_service_output_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "app" / "secflow-app-binary-security" / "task1"
            source_output = root / "app" / "secflow-app-firmware-unpacker" / "down1" / "output"
            source_output.mkdir(parents=True)
            (source_output / "summary.md").write_text("ok", encoding="utf-8")
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_BINARY,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            item = type("Item", (), {
                "downstream_service": "firmware_unpacker",
                "stage_name": "firmware_unpack",
                "downstream_task_id": "down1",
                "item_key": "fw1",
                "id": "si1",
            })()

            target = self.manager._archive_downstream_output(
                _FakeDb(),
                task,
                item,
                semantic_key="fw1",
                payload={"output_path": str(workspace / "run" / "firmware-unpacker" / "fw1")},
            )

            self.assertIsNotNone(target)
            assert target is not None
            self.assertTrue((target / "summary.md").is_file())
            self.assertEqual("firmware-unpacker", target.parent.name)

    def test_archive_downstream_output_does_not_copy_other_downstream_tasks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service_root = root / "secflow-app-entry-analyse"
            current_output = service_root / "eat_current" / "output"
            other_output = service_root / "eat_other" / "output"
            current_output.mkdir(parents=True)
            other_output.mkdir(parents=True)
            (current_output / "entry-details.json").write_text("[]", encoding="utf-8")
            (other_output / "foreign.txt").write_text("x", encoding="utf-8")
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(root / "task-output"),
                workspace_root=str(root / "workspace-root"),
            )
            item = type("Item", (), {
                "downstream_service": "entry_analyse",
                "stage_name": "entry_analysis",
                "downstream_task_id": "eat_current",
                "item_key": "source_project-image",
                "id": "si1",
            })()

            target = self.manager._archive_downstream_output(
                _FakeDb(),
                task,
                item,
                semantic_key="source_project-image",
                payload={"output_path": str(service_root)},
            )

            self.assertIsNotNone(target)
            assert target is not None
            self.assertTrue((target / "entry-details.json").is_file())
            self.assertFalse((target / "eat_other").exists())
            self.assertFalse((target / "foreign.txt").exists())

    def test_archive_downstream_output_skips_empty_sources_without_creating_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            empty_output = workspace / "output"
            empty_output.mkdir(parents=True)
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_BINARY,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(root / "task-output"),
                workspace_root=str(root / "workspace-root"),
            )
            item = type("Item", (), {
                "downstream_service": "system_analyse",
                "stage_name": "system_analysis",
                "downstream_task_id": "down1",
                "item_key": "fw1",
                "id": "si1",
            })()

            target = self.manager._archive_downstream_output(
                _FakeDb(),
                task,
                item,
                semantic_key="fw1",
                payload={"workspace_root": str(workspace)},
            )

            self.assertIsNone(target)
            self.assertFalse((root / "task-output" / "system-analyse" / "fw1__down1").exists())

    def test_archive_job_payload_uses_compact_downstream_payload(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        item = type("Item", (), {
            "id": "si1",
            "stage_name": "system_analysis",
            "item_key": "source_project",
            "downstream_service": "system_analyse",
            "downstream_task_id": "sat1",
        })()
        db = _ModelAwareDb()

        job = self.manager._ensure_downstream_archive_job(
            db,
            task,
            item,
            payload={
                "task_id": "sat1",
                "status": "success",
                "workspace_root": "/tmp/system-analysis/sat1",
                "modules": [{"name": f"module-{idx}", "blob": "x" * 1000} for idx in range(100)],
                "result": {
                    "output_root": "/tmp/system-analysis/sat1/output",
                    "modules": [{"name": f"nested-{idx}", "blob": "y" * 1000} for idx in range(100)],
                },
            },
            mapped_status="success",
            before_status="running",
        )

        payload = job.payload
        downstream_payload = payload["downstream_payload"]
        self.assertEqual("sat1", downstream_payload["task_id"])
        self.assertEqual("/tmp/system-analysis/sat1", downstream_payload["workspace_root"])
        self.assertEqual("/tmp/system-analysis/sat1/output", downstream_payload["result"]["output_root"])
        self.assertNotIn("modules", downstream_payload)
        self.assertNotIn("modules", downstream_payload["result"])
        self.assertLess(len(job.payload_json or ""), 2048)

    def test_ensure_downstream_archive_job_keeps_success_job_when_downstream_payload_changes(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="task1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="entry_analysis",
            item_key="source_project-images",
            item_name="images",
            downstream_service="entry_analyse",
            downstream_task_id="eat_1",
            status="failed",
        )
        job = BinarySecurityArchiveJob(
            id="aj1",
            task_id="task1",
            project_id="p1",
            stage_name="entry_analysis",
            item_id="si1",
            item_key="source_project-images",
            downstream_service="entry_analyse",
            downstream_task_id="eat_1",
            job_dedupe_key="si1::eat_1",
            archive_status="success",
            archive_root="/old/archive",
        )
        job.payload = {
            "mapped_status": "failed",
            "before_status": "running",
            "force": False,
            "downstream_payload": {
                "task_id": "eat_1",
                "status": "failed",
                "updated_at": "2026-05-15T20:05:39+08:00",
                "error": "old failed",
            },
            "extra_paths": [],
            "archive_copy_stats": {"copied_files": 10},
        }
        db = _LockingDb(_FakeConnection(lock_result=True))
        db.tasks.append(task)
        db.stage_items.append(item)
        db.archive_jobs.append(job)

        refreshed = self.manager._ensure_downstream_archive_job(
            db,
            task,
            item,
            payload={
                "task_id": "eat_1",
                "status": "passed",
                "updated_at": "2026-05-15T21:18:53+08:00",
                "finished_at": "2026-05-15T21:18:53+08:00",
                "output_path": "/data/files/p1/app/secflow-app-entry-analyse",
            },
            mapped_status="success",
            before_status="failed",
        )

        self.assertIs(job, refreshed)
        self.assertEqual("success", refreshed.archive_status)
        self.assertEqual("/old/archive", refreshed.archive_root)
        self.assertEqual("failed", refreshed.payload["mapped_status"])
        self.assertEqual("failed", refreshed.payload["downstream_payload"]["status"])
        self.assertIn("archive_copy_stats", refreshed.payload)

    def test_ensure_downstream_archive_job_keeps_failed_job_until_manual_retry(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="task1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="entry_analysis",
            item_key="source_project-images",
            item_name="images",
            downstream_service="entry_analyse",
            downstream_task_id="eat_1",
            status="success",
        )
        job = BinarySecurityArchiveJob(
            id="aj1",
            task_id="task1",
            project_id="p1",
            stage_name="entry_analysis",
            item_id="si1",
            item_key="source_project-images",
            downstream_service="entry_analyse",
            downstream_task_id="eat_1",
            job_dedupe_key="si1::eat_1",
            archive_status="failed",
            archive_root="/old/archive",
            error_message="copy failed",
        )
        job.payload = {
            "mapped_status": "success",
            "before_status": "running",
            "force": False,
            "downstream_payload": {
                "task_id": "eat_1",
                "status": "passed",
            },
            "extra_paths": [],
        }
        db = _LockingDb(_FakeConnection(lock_result=True))
        db.tasks.append(task)
        db.stage_items.append(item)
        db.archive_jobs.append(job)

        refreshed = self.manager._ensure_downstream_archive_job(
            db,
            task,
            item,
            payload={
                "task_id": "eat_1",
                "status": "passed",
                "updated_at": "2026-05-15T21:18:53+08:00",
            },
            mapped_status="success",
            before_status="running",
        )

        self.assertIs(job, refreshed)
        self.assertEqual("failed", refreshed.archive_status)
        self.assertEqual("/old/archive", refreshed.archive_root)
        self.assertEqual("copy failed", refreshed.error_message)

    def test_ensure_downstream_archive_job_retries_retryable_deadlock(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="task1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="entry_analysis",
            item_key="source_project-images",
            item_name="images",
            downstream_service="entry_analyse",
            downstream_task_id="eat_1",
            status="success",
        )
        db = _FlakyArchiveJobDb(
            _FakeConnection(lock_result=True),
            tasks=[task],
            stage_items=[item],
            archive_jobs=[],
            fail_flushes=1,
            fail_commits=1,
        )

        created = self.manager._ensure_downstream_archive_job(
            db,
            task,
            item,
            payload={"task_id": "eat_1", "status": "passed", "output_path": "/tmp/out"},
            mapped_status="success",
            before_status="running",
        )

        self.assertIsNotNone(created)
        self.assertEqual("pending", created.archive_status)
        self.assertGreaterEqual(db.flush_calls, 2)
        self.assertGreaterEqual(db.commit_calls, 2)
        self.assertGreaterEqual(db.rollback_calls, 1)

    def test_collect_downstream_refs_dedupes_same_service_and_task_id(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        items = []
        for item_id, task_id in [("i1", "down1"), ("i2", "down1"), ("i3", "down2")]:
            item = type("Item", (), {})()
            item.id = item_id
            item.downstream_service = "entry_analyse"
            item.downstream_task_id = task_id
            item.project_id = "p1"
            item.stage_name = "entry_analysis"
            items.append(item)

        refs = self.manager._collect_downstream_refs(task, items)

        self.assertEqual(2, len(refs))
        self.assertEqual(
            [
                {"service": "entry_analyse", "task_id": "down1", "project_id": "p1", "stage_name": "entry_analysis"},
                {"service": "entry_analyse", "task_id": "down2", "project_id": "p1", "stage_name": "entry_analysis"},
            ],
            refs,
        )

    def test_stage_retry_support_allows_missing_downstream_task_id_for_recreate(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        stage_run = SimpleNamespace(task_id="task1", stage_name="firmware_unpack", status="failed")
        stage_item = SimpleNamespace(
            task_id="task1",
            stage_name="firmware_unpack",
            item_key="fw1",
            parent_key="fw1",
            downstream_service="firmware_unpacker",
            downstream_task_id=None,
            created_at=1,
        )

        supported, reason = self.manager._stage_retry_support(
            _ModelAwareDb(stage_runs=[stage_run], stage_items=[stage_item]),
            task,
            "firmware_unpack",
        )

        self.assertTrue(supported)
        self.assertIsNone(reason)

    def test_stage_retry_support_rejects_duplicate_history_items(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        stage_run = SimpleNamespace(task_id="task1", stage_name="firmware_unpack", status="failed")
        item1 = SimpleNamespace(
            task_id="task1",
            stage_name="firmware_unpack",
            item_key="fw1",
            parent_key="fw1",
            downstream_service="firmware_unpacker",
            downstream_task_id="down-1",
            created_at=1,
        )
        item2 = SimpleNamespace(
            task_id="task1",
            stage_name="firmware_unpack",
            item_key="fw1",
            parent_key="fw1",
            downstream_service="firmware_unpacker",
            downstream_task_id="down-2",
            created_at=2,
        )

        supported, reason = self.manager._stage_retry_support(
            _ModelAwareDb(stage_runs=[stage_run], stage_items=[item1, item2]),
            task,
            "firmware_unpack",
        )

        self.assertFalse(supported)
        self.assertIn("重复历史 item", reason or "")

    def test_stage_retry_support_allows_cancelled_task(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="cancelled",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="task1",
            project_id="p1",
            stage_name="firmware_unpack",
            sequence_no=1,
            status="cancelled",
            finished_at=None,
        )
        stage_item = BinarySecurityStageItem(
            id="si1",
            task_id="task1",
            project_id="p1",
            stage_name="firmware_unpack",
            item_key="fw1",
            parent_key="fw1",
            downstream_service="firmware_unpacker",
            downstream_task_id="down-1",
            status="cancelled",
            created_at=_now(),
            finished_at=None,
        )

        supported, reason = self.manager._stage_retry_support(
            _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[stage_item]),
            task,
            "firmware_unpack",
        )

        self.assertTrue(supported)
        self.assertIsNone(reason)

    def test_retry_stage_accepts_cancelled_task(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="cancelled",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="task1",
            project_id="p1",
            stage_name="firmware_unpack",
            sequence_no=1,
            status="cancelled",
        )
        stage_item = BinarySecurityStageItem(
            id="si1",
            task_id="task1",
            project_id="p1",
            stage_name="firmware_unpack",
            item_key="fw1",
            parent_key="fw1",
            downstream_service="firmware_unpacker",
            downstream_task_id="down-1",
            status="cancelled",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[stage_item])

        self.manager.retry_stage(db, project_id="p1", task_id="task1", stage_name="firmware_unpack")

        self.assertEqual("cancelled", task.status)
        self.assertIsNone(task.pending_action)
        state_events = [row for row in db.added if row.__class__.__name__ == "BinarySecurityStateEvent"]
        self.assertTrue(state_events)
        event = state_events[-1]
        self.assertEqual("manual_blocking_action_requested", event.event_type)
        self.assertEqual("firmware_unpack", event.stage_name)
        self.assertEqual("retry_stage_full", event.payload.get("action"))

    def test_task_retry_support_targets_first_stage_for_full_restart(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        stage_runs = [
            SimpleNamespace(task_id="task1", stage_name="firmware_unpack", status="success"),
            SimpleNamespace(task_id="task1", stage_name="system_analysis", status="failed"),
        ]
        stage_items = [
            SimpleNamespace(
                task_id="task1",
                stage_name="system_analysis",
                item_key="fw1",
                parent_key="fw1",
                downstream_service="system_analyse",
                downstream_task_id="sa-1",
                created_at=1,
            ),
        ]

        supported, reason, stage_name = self.manager._task_retry_support(
            _ModelAwareDb(stage_runs=stage_runs, stage_items=stage_items),
            task,
        )

        self.assertTrue(supported)
        self.assertIsNone(reason)
        self.assertEqual("firmware_unpack", stage_name)

    def test_seconds_until_prefers_local_expired_interpretation(self):
        lease_value = _now() - timedelta(minutes=5)
        remaining = _seconds_until(lease_value)
        self.assertIsNotNone(remaining)
        self.assertLess(remaining, 0)
        self.assertGreater(remaining, -600)

    def test_seconds_until_prefers_nearest_future_interpretation(self):
        lease_value = datetime.utcnow() + timedelta(minutes=5)
        remaining = _seconds_until(lease_value)
        self.assertIsNotNone(remaining)
        self.assertGreater(remaining, 0)
        self.assertLess(remaining, 600)

    def test_reclaim_stale_running_task_marks_stage_and_items_failed(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            current_stage="firmware_unpack",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.dispatch_started_at = _now()
        task.updated_at = task.dispatch_started_at - timedelta(seconds=360)
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="task1",
            project_id="p1",
            stage_name="firmware_unpack",
            sequence_no=1,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="task1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="firmware_unpack",
            item_key="fw1",
            status="running",
        )

        class _ReclaimDb(_FakeDb):
            def query(self, model, *args, **kwargs):
                model_name = getattr(model, "__name__", "")
                if model_name == "BinarySecurityTask":
                    return _FakeQuery([task])
                if model_name == "BinarySecurityStageRun":
                    return _FakeQuery([stage_run])
                if model_name == "BinarySecurityStageItem":
                    return _FakeQuery([item])
                return _FakeQuery([])

            def flush(self):
                pass

        original_loader = self.manager._load_service_config
        self.manager._load_service_config = lambda db: SimpleNamespace(dispatch_timeout_seconds=60)
        try:
            reclaimed = self.manager._reclaim_stale_running_locked(_ReclaimDb())
        finally:
            self.manager._load_service_config = original_loader

        self.assertTrue(reclaimed)
        self.assertEqual("failed", task.status)
        self.assertEqual("failed", stage_run.status)
        self.assertEqual("failed", item.status)
        self.assertIsNotNone(task.finished_at)
        self.assertIn("心跳超时", task.last_error or "")

    def test_reclaim_stale_running_task_does_not_skip_foreign_owner_local_worker(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            current_stage="dataflow_analysis",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw.bin",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="dead-worker-pod",
        )
        task.dispatch_started_at = _now() - timedelta(seconds=600)
        task.lease_expires_at = None
        task.updated_at = _now() - timedelta(seconds=600)

        active_item = BinarySecurityStageItem(
            id="si1",
            task_id="task1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="dataflow_analysis",
            item_key="k1",
            status="running",
            downstream_task_id="dfa-1",
        )

        class _ReclaimDb(_FakeDb):
            def query(self, model, *args, **kwargs):
                model_name = getattr(model, "__name__", "")
                if model_name == "BinarySecurityTask":
                    return _FakeQuery([task])
                if model_name == "BinarySecurityStageRun":
                    return _FakeQuery([])
                if model_name == "BinarySecurityStageItem":
                    return _FakeQuery([active_item])
                return _FakeQuery([])

            def flush(self):
                pass

        class _ActiveWorker:
            def done(self):
                return False

        original_loader = self.manager._load_service_config
        self.manager._load_service_config = lambda db: SimpleNamespace(dispatch_timeout_seconds=60)
        self.manager._workers[task.id] = _ActiveWorker()
        try:
            reclaimed = self.manager._reclaim_stale_running_locked(_ReclaimDb())
        finally:
            self.manager._load_service_config = original_loader
            self.manager._workers.clear()

        self.assertTrue(reclaimed)
        self.assertEqual("pending", task.status)
        self.assertIsNone(task.dispatcher_instance_id)
        self.assertIsNone(task.dispatch_started_at)
        self.assertIsNone(task.lease_expires_at)
        self.assertIsNone(task.last_error)

    def test_requeue_released_running_task_marks_task_pending(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            current_stage="binary_to_source",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw.bin",
            output_root="/o",
            workspace_root="/w",
        )
        task.updated_at = _now() - timedelta(seconds=120)
        active_item = BinarySecurityStageItem(
            id="si1",
            task_id="task1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="binary_to_source",
            item_key="k1",
            status="running",
            downstream_task_id="b2s-1",
        )

        class _RequeueDb(_FakeDb):
            def query(self, model, *args, **kwargs):
                model_name = getattr(model, "__name__", "")
                if model_name == "BinarySecurityTask":
                    return _FakeQuery([task])
                if model_name == "BinarySecurityStageItem":
                    return _FakeQuery([active_item])
                return _FakeQuery([])

            def flush(self):
                pass

        requeued = self.manager._requeue_released_running_locked(_RequeueDb())

        self.assertTrue(requeued)
        self.assertEqual("pending", task.status)
        self.assertIsNone(task.dispatcher_instance_id)
        self.assertIsNone(task.dispatch_started_at)
        self.assertIsNone(task.lease_expires_at)

    def test_recover_missing_stage_terminal_events_requeues_missing_terminal_signal(self):
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                current_stage="entry_analysis",
                task_type=TASK_TYPE_SOURCE,
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root="/o",
                workspace_root=tmp,
            )
            task.dispatch_started_at = _now()
            task.dispatcher_instance_id = "worker-a"
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="task1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="failed",
            )
            stage_run.output_summary = {"error": "input contract mismatch", "failed_count": 1}
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], state_events=[], events=[])

            recovered = self.manager._recover_missing_stage_terminal_events_locked(db)

            self.assertTrue(recovered)
            terminal_events = [row for row in db.added if row.__class__.__name__ == "BinarySecurityStateEvent"]
            self.assertEqual(1, len(terminal_events))
            self.assertEqual("stage_worker_terminal_observed", terminal_events[0].event_type)
            self.assertEqual("failed", terminal_events[0].payload["status"])
            self.assertTrue(any(row.event_type == "stage_worker_terminal_event_missing" for row in db.added if row.__class__.__name__ == "BinarySecurityEvent"))

    def test_recover_missing_stage_terminal_events_skips_when_event_already_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                current_stage="entry_analysis",
                task_type=TASK_TYPE_SOURCE,
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root="/o",
                workspace_root=tmp,
            )
            task.dispatch_started_at = _now()
            execution_token = task.dispatch_started_at.isoformat()
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="task1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="failed",
            )
            existing = BinarySecurityStateEvent(
                id="sev-existing",
                task_id="task1",
                project_id="p1",
                stage_name="entry_analysis",
                event_type="stage_worker_terminal_observed",
                idempotency_key=f"stage_worker_terminal_observed:task1:entry_analysis:{execution_token}:failed",
                status="pending",
                available_at=_now(),
            )
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], state_events=[existing], events=[])

            recovered = self.manager._recover_missing_stage_terminal_events_locked(db)

            self.assertFalse(recovered)
            self.assertFalse(any(row.__class__.__name__ == "BinarySecurityEvent" and row.event_type == "stage_worker_terminal_event_missing" for row in db.added))

    def test_recover_missing_stage_terminal_events_without_dispatch_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                current_stage="entry_analysis",
                task_type=TASK_TYPE_BINARY_MODULE,
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root="/o",
                workspace_root=tmp,
            )
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="task1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="failed",
            )
            stage_run.output_summary = {"error": "missing input contract", "failed_count": 1}
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], state_events=[], events=[])

            recovered = self.manager._recover_missing_stage_terminal_events_locked(db)

            self.assertTrue(recovered)
            terminal_events = [row for row in db.added if row.__class__.__name__ == "BinarySecurityStateEvent"]
            self.assertEqual(1, len(terminal_events))
            self.assertEqual(
                "stage_worker_terminal_observed:task1:entry_analysis::failed",
                terminal_events[0].idempotency_key,
            )
            warnings = [row for row in db.added if row.__class__.__name__ == "BinarySecurityEvent"]
            self.assertTrue(any(row.event_type == "stage_worker_terminal_event_missing" for row in warnings))
            self.assertTrue(any("missing_execution_token" in str((row.payload_json or "")) for row in warnings))

    def test_normalize_entry_analysis_module_input_prepares_binary_module_descriptor(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact_root = Path(tmp) / "artifact"
            module_dir = artifact_root / "output" / "src"
            module_dir.mkdir(parents=True)
            source_file = module_dir / "main.c"
            source_file.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                current_stage="binary_to_source",
                task_type=TASK_TYPE_BINARY_MODULE,
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root="/o",
                workspace_root=tmp,
            )

            normalized = self.manager._normalize_entry_analysis_module_input(
                task,
                {
                    "module_key": "m1",
                    "module_name": "mod",
                    "artifact_root": str(artifact_root),
                    "archive_root": str(artifact_root),
                },
            )

            self.assertTrue(normalized.get("entry_descriptor_ready"))
            self.assertEqual(str(artifact_root), normalized.get("entry_descriptor_root"))
            self.assertEqual(str(artifact_root), normalized.get("source_root"))
            self.assertEqual(str(artifact_root), normalized.get("source_root_path"))
            self.assertTrue(str(normalized.get("files_list_path") or "").endswith("files.list"))

    def test_build_entry_analysis_input_contract_requires_explicit_fields(self):
        contract = self.manager._build_entry_analysis_input_contract(
            {
                "module_dir": "/tmp/mod",
                "files_list_path": "/tmp/mod/files.list",
                "source_root": "/tmp/root",
                "source_root_path": "/tmp/root",
                "source_dir": "/tmp/root",
            }
        )
        self.assertEqual("/tmp/mod", contract["module_dir"])
        self.assertEqual("/tmp/mod/files.list", contract["files_list_path"])
        self.assertEqual("/tmp/root", contract["source_root"])

    def test_list_tasks_needing_downstream_sync_includes_failed_tasks_when_retry_target_stage_is_active(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="failed",
            current_stage="entry_analysis",
            execution_mode="stage_retry_full",
            target_stage_name="system_analysis",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw.bin",
            output_root="/o",
            workspace_root="/w",
        )
        retry_target_item = BinarySecurityStageItem(
            id="si1",
            task_id="task1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="system_analysis",
            item_key="k1",
            status="failed",
            downstream_service="system_analyse",
            downstream_task_id="sat-1",
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[retry_target_item])
        refs = self.manager._list_tasks_needing_downstream_sync(db)
        self.assertEqual([{"project_id": "p1", "task_id": "task1"}], refs)

    def test_poll_until_terminal_preserves_downstream_cancelled_status(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )

        async def _fetch():
            return {"status": "cancelled", "error": "任务已取消"}

        async def _noop_async(*_args, **_kwargs):
            return None

        original_ensure = self.manager._ensure_task_execution_current_async
        original_touch = self.manager._touch_task_heartbeat_async
        original_cancelled = self.manager._is_task_cancelled_async
        self.manager._ensure_task_execution_current_async = _noop_async
        self.manager._touch_task_heartbeat_async = _noop_async
        self.manager._is_task_cancelled_async = unittest.mock.AsyncMock(return_value=False)
        try:
            status, payload = asyncio.run(
                self.manager._poll_until_terminal(
                    _fetch,
                    success_statuses={"passed", "success"},
                    failure_statuses={"failed", "error", "cancelled"},
                    task=task,
                )
            )
        finally:
            self.manager._ensure_task_execution_current_async = original_ensure
            self.manager._touch_task_heartbeat_async = original_touch
            self.manager._is_task_cancelled_async = original_cancelled

        self.assertEqual("cancelled", status)
        self.assertEqual("cancelled", payload["status"])

    def test_run_task_ignores_stale_worker_failure_after_retry(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="dispatching",
            current_stage="firmware_unpack",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id=self.manager.instance_id,
        )
        task.latest_abnormal_reason = {
            "is_abnormal": True,
            "category": "downstream",
            "code": "downstream_cancelled",
            "title": "旧异常",
            "message": "旧异常",
            "terminal": True,
            "source_layer": "task",
            "status": "failed",
            "service": "binary_to_source",
            "stage_name": "binary_to_source",
            "evidence": [],
            "related_event_ids": [],
        }
        task.dispatch_started_at = _now()
        task.lease_expires_at = task.dispatch_started_at + timedelta(seconds=30)
        original_token = task.dispatch_started_at

        class _RunTaskDb(_ModelAwareDb):
            def __init__(self, current_task):
                super().__init__(tasks=[current_task])
                self.current_task = current_task
                self.commits = 0
                self.closed = False

            def commit(self):
                self.commits += 1

            def close(self):
                self.closed = True

        db = _RunTaskDb(task)
        original_factory = task_manager_module.get_session_factory
        original_execute_task = self.manager._execute_task

        async def fake_execute_task(task_id: str):
            task.dispatch_started_at = original_token + timedelta(seconds=1)
            raise RuntimeError("stale worker boom")

        task_manager_module.get_session_factory = lambda: (lambda: db)
        self.manager._execute_task = fake_execute_task
        try:
            asyncio.run(self.manager._run_task("task1"))
        finally:
            task_manager_module.get_session_factory = original_factory
            self.manager._execute_task = original_execute_task

        self.assertEqual("running", task.status)
        self.assertIsNone(task.last_error)
        self.assertIsNone(task.latest_abnormal_reason)
        self.assertTrue(db.closed)

    def test_execute_task_failed_stage_does_not_requeue_same_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                current_stage="binary_to_source",
                task_type=TASK_TYPE_BINARY,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(Path(tmp) / "output"),
                workspace_root=tmp,
                dispatcher_instance_id=self.manager.instance_id,
            )
            task.summary = {"selected_modules": [{"module_key": "m1", "module_name": "m1"}]}
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="task1",
                project_id="p1",
                stage_name="binary_to_source",
                sequence_no=3,
                status="queued",
            )
            prev_runs = [
                BinarySecurityStageRun(
                    id="sr-fw",
                    task_id="task1",
                    project_id="p1",
                    stage_name="firmware_unpack",
                    sequence_no=1,
                    status="success",
                ),
                BinarySecurityStageRun(
                    id="sr-sa",
                    task_id="task1",
                    project_id="p1",
                    stage_name="system_analysis",
                    sequence_no=2,
                    status="success",
                ),
            ]

            class _ExecuteTaskDb(_ModelAwareDb):
                def __init__(self, current_task, current_stage_run):
                    super().__init__(tasks=[current_task], stage_runs=[*prev_runs, current_stage_run])
                    self.closed = False

                def refresh(self, obj):
                    del obj

                def close(self):
                    self.closed = True

            db = _ExecuteTaskDb(task, stage_run)
            original_factory = task_manager_module.get_session_factory
            original_handler = self.manager._stage_binary_to_source
            original_counts = self.manager._stage_counts
            original_persist = self.manager._persist_stage_run_output_summary_async
            original_write_meta = self.manager._write_task_metadata_async

            async def fake_stage_handler(db_arg, task_arg, stage_run_arg, token, retry_existing):
                del db_arg, task_arg, stage_run_arg, token, retry_existing
                return "failed", {"error": "无法连接下游服务: [Errno -2] Name or service not known"}

            async def fake_persist(task_arg, stage_run_arg, payload):
                del task_arg, stage_run_arg
                return payload

            async def fake_write_meta(task_arg, path, status=None):
                del task_arg, path, status

            task_manager_module.get_session_factory = lambda: (lambda: db)
            self.manager._stage_binary_to_source = fake_stage_handler
            self.manager._stage_counts = lambda db_arg, stage_run_arg: {}
            self.manager._persist_stage_run_output_summary_async = fake_persist
            self.manager._write_task_metadata_async = fake_write_meta
            try:
                asyncio.run(self.manager._execute_task("task1"))
            finally:
                task_manager_module.get_session_factory = original_factory
                self.manager._stage_binary_to_source = original_handler
                self.manager._stage_counts = original_counts
                self.manager._persist_stage_run_output_summary_async = original_persist
                self.manager._write_task_metadata_async = original_write_meta

            event_types = [event.event_type for event in db.added if isinstance(event, BinarySecurityEvent)]
            self.assertIn("stage_worker_terminal_observed", event_types)
            self.assertNotIn("task_requeued_after_stage_completion", event_types)
            self.assertTrue(db.closed)

    def test_run_stage_pool_retries_existing_path_after_first_failure(self):
        calls: list[bool] = []

        async def runner(item, retrying=False):
            del item
            calls.append(bool(retrying))
            if len(calls) < 3:
                return {"status": "failed"}
            return {"status": "success"}

        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )

        original_is_cancelled = self.manager._is_task_cancelled
        self.manager._is_task_cancelled = lambda task_id: False
        results = asyncio.run(self.manager._run_stage_pool(task, [{"id": 1}], 1, runner, retries=2))
        self.manager._is_task_cancelled = original_is_cancelled

        self.assertEqual("success", results[0]["status"])
        self.assertEqual([False, True, True], calls)

    def test_run_stage_pool_stops_when_execution_token_is_invalidated(self):
        async def runner(item, retrying=False):
            del item, retrying
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            return {"status": "success"}

        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id=self.manager.instance_id,
            dispatch_started_at=_now(),
        )
        self.manager._bind_execution_token(task)
        db = _ModelAwareDb(tasks=[task])
        original_factory = task_manager_module.get_session_factory
        original_is_cancelled = self.manager._is_task_cancelled
        task_manager_module.get_session_factory = lambda: (lambda: db)
        self.manager._is_task_cancelled = lambda task_id: False
        try:
            with self.assertRaises(task_manager_module.StaleTaskExecution):
                asyncio.run(self.manager._run_stage_pool(task, [{"id": 1}], 1, runner))
        finally:
            task_manager_module.get_session_factory = original_factory
            self.manager._is_task_cancelled = original_is_cancelled

    def test_run_stage_pool_respects_concurrency_limit_for_retry_mode(self):
        active = 0
        max_active = 0

        async def runner(item, retrying=False):
            nonlocal active, max_active
            self.assertTrue(retrying)
            active += 1
            max_active = max(max_active, active)
            await asyncio.sleep(0.01)
            active -= 1
            return {"status": "success", "item": item}

        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )

        original_is_cancelled = self.manager._is_task_cancelled
        self.manager._is_task_cancelled = lambda task_id: False
        try:
            results = asyncio.run(
                self.manager._run_stage_pool(
                    task,
                    [{"id": idx} for idx in range(6)],
                    2,
                    runner,
                    initial_retry=True,
                )
            )
        finally:
            self.manager._is_task_cancelled = original_is_cancelled

        self.assertEqual(6, len(results))
        self.assertEqual(2, max_active)

    def test_run_system_analysis_item_reuses_existing_active_downstream_task(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="task1",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=1,
            status="running",
        )
        existing_item = BinarySecurityStageItem(
            id="i1",
            task_id="task1",
            project_id="p1",
            stage_run_id="sr0",
            stage_name="system_analysis",
            item_key="source_project",
            item_name="source-project",
            parent_key="source_project",
            downstream_service="system_analyse",
            downstream_task_id="sat_existing",
            status="running",
        )

        class _SessionDb(_ModelAwareDb):
            def __init__(self):
                super().__init__(tasks=[task], stage_runs=[stage_run], stage_items=[existing_item])
                self.commits = 0
                self.closed = False

            def commit(self):
                self.commits += 1

            def close(self):
                self.closed = True

        db = _SessionDb()
        firmware = {
            "firmware_key": "source_project",
            "firmware_name": "source",
            "filename": "source-project",
            "unpacked_root": "/w/input",
            "source_root": "/w/input",
            "task_type": TASK_TYPE_SOURCE,
        }

        class _FakeSystemAnalyseClient:
            def __init__(self):
                self.create_calls = 0
                self.get_calls = 0
                self.list_calls = 0

            async def list_tasks(self, *args, **kwargs):
                self.list_calls += 1
                return {
                    "items": [
                        {
                            "task_id": "sat_existing",
                            "status": "running",
                            "parent_stage_item_id": "i1",
                            "updated_at": "2026-05-19T00:00:00",
                        }
                    ]
                }

            async def create_task(self, *args, **kwargs):
                self.create_calls += 1
                return {"task_id": "sat_new"}

            async def get_task(self, task_id):
                self.get_calls += 1
                if self.get_calls == 1:
                    return {"task_id": task_id, "status": "running"}
                return {"task_id": task_id, "status": "success"}

            async def get_task_result(self, task_id):
                return {"task_id": task_id}

        fake_client = _FakeSystemAnalyseClient()
        original_factory = task_manager_module.get_session_factory
        original_client = task_manager_module.get_system_analyse_client
        original_queue_archive = self.manager._queue_archive_and_wait
        original_parse_modules = self.manager._parse_system_analysis_modules
        original_is_cancelled = self.manager._is_task_cancelled
        task_manager_module.get_session_factory = lambda: (lambda: db)
        task_manager_module.get_system_analyse_client = lambda: fake_client
        self.manager._is_task_cancelled = lambda task_id: False

        async def fake_queue_archive_and_wait(session, task_arg, item_arg, payload, mapped_status, before_status):
            del session, task_arg, item_arg, payload, mapped_status, before_status
            return Path("/tmp/archive"), SimpleNamespace(error_message=None)

        self.manager._queue_archive_and_wait = fake_queue_archive_and_wait
        self.manager._parse_system_analysis_modules = lambda archive_root, firmware_arg, result_payload=None: []

        try:
            result = asyncio.run(self.manager._run_system_analysis_item(task, stage_run, firmware, retrying=False))
        finally:
            task_manager_module.get_session_factory = original_factory
            task_manager_module.get_system_analyse_client = original_client
            self.manager._queue_archive_and_wait = original_queue_archive
            self.manager._parse_system_analysis_modules = original_parse_modules
            self.manager._is_task_cancelled = original_is_cancelled

        self.assertEqual(0, fake_client.create_calls)
        self.assertEqual(0, fake_client.list_calls)
        self.assertEqual("sat_existing", existing_item.downstream_task_id)
        self.assertEqual("success", result["status"])

    def test_stage_item_supports_identity_key_field(self):
        item = BinarySecurityStageItem(
            id="i1",
            task_id="task1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="system_analysis",
            item_key="module1",
            item_identity_key="module1::root",
            status="pending",
        )

        self.assertEqual("module1::root", item.item_identity_key)

    def test_run_with_limits_respects_concurrency(self):
        active = 0
        max_active = 0

        async def worker(value):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            await asyncio.sleep(0.01)
            active -= 1
            return value * 2

        results = asyncio.run(
            self.manager._run_with_limits(
                [1, 2, 3, 4],
                worker,
                concurrency=2,
                timeout_seconds=1,
            )
        )

        self.assertEqual(2, max_active)
        self.assertEqual([(1, 2, None), (2, 4, None), (3, 6, None), (4, 8, None)], results)

    def test_run_with_limits_captures_timeout(self):
        async def worker(value):
            await asyncio.sleep(0.05)
            return value

        results = asyncio.run(
            self.manager._run_with_limits(
                [1],
                worker,
                concurrency=1,
                timeout_seconds=0.01,
            )
        )

        self.assertEqual(1, len(results))
        row, payload, exc = results[0]
        self.assertEqual(1, row)
        self.assertIsNone(payload)
        self.assertIsInstance(exc, TimeoutError)

    def test_list_artifact_page_returns_paged_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(5):
                path = root / f"dir-{index}" / f"file-{index}.txt"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"payload-{index}", encoding="utf-8")

            page = self.manager._list_artifact_page(root, limit=2, offset=1)

        self.assertEqual(5, page["total"])
        self.assertEqual(2, page["limit"])
        self.assertEqual(1, page["offset"])
        self.assertTrue(page["has_more"])
        self.assertEqual(
            ["dir-1/file-1.txt", "dir-2/file-2.txt"],
            [entry["path"] for entry in page["files"]],
        )

    def test_get_artifacts_prefers_b2s_artifact_index_groups_when_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            artifact_index = workspace / "output" / "binary_to_source" / "openssl" / "artifacts" / "index.json"
            artifact_index.parent.mkdir(parents=True, exist_ok=True)
            artifact_index.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "artifacts": [
                            {
                                "relative_path": "main.c",
                                "kind": "c",
                                "size": 123,
                                "stage": "输出产物",
                                "section": "文件",
                                "batch_no": None,
                                "attempt_no": None,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_BINARY,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
                summary={
                    "b2s_results": [
                        {
                            "module_key": "openssl",
                            "module_name": "OpenSSL",
                            "source_root": str(workspace / "output" / "binary_to_source" / "openssl"),
                            "primary_result_kind": "recovered_source",
                            "result_kinds": ["recovered_source"],
                            "artifact_kind_summary": {"c": 1},
                            "result_kind_summary": {"recovered_source": 1},
                            "artifact_index_path": str(artifact_index),
                            "result_summary_version": 1,
                        }
                    ]
                },
            )
            db = _ModelAwareDb(tasks=[task])

            response = self.manager.get_artifacts(db, project_id="p1", task_id="t1")

        self.assertTrue(response.grouped_by_index)
        self.assertEqual(1, len(response.artifact_groups))
        self.assertEqual("openssl", response.artifact_groups[0].module_key)
        self.assertEqual("main.c", response.artifact_groups[0].artifacts[0].relative_path)

    def test_safe_extract_archive_rejects_excessive_file_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = TaskManager()
            manager.cfg.storage.max_source_extract_files = 1
            archive_path = Path(tmp) / "source.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("a.txt", "a")
                archive.writestr("b.txt", "b")
            with self.assertRaises(ValidationError):
                manager._safe_extract_archive(archive_path, Path(tmp) / "out")

    def test_validate_uploaded_archive_size_rejects_oversized_source_archive(self):
        manager = TaskManager()
        manager.cfg.storage.max_upload_file_bytes = 10
        manager.cfg.storage.max_source_archive_bytes = 8
        with self.assertRaises(ValidationError):
            manager._validate_uploaded_archive_size("archive.zip", 11, source_task=True)

    def test_service_config_includes_lease_timeout_default(self):
        payload = BinarySecurityServiceConfigPayload()
        self.assertEqual(90, payload.lease_timeout_seconds)

    def test_project_config_includes_partial_success_stage_advancement_defaults(self):
        payload = BinarySecurityProjectConfigPayload()
        self.assertEqual(
            {
                "binary_to_source": False,
                "entry_analysis": False,
                "dataflow_analysis": False,
            },
            payload.partial_success_stage_advancement,
        )

    def test_save_project_config_normalizes_pipeline_mode(self):
        row = BinarySecurityProjectConfig(project_id="p1")
        db = _FakeDb(rows=[row])

        response = self.manager.save_project_config(
            db,
            "p1",
            BinarySecurityProjectConfigPayload(pipeline_mode=" Mixed_Streaming "),
        )

        self.assertEqual("mixed_streaming", response.config.pipeline_mode)
        self.assertEqual("mixed_streaming", row.config["pipeline_mode"])

    def test_get_project_config_normalizes_legacy_pipeline_mode(self):
        row = BinarySecurityProjectConfig(project_id="p1")
        row.config = {
            "pipeline_mode": "legacy-mode",
            "partial_success_stage_advancement": {
                "binary_to_source": False,
                "entry_analysis": True,
                "dataflow_analysis": False,
            },
        }
        db = _FakeDb(rows=[row])

        response = self.manager.get_project_config(db, "p1")

        self.assertEqual("barrier", response.config.pipeline_mode)
        self.assertEqual(
            {
                "binary_to_source": False,
                "entry_analysis": True,
                "dataflow_analysis": False,
            },
            response.config.partial_success_stage_advancement,
        )

    def test_merge_policy_merges_partial_success_stage_advancement(self):
        row = BinarySecurityProjectConfig(project_id="p1")
        row.config = {
            "partial_success_stage_advancement": {
                "binary_to_source": False,
                "entry_analysis": True,
                "dataflow_analysis": False,
            }
        }
        policy = self.manager._merge_policy(
            _FakeDb(rows=[row]),
            "p1",
            {
                "task_type": TASK_TYPE_BINARY,
                "partial_success_stage_advancement": {
                    "entry_analysis": False,
                },
            },
            {},
        )

        self.assertEqual(
            {
                "binary_to_source": False,
                "entry_analysis": False,
                "dataflow_analysis": False,
            },
            policy["partial_success_stage_advancement"],
        )

    def test_merge_policy_prunes_binary_to_source_partial_success_advancement_for_source_tasks(self):
        row = BinarySecurityProjectConfig(project_id="p1")
        row.config = {
            "partial_success_stage_advancement": {
                "binary_to_source": False,
                "entry_analysis": True,
                "dataflow_analysis": False,
            }
        }
        policy = self.manager._merge_policy(
            _FakeDb(rows=[row]),
            "p1",
            {
                "task_type": TASK_TYPE_SOURCE,
            },
            {},
        )

        self.assertEqual(
            {
                "entry_analysis": True,
                "dataflow_analysis": False,
            },
            policy["partial_success_stage_advancement"],
        )

    def test_merge_policy_normalizes_legacy_project_pipeline_mode(self):
        self.manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        row = BinarySecurityProjectConfig(project_id="p1")
        row.config = {"pipeline_mode": "legacy-mode"}

        policy = self.manager._merge_policy(
            _FakeDb(rows=[row]),
            "p1",
            {"task_type": TASK_TYPE_SOURCE},
            {},
        )

        self.assertEqual("barrier", policy["pipeline_mode"])

    def test_merge_policy_pipeline_override_wins_over_project_config(self):
        row = BinarySecurityProjectConfig(project_id="p1")
        row.config = {"pipeline_mode": "barrier"}

        policy = self.manager._merge_policy(
            _FakeDb(rows=[row]),
            "p1",
            {"task_type": TASK_TYPE_SOURCE, "pipeline_mode": " Mixed_Streaming "},
            {},
        )

        self.assertEqual("mixed_streaming", policy["pipeline_mode"])

    def test_claim_pending_tasks_reclaims_expired_lease(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="n",
            status="pending",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/tmp/ws",
        )
        task.dispatcher_instance_id = "other-worker"
        task.dispatch_started_at = _now() - timedelta(minutes=10)
        task.lease_expires_at = _now() - timedelta(seconds=1)

        class _ClaimPendingDb(_ModelAwareDb):
            def query(self, model, *args, **kwargs):
                del args, kwargs
                model_name = getattr(model, "__name__", "")
                if model_name == "BinarySecurityTask":
                    return _FakeQuery([task])
                if getattr(model, "name", None) == "id":
                    return _FakeQuery([("t1",)])
                return _FakeQuery([])

        db = _ClaimPendingDb(tasks=[task])

        claimed = self.manager._claim_pending_tasks(db, 1)

        self.assertEqual([], claimed)
        self.assertEqual("other-worker", task.dispatcher_instance_id)
        self.assertLess(task.lease_expires_at, _now())

    def test_find_reusable_dataflow_payload_prefers_active_duplicate_task(self):
        task = BinarySecurityTask(id="t1", project_id="p1")
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            item_key="entry-1",
            downstream_service="dataflow_analyse",
            downstream_task_id="dfa-old",
            status="queued",
        )
        client = _AsyncDataflowClientStub(
            listed={
                "items": [
                    {"task_id": "dfa-passed", "status": "passed", "updated_at": "2026-05-18T23:32:56"},
                    {"task_id": "dfa-pending", "status": "pending", "updated_at": "2026-05-18T23:27:54"},
                    {"task_id": "dfa-running", "status": "running", "updated_at": "2026-05-18T23:34:41"},
                ]
            }
        )

        with patch.object(task_manager_module, "get_dataflow_analyse_client", return_value=client):
            payload = asyncio.run(self.manager._find_reusable_dataflow_payload(task, item))

        self.assertIsNotNone(payload)
        self.assertEqual("dfa-running", payload["task_id"])
        self.assertEqual("dfa-running", item.downstream_task_id)

    def test_find_reusable_dataflow_payload_prefers_success_over_newer_pending_duplicate(self):
        task = BinarySecurityTask(id="t1", project_id="p1")
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            item_key="entry-1",
            downstream_service="dataflow_analyse",
            downstream_task_id="dfa-old",
            status="queued",
        )
        client = _AsyncDataflowClientStub(
            listed={
                "items": [
                    {"task_id": "dfa-pending", "status": "pending", "updated_at": "2026-05-18T23:27:54"},
                    {"task_id": "dfa-passed", "status": "passed", "updated_at": "2026-05-18T23:20:00"},
                ]
            }
        )

        with patch.object(task_manager_module, "get_dataflow_analyse_client", return_value=client):
            payload = asyncio.run(self.manager._find_reusable_dataflow_payload(task, item))

        self.assertIsNotNone(payload)
        self.assertEqual("dfa-passed", payload["task_id"])
        self.assertEqual("dfa-passed", item.downstream_task_id)

    def test_find_reusable_system_analysis_payload_prefers_active_duplicate_task(self):
        task = BinarySecurityTask(id="t1", project_id="p1")
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="system_analysis",
            item_key="fw-1",
            downstream_service="system_analyse",
            downstream_task_id="sat-old",
            status="queued",
        )
        client = _AsyncSystemAnalyseClientStub(
            listed={
                "items": [
                    {"task_id": "sat-passed", "status": "passed", "item_key": "fw-1", "updated_at": "2026-05-18T23:32:56"},
                    {"task_id": "sat-pending", "status": "pending", "item_key": "fw-1", "updated_at": "2026-05-18T23:27:54"},
                    {"task_id": "sat-running", "status": "running", "parent_stage_item_id": "si1", "updated_at": "2026-05-18T23:34:41"},
                ]
            }
        )

        with patch.object(task_manager_module, "get_system_analyse_client", return_value=client):
            payload = asyncio.run(self.manager._find_reusable_system_analysis_payload(task, item))

        self.assertIsNotNone(payload)
        self.assertEqual("sat-running", payload["task_id"])
        self.assertEqual("sat-running", item.downstream_task_id)

    def test_find_reusable_b2s_payload_prefers_active_duplicate_task(self):
        task = BinarySecurityTask(id="t1", project_id="p1")
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="binary_to_source",
            item_key="module-1",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-old",
            status="queued",
        )
        client = _AsyncBinaryToSourceClientStub(
            listed={
                "items": [
                    {"id": "b2s-passed", "status": "success", "parent_stage_item_id": "si1", "updated_at": "2026-05-18T23:32:56"},
                    {"id": "b2s-running", "status": "running", "parent_stage_item_id": "si1", "updated_at": "2026-05-18T23:34:41"},
                    {"id": "b2s-other", "status": "running", "parent_stage_item_id": "si2", "updated_at": "2026-05-18T23:40:00"},
                ]
            }
        )

        with patch.object(task_manager_module, "get_binary_to_source_client", return_value=client):
            payload = asyncio.run(self.manager._find_reusable_b2s_payload(task, item, "tok"))

        self.assertIsNotNone(payload)
        self.assertEqual("b2s-running", payload["id"])
        self.assertEqual("b2s-running", item.downstream_task_id)

    def test_find_reusable_entry_payload_prefers_active_duplicate_task(self):
        task = BinarySecurityTask(id="t1", project_id="p1")
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="module-1",
            downstream_service="entry_analyse",
            downstream_task_id="eat-old",
            status="queued",
        )
        client = _AsyncEntryAnalyseClientStub(
            listed={
                "items": [
                    {"task_id": "eat-passed", "status": "passed", "parent_stage_item_id": "si1", "updated_at": "2026-05-18T23:32:56"},
                    {"task_id": "eat-running", "status": "running", "parent_stage_item_id": "si1", "updated_at": "2026-05-18T23:34:41"},
                ]
            }
        )

        with patch.object(task_manager_module, "get_entry_analyse_client", return_value=client):
            payload = asyncio.run(self.manager._find_reusable_entry_payload(task, item, "tok"))

        self.assertIsNotNone(payload)
        self.assertEqual("eat-running", payload["task_id"])
        self.assertEqual("eat-running", item.downstream_task_id)

    def test_find_reusable_firmware_unpack_payload_prefers_active_duplicate_task(self):
        task = BinarySecurityTask(id="t1", project_id="p1")
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="firmware_unpack",
            item_key="fw-1",
            downstream_service="firmware_unpacker",
            downstream_task_id="fu-old",
            status="queued",
        )
        client = _AsyncFirmwareUnpackerClientStub(
            listed={
                "items": [
                    {"task_id": "fu-passed", "status": "success", "parent_task_id": "t1", "parent_stage_item_id": "si1", "updated_at": "2026-05-18T23:32:56"},
                    {"task_id": "fu-running", "status": "running", "parent_task_id": "t1", "parent_stage_item_id": "si1", "updated_at": "2026-05-18T23:34:41"},
                ]
            }
        )

        with patch.object(task_manager_module, "get_firmware_unpacker_client", return_value=client):
            payload = asyncio.run(self.manager._find_reusable_firmware_unpack_payload(task, item, "tok"))

        self.assertIsNotNone(payload)
        self.assertEqual("fu-running", payload["task_id"])
        self.assertEqual("fu-running", item.downstream_task_id)

    def test_find_reusable_vuln_payload_prefers_active_duplicate_task(self):
        task = BinarySecurityTask(id="t1", project_id="p1")
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="vuln_scan",
            item_key="entry-1",
            downstream_service="dataflow_vuln_scanner",
            downstream_task_id="dfvs-old",
            status="queued",
        )
        client = _AsyncDataflowVulnScannerClientStub(
            listed=[
                {"task_id": "dfvs-passed", "status": "completed", "parent_task_id": "t1", "parent_stage_item_id": "si1"},
                {"task_id": "dfvs-running", "status": "running", "parent_task_id": "t1", "parent_stage_item_id": "si1"},
            ]
        )

        with patch.object(task_manager_module, "get_dataflow_vuln_scanner_client", return_value=client):
            payload = asyncio.run(self.manager._find_reusable_vuln_payload(task, item, "tok"))

        self.assertIsNotNone(payload)
        self.assertEqual("dfvs-running", payload["task_id"])
        self.assertEqual("dfvs-running", item.downstream_task_id)

    def test_duplicate_downstream_refs_for_item_skips_kept_task_id(self):
        task = BinarySecurityTask(id="t1", project_id="p1")
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="module-1",
            downstream_service="entry_analyse",
            downstream_task_id="eat-keep",
            status="running",
        )
        client = _AsyncEntryAnalyseClientStub(
            listed={
                "items": [
                    {"task_id": "eat-keep", "status": "running", "parent_stage_item_id": "si1"},
                    {"task_id": "eat-old-1", "status": "failed", "parent_stage_item_id": "si1"},
                    {"task_id": "eat-old-2", "status": "cancelled", "parent_stage_item_id": "si1"},
                ]
            }
        )

        with patch.object(task_manager_module, "get_entry_analyse_client", return_value=client):
            refs = asyncio.run(
                self.manager._duplicate_downstream_refs_for_item(
                    task,
                    item,
                    "tok",
                    keep_task_ids={"eat-keep"},
                )
            )

        self.assertEqual(
            [
                {"service": "entry_analyse", "task_id": "eat-old-1", "project_id": "p1", "stage_name": "entry_analysis"},
                {"service": "entry_analyse", "task_id": "eat-old-2", "project_id": "p1", "stage_name": "entry_analysis"},
            ],
            refs,
        )

    def test_run_b2s_item_reuses_active_downstream_task_instead_of_creating_new_one(self):
        task = BinarySecurityTask(
            id="t1",
            name="source-task",
            project_id="p1",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw",
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="binary_to_source",
            sequence_no=2,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="binary_to_source",
            item_key="module-1",
            item_name="mod.so",
            parent_key="fw-1",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-live",
            status="running",
        )
        module = {
            "module_key": "module-1",
            "module_name": "mod.so",
            "firmware_key": "fw-1",
        }
        fake_session = _ModelAwareDb(stage_items=[item])
        client = _AsyncBinaryToSourceClientStub(fail_on_create=True)

        async def fake_poll(*args, **kwargs):
            del args, kwargs
            return "success", {"id": "b2s-live", "status": "success", "items": []}

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(task_manager_module, "get_binary_to_source_client", return_value=client),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(self.manager, "_build_module_elf_tasks", return_value=[{"elf_path": "/tmp/mod.so", "file_list": []}]),
            patch.object(self.manager, "_active_downstream_payload", return_value={"id": "b2s-live", "status": "running"}),
            patch.object(self.manager, "_poll_until_terminal", side_effect=fake_poll),
            patch.object(self.manager, "_queue_archive_and_wait", return_value=(Path("/tmp"), None)),
            patch.object(self.manager, "_lightweight_downstream_payload", side_effect=lambda payload: {"status": payload.get("status")}),
            patch.object(self.manager, "_compact_result_for_storage", side_effect=lambda stage_name, result: result),
        ):
            result = asyncio.run(self.manager._run_b2s_item(task, stage_run, module, token="tok", retrying=False))

        self.assertEqual("b2s-live", item.downstream_task_id)
        self.assertEqual(0, client.created)
        self.assertEqual("success", result["status"])

    def test_run_b2s_item_reuses_active_duplicate_before_creating_new_one(self):
        task = BinarySecurityTask(id="t1", name="source-task", project_id="p1", workspace_root="/tmp/ws")
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="binary_to_source",
            sequence_no=2,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="binary_to_source",
            item_key="module-1",
            item_name="mod.so",
            parent_key="fw-1",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-stale-ref",
            status="running",
        )
        module = {
            "module_key": "module-1",
            "module_name": "mod.so",
            "firmware_key": "fw-1",
        }
        fake_session = _ModelAwareDb(stage_items=[item])
        client = _AsyncBinaryToSourceClientStub(fail_on_create=True)

        async def fake_poll(*args, **kwargs):
            del args, kwargs
            return "success", {"id": "b2s-dup-live", "status": "success", "items": []}

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(task_manager_module, "get_binary_to_source_client", return_value=client),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(self.manager, "_build_module_elf_tasks", return_value=[{"elf_path": "/tmp/mod.so", "file_list": []}]),
            patch.object(self.manager, "_active_downstream_payload", return_value=None),
            patch.object(self.manager, "_find_reusable_b2s_payload", return_value={"id": "b2s-dup-live", "status": "running"}),
            patch.object(self.manager, "_poll_until_terminal", side_effect=fake_poll),
            patch.object(self.manager, "_queue_archive_and_wait", return_value=(Path("/tmp"), None)),
            patch.object(self.manager, "_lightweight_downstream_payload", side_effect=lambda payload: {"status": payload.get("status")}),
            patch.object(self.manager, "_compact_result_for_storage", side_effect=lambda stage_name, result: result),
        ):
            result = asyncio.run(self.manager._run_b2s_item(task, stage_run, module, token="tok", retrying=False))

        self.assertEqual(0, client.created)
        self.assertEqual("success", result["status"])

    def test_run_b2s_item_treats_completed_status_as_success(self):
        task = BinarySecurityTask(id="t1", name="source-task", project_id="p1", workspace_root="/tmp/ws")
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="binary_to_source",
            sequence_no=2,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="binary_to_source",
            item_key="module-1",
            item_name="mod.so",
            parent_key="fw-1",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-live",
            status="running",
        )
        module = {
            "module_key": "module-1",
            "module_name": "mod.so",
            "firmware_key": "fw-1",
        }
        fake_session = _ModelAwareDb(stage_items=[item])
        client = _AsyncBinaryToSourceClientStub(fail_on_create=True)
        poll_kwargs = {}

        async def fake_poll(*args, **kwargs):
            del args
            poll_kwargs.update(kwargs)
            return "success", {"id": "b2s-live", "status": "completed", "items": []}

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(task_manager_module, "get_binary_to_source_client", return_value=client),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(self.manager, "_build_module_elf_tasks", return_value=[{"elf_path": "/tmp/mod.so", "file_list": []}]),
            patch.object(self.manager, "_active_downstream_payload", return_value={"id": "b2s-live", "status": "running"}),
            patch.object(self.manager, "_poll_until_terminal", side_effect=fake_poll),
            patch.object(self.manager, "_queue_archive_and_wait", return_value=(Path("/tmp"), None)),
            patch.object(self.manager, "_lightweight_downstream_payload", side_effect=lambda payload: {"status": payload.get("status")}),
            patch.object(self.manager, "_compact_result_for_storage", side_effect=lambda stage_name, result: result),
        ):
            result = asyncio.run(self.manager._run_b2s_item(task, stage_run, module, token="tok", retrying=False))

        self.assertIn("completed", poll_kwargs["success_statuses"])
        self.assertEqual("success", result["status"])
        self.assertEqual("success", item.status)

    def test_run_b2s_item_seeds_entry_item_when_streaming_mode_enabled(self):
        task = BinarySecurityTask(
            id="t1",
            name="source-task",
            project_id="p1",
            workspace_root="/tmp/ws",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="binary_to_source",
            sequence_no=2,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="binary_to_source",
            item_key="module-1",
            item_name="mod.so",
            parent_key="fw-1",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-live",
            status="running",
        )
        module = {
            "module_key": "module-1",
            "module_name": "mod.so",
            "firmware_key": "fw-1",
        }
        fake_session = _ModelAwareDb(stage_items=[item])
        client = _AsyncBinaryToSourceClientStub(fail_on_create=True)
        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(task_manager_module, "get_binary_to_source_client", return_value=client),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(self.manager, "_build_module_elf_tasks", return_value=[{"elf_path": "/tmp/mod.so", "file_list": []}]),
            patch.object(self.manager, "_active_downstream_payload", return_value={"id": "b2s-live", "status": "running"}),
            patch.object(self.manager, "_poll_until_terminal", return_value=("success", {"id": "b2s-live", "status": "completed", "items": []})),
            patch.object(self.manager, "_queue_archive_and_wait", return_value=(Path("/tmp"), None)),
            patch.object(self.manager, "_lightweight_downstream_payload", side_effect=lambda payload: {"status": payload.get("status")}),
            patch.object(self.manager, "_compact_result_for_storage", side_effect=lambda stage_name, result: result),
            patch.object(self.manager, "_streaming_mode_enabled", return_value=True),
            patch.object(self.manager, "_trigger_entry_items_from_b2s_result") as trigger_mock,
        ):
            result = asyncio.run(self.manager._run_b2s_item(task, stage_run, module, token="tok", retrying=False))

        self.assertEqual("success", result["status"])
        trigger_mock.assert_called_once()
        call_args = trigger_mock.call_args
        self.assertIs(fake_session, call_args.args[0])
        self.assertIs(task, call_args.args[1])
        self.assertEqual("module-1", call_args.args[2]["module_key"])
        self.assertIs(item, call_args.kwargs["upstream_item"])

    def test_run_dataflow_item_retry_path_polls_after_restart(self):
        task = BinarySecurityTask(id="t1", name="source-task", project_id="p1", workspace_root="/tmp/ws")
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            sequence_no=3,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            item_key="entry-1",
            item_name="entry-1",
            parent_key="module-1",
            downstream_service="dataflow_analyse",
            downstream_task_id="dfa-old",
            status="failed",
            output_ref={},
        )
        entry = {
            "entry_key": "entry-1",
            "function_name": "main",
            "module_name": "module-1",
            "source_dir": "/tmp/src",
            "source_file": "main.c",
            "file_name": "main.c",
            "module_key": "module-1",
            "module_input_path": "/tmp/repo/modules/module-1",
            "source_root_path": "/tmp/repo/src",
            "is_definition_found": True,
            "definition_kind": "definition",
            "definition_file": "main.c",
            "definition_line": "10",
            "taint_params": ["argv"],
        }
        fake_session = _ModelAwareDb()

        async def fake_control(*args, **kwargs):
            del args, kwargs
            return {"outcome": "accepted", "payload": {"task_id": "dfa-retried"}}

        async def fake_poll(*args, **kwargs):
            del args, kwargs
            return "failed", {"task_id": "dfa-retried", "status": "error", "error": "boom"}

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(self.manager, "_find_reusable_dataflow_payload", return_value=None),
            patch.object(self.manager, "_control_existing_downstream_task", side_effect=fake_control),
            patch.object(self.manager, "_poll_until_terminal", side_effect=fake_poll),
            patch.object(self.manager, "_service_output_dir", return_value=Path("/tmp")),
            patch.object(self.manager, "_materialize_stage_artifact", return_value=Path("/tmp")),
            patch.object(self.manager, "_find_first", return_value=None),
            patch.object(self.manager, "_queue_archive_and_wait", return_value=(Path("/tmp"), None)),
            patch.object(self.manager, "_lightweight_downstream_payload", side_effect=lambda payload: {"status": payload.get("status")}),
            patch.object(self.manager, "_normalize_dfa_source_file", return_value="main.c"),
        ):
            result = asyncio.run(self.manager._run_dataflow_item(task, stage_run, entry, token=None, retrying=True))

        self.assertEqual("dfa-retried", item.downstream_task_id)
        self.assertEqual("failed", result["status"])
        self.assertEqual("boom", result["error"])

    def test_run_dataflow_item_seeds_vuln_item_when_streaming_mode_enabled(self):
        task = BinarySecurityTask(
            id="t1",
            name="source-task",
            project_id="p1",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            sequence_no=3,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            item_key="entry-1",
            item_name="main",
            parent_key="module-1",
            downstream_service="dataflow_analyse",
            downstream_task_id="dfa-live",
            status="running",
            output_ref={},
        )
        entry = {
            "entry_key": "entry-1",
            "function_name": "main",
            "module_name": "module-1",
            "source_dir": "/tmp/src",
            "source_file": "main.c",
            "file_name": "main.c",
            "module_key": "module-1",
            "module_input_path": "/tmp/repo/modules/module-1",
            "source_root_path": "/tmp/repo/src",
            "is_definition_found": True,
            "definition_kind": "definition",
            "definition_file": "main.c",
            "definition_line": "10",
            "taint_params": ["argv"],
        }
        fake_session = _ModelAwareDb()

        async def fake_create_task(*args, **kwargs):
            del args, kwargs
            return {"task_id": "dfa-live"}

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(self.manager, "_find_reusable_dataflow_payload", return_value=None),
            patch.object(task_manager_module, "get_dataflow_analyse_client", return_value=SimpleNamespace(create_task=fake_create_task, get_task=lambda *args, **kwargs: None)),
            patch.object(self.manager, "_poll_until_terminal", return_value=("success", {"task_id": "dfa-live", "status": "passed"})),
            patch.object(self.manager, "_service_output_dir", return_value=Path("/tmp")),
            patch.object(self.manager, "_materialize_stage_artifact", return_value=Path("/tmp")),
            patch.object(self.manager, "_find_first", return_value=Path("/tmp/dataflow.md")),
            patch.object(self.manager, "_queue_archive_and_wait", return_value=(Path("/tmp"), None)),
            patch.object(self.manager, "_lightweight_downstream_payload", side_effect=lambda payload: {"status": payload.get("status")}),
            patch.object(self.manager, "_compact_result_for_storage", side_effect=lambda stage_name, result: result),
            patch.object(self.manager, "_normalize_dfa_source_file", return_value="main.c"),
            patch.object(self.manager, "_streaming_mode_enabled", return_value=True),
            patch.object(self.manager, "_trigger_vuln_items_from_dataflow_result") as trigger_mock,
        ):
            result = asyncio.run(self.manager._run_dataflow_item(task, stage_run, entry, token=None, retrying=False))

        self.assertEqual("success", result["status"])
        trigger_mock.assert_called_once()
        call_args = trigger_mock.call_args
        self.assertIs(fake_session, call_args.args[0])
        self.assertIs(task, call_args.args[1])
        self.assertEqual("entry-1", call_args.args[2]["entry_key"])
        self.assertTrue(call_args.args[2]["data_flow_file"].endswith("dataflow.md"))
        self.assertEqual("/tmp/repo/modules/module-1", call_args.args[2]["module_input_path"])
        self.assertEqual("/tmp/repo/src", call_args.args[2]["source_root_path"])
        self.assertEqual("main.c", call_args.args[2]["source_file"])
        self.assertIs(item, call_args.kwargs["upstream_item"])
        self.assertEqual("/tmp/repo/modules/module-1", item.output_ref["module_input_path"])
        self.assertEqual("/tmp/repo/src", item.output_ref["source_root_path"])
        self.assertEqual("main.c", item.output_ref["source_file"])

    def test_run_dataflow_item_reusable_payload_keeps_token_available_for_cleanup(self):
        task = BinarySecurityTask(id="t1", name="source-task", project_id="p1", workspace_root="/tmp/ws")
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            sequence_no=3,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            item_key="entry-1",
            item_name="main",
            parent_key="module-1",
            downstream_service="dataflow_analyse",
            downstream_task_id="dfa-live",
            status="pending",
            output_ref={},
        )
        entry = {
            "entry_key": "entry-1",
            "function_name": "main",
            "module_name": "module-1",
            "source_dir": "/tmp/src",
            "source_file": "main.c",
            "file_name": "main.c",
            "module_key": "module-1",
            "module_input_path": "/tmp/repo/modules/module-1",
            "source_root_path": "/tmp/repo/src",
            "is_definition_found": True,
            "definition_kind": "definition",
            "definition_file": "main.c",
            "definition_line": "10",
            "taint_params": ["argv"],
        }
        fake_session = _ModelAwareDb()
        cleanup_calls: list[dict[str, object]] = []

        async def fake_cleanup(*args, **kwargs):
            cleanup_calls.append({
                "args": args,
                "kwargs": kwargs,
            })

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(self.manager, "_find_reusable_dataflow_payload", return_value={"task_id": "dfa-live", "status": "running"}),
            patch.object(self.manager, "_cleanup_duplicate_downstream_refs_for_item", side_effect=fake_cleanup),
            patch.object(self.manager, "_poll_until_terminal", return_value=("success", {"task_id": "dfa-live", "status": "passed"})),
            patch.object(self.manager, "_service_output_dir", return_value=Path("/tmp")),
            patch.object(self.manager, "_materialize_stage_artifact", return_value=Path("/tmp")),
            patch.object(self.manager, "_find_first", return_value=Path("/tmp/dataflow.md")),
            patch.object(self.manager, "_queue_archive_and_wait", return_value=(Path("/tmp"), None)),
            patch.object(self.manager, "_lightweight_downstream_payload", side_effect=lambda payload: {"status": payload.get("status")}),
            patch.object(self.manager, "_compact_result_for_storage", side_effect=lambda stage_name, result: result),
            patch.object(self.manager, "_normalize_dfa_source_file", return_value="main.c"),
        ):
            result = asyncio.run(self.manager._run_dataflow_item(task, stage_run, entry, token="tok", retrying=False))

        self.assertEqual("success", result["status"])
        self.assertEqual(1, len(cleanup_calls))
        self.assertEqual("tok", cleanup_calls[0]["args"][3])

    def test_run_dataflow_item_falls_back_to_definition_parent_when_source_dir_missing(self):
        task = BinarySecurityTask(id="t1", name="source-task", project_id="p1", workspace_root="/tmp/ws")
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            sequence_no=3,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            item_key="entry-1",
            item_name="main",
            parent_key="module-1",
            downstream_service="dataflow_analyse",
            status="pending",
            output_ref={},
        )
        entry = {
            "entry_key": "entry-1",
            "function_name": "main",
            "file_name": "main.c",
            "module_key": "module-1",
            "module_name": "module-1",
            "source_dir": "/tmp/repo/src",
            "is_definition_found": True,
            "definition_kind": "definition",
            "definition_file": "/tmp/repo/src/main.c",
            "definition_line": "10",
            "taint_params": ["argv"],
            "module_input_path": "/tmp/repo/modules/module-1",
            "source_root_path": "/tmp/repo/src",
        }
        fake_session = _ModelAwareDb()
        create_calls: list[dict[str, str]] = []

        async def fake_create_task(project_id, module_task_name, module_input_path, source_root_path, prompt, origin, **kwargs):
            create_calls.append(
                {
                    "project_id": project_id,
                    "task_name": module_task_name,
                    "module_input_path": module_input_path,
                    "source_root_path": source_root_path,
                    "source_file": str(kwargs.get("source_file") or ""),
                }
            )
            return {"task_id": "dfa-live"}

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(self.manager, "_find_reusable_dataflow_payload", return_value=None),
            patch.object(task_manager_module, "get_dataflow_analyse_client", return_value=SimpleNamespace(create_task=fake_create_task, get_task=lambda *args, **kwargs: None)),
            patch.object(self.manager, "_poll_until_terminal", return_value=("success", {"task_id": "dfa-live", "status": "passed"})),
            patch.object(self.manager, "_service_output_dir", return_value=Path("/tmp")),
            patch.object(self.manager, "_materialize_stage_artifact", return_value=Path("/tmp")),
            patch.object(self.manager, "_find_first", return_value=Path("/tmp/dataflow.md")),
            patch.object(self.manager, "_queue_archive_and_wait", return_value=(Path("/tmp"), None)),
            patch.object(self.manager, "_lightweight_downstream_payload", side_effect=lambda payload: {"status": payload.get("status")}),
            patch.object(self.manager, "_compact_result_for_storage", side_effect=lambda stage_name, result: result),
            patch.object(self.manager, "_normalize_dfa_source_file", return_value="main.c"),
        ):
            result = asyncio.run(self.manager._run_dataflow_item(task, stage_run, entry, token=None, retrying=False))

        self.assertEqual("success", result["status"])
        self.assertEqual(1, len(create_calls))
        self.assertEqual("/tmp/repo/modules/module-1", create_calls[0]["module_input_path"])
        self.assertEqual("/tmp/repo/src", create_calls[0]["source_root_path"])
        self.assertEqual("main.c", create_calls[0]["source_file"])
        self.assertEqual("/tmp/repo/modules/module-1", item.output_ref["module_input_path"])
        self.assertEqual("/tmp/repo/src", item.output_ref["source_root_path"])
        self.assertEqual("main.c", item.output_ref["source_file"])
        self.assertEqual("/tmp", item.output_ref["data_flow_root"])
        self.assertEqual("/tmp/dataflow.md", item.output_ref["primary_report_path"])

    def test_run_dataflow_item_rejects_declaration_only_entries(self):
        task = BinarySecurityTask(id="t1", name="source-task", project_id="p1", workspace_root="/tmp/ws")
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            sequence_no=3,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            item_key="entry-1",
            item_name="PullImage",
            parent_key="module-1",
            downstream_service="dataflow_analyse",
            status="pending",
            output_ref={},
        )
        entry = {
            "entry_key": "entry-1",
            "function_name": "PullImage",
            "file_name": "demo.h",
            "module_key": "module-1",
            "module_name": "module-1",
            "source_dir": "/tmp/repo/src",
            "is_definition_found": True,
            "definition_kind": "declaration",
            "definition_file": "demo.h",
            "definition_line": "10",
            "taint_params": ["request"],
            "module_input_path": "/tmp/repo/modules/module-1",
            "source_root_path": "/tmp/repo/src",
        }
        fake_session = _ModelAwareDb()

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(self.manager, "_compact_result_for_storage", side_effect=lambda stage_name, result: result),
        ):
            result = asyncio.run(self.manager._run_dataflow_item(task, stage_run, entry, token=None, retrying=False))

        self.assertEqual("failed", result["status"])
        self.assertIn("声明", result["error"])

    def test_run_dataflow_item_rejects_incomplete_entry_contract(self):
        task = BinarySecurityTask(id="t1", name="source-task", project_id="p1", workspace_root="/tmp/ws")
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            sequence_no=3,
            status="running",
        )
        entry = {
            "entry_key": "entry-1",
            "function_name": "main",
            "module_key": "module-1",
            "module_name": "module-1",
            "definition_file": "main.c",
            "definition_line": "8",
            "definition_kind": "definition",
            "source_dir": "/tmp/src",
            "source_root_path": "/tmp/src",
        }
        fake_session = _ModelAwareDb()

        with patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session):
            result = asyncio.run(self.manager._run_dataflow_item(task, stage_run, entry, token=None, retrying=False))

        self.assertEqual("failed", result["status"])
        self.assertIn("module_input_path", result["error"])

    def test_run_entry_item_retry_running_conflict_polls_existing_downstream(self):
        task = BinarySecurityTask(
            id="t1",
            name="source-task",
            project_id="p1",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw",
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="module-1",
            item_name="mod",
            parent_key="fw-1",
            downstream_service="entry_analyse",
            downstream_task_id="ea-old",
            status="failed",
            output_ref={},
        )
        module = {
            "module_key": "module-1",
            "module_name": "mod",
            "firmware_key": "fw-1",
            "source_dir": "/tmp/src",
        }
        fake_session = _ModelAwareDb()
        polled = {"count": 0}

        async def fake_poll(*args, **kwargs):
            del args, kwargs
            polled["count"] += 1
            return "success", {"task_id": "ea-old", "status": "passed"}

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(
                self.manager,
                "_control_existing_downstream_task",
                return_value={"outcome": "already_running", "payload": {"task_id": "ea-old", "status": "running"}},
            ),
            patch.object(self.manager, "_poll_until_terminal", side_effect=fake_poll),
            patch.object(self.manager, "_materialize_stage_artifact", return_value=Path("/tmp")),
            patch.object(self.manager, "_parse_entries", return_value=[]),
            patch.object(self.manager, "_queue_archive_and_wait", return_value=(Path("/tmp"), None)),
            patch.object(self.manager, "_compact_result_for_storage", side_effect=lambda stage_name, result: result),
        ):
            result = asyncio.run(self.manager._run_entry_item(task, stage_run, module, token="tok", retrying=True))

        self.assertEqual(1, polled["count"])
        self.assertEqual("success", result["status"])
        self.assertEqual("success", item.status)
        self.assertIsNone(item.error_message)

    def test_run_entry_item_reuses_duplicate_downstream_task_before_create(self):
        task = BinarySecurityTask(
            id="t1",
            name="source-task",
            project_id="p1",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw",
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="module-1",
            item_name="mod",
            parent_key="fw-1",
            downstream_service="entry_analyse",
            downstream_task_id="ea-old",
            status="failed",
            output_ref={},
        )
        module = {
            "module_key": "module-1",
            "module_name": "mod",
            "firmware_key": "fw-1",
            "source_dir": "/tmp/src",
        }
        fake_session = _ModelAwareDb()
        client = _AsyncEntryAnalyseClientStub(fail_on_create=True)

        async def fake_poll(*args, **kwargs):
            del args, kwargs
            return "success", {"task_id": "ea-live", "status": "passed"}

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(task_manager_module, "get_entry_analyse_client", return_value=client),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(self.manager, "_active_downstream_payload", return_value=None),
            patch.object(self.manager, "_find_reusable_entry_payload", return_value={"task_id": "ea-live", "status": "running"}),
            patch.object(self.manager, "_poll_until_terminal", side_effect=fake_poll),
            patch.object(self.manager, "_materialize_stage_artifact", return_value=Path("/tmp")),
            patch.object(self.manager, "_parse_entries", return_value=[]),
            patch.object(self.manager, "_queue_archive_and_wait", return_value=(Path("/tmp"), None)),
            patch.object(self.manager, "_compact_result_for_storage", side_effect=lambda stage_name, result: result),
        ):
            result = asyncio.run(self.manager._run_entry_item(task, stage_run, module, token="tok", retrying=False))

        self.assertEqual("success", result["status"])
        self.assertEqual("ea-live", item.downstream_task_id)
        self.assertEqual("success", item.status)

    def test_run_firmware_item_reuses_duplicate_downstream_task_before_create(self):
        task = BinarySecurityTask(
            id="t1",
            name="fw-task",
            project_id="p1",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw",
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="firmware_unpack",
            sequence_no=1,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="firmware_unpack",
            item_key="fw-1",
            item_name="a.bin",
            parent_key="fw-1",
            downstream_service="firmware_unpacker",
            downstream_task_id="fu-old",
            status="failed",
            output_ref={"downstream_service": "firmware_unpacker"},
        )
        input_file = {"firmware_key": "fw-1", "filename": "a.bin"}
        fake_session = _ModelAwareDb()
        client = _AsyncFirmwareUnpackerClientStub(fail_on_create=True)

        async def fake_poll(*args, **kwargs):
            del args, kwargs
            return "success", {"task_id": "fu-live", "status": "success"}

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(task_manager_module, "get_firmware_unpacker_client", return_value=client),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(self.manager, "_active_downstream_payload", return_value=None),
            patch.object(self.manager, "_find_reusable_firmware_unpack_payload", return_value={"task_id": "fu-live", "status": "running"}),
            patch.object(self.manager, "_poll_until_terminal", side_effect=fake_poll),
            patch.object(self.manager, "_queue_archive_and_wait", return_value=(Path("/tmp"), None)),
            patch.object(self.manager, "_compact_result_for_storage", side_effect=lambda stage_name, result: result),
        ):
            result = asyncio.run(self.manager._run_firmware_item(task, stage_run, input_file, token="tok", retrying=False))

        self.assertEqual("success", result["status"])
        self.assertEqual("fu-live", item.downstream_task_id)
        self.assertEqual("success", item.status)

    def test_run_vuln_item_reuses_duplicate_downstream_task_before_create(self):
        task = BinarySecurityTask(
            id="t1",
            name="scan-task",
            project_id="p1",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw",
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="vuln_scan",
            sequence_no=4,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="vuln_scan",
            item_key="entry-1",
            item_name="main",
            parent_key="module-1",
            downstream_service="dataflow_vuln_scanner",
            downstream_task_id="dfvs-old",
            status="failed",
            output_ref={},
        )
        dataflow_result = {
            "entry_key": "entry-1",
            "function_name": "main",
            "module_key": "module-1",
            "data_flow_file": "/tmp/flow.md",
            "source_dir": "/tmp/src",
        }
        fake_session = _ModelAwareDb()
        client = _AsyncDataflowVulnScannerClientStub(fail_on_create=True)

        async def fake_poll(*args, **kwargs):
            del args, kwargs
            return "success", {"task_id": "dfvs-live", "status": "completed"}

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(task_manager_module, "get_dataflow_vuln_scanner_client", return_value=client),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(self.manager, "_active_downstream_payload", return_value=None),
            patch.object(self.manager, "_find_reusable_vuln_payload", return_value={"task_id": "dfvs-live", "status": "running"}),
            patch.object(self.manager, "_poll_until_terminal", side_effect=fake_poll),
            patch.object(self.manager, "_queue_archive_and_wait", return_value=(Path("/tmp"), None)),
        ):
            result = asyncio.run(self.manager._run_vuln_item(task, stage_run, dataflow_result, token="tok", retrying=False))

        self.assertEqual("success", result["status"])
        self.assertEqual("dfvs-live", item.downstream_task_id)
        self.assertEqual("success", item.status)

    def test_run_entry_item_uses_descriptor_contract_for_binary_module(self):
        task = BinarySecurityTask(
            id="t1",
            name="module-task",
            project_id="p1",
            task_type=TASK_TYPE_BINARY_MODULE,
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw",
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="module-1",
            item_name="IPSEC",
            parent_key="fw-1",
            downstream_service="entry_analyse",
            status="pending",
            output_ref={},
        )
        with tempfile.TemporaryDirectory() as tmp:
            artifact_root = Path(tmp)
            (artifact_root / "libipsec.c").write_text("int entry(void) { return 0; }\n", encoding="utf-8")
            module = {
                "module_key": "module-1",
                "module_name": "IPSEC",
                "firmware_key": "fw-1",
                "source_dir": str(artifact_root),
            }
            fake_session = _ModelAwareDb()
            create_calls: list[dict[str, str | None]] = []

            async def fake_create_task(project_id, task_name, input_path, module_name, token=None, source_path=None, origin=None):
                create_calls.append(
                    {
                        "project_id": project_id,
                        "task_name": task_name,
                        "input_path": input_path,
                        "module_name": module_name,
                        "token": token,
                        "source_path": source_path,
                        "entry_files_list": None if origin is None else origin.get("entry_files_list"),
                        "input_contract": None if origin is None else origin.get("input_contract"),
                    }
                )
                return {"task_id": "ea-new"}

            with (
                patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
                patch.object(self.manager, "_upsert_stage_item", return_value=item),
                patch.object(task_manager_module, "get_entry_analyse_client", return_value=SimpleNamespace(create_task=fake_create_task, get_task=lambda *args, **kwargs: None)),
                patch.object(self.manager, "_poll_until_terminal", return_value=("success", {"task_id": "ea-new", "status": "passed"})),
                patch.object(self.manager, "_materialize_stage_artifact", return_value=Path("/tmp")),
                patch.object(self.manager, "_parse_entries", return_value=[]),
                patch.object(self.manager, "_queue_archive_and_wait", return_value=(Path("/tmp"), None)),
                patch.object(self.manager, "_compact_result_for_storage", side_effect=lambda stage_name, result: result),
            ):
                result = asyncio.run(self.manager._run_entry_item(task, stage_run, module, token="tok", retrying=False))

        self.assertEqual("success", result["status"])
        self.assertEqual(1, len(create_calls))
        self.assertTrue(create_calls[0]["input_path"].endswith(str(Path("modules") / "IPSEC").replace("\\", "/")) or create_calls[0]["input_path"].endswith(str(artifact_root)))
        self.assertEqual("IPSEC", create_calls[0]["module_name"])
        self.assertEqual(str(artifact_root), create_calls[0]["source_path"])
        self.assertTrue(str(create_calls[0]["entry_files_list"]).endswith("modules/IPSEC/files.list"))
        self.assertEqual(create_calls[0]["input_path"], create_calls[0]["input_contract"]["module_dir"])
        self.assertEqual(str(artifact_root), create_calls[0]["input_contract"]["source_root"])
        self.assertTrue(str(create_calls[0]["input_contract"]["files_list_path"]).endswith("modules/IPSEC/files.list"))

    def test_run_entry_item_seeds_dataflow_items_when_streaming_mode_enabled(self):
        task = BinarySecurityTask(
            id="t1",
            name="source-task",
            project_id="p1",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="module-1",
            item_name="mod",
            parent_key="fw-1",
            downstream_service="entry_analyse",
            downstream_task_id="ea-live",
            status="running",
            output_ref={},
        )
        module = {
            "module_key": "module-1",
            "module_name": "mod",
            "firmware_key": "fw-1",
            "source_dir": "/tmp/source",
        }
        entries = [{"entry_key": "entry-1", "module_key": "module-1", "function_name": "handle_req", "file_name": "main.c"}]
        fake_session = _ModelAwareDb(stage_items=[item])

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(self.manager, "_active_downstream_payload", return_value={"id": "ea-live", "status": "running"}),
            patch.object(self.manager, "_poll_until_terminal", return_value=("success", {"task_id": "ea-live", "status": "passed"})),
            patch.object(self.manager, "_materialize_stage_artifact", return_value=Path("/tmp")),
            patch.object(self.manager, "_parse_entries", return_value=entries),
            patch.object(self.manager, "_queue_archive_and_wait", return_value=(Path("/tmp"), None)),
            patch.object(self.manager, "_compact_result_for_storage", side_effect=lambda stage_name, result: result),
            patch.object(self.manager, "_streaming_mode_enabled", return_value=True),
            patch.object(self.manager, "_trigger_dataflow_items_from_entry_result") as trigger_mock,
        ):
            result = asyncio.run(self.manager._run_entry_item(task, stage_run, module, token="tok", retrying=False))

        self.assertEqual("success", result["status"])
        trigger_mock.assert_called_once()
        call_args = trigger_mock.call_args
        self.assertIs(fake_session, call_args.args[0])
        self.assertIs(task, call_args.args[1])
        self.assertEqual(entries, call_args.args[2]["entries"])
        self.assertIs(item, call_args.kwargs["upstream_item"])

    def test_trigger_dataflow_items_from_entry_result_preserves_explicit_contract(self):
        task = BinarySecurityTask(
            id="t1",
            name="module-task",
            project_id="p1",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw",
            task_type=TASK_TYPE_BINARY_MODULE,
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        stage_run = BinarySecurityStageRun(
            id="sr-dfa",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            sequence_no=3,
            status="running",
        )
        upstream_item = BinarySecurityStageItem(
            id="si-entry",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="module-input",
            downstream_service="entry_analyse",
            status="success",
            result={
                "source_dir": "/archive/IPSEC",
                "source_root": "/archive/IPSEC",
                "source_root_path": "/archive/IPSEC",
                "module_input_path": "/archive/IPSEC/modules/IPSEC",
                "files_list_path": "/archive/IPSEC/modules/IPSEC/files.list",
                "entry_descriptor_root": "/archive/IPSEC",
                "entry_files_list": "/archive/IPSEC/modules/IPSEC/files.list",
                "descriptor_root": "/archive/IPSEC",
            },
        )
        entry_result = {
            "module_key": "IPSEC",
            "module_name": "IPSEC",
            "source_dir": ".",
            "entries": [
                {
                    "entry_key": "entry-1",
                    "module_key": "IPSEC",
                    "function_name": "handle",
                    "file_name": "libipsec.c",
                    "definition_file": "libipsec.c",
                    "definition_line": "10",
                    "is_definition_found": True,
                    "definition_kind": "definition",
                    "taint_params": ["ctx"],
                }
            ],
        }
        fake_session = _ModelAwareDb()
        seeded: list[dict[str, Any]] = []

        def fake_upsert(*args, **kwargs):
            seeded.append(dict(kwargs["input_ref"]))
            return BinarySecurityStageItem(
                id="si-dfa",
                task_id="t1",
                project_id="p1",
                stage_name="dataflow_analysis",
                item_key="entry-1",
                item_name="handle",
                parent_key="IPSEC",
                downstream_service="dataflow_analyse",
                status="pending",
                retry_count=0,
            )

        with (
            patch.object(self.manager, "_streaming_mode_enabled", return_value=True),
            patch.object(self.manager, "_streaming_tail_stage_names", return_value=("dataflow_analysis",)),
            patch.object(self.manager, "_ensure_stage_run", return_value=stage_run),
            patch.object(self.manager, "_find_stage_item", return_value=None),
            patch.object(self.manager, "_upsert_stage_item", side_effect=fake_upsert),
            patch.object(self.manager, "_record_event"),
        ):
            items = self.manager._trigger_dataflow_items_from_entry_result(
                fake_session,
                task,
                entry_result,
                upstream_item=upstream_item,
            )

        self.assertEqual(1, len(items))
        self.assertEqual("/archive/IPSEC/modules/IPSEC", seeded[0]["module_input_path"])
        self.assertEqual("/archive/IPSEC", seeded[0]["source_root_path"])
        self.assertEqual("/archive/IPSEC/modules/IPSEC/files.list", seeded[0]["files_list_path"])
        self.assertEqual("/archive/IPSEC/modules/IPSEC/files.list", seeded[0]["entry_files_list"])
        self.assertEqual("/archive/IPSEC", seeded[0]["entry_descriptor_root"])

    def test_trigger_dataflow_items_from_entry_result_refresh_does_not_increment_retry_count(self):
        task = BinarySecurityTask(
            id="t1",
            name="module-task",
            project_id="p1",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        stage_run = BinarySecurityStageRun(
            id="sr-dfa",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            sequence_no=3,
            status="running",
        )
        existing_item = BinarySecurityStageItem(
            id="si-dfa",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            item_key="entry-1",
            item_name="handle",
            parent_key="IPSEC",
            downstream_service="dataflow_analyse",
            status="queued",
            retry_count=144,
            input_ref={"module_input_path": "/archive/IPSEC/modules/IPSEC", "source_root_path": "/archive/IPSEC"},
        )
        upstream_item = BinarySecurityStageItem(
            id="si-entry",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="module-input",
            downstream_service="entry_analyse",
            status="success",
        )
        entry_result = {
            "entries": [
                {
                    "entry_key": "entry-1",
                    "module_key": "IPSEC",
                    "function_name": "handle",
                    "file_name": "libipsec.c",
                }
            ]
        }
        fake_session = _ModelAwareDb(stage_items=[existing_item])

        def fake_upsert(*args, **kwargs):
            self.assertFalse(kwargs["retrying"])
            return existing_item

        with (
            patch.object(self.manager, "_streaming_mode_enabled", return_value=True),
            patch.object(self.manager, "_streaming_tail_stage_names", return_value=("dataflow_analysis",)),
            patch.object(self.manager, "_ensure_stage_run", return_value=stage_run),
            patch.object(self.manager, "_find_stage_item", return_value=existing_item),
            patch.object(self.manager, "_upsert_stage_item", side_effect=fake_upsert),
            patch.object(self.manager, "_record_event"),
        ):
            self.manager._trigger_dataflow_items_from_entry_result(
                fake_session,
                task,
                entry_result,
                upstream_item=upstream_item,
            )

        self.assertEqual(144, existing_item.retry_count)

    def test_run_dataflow_item_recovers_missing_contract_from_entry_stage_result(self):
        task = BinarySecurityTask(
            id="t1",
            name="module-task",
            project_id="p1",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_path="/tmp/fw",
        )
        stage_run = BinarySecurityStageRun(
            id="sr-dfa",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            sequence_no=3,
            status="running",
        )
        entry_stage_item = BinarySecurityStageItem(
            id="si-entry",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="module-input",
            downstream_service="entry_analyse",
            status="success",
            input_ref={
                "module_key": "IPSEC",
                "module_name": "IPSEC",
                "module_input_path": "/archive/IPSEC/modules/IPSEC",
                "source_root_path": "/archive/IPSEC",
                "source_dir": "/archive/IPSEC",
                "entry_descriptor_root": "/archive/IPSEC",
                "entry_files_list": "/archive/IPSEC/modules/IPSEC/files.list",
            },
            result={
                "module_key": "IPSEC",
                "module_name": "IPSEC",
                "artifact_root": "/artifact/IPSEC",
                "entries_preview": [
                    {
                        "entry_key": "entry-1",
                        "module_key": "IPSEC",
                        "module_name": "IPSEC",
                        "function_name": "handle",
                        "file_name": "libipsec.c",
                        "definition_file": "libipsec.c",
                        "definition_line": "10",
                        "line_no": "10",
                        "definition_kind": "definition",
                        "taint_params": ["ctx"],
                    }
                ],
            },
            output_ref={"artifact_root": "/artifact/IPSEC"},
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-dfa",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_analysis",
            item_key="entry-1",
            item_name="handle",
            parent_key="IPSEC",
            downstream_service="dataflow_analyse",
            status="running",
            output_ref={},
        )
        stale_entry = {
            "entry_key": "entry-1",
            "module_key": "IPSEC",
            "module_name": "IPSEC",
            "function_name": "handle",
            "file_name": "libipsec.c",
            "definition_file": "libipsec.c",
            "definition_line": "10",
            "line_no": "10",
            "definition_kind": "definition",
            "taint_params": ["ctx"],
            "source_dir": ".",
        }
        fake_session = _ModelAwareDb(stage_items=[entry_stage_item, dataflow_item])
        create_calls: list[dict[str, str]] = []

        async def fake_create_task(
            project_id,
            task_name,
            module_input_path,
            source_root_path,
            prompt,
            origin,
            **kwargs,
        ):
            del task_name, prompt, origin
            create_calls.append(
                {
                    "project_id": project_id,
                    "module_input_path": module_input_path,
                    "source_root_path": source_root_path,
                    "source_file": kwargs.get("source_file"),
                }
            )
            return {"task_id": "dfa-new"}

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(task_manager_module, "get_dataflow_analyse_client", return_value=SimpleNamespace(create_task=fake_create_task)),
            patch.object(self.manager, "_upsert_stage_item", return_value=dataflow_item),
            patch.object(self.manager, "_normalize_dfa_source_file", return_value="libipsec.c"),
            patch.object(self.manager, "_poll_until_terminal", return_value=("success", {"task_id": "dfa-new", "status": "passed"})),
            patch.object(self.manager, "_service_output_dir", return_value=Path("/tmp")),
            patch.object(self.manager, "_materialize_stage_artifact", return_value=Path("/tmp")),
            patch.object(self.manager, "_find_first", return_value=Path("/tmp/dataflow.md")),
            patch.object(self.manager, "_queue_archive_and_wait", return_value=(Path("/tmp"), None)),
            patch.object(self.manager, "_compact_result_for_storage", side_effect=lambda stage_name, result: result),
            patch.object(self.manager, "_lightweight_downstream_payload", side_effect=lambda payload: {"status": payload.get("status")}),
        ):
            result = asyncio.run(self.manager._run_dataflow_item(task, stage_run, stale_entry, token=None, retrying=False))

        self.assertEqual("success", result["status"])
        self.assertEqual(1, len(create_calls))
        self.assertEqual("/archive/IPSEC/modules/IPSEC", create_calls[0]["module_input_path"])
        self.assertEqual("/archive/IPSEC", create_calls[0]["source_root_path"])
        self.assertEqual("libipsec.c", create_calls[0]["source_file"])

    def test_compact_result_for_storage_keeps_entry_preview_small(self):
        entries = []
        for index in range(12):
            entries.append(
                {
                    "entry_key": f"e-{index}",
                    "firmware_key": "source_project",
                    "firmware_name": "src",
                    "module_key": "m1",
                    "module_name": "mod",
                    "file_name": "main.go",
                    "function_name": f"fn_{index}",
                    "raw_function_name": f"fn_{index}(ctx context.Context, req *Request, verbose bool)",
                    "line_no": str(index + 1),
                    "definition_file": "main.go",
                    "definition_line": str(index + 1),
                    "is_definition_found": True,
                    "tag": "P",
                    "taint_params": ["ctx", "req", "verbose"],
                    "function_description": "x" * 400,
                    "function_description_source": "llm",
                    "entry_reason": "y" * 400,
                    "entry_reason_source": "llm",
                    "taint_details": [{"name": "ctx", "reason": "z" * 400}],
                    "signature_params": ["ctx", "req", "verbose"],
                    "entry_file": "/tmp/entry-details.json",
                    "source_dir": "/tmp/src",
                }
            )

        result = self.manager._compact_result_for_storage(
            "entry_analysis",
            {
                "module_key": "m1",
                "module_name": "mod",
                "artifact_root": "/tmp/out",
                "entries": entries,
            },
        )

        self.assertEqual(12, result["entry_count"])
        self.assertEqual(5, len(result["entries_preview"]))
        self.assertNotIn("entries", result)
        first = result["entries_preview"][0]
        self.assertIn("function_name", first)
        self.assertIn("taint_params", first)
        self.assertNotIn("function_description", first)
        self.assertNotIn("entry_reason", first)
        self.assertNotIn("taint_details", first)
        self.assertNotIn("entry_file", first)

    def test_run_entry_item_rolls_back_before_marking_failure(self):
        task = BinarySecurityTask(
            id="t1",
            name="source-task",
            project_id="p1",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw",
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="module-1",
            item_name="mod",
            parent_key="fw-1",
            downstream_service="entry_analyse",
            downstream_task_id="ea-old",
            status="queued",
            output_ref={},
        )
        module = {
            "module_key": "module-1",
            "module_name": "mod",
            "firmware_key": "fw-1",
            "source_dir": "/tmp/src",
        }

        class _SessionWithFailingCommit(_ModelAwareDb):
            def __init__(self):
                super().__init__()
                self.rollback_calls = 0
                self.commit_calls = 0

            def commit(self):
                self.commit_calls += 1
                if self.commit_calls == 3:
                    raise RuntimeError("result_json too large")

            def rollback(self):
                self.rollback_calls += 1

        fake_session = _SessionWithFailingCommit()

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(task_manager_module, "get_entry_analyse_client") as client_factory,
            patch.object(self.manager, "_poll_until_terminal", return_value=("success", {"task_id": "ea-new", "status": "passed"})),
            patch.object(self.manager, "_materialize_stage_artifact", return_value=Path("/tmp")),
            patch.object(self.manager, "_parse_entries", return_value=[]),
            patch.object(self.manager, "_queue_archive_and_wait", return_value=(Path("/tmp"), None)),
            patch.object(self.manager, "_compact_result_for_storage", return_value={"entry_count": 0, "entries_preview": []}),
        ):
            client_factory.return_value.create_task = unittest.mock.AsyncMock(return_value={"task_id": "ea-new"})
            client_factory.return_value.get_task = unittest.mock.AsyncMock(return_value={"task_id": "ea-new", "status": "passed"})
            result = asyncio.run(self.manager._run_entry_item(task, stage_run, module, token="tok", retrying=False))

        self.assertEqual("failed", result["status"])
        self.assertEqual("failed", item.status)
        self.assertEqual("result_json too large", item.error_message)
        self.assertGreaterEqual(fake_session.rollback_calls, 1)

    def test_run_entry_item_defers_transport_error_when_downstream_is_temporarily_unreachable(self):
        task = BinarySecurityTask(
            id="t1",
            name="source-task",
            project_id="p1",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw",
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="module-1",
            item_name="mod",
            parent_key="fw-1",
            downstream_service="entry_analyse",
            downstream_task_id="ea-old",
            status="running",
            output_ref={},
        )
        module = {
            "module_key": "module-1",
            "module_name": "mod",
            "firmware_key": "fw-1",
            "source_dir": "/tmp/src",
        }
        fake_session = _AppendingModelAwareDb()

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(
                self.manager,
                "_control_existing_downstream_task",
                return_value={"outcome": "already_running", "payload": {"task_id": "ea-old", "status": "running"}},
            ),
            patch.object(self.manager, "_poll_until_terminal", side_effect=UpstreamError("无法连接下游服务: All connection attempts failed")),
        ):
            result = asyncio.run(self.manager._run_entry_item(task, stage_run, module, token="tok", retrying=True))

        deferred_events = [event for event in fake_session.events if event.event_type == "downstream_transport_deferred"]
        self.assertEqual("running", result["status"])
        self.assertEqual("running", item.status)
        self.assertEqual("无法连接下游服务: All connection attempts failed", item.error_message)
        self.assertTrue(deferred_events)
        self.assertEqual("reconcile", deferred_events[-1].payload.get("deferred_mode"))

    def test_run_entry_item_defers_transport_error_from_retry_control(self):
        task = BinarySecurityTask(
            id="t1",
            name="source-task",
            project_id="p1",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw",
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="module-1",
            item_name="mod",
            parent_key="fw-1",
            downstream_service="entry_analyse",
            downstream_task_id="ea-old",
            status="running",
            output_ref={},
        )
        module = {
            "module_key": "module-1",
            "module_name": "mod",
            "firmware_key": "fw-1",
            "source_dir": "/tmp/src",
        }
        fake_session = _AppendingModelAwareDb()

        with (
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
            patch.object(self.manager, "_upsert_stage_item", return_value=item),
            patch.object(
                self.manager,
                "_control_existing_downstream_task",
                return_value={"outcome": "transport_error", "error_message": "无法连接下游服务: All connection attempts failed"},
            ),
        ):
            result = asyncio.run(self.manager._run_entry_item(task, stage_run, module, token="tok", retrying=True))

        deferred_events = [event for event in fake_session.events if event.event_type == "downstream_transport_deferred"]
        self.assertEqual("running", result["status"])
        self.assertEqual("running", item.status)
        self.assertEqual("无法连接下游服务: All connection attempts failed", item.error_message)
        self.assertTrue(deferred_events)
        self.assertEqual("reconcile", deferred_events[-1].payload.get("deferred_mode"))


if __name__ == "__main__":
    unittest.main()
