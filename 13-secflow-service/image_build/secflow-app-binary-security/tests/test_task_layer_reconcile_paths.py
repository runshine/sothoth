import asyncio
import json
import tempfile
import unittest
from datetime import timedelta
from unittest.mock import patch

from app.model import (
    BinarySecurityArchiveJob,
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityStateEvent,
    BinarySecurityTask,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_TYPE_BINARY,
    TASK_TYPE_SOURCE,
)
from app.service.task_manager import TaskManager, _now
from test_task_manager import _AppendingModelAwareDb


class TaskLayerReconcilePathTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_stage_worker_terminal_event_preserves_stage_fact_when_task_layer_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_BINARY,
                current_stage="firmware_unpack",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root="/o",
                workspace_root=tmp,
                started_at=_now(),
            )
            stage_run = BinarySecurityStageRun(
                id="sr-sa",
                task_id="task1",
                project_id="p1",
                stage_name="firmware_unpack",
                sequence_no=1,
                status="running",
                started_at=_now(),
            )
            event = BinarySecurityStateEvent(
                id="sev-sa-success",
                task_id="task1",
                project_id="p1",
                stage_name="firmware_unpack",
                event_type="stage_worker_terminal_observed",
                idempotency_key="stage_worker_terminal_observed:task1:firmware_unpack:seq:1:success",
            )
            event.payload = {
                "stage_name": "firmware_unpack",
                "status": "success",
                "summary": {"success_count": 1},
            }
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], state_events=[event], events=[])

            async def _noop_write(*_args, **_kwargs):
                return None

            original_write = self.manager._write_task_metadata_async
            original_request = self.manager._request_task_layer_reconcile
            calls = []
            self.manager._write_task_metadata_async = _noop_write

            def _capture_request(_db, _task, **kwargs):
                calls.append(dict(kwargs))
                return None

            self.manager._request_task_layer_reconcile = _capture_request
            try:
                asyncio.run(self.manager._apply_stage_worker_terminal_event_locked(db, event))
            finally:
                self.manager._write_task_metadata_async = original_write
                self.manager._request_task_layer_reconcile = original_request

            self.assertEqual("success", stage_run.status)
            self.assertIsNotNone(stage_run.finished_at)
            self.assertEqual("firmware_unpack", task.current_stage)
            self.assertEqual("stage_worker_terminal_observed", calls[0]["source_event_type"])
            self.assertEqual("stage_worker_terminal_observed", calls[0]["reconcile_reason"])

    def test_downstream_status_event_applied_uses_explicit_task_layer_reconcile(self):
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_BINARY,
                current_stage="binary_to_source",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root="/o",
                workspace_root=tmp,
                runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            )
            stage_run = BinarySecurityStageRun(
                id="sr-b2s",
                task_id="task1",
                project_id="p1",
                stage_name="binary_to_source",
                sequence_no=3,
                status="running",
            )
            item = BinarySecurityStageItem(
                id="si-b2s",
                task_id="task1",
                project_id="p1",
                stage_run_id="sr-b2s",
                stage_name="binary_to_source",
                item_key="m1",
                parent_key="fw1",
                status="running",
                downstream_service="binary_to_source",
                downstream_task_id="b2s-task-1",
            )
            event = BinarySecurityStateEvent(
                id="sev-downstream",
                task_id="task1",
                project_id="p1",
                stage_name="binary_to_source",
                item_id="si-b2s",
                event_type="downstream_terminal_observed",
                idempotency_key="downstream-terminal:si-b2s",
            )
            event.payload = {
                "mapped_status": "success",
                "downstream_status": "success",
                "downstream_payload": {"task_id": "b2s-task-1", "status": "success"},
                "status_raw": "success",
                "state_applied": True,
            }
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[item], state_events=[event], events=[])

            async def _noop_write(*_args, **_kwargs):
                return None

            original_write = self.manager._write_task_metadata_async
            original_reconcile_stage = self.manager._reconcile_stage_domain_in_session
            original_request = self.manager._request_task_layer_reconcile
            calls = []

            def _capture_reconcile_stage(_db, _task, _stage_name):
                return stage_run

            def _capture_request(_db, _task, **kwargs):
                calls.append(dict(kwargs))
                return None

            self.manager._write_task_metadata_async = _noop_write
            self.manager._reconcile_stage_domain_in_session = _capture_reconcile_stage
            self.manager._request_task_layer_reconcile = _capture_request
            try:
                asyncio.run(self.manager._apply_downstream_terminal_observed_locked(db, event))
            finally:
                self.manager._write_task_metadata_async = original_write
                self.manager._reconcile_stage_domain_in_session = original_reconcile_stage
                self.manager._request_task_layer_reconcile = original_request

            self.assertEqual("success", item.status)
            self.assertEqual("binary_to_source", calls[0]["stage_name"])
            self.assertEqual("downstream_terminal_observed", calls[0]["source_event_type"])
            self.assertEqual("downstream_status_event_applied", calls[0]["reconcile_reason"])

    def test_archive_apply_uses_explicit_task_layer_reconcile(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="firmware_unpack",
            firmware_source="project_filesystem",
            firmware_path="/fw.bin",
            output_root="/o",
            workspace_root="/tmp",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="firmware_unpack",
            item_key="fw-1",
            item_name="fw-1",
            status="running",
            downstream_service="firmware_unpacker",
            downstream_task_id="child1",
        )
        job = BinarySecurityArchiveJob(
            id="job1",
            task_id="t1",
            project_id="p1",
            stage_name="firmware_unpack",
            item_id="si1",
            item_key="fw-1",
            downstream_service="firmware_unpacker",
            downstream_task_id="child1",
            archive_status="archived",
        )
        job.payload = {
            "mapped_status": "success",
            "bound_downstream_task_id": "child1",
            "downstream_payload": {"task_id": "child1", "status": "success"},
        }
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], archive_jobs=[job], events=[])

        async def _noop_refresh_terminal(*_args, **_kwargs):
            return None

        async def _noop_write(*_args, **_kwargs):
            return None

        original_new = self.manager._reconcile_item_layer_facts_in_session
        original_refresh_terminal = self.manager._refresh_terminal_item_result_from_downstream
        original_write = self.manager._write_task_metadata_async
        original_request = self.manager._request_task_layer_reconcile
        calls = []

        def _capture_new(_db, _task, **kwargs):
            calls.append(("facts", dict(kwargs)))
            return None, self.manager._task_state_snapshot(task)

        def _capture_request(_db, _task, **kwargs):
            calls.append(("request", dict(kwargs)))
            return None

        self.manager._reconcile_item_layer_facts_in_session = _capture_new
        self.manager._refresh_terminal_item_result_from_downstream = _noop_refresh_terminal
        self.manager._write_task_metadata_async = _noop_write
        self.manager._request_task_layer_reconcile = _capture_request
        try:
            asyncio.run(self.manager._apply_archive_job_status_locked(db, "job1", "/tmp/archive"))
        finally:
            self.manager._reconcile_item_layer_facts_in_session = original_new
            self.manager._refresh_terminal_item_result_from_downstream = original_refresh_terminal
            self.manager._write_task_metadata_async = original_write
            self.manager._request_task_layer_reconcile = original_request

        self.assertEqual("facts", calls[0][0])
        self.assertEqual("firmware_unpack", calls[0][1]["stage_name"])
        self.assertEqual("request", calls[1][0])
        self.assertEqual("archive_job_copied", calls[1][1]["source_event_type"])
        self.assertEqual("archive_apply", calls[1][1]["reconcile_reason"])
        event_types = [event.event_type for event in db.events]
        self.assertNotIn("task_finalize_deferred_for_incomplete_stage", event_types)
        self.assertNotIn("main_state_write_blocked", event_types)

    def test_run_task_layer_reconcile_signal_applies_stage_terminal_decision(self):
        task = BinarySecurityTask(
            id="task-reconcile",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        stage_run = BinarySecurityStageRun(
            id="sr-system",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            output_summary={"success_count": 1},
        )
        next_run = BinarySecurityStageRun(
            id="sr-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run, next_run], events=[])

        original_refresh = self.manager._refresh_task_status_after_sync
        original_apply = self.manager._apply_task_action_after_stage_terminal
        original_write = self.manager._write_task_metadata_async
        calls = []

        def _capture_refresh(_db, _task):
            calls.append(("refresh", str(_task.current_stage or "")))
            return original_refresh(_db, _task)

        async def _capture_apply(_db, _task, **kwargs):
            calls.append(("apply", dict(kwargs)))
            return True

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._refresh_task_status_after_sync = _capture_refresh
        self.manager._apply_task_action_after_stage_terminal = _capture_apply
        self.manager._write_task_metadata_async = _noop_write
        try:
            changed = asyncio.run(
                self.manager._run_task_layer_reconcile_signal(
                    db,
                    task,
                    signal={
                        "source_event_type": "stage_worker_terminal_observed",
                        "state_event_id": "sev1",
                        "reconcile_reason": "stage_worker_terminal_observed",
                        "stage_name": "system_analysis",
                        "fact_applied": True,
                    },
                )
            )
        finally:
            self.manager._refresh_task_status_after_sync = original_refresh
            self.manager._apply_task_action_after_stage_terminal = original_apply
            self.manager._write_task_metadata_async = original_write

        self.assertFalse(changed)
        self.assertEqual("refresh", calls[0][0])
        self.assertEqual(1, len(calls))
        self.assertEqual("system_analysis", task.current_stage)

    def test_run_task_layer_reconcile_signal_archive_apply_uses_owner_stage_terminal_apply(self):
        task = BinarySecurityTask(
            id="task-archive-reconcile",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        stage_run = BinarySecurityStageRun(
            id="sr-system-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            output_summary={"success_count": 1},
        )
        next_run = BinarySecurityStageRun(
            id="sr-entry-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run, next_run], events=[])

        original_refresh = self.manager._refresh_task_status_after_sync
        original_apply = self.manager._apply_task_action_after_stage_terminal
        original_write = self.manager._write_task_metadata_async
        calls = []

        def _capture_refresh(_db, _task):
            calls.append(("refresh", str(_task.current_stage or "")))
            return original_refresh(_db, _task)

        async def _capture_apply(_db, _task, **kwargs):
            calls.append(("apply", dict(kwargs)))
            return True

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._refresh_task_status_after_sync = _capture_refresh
        self.manager._apply_task_action_after_stage_terminal = _capture_apply
        self.manager._write_task_metadata_async = _noop_write
        try:
            changed = asyncio.run(
                self.manager._run_task_layer_reconcile_signal(
                    db,
                    task,
                    signal={
                        "source_event_type": "archive_job_copied",
                        "state_event_id": "sev-archive-1",
                        "reconcile_reason": "archive_apply",
                        "stage_name": "system_analysis",
                        "fact_applied": True,
                        "archive_job_id": "aj-1",
                    },
                )
            )
        finally:
            self.manager._refresh_task_status_after_sync = original_refresh
            self.manager._apply_task_action_after_stage_terminal = original_apply
            self.manager._write_task_metadata_async = original_write

        self.assertFalse(changed)
        self.assertEqual("refresh", calls[0][0])
        self.assertEqual([("refresh", "system_analysis")], calls)
        self.assertEqual("running", task.status)
        self.assertEqual("system_analysis", task.current_stage)

    def test_run_task_layer_reconcile_signal_noops_for_stage_worker_start_requested(self):
        task = BinarySecurityTask(
            id="task-start-reconcile",
            project_id="p1",
            name="n",
            status="pending",
            task_type=TASK_TYPE_BINARY,
            current_stage="binary_to_source",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        db = _AppendingModelAwareDb(tasks=[task], events=[])

        original_refresh = self.manager._refresh_task_status_after_sync
        original_apply = self.manager._apply_task_layer_reconcile_decision
        calls = []

        def _capture_refresh(_db, _task):
            calls.append("refresh")
            return None

        async def _capture_apply(_db, _task, *, decision, signal):
            calls.append({"action": decision.action, "source": signal.get("source_event_type")})
            return False

        self.manager._refresh_task_status_after_sync = _capture_refresh
        self.manager._apply_task_layer_reconcile_decision = _capture_apply
        try:
            changed = asyncio.run(
                self.manager._run_task_layer_reconcile_signal(
                    db,
                    task,
                    signal={
                        "source_event_type": "stage_worker_start_requested",
                        "reconcile_reason": "stage_worker_start_requested",
                        "stage_name": "entry_analysis",
                        "fact_applied": True,
                    },
                )
            )
        finally:
            self.manager._refresh_task_status_after_sync = original_refresh
            self.manager._apply_task_layer_reconcile_decision = original_apply

        self.assertFalse(changed)
        self.assertEqual("refresh", calls[0])
        self.assertEqual("refresh_only", calls[1]["action"])
        self.assertEqual("stage_worker_start_requested", calls[1]["source"])

    def test_sync_downstream_status_uses_owner_reconcile_instead_of_direct_task_layer_requeue(self):
        task = BinarySecurityTask(
            id="t-sync-reconcile",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
        )
        run = BinarySecurityStageRun(
            id="sr-system",
            task_id="t-sync-reconcile",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=1,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si-system",
            task_id="t-sync-reconcile",
            project_id="p1",
            stage_run_id="sr-system",
            stage_name="system_analysis",
            item_key="source_project",
            parent_key="source_project",
            status="queued",
            downstream_service="system_analyse",
            downstream_task_id="sat-1",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[run], stage_items=[item], events=[])

        original_fetch = self.manager._fetch_downstream_task_payload
        original_write = self.manager._write_task_metadata_async
        original_reconcile = self.manager._run_task_layer_reconcile_signal
        original_request = self.manager._request_task_layer_reconcile
        calls = []

        async def _fetch(_task, _item, _token):
            return {"task_id": "sat-1", "status": "success"}

        async def _noop_write(*_args, **_kwargs):
            return None

        async def _capture_reconcile(_db, _task, *, signal):
            calls.append(dict(signal))
            return False

        def _capture_request(_db, _task, **kwargs):
            calls.append({"requested": True, **dict(kwargs)})

        self.manager._fetch_downstream_task_payload = _fetch
        self.manager._write_task_metadata_async = _noop_write
        self.manager._run_task_layer_reconcile_signal = _capture_reconcile
        self.manager._request_task_layer_reconcile = _capture_request
        try:
            asyncio.run(
                self.manager.sync_downstream_status(
                    db,
                    project_id="p1",
                    task_id="t-sync-reconcile",
                    stage_name="system_analysis",
                    apply_state=True,
                )
            )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch
            self.manager._write_task_metadata_async = original_write
            self.manager._run_task_layer_reconcile_signal = original_reconcile
            self.manager._request_task_layer_reconcile = original_request

        self.assertTrue(calls[0]["requested"])
        self.assertEqual("downstream_status_observed", calls[0]["source_event_type"])
        self.assertEqual("system_analysis_sync_next_stage_active_without_owner", calls[0]["reconcile_reason"])
        self.assertEqual("system_analysis", calls[0]["stage_name"])

    def test_sync_downstream_status_runs_inline_reconcile_when_current_instance_is_owner(self):
        task = BinarySecurityTask(
            id="t-sync-reconcile-owner",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            dispatcher_instance_id=self.manager.instance_id,
            lease_expires_at=_now() + timedelta(minutes=1),
        )
        run = BinarySecurityStageRun(
            id="sr-system-owner",
            task_id="t-sync-reconcile-owner",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=1,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si-system-owner",
            task_id="t-sync-reconcile-owner",
            project_id="p1",
            stage_run_id="sr-system-owner",
            stage_name="system_analysis",
            item_key="source_project",
            parent_key="source_project",
            status="queued",
            downstream_service="system_analyse",
            downstream_task_id="sat-1",
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id=self.manager.instance_id,
            heartbeat_at=_now(),
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[run], stage_items=[item], runtime_leases=[lease], events=[])

        original_fetch = self.manager._fetch_downstream_task_payload
        original_write = self.manager._write_task_metadata_async
        original_reconcile = self.manager._run_task_layer_reconcile_signal
        original_request = self.manager._request_task_layer_reconcile
        calls = []

        async def _fetch(_task, _item, _token):
            return {"task_id": "sat-1", "status": "success"}

        async def _noop_write(*_args, **_kwargs):
            return None

        async def _capture_reconcile(_db, _task, *, signal):
            calls.append({"inline": True, **dict(signal)})
            return False

        def _capture_request(_db, _task, **kwargs):
            calls.append({"requested": True, **dict(kwargs)})

        self.manager._fetch_downstream_task_payload = _fetch
        self.manager._write_task_metadata_async = _noop_write
        self.manager._run_task_layer_reconcile_signal = _capture_reconcile
        self.manager._request_task_layer_reconcile = _capture_request
        try:
            asyncio.run(
                self.manager.sync_downstream_status(
                    db,
                    project_id=task.project_id,
                    task_id=task.id,
                    stage_name="system_analysis",
                    apply_state=True,
                )
            )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch
            self.manager._write_task_metadata_async = original_write
            self.manager._run_task_layer_reconcile_signal = original_reconcile
            self.manager._request_task_layer_reconcile = original_request

        self.assertTrue(calls[0]["inline"])
        self.assertEqual("downstream_status_observed", calls[0]["source_event_type"])
        self.assertEqual("system_analysis_sync_next_stage_active_without_owner", calls[0]["reconcile_reason"])
        self.assertEqual("system_analysis", calls[0]["stage_name"])

    def test_run_task_layer_reconcile_signal_failure_finalize_uses_authoritative_failure(self):
        task = BinarySecurityTask(
            id="task-failure-reconcile",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        db = _AppendingModelAwareDb(tasks=[task], events=[])

        original_refresh = self.manager._refresh_task_status_after_sync
        original_current_failure = self.manager._current_stage_authoritative_failure_context
        original_earlier_failure = self.manager._earlier_stage_authoritative_failure_context
        original_finalize = self.manager._finalize_task_after_authoritative_failure
        original_write = self.manager._write_task_metadata_async
        calls = []

        def _capture_refresh(_db, _task):
            calls.append(("refresh", str(_task.current_stage or "")))
            return None

        def _capture_failure(_db, _task, stage_runs=None):
            del stage_runs
            return {
                "stage_name": "entry_analysis",
                "failure_code": "archive_blocked",
                "failure_category": "archive_blocked",
                "failure_message": "archive blocked",
                "reason": "authoritative_archive_blocked",
            }

        def _capture_finalize(_db, _task, *, failure_ctx, previous_status=None, event_type="dispatching_state_force_terminalized"):
            calls.append(
                (
                    "finalize",
                    {
                        "failure_ctx": dict(failure_ctx or {}),
                        "previous_status": previous_status,
                        "event_type": event_type,
                    },
                )
            )
            _task.status = "failed"
            return None

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._refresh_task_status_after_sync = _capture_refresh
        self.manager._current_stage_authoritative_failure_context = _capture_failure
        self.manager._earlier_stage_authoritative_failure_context = lambda *_args, **_kwargs: None
        self.manager._finalize_task_after_authoritative_failure = _capture_finalize
        self.manager._write_task_metadata_async = _noop_write
        try:
            changed = asyncio.run(
                self.manager._run_task_layer_reconcile_signal(
                    db,
                    task,
                    signal={
                        "source_event_type": "task_execution_failed",
                        "state_event_id": "sev-fail-1",
                        "reconcile_reason": "task_execution_failed",
                        "stage_name": "entry_analysis",
                        "fact_applied": True,
                    },
                )
            )
        finally:
            self.manager._refresh_task_status_after_sync = original_refresh
            self.manager._current_stage_authoritative_failure_context = original_current_failure
            self.manager._earlier_stage_authoritative_failure_context = original_earlier_failure
            self.manager._finalize_task_after_authoritative_failure = original_finalize
            self.manager._write_task_metadata_async = original_write

        self.assertTrue(changed)
        self.assertEqual("refresh", calls[0][0])
        self.assertEqual("finalize", calls[1][0])
        self.assertEqual("entry_analysis", calls[1][1]["failure_ctx"]["stage_name"])
        self.assertEqual("archive_blocked", calls[1][1]["failure_ctx"]["failure_code"])

    def test_run_task_layer_reconcile_signal_archive_apply_advances_system_analysis_only_via_owner(self):
        task = BinarySecurityTask(
            id="task-archive-owner-advance",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        stage_run = BinarySecurityStageRun(
            id="sr-system-owner-advance",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            output_summary={"success_count": 1},
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], events=[])

        original_entry_inputs = self.manager._entry_analysis_inputs
        original_should_auto = self.manager._should_auto_advance_to_stage
        original_apply_resume = self.manager._apply_task_resume_decision
        original_enqueue = self.manager._enqueue_task
        original_write = self.manager._write_task_metadata_async
        applied = []
        queued = []

        self.manager._entry_analysis_inputs = lambda *_args, **_kwargs: [{"entry_key": "entry-a"}]
        self.manager._should_auto_advance_to_stage = lambda *_args, **_kwargs: True
        self.manager._enqueue_task = lambda task_id: queued.append(task_id)

        def _capture_apply_resume(_db, _task, decision, *, operation=None, enqueue_task=True):
            del operation
            applied.append(
                {
                    "next_stage": decision.next_stage,
                    "source": decision.source,
                    "event_type": decision.event_type,
                }
            )
            return original_apply_resume(_db, _task, decision, enqueue_task=enqueue_task)

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._apply_task_resume_decision = _capture_apply_resume
        self.manager._write_task_metadata_async = _noop_write
        try:
            with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
                changed = asyncio.run(
                    self.manager._run_task_layer_reconcile_signal(
                        db,
                        task,
                        signal={
                            "source_event_type": "archive_job_copied",
                            "state_event_id": "sev-archive-owner-advance",
                            "reconcile_reason": "archive_apply",
                            "stage_name": "system_analysis",
                            "fact_applied": True,
                            "archive_job_id": "aj-system-1",
                        },
                    )
                )
        finally:
            self.manager._entry_analysis_inputs = original_entry_inputs
            self.manager._should_auto_advance_to_stage = original_should_auto
            self.manager._apply_task_resume_decision = original_apply_resume
            self.manager._enqueue_task = original_enqueue
            self.manager._write_task_metadata_async = original_write

        self.assertTrue(changed)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual("running", task.status)
        self.assertEqual(["task-archive-owner-advance"], queued)
        if applied:
            self.assertEqual("entry_analysis", applied[0]["next_stage"])
        self.assertIn(applied[0]["source"], {"stage_terminal", "downstream_sync"})
        self.assertIn(applied[0]["event_type"], {"task_requeued_after_stage_completion", "task_requeued_after_downstream_sync"})
        blocked_events = [event for event in db.events if event.event_type == "main_state_write_blocked"]
        attempted_stages = {
            str((event.payload or {}).get("attempted_stage_name") or "")
            for event in blocked_events
        }
        self.assertFalse({"entry_analysis", "dataflow_vuln_scan"} & attempted_stages)
        self.assertTrue(
            any(
                event.event_type in {
                    "task_requeued_after_stage_completion",
                    "task_finalize_deferred_for_incomplete_stage",
                    "task_layer_reconcile_completed",
                }
                for event in db.events
            )
        )

    def test_run_task_layer_reconcile_signal_archive_apply_keeps_streaming_entry_parent_running(self):
        task = BinarySecurityTask(
            id="task-archive-streaming-entry",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
            summary={
                "entry_results": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "entries": [{"entry_key": "entry-a", "function_name": "f"}],
                    }
                ]
            },
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-streaming",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
            output_summary={"success_count": 1, "entry_count": 1},
        )
        tail_run = BinarySecurityStageRun(
            id="sr-tail-streaming",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="pending",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[entry_run, tail_run], events=[])

        original_refresh = self.manager._refresh_task_status_after_sync
        original_apply = self.manager._apply_task_action_after_stage_terminal
        original_write = self.manager._write_task_metadata_async
        calls = []

        def _capture_refresh(_db, _task):
            calls.append(("refresh", str(_task.current_stage or ""), str(_task.status or "")))
            return None

        async def _capture_apply(_db, _task, **kwargs):
            calls.append(("apply", dict(kwargs)))
            return True

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._refresh_task_status_after_sync = _capture_refresh
        self.manager._apply_task_action_after_stage_terminal = _capture_apply
        self.manager._write_task_metadata_async = _noop_write
        try:
            changed = asyncio.run(
                self.manager._run_task_layer_reconcile_signal(
                    db,
                    task,
                    signal={
                        "source_event_type": "archive_job_copied",
                        "state_event_id": "sev-archive-streaming-entry",
                        "reconcile_reason": "archive_apply",
                        "stage_name": "entry_analysis",
                        "fact_applied": True,
                        "archive_job_id": "aj-entry-1",
                    },
                )
            )
        finally:
            self.manager._refresh_task_status_after_sync = original_refresh
            self.manager._apply_task_action_after_stage_terminal = original_apply
            self.manager._write_task_metadata_async = original_write

        self.assertFalse(changed)
        self.assertEqual("running", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual([("refresh", "entry_analysis", "running")], calls)
        self.assertTrue(any(event.event_type == "task_layer_reconcile_noop" for event in db.events))
        self.assertFalse(any(event.event_type == "task_requeued_after_stage_completion" for event in db.events))
