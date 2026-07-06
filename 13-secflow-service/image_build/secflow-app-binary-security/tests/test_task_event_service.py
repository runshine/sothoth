import tempfile
import unittest
import os
from pathlib import Path

from app.model import BinarySecurityEvent, BinarySecurityTask, TASK_TYPE_SOURCE
from app.service.task.events import TaskEventServiceMixin
from app.service.task_manager import TaskManager
from test_task_manager import _ModelAwareDb, _now
from datetime import timedelta


class TaskEventServiceStructureTests(unittest.TestCase):
    def test_task_manager_event_methods_are_bound_to_event_mixin(self):
        self.assertIs(TaskManager._record_event, TaskEventServiceMixin._record_event)
        self.assertIs(TaskManager._set_task_status, TaskEventServiceMixin._set_task_status)
        self.assertIs(TaskManager._prepare_event_payload_for_db, TaskEventServiceMixin._prepare_event_payload_for_db)
        self.assertIs(TaskManager._load_externalized_event_payload, TaskEventServiceMixin._load_externalized_event_payload)


class TaskEventServiceBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()
        self._old_env = {key: os.environ.get(key) for key in ("POD_NAME", "HOSTNAME", "NODE_NAME", "SECFLOW_BINARY_SECURITY_ROLE")}
        os.environ["POD_NAME"] = "binary-security-worker-pod"
        os.environ["HOSTNAME"] = "binary-security-worker-pod"
        os.environ["NODE_NAME"] = "secflow-node-01"
        os.environ["SECFLOW_BINARY_SECURITY_ROLE"] = "worker"

    def tearDown(self):
        for key, value in self._old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_record_event_trims_task_timeline_to_limit(self):
        task = BinarySecurityTask(
            id="task-timeline-cap",
            project_id="p1",
            name="timeline-cap",
            status="running",
            current_stage="system_analysis",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/out",
            workspace_root="/ws",
        )
        events = []
        base_time = _now() - timedelta(seconds=10001)
        for index in range(10_000):
            event = BinarySecurityEvent(
                id=f"evt-{index:05d}",
                task_id=task.id,
                project_id=task.project_id,
                level="info",
                event_type="seed",
                message=f"seed-{index}",
            )
            event.created_at = base_time + timedelta(seconds=index)
            events.append(event)
        db = _ModelAwareDb(tasks=[task], events=events)

        self.manager._record_event(
            db,
            task,
            "overflow",
            "overflow-event",
            stage_name="system_analysis",
        )

        self.assertEqual(10_000, len(db.events))
        self.assertFalse(any(event.id == "evt-00000" for event in db.events))
        self.assertTrue(any(event.event_type == "overflow" for event in db.events))

    def test_record_event_skips_duplicate_owned_execution_takeover_requeued_events(self):
        task = BinarySecurityTask(
            id="task-dedupe",
            project_id="p1",
            name="timeline-dedupe",
            status="running",
            current_stage="entry_analysis",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/out",
            workspace_root="/ws",
        )
        existing = BinarySecurityEvent(
            id="evt-existing",
            task_id=task.id,
            project_id=task.project_id,
            level="warning",
            event_type="owned_execution_takeover_requeued",
            stage_name="entry_analysis",
            item_id=None,
            item_key=None,
            message="检测到执行接管悬空，已重新排队等待 worker 接管",
            payload={
                "takeover_action": "requeue_owned_execution",
                "takeover_reason": "refresh_task_status_no_active_owner",
                "runtime_lease_owner": "worker-a",
                "task_execution_token": "2026-06-13T11:15:13",
            },
        )
        existing.created_at = _now()
        db = _ModelAwareDb(tasks=[task], events=[existing])

        self.manager._record_event(
            db,
            task,
            "owned_execution_takeover_requeued",
            "检测到执行接管悬空，已重新排队等待 worker 接管",
            level="warning",
            stage_name="entry_analysis",
            payload={
                "takeover_action": "requeue_owned_execution",
                "takeover_reason": "refresh_task_status_no_active_owner",
                "runtime_lease_owner": "worker-a",
                "task_execution_token": "2026-06-13T11:15:13",
            },
        )

        requeue_events = [event for event in db.events if event.event_type == "owned_execution_takeover_requeued"]
        self.assertEqual(1, len(requeue_events))

    def test_prepare_event_payload_externalizes_large_payload_and_can_load_it_back(self):
        with tempfile.TemporaryDirectory() as workspace:
            task = BinarySecurityTask(
                id="task-large-payload",
                project_id="p1",
                name="payload-task",
                status="running",
                current_stage="system_analysis",
                task_type=TASK_TYPE_SOURCE,
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root="/out",
                workspace_root=workspace,
            )
            db = _ModelAwareDb(tasks=[task])
            payload = {"summary": {"huge": "x" * 12000}, "status": "success", "stage_name": "system_analysis"}

            compact = self.manager._prepare_event_payload_for_db(
                db,
                task=task,
                event_id="evt-large",
                event_type="generic_large_payload",
                stage_name="system_analysis",
                payload=payload,
                state_event=False,
            )

            self.assertEqual("success", compact["status"])
            self.assertEqual("system_analysis", compact["stage_name"])
            if compact.get("payload_externalized"):
                payload_file = Path(str(compact["payload_file"]))
                self.assertTrue(payload_file.is_file())
                loaded = self.manager._load_externalized_event_payload(task, compact)
                self.assertEqual(payload["summary"]["huge"], loaded["summary"]["huge"])
            else:
                self.assertIn("summary", compact)
                self.assertEqual(payload["summary"]["huge"], compact["summary"]["huge"])

    def test_record_event_injects_recorder_metadata(self):
        task = BinarySecurityTask(
            id="task-recorder",
            project_id="p1",
            name="timeline-recorder",
            status="running",
            current_stage="system_analysis",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/out",
            workspace_root="/ws",
        )
        db = _ModelAwareDb(tasks=[task], events=[])

        self.manager._record_event(
            db,
            task,
            "stage_started",
            "阶段开始执行: system_analysis",
            stage_name="system_analysis",
        )

        self.assertEqual(1, len(db.events))
        recorder = dict(db.events[0].payload.get("recorder") or {})
        self.assertEqual("binary-security", recorder.get("service"))
        self.assertEqual("worker", recorder.get("role"))
        self.assertEqual("binary-security-worker-pod", recorder.get("pod_name"))
        self.assertEqual("binary-security-worker-pod", recorder.get("hostname"))
        self.assertEqual("secflow-node-01", recorder.get("node_name"))

    def test_set_task_status_records_structured_status_change_event(self):
        task = BinarySecurityTask(
            id="task-status-change",
            project_id="p1",
            name="timeline-status-change",
            status="pending",
            current_stage="system_analysis",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/out",
            workspace_root="/ws",
        )
        db = _ModelAwareDb(tasks=[task], events=[])

        changed = self.manager._set_task_status(
            db,
            task,
            "running",
            reason="任务进入调度执行",
            source="runtime_worker",
            stage_name="system_analysis",
        )

        self.assertTrue(changed)
        self.assertEqual("running", task.status)
        self.assertEqual(1, len(db.events))
        self.assertEqual("task_status_changed", db.events[0].event_type)
        self.assertEqual("任务状态变更: pending -> running", db.events[0].message)
        self.assertEqual("pending", db.events[0].payload.get("from_status"))
        self.assertEqual("running", db.events[0].payload.get("to_status"))
        self.assertEqual("任务进入调度执行", db.events[0].payload.get("reason"))
        self.assertEqual("runtime_worker", db.events[0].payload.get("source"))

    def test_set_task_status_skips_noop_by_default(self):
        task = BinarySecurityTask(
            id="task-status-noop",
            project_id="p1",
            name="timeline-status-noop",
            status="pending",
            current_stage="system_analysis",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/out",
            workspace_root="/ws",
        )
        db = _ModelAwareDb(tasks=[task], events=[])

        changed = self.manager._set_task_status(
            db,
            task,
            "pending",
            reason="状态未变化",
            source="task_manager",
        )

        self.assertFalse(changed)
        self.assertEqual([], db.events)
