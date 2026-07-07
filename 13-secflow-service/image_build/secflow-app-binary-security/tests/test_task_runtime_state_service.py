import unittest
from datetime import timedelta
from unittest.mock import patch

from app.model import (
    BinarySecurityTask,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_RUNTIME_PHASE_TERMINAL,
    TASK_TYPE_BINARY,
)
from app.service import task_manager as task_manager_module
from app.service.task.runtime_state import TaskRuntimeStateServiceMixin
from app.service.task_manager import TaskManager, _now
from test_task_manager import _ModelAwareDb


class TaskRuntimeStateServiceStructureTests(unittest.TestCase):
    def test_task_manager_runtime_state_methods_are_bound_to_mixin(self):
        self.assertIs(TaskManager._task_runtime_policy_update_support, TaskRuntimeStateServiceMixin._task_runtime_policy_update_support)
        self.assertIs(TaskManager._task_policy_update_support, TaskRuntimeStateServiceMixin._task_policy_update_support)
        self.assertIs(TaskManager._runtime_lease_capable, TaskRuntimeStateServiceMixin._runtime_lease_capable)
        self.assertIs(TaskManager._task_runtime_override, TaskRuntimeStateServiceMixin._task_runtime_override)
        self.assertIs(TaskManager._effective_runtime_policy, TaskRuntimeStateServiceMixin._effective_runtime_policy)
        self.assertIs(TaskManager._runtime_policy_effect_scope, TaskRuntimeStateServiceMixin._runtime_policy_effect_scope)
        self.assertIs(TaskManager._service_token, TaskRuntimeStateServiceMixin._service_token)
        self.assertIs(TaskManager._resolve_downstream_token, TaskRuntimeStateServiceMixin._resolve_downstream_token)
        self.assertIs(TaskManager._root_task_key_secret, TaskRuntimeStateServiceMixin._root_task_key_secret)
        self.assertIs(TaskManager._task_runtime_phase, TaskRuntimeStateServiceMixin._task_runtime_phase)
        self.assertIs(TaskManager._set_task_runtime_phase, TaskRuntimeStateServiceMixin._set_task_runtime_phase)
        self.assertIs(TaskManager._task_control_mode, TaskRuntimeStateServiceMixin._task_control_mode)


class TaskRuntimeStateServiceBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()
        self._original_get_task_queue = task_manager_module.get_task_queue
        from test_task_manager import _FakeTaskSyncQueue

        self.fake_task_queue = _FakeTaskSyncQueue()
        task_manager_module.get_task_queue = lambda: self.fake_task_queue

    def tearDown(self):
        task_manager_module.get_task_queue = self._original_get_task_queue

    def _task(self, **overrides):
        data = {
            "id": "task-1",
            "project_id": "project-1",
            "name": "task",
            "status": "running",
            "task_type": TASK_TYPE_BINARY,
            "current_stage": "system_analysis",
            "policy": {"stage_parallelism": {"system_analysis": 1}, "module_risk_levels": ["高", "中"]},
            "runtime_override": {},
            "summary": {},
        }
        data.update(overrides)
        return BinarySecurityTask(**data)

    def test_effective_runtime_policy_merges_stage_parallelism_and_throttle(self):
        task = self._task(
            runtime_override={
                "stage_parallelism": {"system_analysis": 3},
                "dispatch_throttle": {"system_analysis": {"max_new_items_per_tick": 4}},
                "continue_on_item_failure": True,
            }
        )
        self.manager._stage_sequence_for_task = lambda _task: ["system_analysis", "binary_to_source"]

        effective = self.manager._effective_runtime_policy(task)

        self.assertEqual(3, effective["stage_parallelism"]["system_analysis"])
        self.assertEqual(3, effective["max_stage_parallelism"])
        self.assertEqual(4, effective["dispatch_throttle"]["system_analysis"]["max_new_items_per_tick"])
        self.assertTrue(effective["continue_on_item_failure"])

    def test_runtime_policy_effect_scope_marks_current_and_tail_stages(self):
        task = self._task(current_stage="binary_to_source")
        self.manager._stage_sequence_for_task = lambda _task: ["system_analysis", "binary_to_source", "entry_analysis"]

        scope = self.manager._runtime_policy_effect_scope(task)

        self.assertEqual("future_stage_only", scope["system_analysis"])
        self.assertEqual("next_dispatch_batch", scope["binary_to_source"])
        self.assertEqual("tail_claim_immediate", scope["entry_analysis"])

    def test_resolve_downstream_token_prefers_explicit_value(self):
        self.manager.cfg.auth_service.service_machine_token = "service-token"
        self.assertEqual("preferred", self.manager._resolve_downstream_token(" preferred "))
        self.assertEqual("service-token", self.manager._resolve_downstream_token())

    def test_root_task_key_secret_reads_summary_runtime_keys(self):
        task = self._task(summary={"runtime_task_keys": {"root_task_key_secret": "secret-1"}})
        self.assertEqual("secret-1", self.manager._root_task_key_secret(task))

    def test_task_runtime_phase_and_control_mode_follow_phase_and_terminal_state(self):
        task = self._task(status="success", runtime_phase=None)
        self.assertEqual(TASK_RUNTIME_PHASE_TERMINAL, self.manager._task_runtime_phase(task))
        self.assertEqual(TASK_RUNTIME_PHASE_TERMINAL, self.manager._task_control_mode(task))

        self.manager._set_task_runtime_phase(task, "")
        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, self.manager._task_runtime_phase(task))

    def test_repair_running_lease_invariant_requeues_owned_execution_task_without_active_lease(self):
        task = self._task(
            status="running",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[], events=[])
        repaired = self.manager._repair_running_lease_invariant(
            db,
            task,
            reason="unit_test",
            stage_name="system_analysis",
        )

        self.assertTrue(repaired)
        self.assertEqual("pending", task.status)
        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, self.manager._task_runtime_phase(task))
        self.assertEqual("idle", task.tail_reconcile_state)
        self.assertEqual(
            [{"task_id": "task-1", "context": "owned_execution_release_for_takeover"}],
            self.fake_task_queue.requeued_tasks,
        )
        self.assertIn("running_without_active_lease_requeued", [row.event_type for row in db.events])

    def test_repair_running_lease_invariant_keeps_tail_task_with_active_runtime_lease(self):
        task = self._task(
            status="running",
            current_stage="dataflow_vuln_scan",
            runtime_phase="tail_reconciliation",
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-a",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[lease], events=[])

        self.manager._enqueue_task = lambda _task_id: self.fail("should not enqueue healthy tail task")
        repaired = self.manager._repair_running_lease_invariant(
            db,
            task,
            reason="unit_test",
        )

        self.assertFalse(repaired)
        self.assertEqual("running", task.status)
        self.assertEqual([], db.events)

    def test_repair_running_lease_invariant_defers_when_runtime_lease_clear_hits_lock_conflict(self):
        task = self._task(
            status="running",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-a",
            lease_expires_at=_now() - timedelta(minutes=1),
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[lease], events=[])
        original_clear = self.manager._clear_runtime_lease

        def _defer_clear(*_args, **_kwargs):
            return task_manager_module.RuntimeLeaseClearResult(
                status="lease_locked_retry_later",
                task_id=task.id,
                owner_instance_id="worker-a",
                error_message="deadlock",
            )

        self.manager._clear_runtime_lease = _defer_clear
        try:
            repaired = self.manager._repair_running_lease_invariant(
                db,
                task,
                reason="unit_test_lock_conflict",
                stage_name="system_analysis",
            )
        finally:
            self.manager._clear_runtime_lease = original_clear

        self.assertFalse(repaired)
        self.assertEqual("running", task.status)
        event_types = [row.event_type for row in db.events]
        self.assertIn("parent_takeover_lock_acquired", event_types)
        self.assertIn("parent_takeover_recovery_deferred_by_db_lock", event_types)

    def test_repair_running_tasks_without_active_lease_uses_single_task_sessions_for_real_session_path(self):
        class _CountingDb(_ModelAwareDb):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                self.commit_count = 0
                self.rollback_count = 0

            def commit(self):
                self.commit_count += 1

            def rollback(self):
                self.rollback_count += 1
                return None

        task1 = self._task(id="task-1", current_stage="system_analysis")
        task2 = self._task(id="task-2", current_stage="entry_analysis")
        outer_db = _CountingDb(tasks=[task1, task2], runtime_leases=[], events=[])
        task_db_1 = _CountingDb(tasks=[task1], runtime_leases=[], events=[])
        task_db_2 = _CountingDb(tasks=[task2], runtime_leases=[], events=[])
        session_sequence = [task_db_1, task_db_2]

        def _next_session():
            return session_sequence.pop(0)

        calls: list[tuple[str, str]] = []

        def _repair_single(session, task_id):
            calls.append((task_id, getattr(session.tasks[0], "id", None)))
            return task_id == "task-1"

        with (
            patch("app.service.task.runtime.Session", _CountingDb),
            patch("app.service.task_manager.get_session_factory", return_value=_next_session),
            patch.object(self.manager, "_running_without_active_lease_candidate_task_ids", return_value=["task-1", "task-2"]),
            patch.object(self.manager, "_repair_running_lease_invariant_single_task_locked", side_effect=_repair_single),
        ):
            repaired = self.manager._repair_running_tasks_without_active_lease_locked(outer_db)

        self.assertTrue(repaired)
        self.assertEqual([("task-1", "task-1"), ("task-2", "task-2")], calls)
        self.assertEqual(1, task_db_1.commit_count)
        self.assertEqual(0, task_db_1.rollback_count)
        self.assertEqual(0, task_db_2.commit_count)
        self.assertEqual(1, task_db_2.rollback_count)

    def test_repair_running_lease_invariant_single_task_locked_skips_pending_claim_task(self):
        task = self._task(
            status="running",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            summary={
                "parent_takeover_pending_claim": {
                    "active": True,
                    "released_at": _now().isoformat(),
                    "enqueue_context": "owned_execution_release_for_takeover",
                }
            },
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[], events=[])

        repaired = self.manager._repair_running_lease_invariant_single_task_locked(db, task.id)

        self.assertFalse(repaired)
        self.assertEqual("running", task.status)
        self.assertEqual([], db.events)


if __name__ == "__main__":
    unittest.main()
