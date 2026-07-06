import unittest
from datetime import timedelta

from app.model import (
    BinarySecurityTask,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_RUNTIME_PHASE_TERMINAL,
    TASK_TYPE_BINARY,
)
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
        enqueued: list[str] = []

        self.manager._enqueue_task = lambda task_id: enqueued.append(task_id)
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
        self.assertEqual(["task-1"], enqueued)
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


if __name__ == "__main__":
    unittest.main()
