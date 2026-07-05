import unittest

from app.service.task.lifecycle import TaskLifecycleServiceMixin
from app.service.task_manager import TaskManager


class TaskLifecycleServiceStructureTests(unittest.TestCase):
    def test_task_manager_lifecycle_methods_are_bound_to_lifecycle_mixin(self):
        self.assertIs(TaskManager._task_operation_lock_ttl_seconds, TaskLifecycleServiceMixin._task_operation_lock_ttl_seconds)
        self.assertIs(TaskManager._task_operation_lock_heartbeat_interval_seconds, TaskLifecycleServiceMixin._task_operation_lock_heartbeat_interval_seconds)
        self.assertIs(TaskManager._operation_step_batch_size, TaskLifecycleServiceMixin._operation_step_batch_size)
        self.assertIs(TaskManager._loop_stale_threshold_seconds, TaskLifecycleServiceMixin._loop_stale_threshold_seconds)
        self.assertIs(TaskManager._mark_loop_heartbeat, TaskLifecycleServiceMixin._mark_loop_heartbeat)
        self.assertIs(TaskManager._recover_loop_db_error, TaskLifecycleServiceMixin._recover_loop_db_error)
        self.assertIs(TaskManager._loop_runtime_detail, TaskLifecycleServiceMixin._loop_runtime_detail)
        self.assertIs(TaskManager._collect_runtime_metrics_snapshot_sync, TaskLifecycleServiceMixin._collect_runtime_metrics_snapshot_sync)
        self.assertIs(TaskManager._observe_worker_counts, TaskLifecycleServiceMixin._observe_worker_counts)
        self.assertIs(TaskManager._observe_runtime_metrics, TaskLifecycleServiceMixin._observe_runtime_metrics)
        self.assertIs(TaskManager._archive_dispatch_loop, TaskLifecycleServiceMixin._archive_dispatch_loop)
        self.assertIs(TaskManager._schedule_archive_workers, TaskLifecycleServiceMixin._schedule_archive_workers)
        self.assertIs(TaskManager._archive_worker, TaskLifecycleServiceMixin._archive_worker)
        self.assertIs(TaskManager._downstream_reconcile_loop, TaskLifecycleServiceMixin._downstream_reconcile_loop)
        self.assertIs(TaskManager._stage_item_sync_reconcile_loop, TaskLifecycleServiceMixin._stage_item_sync_reconcile_loop)
        self.assertIs(TaskManager._list_tasks_with_stale_stage_item_syncs, TaskLifecycleServiceMixin._list_tasks_with_stale_stage_item_syncs)
        self.assertIs(TaskManager._reconcile_downstream_task_ref, TaskLifecycleServiceMixin._reconcile_downstream_task_ref)
        self.assertIs(TaskManager._reconcile_stale_stage_item_sync_ref, TaskLifecycleServiceMixin._reconcile_stale_stage_item_sync_ref)
        self.assertIs(TaskManager._archive_runtime_reconcile_loop, TaskLifecycleServiceMixin._archive_runtime_reconcile_loop)
        self.assertIs(TaskManager._state_repair_reconcile_loop, TaskLifecycleServiceMixin._state_repair_reconcile_loop)
        self.assertIs(TaskManager._reclaim_stale_archive_jobs, TaskLifecycleServiceMixin._reclaim_stale_archive_jobs)


if __name__ == "__main__":
    unittest.main()
