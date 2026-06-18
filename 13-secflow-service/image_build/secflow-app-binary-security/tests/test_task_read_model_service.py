import unittest

from app.service.task.read_model import TaskReadModelServiceMixin
from app.service.task_manager import TaskManager


class TaskReadModelServiceStructureTests(unittest.TestCase):
    def test_task_manager_read_model_methods_are_bound_to_mixin(self):
        self.assertIs(TaskManager._build_task_detail_context, TaskReadModelServiceMixin._build_task_detail_context)
        self.assertIs(TaskManager._build_light_task_detail_context, TaskReadModelServiceMixin._build_light_task_detail_context)
        self.assertIs(TaskManager._runtime_health_age_status, TaskReadModelServiceMixin._runtime_health_age_status)
        self.assertIs(TaskManager._runtime_health_summary_message, TaskReadModelServiceMixin._runtime_health_summary_message)
        self.assertIs(TaskManager._build_runtime_health_unit, TaskReadModelServiceMixin._build_runtime_health_unit)
        self.assertIs(TaskManager._build_task_runtime_health, TaskReadModelServiceMixin._build_task_runtime_health)
        self.assertIs(TaskManager._build_queue_info, TaskReadModelServiceMixin._build_queue_info)
        self.assertIs(TaskManager._task_list_stage_state_by_task, TaskReadModelServiceMixin._task_list_stage_state_by_task)
        self.assertIs(TaskManager._task_list_response, TaskReadModelServiceMixin._task_list_response)
        self.assertIs(TaskManager._task_list_operation_maps, TaskReadModelServiceMixin._task_list_operation_maps)
        self.assertIs(TaskManager._load_task_list_cached_value, TaskReadModelServiceMixin._load_task_list_cached_value)
        self.assertIs(TaskManager._load_readonly_projection_cached_value, TaskReadModelServiceMixin._load_readonly_projection_cached_value)
        self.assertIs(TaskManager._log_task_read_projection_built, TaskReadModelServiceMixin._log_task_read_projection_built)
        self.assertIs(TaskManager._log_task_list_query, TaskReadModelServiceMixin._log_task_list_query)
        self.assertIs(TaskManager._task_abnormal_reason, TaskReadModelServiceMixin._task_abnormal_reason)
        self.assertIs(TaskManager._build_stage_summaries, TaskReadModelServiceMixin._build_stage_summaries)
        self.assertIs(TaskManager._build_stage_overview_nodes, TaskReadModelServiceMixin._build_stage_overview_nodes)
        self.assertIs(TaskManager._stage_item_sync_freshness_state, TaskReadModelServiceMixin._stage_item_sync_freshness_state)
        self.assertIs(TaskManager._format_downstream_status_label, TaskReadModelServiceMixin._format_downstream_status_label)
        self.assertIs(TaskManager._stage_item_display_downstream_status, TaskReadModelServiceMixin._stage_item_display_downstream_status)
        self.assertIs(TaskManager._stage_item_response_sort_value, TaskReadModelServiceMixin._stage_item_response_sort_value)
        self.assertIs(TaskManager._filter_stage_item_responses, TaskReadModelServiceMixin._filter_stage_item_responses)
        self.assertIs(TaskManager._sort_stage_item_responses, TaskReadModelServiceMixin._sort_stage_item_responses)
        self.assertIs(TaskManager._stage_item_response, TaskReadModelServiceMixin._stage_item_response)
        self.assertIs(TaskManager._task_response, TaskReadModelServiceMixin._task_response)


if __name__ == "__main__":
    unittest.main()
