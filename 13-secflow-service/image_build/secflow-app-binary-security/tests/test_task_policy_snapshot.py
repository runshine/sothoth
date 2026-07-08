import unittest

from app.model import (
    BinarySecurityTask,
    PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN,
    TASK_TYPE_BINARY_MODULE,
    TASK_TYPE_SOURCE,
)
from app.service.task_manager import TaskManager
from test_task_manager import _ModelAwareDb


class TaskPolicySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_task_detail_policy_snapshot_for_binary_source_workflow(self):
        task = BinarySecurityTask(
            id="t-policy-snapshot-source",
            project_id="p1",
            name="source-task",
            status="pending",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "pipeline_mode": "mixed_streaming",
            "module_selection_mode": "auto",
            "module_risk_levels": ["高", "中"],
            "entry_selection_mode": "auto",
            "entry_auto_selection_strategy": "top_n_per_module_by_confidence",
            "entry_auto_selection_top_n": 15,
            "stage_options": {"entry_analysis": {"enabled": True}, "dataflow_vuln_scan": {"enabled": False}},
            "stage_parallelism": {"system_analysis": 2, "entry_analysis": 3, "dataflow_vuln_scan": 4},
            "partial_success_stage_advancement": {"entry_analysis": True},
            "continue_on_item_failure": True,
        }
        db = _ModelAwareDb(tasks=[task], stage_runs=[], stage_items=[], archive_jobs=[])

        detail = self.manager.get_task_detail(db, project_id="p1", task_id=task.id)

        snapshot = detail.policy_snapshot
        self.assertEqual("default", snapshot["workflow"]["pipeline_profile"])
        self.assertEqual("mixed_streaming", snapshot["workflow"]["pipeline_mode"])
        self.assertIn("module_strategy", snapshot["display_sections"])
        self.assertIn("entry_strategy", snapshot["display_sections"])
        self.assertEqual("top_n", snapshot["entry_strategy"]["display_mode"])
        self.assertEqual(15, snapshot["entry_strategy"]["entry_auto_selection_top_n"])
        self.assertEqual(["高", "中"], snapshot["module_strategy"]["module_risk_levels"])
        self.assertTrue(snapshot["stage_execution"]["continue_on_item_failure"])

    def test_task_detail_policy_snapshot_for_kg_workflow_uses_kg_entry_top_n(self):
        task = BinarySecurityTask(
            id="t-policy-snapshot-kg",
            project_id="p1",
            name="kg-task",
            status="pending",
            task_type=TASK_TYPE_SOURCE,
            current_stage="knowledge_graph_entry_fetch",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "pipeline_profile": PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN,
            "entry_selection_mode": "manual_confirm",
            "entry_auto_selection_strategy": "top_n_per_module_by_confidence",
            "entry_auto_selection_top_n": 9,
            "entry_analysis_auto_selection_top_n": 3,
            "knowledge_graph_entry_auto_selection_top_n": 9,
            "knowledge_graph_db_name": "kg-prod",
            "knowledge_graph_kind": "source",
            "knowledge_graph_module": "libxml2",
            "knowledge_graph_status_filter": "confirmed",
            "knowledge_graph_include_excluded": True,
        }
        db = _ModelAwareDb(tasks=[task], stage_runs=[], stage_items=[], archive_jobs=[])

        detail = self.manager.get_task_detail(db, project_id="p1", task_id=task.id)

        snapshot = detail.policy_snapshot
        self.assertEqual(PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN, snapshot["workflow"]["pipeline_profile"])
        self.assertTrue(snapshot["knowledge_graph_strategy"]["applicable"])
        self.assertEqual("top_n", snapshot["entry_strategy"]["display_mode"])
        self.assertEqual("自动 / 知识图谱 Top 9", snapshot["entry_strategy"]["display_label"])
        self.assertEqual(9, snapshot["entry_strategy"]["entry_auto_selection_top_n"])
        self.assertEqual(3, snapshot["entry_strategy"]["entry_analysis_auto_selection_top_n"])
        self.assertEqual(9, snapshot["entry_strategy"]["knowledge_graph_entry_auto_selection_top_n"])
        self.assertEqual(9, snapshot["knowledge_graph_strategy"]["entry_auto_selection_top_n"])
        self.assertEqual("kg-prod", snapshot["knowledge_graph_strategy"]["knowledge_graph_db_name"])
        self.assertEqual("libxml2", snapshot["knowledge_graph_strategy"]["knowledge_graph_module"])

    def test_task_detail_policy_snapshot_for_binary_module_hides_module_strategy(self):
        task = BinarySecurityTask(
            id="t-policy-snapshot-module",
            project_id="p1",
            name="module-task",
            status="pending",
            task_type=TASK_TYPE_BINARY_MODULE,
            current_stage="binary_to_source",
            firmware_source="project_filesystem",
            firmware_path="/fw.elf",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "pipeline_mode": "barrier",
            "stage_parallelism": {"binary_to_source": 2, "entry_analysis": 2, "dataflow_vuln_scan": 1},
        }
        db = _ModelAwareDb(tasks=[task], stage_runs=[], stage_items=[], archive_jobs=[])

        detail = self.manager.get_task_detail(db, project_id="p1", task_id=task.id)

        snapshot = detail.policy_snapshot
        self.assertFalse(snapshot["module_strategy"]["applicable"])
        self.assertNotIn("module_strategy", snapshot["display_sections"])
        self.assertIn("entry_strategy", snapshot["display_sections"])


if __name__ == "__main__":
    unittest.main()
