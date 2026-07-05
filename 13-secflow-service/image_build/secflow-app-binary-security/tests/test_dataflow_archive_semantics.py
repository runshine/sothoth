import unittest

from app.model import (
    BinarySecurityArchiveJob,
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    TASK_TYPE_BINARY,
    TASK_TYPE_BINARY_MODULE,
    TASK_TYPE_SOURCE,
)
from app.service.task_manager import TaskManager
from test_task_manager import _ModelAwareDb, _now


class DataflowArchiveSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def _task(self):
        task = BinarySecurityTask(
            id="task-dataflow-archive",
            project_id="project-1",
            name="task",
            task_type=TASK_TYPE_SOURCE,
            status="running",
            current_stage="dataflow_vuln_scan",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp/ws",
        )
        task.policy = {"pipeline_mode": "mixed_streaming"}
        return task

    def _task_for_type(self, task_type: str) -> BinarySecurityTask:
        task = BinarySecurityTask(
            id=f"task-{task_type}",
            project_id="project-1",
            name="task",
            task_type=task_type,
            status="running",
            current_stage="dataflow_vuln_scan",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root=f"/tmp/ws-{task_type}",
        )
        task.policy = {"pipeline_mode": "mixed_streaming"}
        return task

    def test_dataflow_stage_summary_carries_archive_progress_without_changing_stage_status(self):
        task = self._task()
        stage_run = BinarySecurityStageRun(
            id="sr-dataflow",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="partial_success",
            started_at=_now(),
            finished_at=_now(),
        )
        items = [
            BinarySecurityStageItem(
                id="si-success-1",
                task_id=task.id,
                project_id=task.project_id,
                stage_run_id=stage_run.id,
                stage_name=stage_run.stage_name,
                item_key="entry-1",
                status="success",
            ),
            BinarySecurityStageItem(
                id="si-success-2",
                task_id=task.id,
                project_id=task.project_id,
                stage_run_id=stage_run.id,
                stage_name=stage_run.stage_name,
                item_key="entry-2",
                status="success",
            ),
            BinarySecurityStageItem(
                id="si-failed-1",
                task_id=task.id,
                project_id=task.project_id,
                stage_run_id=stage_run.id,
                stage_name=stage_run.stage_name,
                item_key="entry-3",
                status="failed",
                error_message="boom",
            ),
        ]
        archive_jobs = [
            BinarySecurityArchiveJob(
                id="aj-1",
                task_id=task.id,
                project_id=task.project_id,
                stage_name="dataflow_vuln_scan",
                item_id="si-success-1",
                archive_status="success",
            ),
        ]
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=items, archive_jobs=archive_jobs)

        summaries = self.manager._build_stage_summaries(
            db,
            task,
            ["system_analysis", "entry_analysis", "dataflow_vuln_scan"],
            [stage_run],
            items,
        )
        summary = next(row for row in summaries if row.stage_name == "dataflow_vuln_scan")

        self.assertEqual("partial_success", summary.status)
        self.assertIsNotNone(summary.archive_progress)
        self.assertEqual("success", summary.archive_progress.status)
        self.assertEqual(2, summary.archive_progress.expected_success_item_count)
        self.assertEqual(1, summary.archive_progress.archived_success_item_count)
        self.assertEqual(1, summary.archive_progress.missing_archive_item_count)

    def test_dataflow_overview_keeps_single_business_node_and_embeds_archive_progress(self):
        task = self._task()
        stage_run = BinarySecurityStageRun(
            id="sr-dataflow-overview",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=2,
            status="success",
            started_at=_now(),
            finished_at=_now(),
        )
        items = [
            BinarySecurityStageItem(
                id="si-success-a",
                task_id=task.id,
                project_id=task.project_id,
                stage_run_id=stage_run.id,
                stage_name=stage_run.stage_name,
                item_key="entry-a",
                status="success",
            )
        ]
        archive_jobs = [
            BinarySecurityArchiveJob(
                id="aj-success-a",
                task_id=task.id,
                project_id=task.project_id,
                stage_name="dataflow_vuln_scan",
                item_id="si-success-a",
                archive_status="running",
            )
        ]
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=items, archive_jobs=archive_jobs)
        summaries = self.manager._build_stage_summaries(
            db,
            task,
            ["knowledge_graph_entry_fetch", "dataflow_vuln_scan"],
            [stage_run],
            items,
        )

        nodes = self.manager._build_stage_overview_nodes(
            db,
            task,
            summaries,
            archive_jobs,
            items,
        )

        dataflow_nodes = [node for node in nodes if node.stage_name == "dataflow_vuln_scan"]
        self.assertEqual(1, len(dataflow_nodes))
        self.assertEqual("business", dataflow_nodes[0].node_type)
        self.assertIsNotNone(dataflow_nodes[0].detail.archive_progress)
        self.assertEqual("running", dataflow_nodes[0].detail.archive_progress.status)
        self.assertEqual([], [node for node in nodes if node.node_id == "archive:dataflow_vuln_scan"])

    def test_stage_summary_snapshot_round_trips_dataflow_archive_progress(self):
        task = self._task()
        task.stage_summary = {
            "dataflow_vuln_scan": {
                "sequence_no": 3,
                "status": "partial_success",
                "success_items": 2,
                "failed_items": 1,
                "archive_progress": {
                    "status": "running",
                    "expected_success_item_count": 2,
                    "archived_success_item_count": 1,
                    "missing_archive_item_count": 1,
                    "job_count": 2,
                    "success_count": 1,
                    "failed_count": 0,
                    "running_count": 1,
                    "applying_count": 0,
                    "pending_count": 0,
                    "latest_error": None,
                },
            }
        }

        summaries = self.manager._build_stage_summaries_from_snapshot(
            task,
            ["system_analysis", "entry_analysis", "dataflow_vuln_scan"],
        )
        summary = next(row for row in summaries if row.stage_name == "dataflow_vuln_scan")

        self.assertIsNotNone(summary.archive_progress)
        self.assertEqual("running", summary.archive_progress.status)
        self.assertEqual(1, summary.archive_progress.missing_archive_item_count)

    def test_stage_runtime_persists_dataflow_archive_progress_into_output_summary(self):
        task = self._task()
        stage_run = BinarySecurityStageRun(
            id="sr-dataflow-runtime",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="running",
            started_at=_now(),
        )
        item = BinarySecurityStageItem(
            id="si-dataflow-runtime",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=stage_run.id,
            stage_name=stage_run.stage_name,
            item_key="entry-runtime",
            status="success",
        )
        archive_job = BinarySecurityArchiveJob(
            id="aj-runtime",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            item_id=item.id,
            archive_status="success",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[item], archive_jobs=[archive_job], events=[])

        self.manager._refresh_stage_run_from_items(db, task, "dataflow_vuln_scan")

        output_summary = dict(stage_run.output_summary or {})
        self.assertIn("archive_progress", output_summary)
        self.assertEqual("success", dict(output_summary["archive_progress"]).get("status"))
        self.assertEqual(1, dict(output_summary["archive_progress"]).get("archived_success_item_count"))

    def test_dataflow_terminalization_ready_requires_entry_terminal_and_archived_for_all_streaming_pipeline_types(self):
        for task_type in (TASK_TYPE_SOURCE, TASK_TYPE_BINARY_MODULE, TASK_TYPE_BINARY):
            with self.subTest(task_type=task_type):
                task = self._task_for_type(task_type)
                entry_run = BinarySecurityStageRun(
                    id=f"sr-entry-{task_type}",
                    task_id=task.id,
                    project_id=task.project_id,
                    stage_name="entry_analysis",
                    sequence_no=2,
                    status="running",
                    started_at=_now(),
                )
                entry_item = BinarySecurityStageItem(
                    id=f"si-entry-{task_type}",
                    task_id=task.id,
                    project_id=task.project_id,
                    stage_run_id=entry_run.id,
                    stage_name="entry_analysis",
                    item_key=f"entry-{task_type}",
                    status="success",
                )
                db = _ModelAwareDb(tasks=[task], stage_runs=[entry_run], stage_items=[entry_item], archive_jobs=[], events=[])

                self.assertFalse(self.manager._streaming_dataflow_terminalization_ready(db, task))

                entry_run.status = "success"
                self.assertFalse(self.manager._streaming_dataflow_terminalization_ready(db, task))

                archive_job = BinarySecurityArchiveJob(
                    id=f"aj-entry-{task_type}",
                    task_id=task.id,
                    project_id=task.project_id,
                    stage_name="entry_analysis",
                    item_id=entry_item.id,
                    archive_status="success",
                )
                db.archive_jobs.append(archive_job)
                self.assertFalse(self.manager._streaming_dataflow_terminalization_ready(db, task))

                task.summary = {
                    "entry_results": [
                        {
                            "module_key": "module-a",
                            "entries": [
                                {
                                    "entry_key": f"entry-{task_type}",
                                    "module_key": "module-a",
                                    "function_name": "main",
                                }
                            ],
                        }
                    ]
                }
                dataflow_item = BinarySecurityStageItem(
                    id=f"si-dataflow-{task_type}",
                    task_id=task.id,
                    project_id=task.project_id,
                    stage_run_id="sr-dataflow",
                    stage_name="dataflow_vuln_scan",
                    item_key=f"entry-{task_type}",
                    status="running",
                )
                db.stage_items.append(dataflow_item)
                self.assertTrue(self.manager._streaming_dataflow_terminalization_ready(db, task))


if __name__ == "__main__":
    unittest.main()
