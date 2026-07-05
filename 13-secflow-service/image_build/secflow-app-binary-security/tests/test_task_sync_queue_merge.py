import unittest

from app.service.task_queue import TaskQueue


class TaskSyncQueueMergeTests(unittest.TestCase):
    def test_merge_task_sync_entries_accepts_lists_and_dict_payloads(self):
        existing = {
            "queue_item_id": "tsq_1",
            "dedupe_key": "sync:a",
            "item_ids": ["i1"],
            "archive_job_ids": ["j1"],
            "payload": {"a": 1},
            "force": False,
            "attempts": 2,
            "priority": 50,
        }
        incoming = {
            "queue_item_id": "tsq_1",
            "dedupe_key": "sync:a",
            "item_ids": ["i2"],
            "archive_job_ids": ["j2"],
            "payload": {"b": 2},
            "force": True,
            "attempts": 1,
            "priority": 40,
        }

        merged = TaskQueue._merge_task_sync_entries(existing, incoming)

        self.assertEqual(["j1", "j2"], merged["archive_job_ids"])
        self.assertEqual(["i1", "i2"], merged["item_ids"])
        self.assertEqual({"a": 1, "b": 2}, merged["payload"])
        self.assertTrue(merged["force"])
        self.assertEqual(1, merged["attempts"])
        self.assertEqual(40, merged["priority"])


if __name__ == "__main__":
    unittest.main()
