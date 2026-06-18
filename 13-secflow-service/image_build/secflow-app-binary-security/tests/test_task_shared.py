import tempfile
import unittest
from pathlib import Path

from app.service.task import shared as task_shared


class TaskSharedTests(unittest.TestCase):
    def test_deduplicate_entry_keys_preserves_unique_keys(self):
        rows = task_shared._deduplicate_entry_keys(
            [
                {"entry_key": "dup", "function_name": "a", "file_name": "a.c"},
                {"entry_key": "dup", "function_name": "b", "file_name": "b.c"},
            ]
        )

        self.assertEqual(2, len(rows))
        self.assertNotEqual(rows[0]["entry_key"], rows[1]["entry_key"])

    def test_write_and_read_json_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "payload.json"
            payload = {"status": "ok", "count": 2}
            task_shared._write_json(path, payload)
            self.assertEqual(payload, task_shared._read_json(path))

    def test_prefer_specific_paths_prefers_task_scoped_path(self):
        paths = [
            Path("/tmp/output"),
            Path("/tmp/tasks/task-1/output"),
            Path("/tmp/other"),
        ]

        preferred = task_shared._prefer_specific_paths(paths, downstream_task_id="task-1")

        self.assertEqual([Path("/tmp/tasks/task-1/output")], preferred)

    def test_normalize_entry_function_name_extracts_symbol(self):
        self.assertEqual("ns::main", task_shared._normalize_entry_function_name("int ns::main(char *arg)"))


if __name__ == "__main__":
    unittest.main()
