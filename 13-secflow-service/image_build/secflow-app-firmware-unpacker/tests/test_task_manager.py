import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services.task_manager import prepare_task_workspace, resolve_task_runtime_paths


class TaskManagerWorkspaceTests(unittest.TestCase):
    def test_prepare_task_workspace_writes_manifest_without_copying_firmware(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            firmware = root / "firmware.bin"
            firmware.write_bytes(b"firmware")

            with patch("app.services.task_manager.PROJECT_FILES_ROOT", root / "data"):
                prepared = prepare_task_workspace("p1", "t1", str(firmware))

            input_dir = root / "data" / "p1" / "app/secflow-app-firmware-unpacker" / "t1" / "input"
            manifest_path = input_dir / "task.json"
            copied_firmware = input_dir / firmware.name

            self.assertEqual(str(firmware), prepared["input_path"])
            self.assertTrue(manifest_path.is_file())
            self.assertFalse(copied_firmware.exists())
            self.assertEqual(
                {
                    "input_path": str(firmware),
                    "output_path": prepared["output_path"],
                    "log_path": prepared["run_path"],
                },
                json.loads(manifest_path.read_text(encoding="utf-8")),
            )

    def test_resolve_task_runtime_paths_refreshes_manifest_and_uses_original_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            firmware = root / "fw.bin"
            firmware.write_bytes(b"x")

            with patch("app.services.task_manager.PROJECT_FILES_ROOT", root / "data"):
                prepare_task_workspace("p1", "t1", str(firmware))
                resolved = resolve_task_runtime_paths("t1", "p1", str(firmware), "/ignored/output")

            manifest_path = root / "data" / "p1" / "app/secflow-app-firmware-unpacker" / "t1" / "input" / "task.json"
            self.assertEqual(str(firmware), resolved["input_path"])
            self.assertTrue(manifest_path.is_file())
            self.assertEqual(str(root / "data" / "p1" / "app/secflow-app-firmware-unpacker" / "t1" / "output"), resolved["output_path"])


if __name__ == "__main__":
    unittest.main()
