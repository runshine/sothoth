import tempfile
import unittest
from pathlib import Path

from app.tool_dispatcher import activate_tool_version, read_family_manifest


class ToolDispatcherTests(unittest.TestCase):
    def test_activate_tool_version_points_active_symlink_to_store_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = root / "tools" / "store"
            active = root / "tools" / "active"
            target = store / "20260528" / "huawei-cc-00000002-v6-20260528141625.py"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("# tool\n", encoding="utf-8")

            active_path = activate_tool_version(
                tools_store_dir=store,
                tools_active_dir=active,
                family_id="huawei-cc-00000002",
                target_path=target,
                magic_hex="00000002",
                source="test",
            )

            self.assertTrue(active_path.is_symlink())
            self.assertEqual(target.resolve(), active_path.resolve())
            manifest = read_family_manifest(store, "huawei-cc-00000002")
            self.assertEqual("20260528/huawei-cc-00000002-v6-20260528141625.py", manifest["current_version"])

    def test_activate_tool_version_rejects_non_store_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = root / "tools" / "store"
            active = root / "tools" / "active"
            bad_target = active / "huawei-cc-00000002.py"
            bad_target.parent.mkdir(parents=True, exist_ok=True)
            bad_target.write_text("# bad tool\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "inside tools store"):
                activate_tool_version(
                    tools_store_dir=store,
                    tools_active_dir=active,
                    family_id="huawei-cc-00000002",
                    target_path=bad_target,
                    magic_hex="00000002",
                    source="test",
                )


if __name__ == "__main__":
    unittest.main()
