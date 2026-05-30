import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.evolution_engine import _publish_tool_to_store


class EvolutionPublishTests(unittest.TestCase):
    def test_publish_tool_to_store_keeps_evolved_versioned_tool_even_when_final_round_not_changed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store_dir = root / "tools" / "store"
            source_dir = root / "tools" / "active"
            source_dir.mkdir(parents=True, exist_ok=True)
            store_dir.mkdir(parents=True, exist_ok=True)

            source_target = store_dir / "20260527" / "huawei-cc-00000002-v5-20260527171433.py"
            source_target.parent.mkdir(parents=True, exist_ok=True)
            source_target.write_text("# old\n", encoding="utf-8")
            source_link = source_dir / "huawei-cc-00000002.py"
            source_link.symlink_to(source_target.relative_to(source_link.parent))

            working_dir = root / "run" / "working_tool"
            working_dir.mkdir(parents=True, exist_ok=True)
            working_tool = working_dir / "huawei-cc-00000002-v6-20260528141625.py"
            working_tool.write_text(
                "\n".join(
                    [
                        "#!/usr/bin/env python3",
                        "# format_id: huawei-cc-00000002",
                        "# description: test",
                        "# extensions: cc",
                        "# magic_hex: 00000002",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with patch("app.evolution_engine.TOOLS_STORE_DIR", store_dir):
                published = _publish_tool_to_store(
                    firmware_path=str(root / "NE20E.cc"),
                    working_tool=working_tool,
                    source_tool=source_link,
                    tool_changed=False,
                )

            self.assertIn("/202605", published)
            self.assertTrue(Path(published).is_file())
            self.assertNotEqual(str(source_link), published)


if __name__ == "__main__":
    unittest.main()
