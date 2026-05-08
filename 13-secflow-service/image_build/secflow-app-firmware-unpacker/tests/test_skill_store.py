import tempfile
import unittest
from pathlib import Path

from app.skill_store import (
    SKILL_STATUS_ACTIVE,
    SKILL_STATUS_ARCHIVED,
    SKILL_STATUS_CANDIDATE,
    compute_family_id,
    match_skill,
    parse_skill_metadata,
    register_skill_success,
    save_candidate_skill,
)


def _skill_doc(*, name: str, family_id: str, status: str, version: int, count: int = 0) -> str:
    return f"""---
name: {name}
description: test skill
format_id: squashfs-fw
extensions: bin, img
magic_hex: 68737173
keywords: squashfs, linux
binwalk_sigs: squashfs filesystem
skill_status: {status}
skill_version: {version}
family_id: {family_id}
promotion_success_count: {count}
promotion_threshold: 5
tools:
---

You are a reusable skill.
"""


class SkillStoreTests(unittest.TestCase):
    def test_match_skill_prefers_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "family-a__v1.md").write_text(
                _skill_doc(name="active-skill", family_id="family-a", status=SKILL_STATUS_ACTIVE, version=1),
                encoding="utf-8",
            )
            features = {
                "filename": "firmware.bin",
                "ext": "bin",
                "ext2": "",
                "fmt": "squashfs",
                "magic_hex": "68737173",
                "binwalk_sigs": ["squashfs filesystem"],
            }
            matched, score, info = match_skill(features, root)
            self.assertIsNotNone(matched)
            self.assertEqual(SKILL_STATUS_ACTIVE, info["matched_status"])
            self.assertGreaterEqual(score, 50)

    def test_save_candidate_skill_assigns_candidate_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            saved = save_candidate_skill(
                root,
                _skill_doc(name="candidate-skill", family_id="family-a", status=SKILL_STATUS_CANDIDATE, version=1),
                {"family_id": "family-a", "source_run_id": "run-1", "source_node_id": "generic_executor"},
            )
            self.assertEqual(SKILL_STATUS_CANDIDATE, saved["skill_status"])
            self.assertEqual(0, saved["promotion_success_count"])
            self.assertEqual(5, saved["promotion_threshold"])
            self.assertEqual("run-1", saved["source_run_id"])
            self.assertEqual("generic_executor", saved["source_node_id"])

    def test_register_skill_success_promotes_candidate_and_archives_old_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            active_path = root / "family-a__v1.md"
            active_path.write_text(
                _skill_doc(name="active-skill", family_id="family-a", status=SKILL_STATUS_ACTIVE, version=1),
                encoding="utf-8",
            )
            candidate_path = root / "family-a__candidate__1.md"
            candidate_path.write_text(
                _skill_doc(
                    name="candidate-skill",
                    family_id="family-a",
                    status=SKILL_STATUS_CANDIDATE,
                    version=2,
                    count=4,
                ),
                encoding="utf-8",
            )

            updated = register_skill_success(root, str(candidate_path))
            archived = parse_skill_metadata(active_path)

            self.assertEqual(SKILL_STATUS_ACTIVE, updated["skill_status"])
            self.assertEqual(5, updated["promotion_success_count"])
            self.assertEqual(SKILL_STATUS_ARCHIVED, archived["skill_status"])

    def test_compute_family_id_is_stable(self):
        family_id = compute_family_id(
            {
                "fmt": "squashfs",
                "ext": "bin",
                "magic_hex": "68737173abcd",
                "binwalk_sigs": ["Squashfs filesystem little endian"],
            }
        )
        self.assertIn("squashfs", family_id)


if __name__ == "__main__":
    unittest.main()
