import subprocess
import unittest
from pathlib import Path
import re


class TaskStatusGuardrailTests(unittest.TestCase):
    def test_task_status_assignments_are_limited_to_allowed_files(self):
        repo_root = Path(__file__).resolve().parents[1]
        assignment_pattern = re.compile(r"\btask\.status\s*=(?!=)")
        lines = []
        for path in sorted((repo_root / "app").rglob("*.py")):
            for lineno, raw_line in enumerate(path.read_text().splitlines(), 1):
                if assignment_pattern.search(raw_line):
                    lines.append(f"{path}:{lineno}:{raw_line.strip()}")
        allowed_fragments = {
            "app/service/task/events.py",
            "app/service/task/operation.py:64:",
            "app/service/task/operation.py:3640:",
        }
        violations = [line for line in lines if not any(fragment in line for fragment in allowed_fragments)]
        self.assertEqual([], violations)


if __name__ == "__main__":
    unittest.main()
