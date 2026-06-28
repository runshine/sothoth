import os
import tempfile
import unittest
from unittest.mock import patch

from app.probe_runtime import ProbeRuntime


class ProbeRuntimeTests(unittest.TestCase):
    def test_startup_ok_after_started_at_marker_without_waiting_grace_window(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pid_file = os.path.join(temp_dir, "main.pid")
            started_at_file = os.path.join(temp_dir, "main.started_at")
            with open(pid_file, "w", encoding="utf-8") as handle:
                handle.write("12345\n")
            with open(started_at_file, "w", encoding="utf-8") as handle:
                handle.write("1.0\n")

            with patch.dict(
                os.environ,
                {
                    "SECFLOW_MAIN_PID_FILE": pid_file,
                    "SECFLOW_MAIN_STARTED_AT_FILE": started_at_file,
                    "SECFLOW_PROBE_STARTUP_GRACE_SECONDS": "300",
                },
                clear=False,
            ), patch.object(ProbeRuntime, "_pid_alive", return_value=True):
                runtime = ProbeRuntime()
                payload, healthy, ready, startup_ok = runtime._status_payload()

        self.assertTrue(healthy)
        self.assertTrue(ready)
        self.assertTrue(startup_ok)
        self.assertEqual(12345, payload["pid"])
        self.assertEqual(300, payload["startup_grace_seconds"])


if __name__ == "__main__":
    unittest.main()
