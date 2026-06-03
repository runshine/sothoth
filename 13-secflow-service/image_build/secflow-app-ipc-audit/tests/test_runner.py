from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

from app.core.config import load_config
from app.workers.runner import StageHooks, run_logged_command


class RunLoggedCommandTest(unittest.TestCase):
    def setUp(self) -> None:
        self.state_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-runner-state-")
        self.state_root = Path(self.state_dir.name)
        self._reset_singletons()
        self._set_env("IPC_AUDIT_STATE_ROOT", str(self.state_root))
        self._set_env("IPC_AUDIT_PROCESS_TERMINATE_GRACE_SECONDS", "0.5")
        self._set_env("IPC_AUDIT_CANCEL_CHECK_INTERVAL_SECONDS", "0.2")
        load_config()

    def tearDown(self) -> None:
        for key in (
            "IPC_AUDIT_STATE_ROOT",
            "IPC_AUDIT_PROCESS_TERMINATE_GRACE_SECONDS",
            "IPC_AUDIT_CANCEL_CHECK_INTERVAL_SECONDS",
        ):
            os.environ.pop(key, None)
        self._reset_singletons()
        self.state_dir.cleanup()

    def test_cancel_terminates_descendant_in_separate_process_group(self) -> None:
        child_pid_path = self.state_root / "child.pid"
        script_path = self.state_root / "spawn_child.py"
        script_path.write_text(
            textwrap.dedent(
                f"""
                import subprocess
                import time
                from pathlib import Path

                child = subprocess.Popen(["sleep", "60"], start_new_session=True)
                Path({str(child_pid_path)!r}).write_text(str(child.pid), encoding="utf-8")
                try:
                    time.sleep(60)
                finally:
                    child.poll()
                """
            ),
            encoding="utf-8",
        )
        cancel_after = time.monotonic() + 0.5
        result = run_logged_command(
            [sys.executable, str(script_path)],
            cwd=self.state_root,
            log_path=self.state_root / "run.log",
            log_header="=== test ===\n",
            hooks=StageHooks(
                heartbeat=lambda: None,
                is_cancel_requested=lambda: time.monotonic() >= cancel_after,
            ),
            timeout_seconds=10,
        )

        self.assertTrue(result.cancelled)
        self.assertLess(result.duration_seconds, 3)
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and self._process_exists(child_pid):
            time.sleep(0.05)
        self.assertFalse(self._process_exists(child_pid))

    def test_hook_exception_terminates_descendant_in_separate_process_group(self) -> None:
        child_pid_path = self.state_root / "hook-child.pid"
        script_path = self.state_root / "spawn_hook_child.py"
        script_path.write_text(
            textwrap.dedent(
                f"""
                import subprocess
                import time
                from pathlib import Path

                child = subprocess.Popen(["sleep", "60"], start_new_session=True)
                Path({str(child_pid_path)!r}).write_text(str(child.pid), encoding="utf-8")
                try:
                    time.sleep(60)
                finally:
                    child.poll()
                """
            ),
            encoding="utf-8",
        )
        checks = 0

        def fail_after_child_started() -> bool:
            nonlocal checks
            checks += 1
            if child_pid_path.exists() and checks >= 2:
                raise RuntimeError("cancel check failed")
            return False

        with self.assertRaisesRegex(RuntimeError, "cancel check failed"):
            run_logged_command(
                [sys.executable, str(script_path)],
                cwd=self.state_root,
                log_path=self.state_root / "hook-run.log",
                log_header="=== test ===\n",
                hooks=StageHooks(
                    heartbeat=lambda: None,
                    is_cancel_requested=fail_after_child_started,
                ),
                timeout_seconds=10,
            )

        child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and self._process_exists(child_pid):
            time.sleep(0.05)
        self.assertFalse(self._process_exists(child_pid))

    @staticmethod
    def _process_exists(pid: int) -> bool:
        try:
            completed = subprocess.run(
                ["ps", "-o", "stat=", "-p", str(pid)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
            )
        except OSError:
            return False
        state = completed.stdout.strip()
        return completed.returncode == 0 and bool(state) and not state.startswith("Z")

    @staticmethod
    def _set_env(key: str, value: str) -> None:
        os.environ[key] = value

    @staticmethod
    def _reset_singletons() -> None:
        import app.core.config as config_module

        config_module._config = None


if __name__ == "__main__":
    unittest.main()
