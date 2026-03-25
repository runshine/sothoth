import os
import subprocess
import time
from typing import Dict, Optional

import psutil

from agent_ai_service.config import settings


class CommandExecutor:
    def __init__(self, timeout: int | None = None):
        self.timeout = timeout or settings.timeout
        self.process = None

    def execute(self, command: str, env_vars: Optional[Dict[str, str]] = None) -> Dict[str, object]:
        result = {
            'success': False,
            'stdout': '',
            'stderr': '',
            'returncode': -1,
            'execution_time': 0,
            'pid': None,
            'error': None,
        }

        if not self._is_command_safe(command):
            result['error'] = 'Command blocked for security reasons'
            return result

        start_time = time.time()
        try:
            env = os.environ.copy()
            if env_vars:
                env.update(env_vars)
            self.process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                env=env,
                preexec_fn=os.setsid,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )
            result['pid'] = self.process.pid
            try:
                stdout, stderr = self.process.communicate(timeout=self.timeout)
                result['stdout'] = stdout
                result['stderr'] = stderr
                result['returncode'] = self.process.returncode
                result['success'] = self.process.returncode == 0
            except subprocess.TimeoutExpired:
                self._terminate_process_tree(self.process.pid)
                result['error'] = f'Command timed out after {self.timeout} seconds'
                result['stderr'] = 'Command execution timeout'
        except Exception as exc:
            result['error'] = str(exc)
        finally:
            result['execution_time'] = round(time.time() - start_time, 3)
        return result

    def _is_command_safe(self, command: str) -> bool:
        for blocked in settings.blocked_commands:
            if blocked in command:
                return False
        allowed = settings.allowed_commands
        if allowed:
            return any(item in command for item in allowed)
        return True

    @staticmethod
    def _terminate_process_tree(pid: int) -> None:
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.terminate()
                except Exception:
                    pass
            parent.terminate()
            gone, alive = psutil.wait_procs(children + [parent], timeout=5)
            for proc in alive:
                try:
                    proc.kill()
                except Exception:
                    pass
        except Exception:
            pass
