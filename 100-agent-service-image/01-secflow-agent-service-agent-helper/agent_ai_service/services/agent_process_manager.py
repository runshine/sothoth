from __future__ import annotations

import os
import queue
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Generator

import psutil

from agent_ai_service.config import settings
from agent_ai_service.models.agent_backend import BackendConfig
from agent_ai_service.persistence.file_store import JsonFileStore


class AgentProcessManager:
    def __init__(self):
        self._procs: dict[str, subprocess.Popen] = {}
        self._store = JsonFileStore(settings.state_dir / 'processes.json', lambda: {'processes': {}})
        self._janitor_started = False
        self._janitor_lock = threading.Lock()

    def _read_pid(self, name: str) -> int | None:
        data = self._store.read()
        pid = data.get('processes', {}).get(name, {}).get('pid')
        try:
            return int(pid) if pid else None
        except Exception:
            return None

    def _write_state(self, name: str, pid: int | None, extra: Dict[str, Any] | None = None) -> None:
        data = self._store.read()
        data.setdefault('processes', {})
        entry = {
            'pid': pid,
            'updated_at': datetime.now(timezone.utc).isoformat(),
        }
        if extra:
            entry.update(extra)
        data['processes'][name] = entry
        self._store.write(data)

    def _read_state(self, name: str) -> Dict[str, Any]:
        return self._store.read().get('processes', {}).get(name, {}) or {}

    def touch(self, name: str) -> None:
        state = self._read_state(name)
        self._write_state(name, state.get('pid'), {
            **{k: v for k, v in state.items() if k != 'updated_at'},
            'last_used_at': datetime.now(timezone.utc).isoformat(),
        })

    def start(self, config: BackendConfig) -> Dict[str, Any]:
        existing_status = self.status(config.name)
        if existing_status.get('running'):
            return {'running': True, 'pid': existing_status.get('pid'), 'already_running': True}

        env = os.environ.copy()
        env.update(config.env or {})
        proc = subprocess.Popen(
            [config.command, *(config.args or [])],
            cwd=config.cwd or None,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        self._procs[config.name] = proc
        now = datetime.now(timezone.utc).isoformat()
        self._write_state(config.name, proc.pid, {
            'name': config.name,
            'command': config.command,
            'args': config.args or [],
            'cwd': config.cwd,
            'started_at': now,
            'last_used_at': now,
        })
        return {
            'running': True,
            'pid': proc.pid,
            'already_running': False,
            'started_at': now,
        }

    def stop(self, name: str) -> Dict[str, Any]:
        proc = self._procs.get(name)
        pid = proc.pid if proc and proc.poll() is None else self._read_pid(name)
        if not pid:
            return {'running': False, 'stopped': True, 'pid': None}
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except Exception:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
        if proc:
            try:
                proc.wait(timeout=5)
            except Exception:
                try:
                    os.killpg(os.getpgid(pid), signal.SIGKILL)
                except Exception:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except Exception:
                        pass
        self._write_state(name, None)
        return {'running': False, 'stopped': True, 'pid': pid}

    def status(self, name: str) -> Dict[str, Any]:
        proc = self._procs.get(name)
        pid = proc.pid if proc and proc.poll() is None else self._read_pid(name)
        if not pid:
            return {'running': False, 'pid': None}
        try:
            target = psutil.Process(pid)
            if not target.is_running():
                self._write_state(name, None)
                return {'running': False, 'pid': None}
            state = self._read_state(name)
            return {
                'running': True,
                'pid': pid,
                'status': target.status(),
                'started_at': state.get('started_at'),
                'last_used_at': state.get('last_used_at'),
                'adopted': proc is None and pid is not None,
            }
        except Exception:
            self._write_state(name, None)
            return {'running': False, 'pid': None}

    def invoke_once(self, config: BackendConfig, prompt: str, messages: list[dict[str, Any]] | None = None) -> Dict[str, Any]:
        env = os.environ.copy()
        env.update(config.env or {})
        args = [config.command, *(config.args or [])]
        if prompt:
            args.append(prompt)
        try:
            completed = subprocess.run(
                args,
                cwd=config.cwd or None,
                env=env,
                text=True,
                capture_output=True,
                timeout=settings.backend_invoke_timeout_sec,
            )
            return {
                'success': completed.returncode == 0,
                'returncode': completed.returncode,
                'stdout': completed.stdout,
                'stderr': completed.stderr,
            }
        except FileNotFoundError:
            return {'success': False, 'error': f'backend command not found: {config.command}'}
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'backend invoke timeout'}

    def invoke_once_stream(self, config: BackendConfig, prompt: str, messages: list[dict[str, Any]] | None = None) -> Generator[Dict[str, Any], None, None]:
        env = os.environ.copy()
        env.update(config.env or {})
        args = [config.command, *(config.args or [])]
        if prompt:
            args.append(prompt)

        try:
            proc = subprocess.Popen(
                args,
                cwd=config.cwd or None,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
            )
        except FileNotFoundError:
            yield {
                'type': 'error',
                'error': f'backend command not found: {config.command}',
            }
            return

        q: queue.Queue[tuple[str, str] | None] = queue.Queue()
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        def _pump(pipe, source: str) -> None:
            try:
                while True:
                    line = pipe.readline()
                    if line == '':
                        break
                    q.put((source, line))
            finally:
                try:
                    pipe.close()
                except Exception:
                    pass
                q.put(None)

        stdout_thread = threading.Thread(target=_pump, args=(proc.stdout, 'stdout'), daemon=True)
        stderr_thread = threading.Thread(target=_pump, args=(proc.stderr, 'stderr'), daemon=True)
        stdout_thread.start()
        stderr_thread.start()

        stream_end = time.time() + settings.backend_invoke_timeout_sec
        done_sentinels = 0
        timed_out = False

        while True:
            if done_sentinels >= 2 and q.empty():
                break

            timeout_left = max(0.1, min(0.5, stream_end - time.time()))
            if stream_end - time.time() <= 0:
                timed_out = True
                try:
                    proc.kill()
                except Exception:
                    pass
                break

            try:
                item = q.get(timeout=timeout_left)
            except queue.Empty:
                continue

            if item is None:
                done_sentinels += 1
                continue

            source, text = item
            if source == 'stdout':
                stdout_parts.append(text)
            else:
                stderr_parts.append(text)
            yield {
                'type': 'chunk',
                'source': source,
                'text': text,
            }

        try:
            returncode = proc.wait(timeout=1)
        except Exception:
            returncode = -1

        stdout = ''.join(stdout_parts)
        stderr = ''.join(stderr_parts)
        if timed_out:
            yield {
                'type': 'error',
                'error': 'backend invoke timeout',
                'returncode': returncode,
                'stdout': stdout,
                'stderr': stderr,
            }
            return

        yield {
            'type': 'done',
            'success': returncode == 0,
            'returncode': returncode,
            'stdout': stdout,
            'stderr': stderr,
        }

    def health(self, pid: int | None) -> Dict[str, Any]:
        if not pid:
            return {'running': False}
        try:
            proc = psutil.Process(pid)
            return {'running': proc.is_running(), 'status': proc.status(), 'create_time': proc.create_time()}
        except Exception:
            return {'running': False}

    def list_states(self) -> Dict[str, Any]:
        return self._store.read().get('processes', {})

    def reap_idle_processes(self, idle_timeout_sec: int | None = None) -> list[Dict[str, Any]]:
        idle_timeout = idle_timeout_sec or settings.backend_idle_timeout_sec
        now = time.time()
        reaped: list[Dict[str, Any]] = []
        for name, state in list(self.list_states().items()):
            pid = state.get('pid')
            if not pid:
                continue
            last_used_at = state.get('last_used_at') or state.get('updated_at') or state.get('started_at')
            if not last_used_at:
                continue
            try:
                last_used_ts = datetime.fromisoformat(str(last_used_at).replace('Z', '+00:00')).timestamp()
            except Exception:
                continue
            if (now - last_used_ts) < idle_timeout:
                continue
            result = self.stop(name)
            reaped.append({'name': name, 'pid': pid, 'result': result, 'reason': 'idle_timeout'})
        return reaped

    def start_housekeeping(self) -> None:
        with self._janitor_lock:
            if self._janitor_started:
                return
            self._janitor_started = True

        def _loop():
            while True:
                try:
                    self.reap_idle_processes()
                except Exception:
                    pass
                time.sleep(max(5, settings.housekeeping_interval_sec))

        thread = threading.Thread(target=_loop, daemon=True, name='agent-helper-janitor')
        thread.start()
