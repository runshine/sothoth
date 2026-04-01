from __future__ import annotations

import errno
import os
import select
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator

from agent_ai_service.models.agent_backend import BackendConfig
from agent_ai_service.persistence.file_store import JsonFileStore


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SessionPipeManager:
    def __init__(self, state_dir: Path):
        self._lock = threading.RLock()
        self._procs: dict[str, subprocess.Popen] = {}
        self._stdout_fds: dict[str, int] = {}
        self._stderr_fds: dict[str, int] = {}
        self._store = JsonFileStore(state_dir / 'pipe_sessions.json', lambda: {'sessions': {}})

    def _write_state(self, session_id: str, state: Dict[str, Any]) -> None:
        data = self._store.read()
        sessions = data.setdefault('sessions', {})
        existing = sessions.get(session_id, {}) or {}
        merged = {
            **existing,
            **state,
            'session_id': session_id,
            'updated_at': _utc_now(),
        }
        sessions[session_id] = merged
        self._store.write(data)

    def _clear_state(self, session_id: str) -> None:
        data = self._store.read()
        sessions = data.setdefault('sessions', {})
        if session_id in sessions:
            sessions.pop(session_id, None)
            self._store.write(data)

    def _safe_close_fd(self, fd: int | None) -> None:
        if fd is None:
            return
        try:
            os.close(fd)
        except Exception:
            pass

    def create_session_pipe(self, session_id: str, config: BackendConfig) -> Dict[str, Any]:
        with self._lock:
            self.close_session_pipe(session_id, remove_state=False)

            env = os.environ.copy()
            env.update(config.env or {})
            args = [config.command, *(config.args or [])]
            proc = subprocess.Popen(
                args,
                cwd=config.cwd or None,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid,
                close_fds=True,
                bufsize=0,
                text=False,
            )
            if not proc.stdin or not proc.stdout or not proc.stderr:
                raise RuntimeError('session PIPE failed to initialize stdio')

            os.set_blocking(proc.stdout.fileno(), False)
            os.set_blocking(proc.stderr.fileno(), False)

            self._procs[session_id] = proc
            self._stdout_fds[session_id] = proc.stdout.fileno()
            self._stderr_fds[session_id] = proc.stderr.fileno()

            started_at = _utc_now()
            self._write_state(session_id, {
                'backend': config.name,
                'pid': proc.pid,
                'started_at': started_at,
                'status': 'ready',
                'last_error': None,
            })
            return {
                'session_id': session_id,
                'backend': config.name,
                'pid': proc.pid,
                'started_at': started_at,
                'status': 'ready',
            }

    def is_alive(self, session_id: str) -> bool:
        with self._lock:
            proc = self._procs.get(session_id)
            return bool(proc and proc.poll() is None)

    def get_pid(self, session_id: str) -> int | None:
        with self._lock:
            proc = self._procs.get(session_id)
            if proc and proc.poll() is None:
                return proc.pid
            return None

    def mark_broken(self, session_id: str, error_message: str) -> None:
        with self._lock:
            self._write_state(session_id, {
                'status': 'broken',
                'last_error': str(error_message or ''),
            })

    def write_stdin(self, session_id: str, text: str, append_newline: bool = True) -> None:
        with self._lock:
            proc = self._procs.get(session_id)
            if not proc or proc.poll() is not None or proc.stdin is None:
                raise RuntimeError('session PIPE is not running')
            payload = str(text or '')
            if append_newline and not payload.endswith('\n'):
                payload = f'{payload}\n'
            try:
                proc.stdin.write(payload.encode('utf-8', errors='ignore'))
                proc.stdin.flush()
            except BrokenPipeError:
                raise RuntimeError('session PIPE stdin closed')

    def _read_chunks(
        self,
        session_id: str,
        quiet_window_ms: int,
        max_window_ms: int,
    ) -> tuple[list[dict[str, str]], bool]:
        with self._lock:
            proc = self._procs.get(session_id)
            stdout_fd = self._stdout_fds.get(session_id)
            stderr_fd = self._stderr_fds.get(session_id)
        if not proc or stdout_fd is None or stderr_fd is None:
            raise RuntimeError('session PIPE not found')

        chunks: list[dict[str, str]] = []
        start_ts = time.time()
        last_data_ts = start_ts
        timed_out = False
        closed_fds: set[int] = set()

        fd_to_source = {
            stdout_fd: 'stdout',
            stderr_fd: 'stderr',
        }

        while True:
            now = time.time()
            if (now - start_ts) * 1000 >= max_window_ms:
                timed_out = True
                break
            if chunks and (now - last_data_ts) * 1000 >= quiet_window_ms:
                break

            watch_fds = [fd for fd in (stdout_fd, stderr_fd) if fd not in closed_fds]
            if not watch_fds:
                break

            timeout_sec = min(0.05, max(0.01, (max_window_ms / 1000) - (now - start_ts)))
            try:
                readable, _, _ = select.select(watch_fds, [], [], timeout_sec)
            except Exception:
                break
            if not readable:
                continue

            for fd in readable:
                try:
                    data = os.read(fd, 4096)
                except BlockingIOError:
                    continue
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        closed_fds.add(fd)
                        continue
                    raise

                if not data:
                    closed_fds.add(fd)
                    continue

                text = data.decode('utf-8', errors='replace')
                if not text:
                    continue
                last_data_ts = time.time()
                chunks.append({
                    'type': 'chunk',
                    'source': fd_to_source.get(fd, 'stdout'),
                    'text': text,
                })

        return chunks, timed_out

    def read_until_idle(
        self,
        session_id: str,
        quiet_window_ms: int = 450,
        max_window_ms: int = 10000,
    ) -> Dict[str, Any]:
        chunks, timed_out = self._read_chunks(session_id, quiet_window_ms=quiet_window_ms, max_window_ms=max_window_ms)
        output = ''.join(chunk.get('text', '') for chunk in chunks)
        pid = self.get_pid(session_id)
        return {
            'chunks': chunks,
            'output': output,
            'timed_out': timed_out,
            'pid': pid,
            'alive': pid is not None,
        }

    def stream_round(
        self,
        session_id: str,
        quiet_window_ms: int = 450,
        max_window_ms: int = 10000,
    ) -> Generator[Dict[str, Any], None, None]:
        chunks, timed_out = self._read_chunks(session_id, quiet_window_ms=quiet_window_ms, max_window_ms=max_window_ms)
        for chunk in chunks:
            yield chunk
        yield {
            'type': 'done',
            'timed_out': timed_out,
            'pid': self.get_pid(session_id),
        }

    def close_session_pipe(self, session_id: str, remove_state: bool = True) -> Dict[str, Any]:
        with self._lock:
            proc = self._procs.pop(session_id, None)
            stdout_fd = self._stdout_fds.pop(session_id, None)
            stderr_fd = self._stderr_fds.pop(session_id, None)

            stopped_pid = None
            if proc and proc.poll() is None:
                stopped_pid = proc.pid
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except Exception:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                try:
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass

            self._safe_close_fd(stdout_fd)
            self._safe_close_fd(stderr_fd)

            if remove_state:
                self._clear_state(session_id)
            else:
                self._write_state(session_id, {
                    'status': 'closed',
                    'pid': None,
                })

            return {
                'session_id': session_id,
                'closed': True,
                'pid': stopped_pid,
            }
