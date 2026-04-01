from __future__ import annotations

import errno
import os
import pty
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


class SessionPtyManager:
    def __init__(self, state_dir: Path):
        self._lock = threading.RLock()
        self._procs: dict[str, subprocess.Popen] = {}
        self._masters: dict[str, int] = {}
        self._store = JsonFileStore(state_dir / 'pty_sessions.json', lambda: {'sessions': {}})

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

    def create_session_pty(self, session_id: str, config: BackendConfig) -> Dict[str, Any]:
        with self._lock:
            self.close_session_pty(session_id, remove_state=False)

            master_fd, slave_fd = pty.openpty()
            env = os.environ.copy()
            env.update(config.env or {})
            args = [config.command, *(config.args or [])]
            proc: subprocess.Popen | None = None
            try:
                proc = subprocess.Popen(
                    args,
                    cwd=config.cwd or None,
                    env=env,
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    preexec_fn=os.setsid,
                    close_fds=True,
                )
            finally:
                self._safe_close_fd(slave_fd)
            os.set_blocking(master_fd, False)
            self._procs[session_id] = proc
            self._masters[session_id] = master_fd
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
            master_fd = self._masters.get(session_id)
            proc = self._procs.get(session_id)
            if master_fd is None or not proc or proc.poll() is not None:
                raise RuntimeError('session PTY is not running')
            payload = str(text or '')
            if append_newline and not payload.endswith('\n'):
                payload = f'{payload}\n'
            os.write(master_fd, payload.encode('utf-8', errors='ignore'))

    def _read_chunks(
        self,
        session_id: str,
        quiet_window_ms: int,
        max_window_ms: int,
    ) -> tuple[list[dict[str, str]], bool]:
        with self._lock:
            master_fd = self._masters.get(session_id)
            proc = self._procs.get(session_id)
        if master_fd is None or not proc:
            raise RuntimeError('session PTY not found')

        chunks: list[dict[str, str]] = []
        start_ts = time.time()
        last_data_ts = start_ts
        timed_out = False

        while True:
            now = time.time()
            if (now - start_ts) * 1000 >= max_window_ms:
                timed_out = True
                break
            if chunks and (now - last_data_ts) * 1000 >= quiet_window_ms:
                break

            timeout_sec = min(0.05, max(0.01, (max_window_ms / 1000) - (now - start_ts)))
            try:
                readable, _, _ = select.select([master_fd], [], [], timeout_sec)
            except Exception:
                break
            if not readable:
                continue
            try:
                data = os.read(master_fd, 4096)
            except BlockingIOError:
                continue
            except OSError as exc:
                if exc.errno == errno.EIO:
                    break
                raise

            if not data:
                break
            text = data.decode('utf-8', errors='replace')
            if not text:
                continue
            last_data_ts = time.time()
            chunks.append({
                'type': 'chunk',
                # PTY 下 stdout/stderr 会合流，统一标记为 stdout 以保持前端兼容
                'source': 'stdout',
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

    def close_session_pty(self, session_id: str, remove_state: bool = True) -> Dict[str, Any]:
        with self._lock:
            proc = self._procs.pop(session_id, None)
            master_fd = self._masters.pop(session_id, None)

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

            self._safe_close_fd(master_fd)

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
