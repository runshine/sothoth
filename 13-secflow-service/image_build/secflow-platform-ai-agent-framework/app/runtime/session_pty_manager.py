from __future__ import annotations

import errno
import os
import pty
import select
import signal
import subprocess
import threading
import time
from typing import Any, Dict


class SessionPtyManager:
    def __init__(self):
        self._lock = threading.RLock()
        self._procs: dict[str, subprocess.Popen] = {}
        self._masters: dict[str, int] = {}

    def create_session(self, session_id: str, command: list[str], cwd: str | None, env: dict[str, str]) -> int:
        with self._lock:
            self.close_session(session_id)
            master_fd, slave_fd = pty.openpty()
            try:
                proc = subprocess.Popen(
                    command,
                    cwd=cwd or None,
                    env=env,
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    preexec_fn=os.setsid,
                    close_fds=True,
                )
            finally:
                os.close(slave_fd)
            os.set_blocking(master_fd, False)
            self._procs[session_id] = proc
            self._masters[session_id] = master_fd
            return proc.pid

    def is_alive(self, session_id: str) -> bool:
        with self._lock:
            proc = self._procs.get(session_id)
            return bool(proc and proc.poll() is None)

    def write_stdin(self, session_id: str, text: str) -> None:
        with self._lock:
            master_fd = self._masters.get(session_id)
            proc = self._procs.get(session_id)
            if master_fd is None or not proc or proc.poll() is not None:
                raise RuntimeError("pty session is not running")
            payload = text if text.endswith("\n") else f"{text}\n"
            os.write(master_fd, payload.encode("utf-8", errors="ignore"))

    def read_until_idle(self, session_id: str, quiet_window_ms: int, max_window_ms: int) -> Dict[str, Any]:
        with self._lock:
            master_fd = self._masters.get(session_id)
        if master_fd is None:
            raise RuntimeError("pty session not found")

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
            readable, _, _ = select.select([master_fd], [], [], 0.05)
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
            text = data.decode("utf-8", errors="replace")
            if not text:
                continue
            last_data_ts = time.time()
            chunks.append({"source": "stdout", "text": text})

        return {
            "output": "".join(chunk["text"] for chunk in chunks),
            "chunks": chunks,
            "timed_out": timed_out,
            "alive": self.is_alive(session_id),
        }

    def close_session(self, session_id: str) -> None:
        with self._lock:
            proc = self._procs.pop(session_id, None)
            master_fd = self._masters.pop(session_id, None)
            if master_fd is not None:
                try:
                    os.close(master_fd)
                except Exception:
                    pass
            if proc and proc.poll() is None:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except Exception:
                    proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except Exception:
                        proc.kill()
