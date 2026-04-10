from __future__ import annotations

import errno
import os
import select
import signal
import subprocess
import threading
import time
from typing import Any, Dict


class SessionPipeManager:
    def __init__(self):
        self._lock = threading.RLock()
        self._procs: dict[str, subprocess.Popen] = {}
        self._stdout_fds: dict[str, int] = {}
        self._stderr_fds: dict[str, int] = {}

    def create_session(self, session_id: str, command: list[str], cwd: str | None, env: dict[str, str]) -> int:
        with self._lock:
            self.close_session(session_id)
            proc = subprocess.Popen(
                command,
                cwd=cwd or None,
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
                raise RuntimeError("pipe session failed to initialize")
            os.set_blocking(proc.stdout.fileno(), False)
            os.set_blocking(proc.stderr.fileno(), False)
            self._procs[session_id] = proc
            self._stdout_fds[session_id] = proc.stdout.fileno()
            self._stderr_fds[session_id] = proc.stderr.fileno()
            return proc.pid

    def is_alive(self, session_id: str) -> bool:
        with self._lock:
            proc = self._procs.get(session_id)
            return bool(proc and proc.poll() is None)

    def write_stdin(self, session_id: str, text: str) -> None:
        with self._lock:
            proc = self._procs.get(session_id)
            if not proc or proc.poll() is not None or proc.stdin is None:
                raise RuntimeError("pipe session is not running")
            payload = text if text.endswith("\n") else f"{text}\n"
            proc.stdin.write(payload.encode("utf-8", errors="ignore"))
            proc.stdin.flush()

    def read_until_idle(self, session_id: str, quiet_window_ms: int, max_window_ms: int) -> Dict[str, Any]:
        with self._lock:
            proc = self._procs.get(session_id)
            stdout_fd = self._stdout_fds.get(session_id)
            stderr_fd = self._stderr_fds.get(session_id)
        if not proc or stdout_fd is None or stderr_fd is None:
            raise RuntimeError("pipe session not found")

        chunks: list[dict[str, str]] = []
        start_ts = time.time()
        last_data_ts = start_ts
        timed_out = False
        closed_fds: set[int] = set()
        sources = {stdout_fd: "stdout", stderr_fd: "stderr"}

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

            readable, _, _ = select.select(watch_fds, [], [], 0.05)
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
                text = data.decode("utf-8", errors="replace")
                if not text:
                    continue
                last_data_ts = time.time()
                chunks.append({"source": sources.get(fd, "stdout"), "text": text})

        return {
            "output": "".join(chunk["text"] for chunk in chunks),
            "chunks": chunks,
            "timed_out": timed_out,
            "alive": self.is_alive(session_id),
        }

    def close_session(self, session_id: str) -> None:
        with self._lock:
            proc = self._procs.pop(session_id, None)
            stdout_fd = self._stdout_fds.pop(session_id, None)
            stderr_fd = self._stderr_fds.pop(session_id, None)
            for fd in (stdout_fd, stderr_fd):
                if fd is not None:
                    try:
                        os.close(fd)
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
