"""Streaming subprocess helpers that avoid pipe backpressure deadlocks."""

from __future__ import annotations

import os
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import BinaryIO, Callable, Optional


@dataclass
class StreamingCompletedProcess:
    args: list[str]
    returncode: int
    stdout: str | bytes | None
    stderr: str | bytes | None


class _TailBuffer:
    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max(0, int(max_bytes))
        self._data = bytearray()
        self._lock = threading.Lock()

    def append(self, chunk: bytes) -> None:
        if self.max_bytes <= 0 or not chunk:
            return
        with self._lock:
            self._data.extend(chunk)
            if len(self._data) > self.max_bytes:
                del self._data[:-self.max_bytes]

    def read(self) -> bytes:
        with self._lock:
            return bytes(self._data)


class StreamingLineSink:
    def __init__(self, callback: Callable[[str], None]) -> None:
        self._callback = callback
        self._buffer = ""

    def feed(self, text: str) -> None:
        if not text:
            return
        self._buffer += text
        while True:
            newline = self._buffer.find("\n")
            if newline < 0:
                break
            line = self._buffer[:newline]
            if line.endswith("\r"):
                line = line[:-1]
            self._callback(line)
            self._buffer = self._buffer[newline + 1 :]

    def flush(self) -> None:
        if self._buffer:
            self._callback(self._buffer.rstrip("\r"))
            self._buffer = ""


def run_streaming_process(
    command: list[str],
    *,
    cancel_check: Optional[Callable[[], bool]] = None,
    register_cancel_hook: Optional[Callable[[Callable[[], None] | None], None]] = None,
    kill_process_tree: Optional[Callable[[subprocess.Popen], None]] = None,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    text: bool = True,
    encoding: str = "utf-8",
    errors: str = "replace",
    stdout_callback: Optional[Callable[[str], None]] = None,
    stderr_callback: Optional[Callable[[str], None]] = None,
    stdout_file: BinaryIO | None = None,
    timeout_seconds: float | None = None,
    max_stdout_bytes: int = 1024 * 1024,
    max_stderr_bytes: int = 1024 * 1024,
    poll_interval: float = 0.2,
) -> StreamingCompletedProcess:
    proc = subprocess.Popen(
        command,
        stdout=stdout_file if stdout_file is not None else stdout,
        stderr=stderr,
        cwd=cwd,
        env=env,
        text=False,
        start_new_session=True,
    )
    stdout_tail = _TailBuffer(max_stdout_bytes)
    stderr_tail = _TailBuffer(max_stderr_bytes)
    reader_errors: list[BaseException] = []

    def _terminate() -> None:
        if kill_process_tree is not None:
            kill_process_tree(proc)
            return
        try:
            proc.terminate()
        except Exception:
            pass

    def _reader(
        stream,
        tail: _TailBuffer,
        callback: Optional[Callable[[str], None]],
    ) -> None:
        try:
            while True:
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    break
                tail.append(chunk)
                if callback is not None:
                    callback(chunk.decode(encoding, errors=errors))
        except BaseException as exc:  # pragma: no cover - defensive
            reader_errors.append(exc)
        finally:
            try:
                stream.close()
            except Exception:
                pass

    threads: list[threading.Thread] = []
    if register_cancel_hook is not None:
        register_cancel_hook(_terminate)
    try:
        for stream, tail, callback in (
            (proc.stdout, stdout_tail, stdout_callback),
            (proc.stderr, stderr_tail, stderr_callback),
        ):
            if stream is None:
                continue
            thread = threading.Thread(target=_reader, args=(stream, tail, callback), daemon=True)
            thread.start()
            threads.append(thread)

        started_at = time.monotonic()
        while True:
            if cancel_check and cancel_check():
                _terminate()
                raise RuntimeError("__CANCELLED__")
            if timeout_seconds is not None and (time.monotonic() - started_at) > float(timeout_seconds):
                _terminate()
                raise RuntimeError(f"process timed out after {timeout_seconds}s")
            if proc.poll() is not None:
                break
            time.sleep(poll_interval)
        return_code = proc.wait()
        for thread in threads:
            thread.join(timeout=5)
        if reader_errors:
            raise RuntimeError(f"stream reader failed: {reader_errors[0]}")
        stdout_bytes = None if stdout_file is not None else stdout_tail.read()
        stderr_bytes = stderr_tail.read() if stderr is subprocess.PIPE else None
        if text:
            stdout_value = None if stdout_bytes is None else stdout_bytes.decode(encoding, errors=errors)
            stderr_value = None if stderr_bytes is None else stderr_bytes.decode(encoding, errors=errors)
        else:
            stdout_value = stdout_bytes
            stderr_value = stderr_bytes
        return StreamingCompletedProcess(command, return_code, stdout_value, stderr_value)
    finally:
        if register_cancel_hook is not None:
            register_cancel_hook(None)
