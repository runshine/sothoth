"""WebSocket file watch service."""

from __future__ import annotations

import asyncio
import base64
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from app.config import get_config

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except Exception:  # pragma: no cover - optional dependency
    FileSystemEventHandler = object  # type: ignore
    Observer = None  # type: ignore


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class FileStat:
    exists: bool
    size: int
    mtime: float
    inode: int
    mode: int


def stat_file(path: str) -> FileStat:
    if not os.path.exists(path):
        return FileStat(False, 0, 0.0, 0, 0)
    st = os.stat(path)
    return FileStat(True, st.st_size, st.st_mtime, st.st_ino, st.st_mode)


class _PathEventHandler(FileSystemEventHandler):  # type: ignore[misc]
    def __init__(self, target_path: str, queue: asyncio.Queue):
        super().__init__()
        self._target = os.path.abspath(target_path)
        self._queue = queue

    def _push(self, evt: str, src: str, dest: Optional[str] = None):
        src_abs = os.path.abspath(src)
        dest_abs = os.path.abspath(dest) if dest else None
        if src_abs == self._target or (dest_abs and dest_abs == self._target):
            self._queue.put_nowait({"event": evt, "src_path": src_abs, "dest_path": dest_abs})

    def on_created(self, event):
        self._push("created", event.src_path)

    def on_deleted(self, event):
        self._push("deleted", event.src_path)

    def on_modified(self, event):
        self._push("modified", event.src_path)

    def on_moved(self, event):
        self._push("renamed", event.src_path, event.dest_path)


class WatchSessionLimiter:
    def __init__(self):
        cfg = get_config().websocket
        self._max_total = cfg.max_connections
        self._max_per_project = cfg.max_connections_per_project
        self._lock = asyncio.Lock()
        self._total = 0
        self._per_project: dict[str, int] = {}
        self._events_total = 0
        self._bytes_total = 0
        self._slow_drops = 0
        self._auth_failures = 0

    async def acquire(self, project_id: str) -> bool:
        async with self._lock:
            per_count = self._per_project.get(project_id, 0)
            if self._total >= self._max_total or per_count >= self._max_per_project:
                return False
            self._total += 1
            self._per_project[project_id] = per_count + 1
            return True

    async def release(self, project_id: str):
        async with self._lock:
            self._total = max(0, self._total - 1)
            per_count = max(0, self._per_project.get(project_id, 0) - 1)
            if per_count == 0:
                self._per_project.pop(project_id, None)
            else:
                self._per_project[project_id] = per_count

    async def inc_events(self):
        async with self._lock:
            self._events_total += 1

    async def inc_bytes(self, size: int):
        async with self._lock:
            self._bytes_total += max(0, size)

    async def inc_slow_drops(self):
        async with self._lock:
            self._slow_drops += 1

    async def inc_auth_failures(self):
        async with self._lock:
            self._auth_failures += 1

    def snapshot(self) -> dict[str, Any]:
        return {
            "active_total": self._total,
            "active_by_project": dict(self._per_project),
            "events_total": self._events_total,
            "delta_bytes_total": self._bytes_total,
            "slow_drops": self._slow_drops,
            "auth_failures": self._auth_failures,
        }


async def build_line_delta(path: str, from_line: int) -> tuple[int, int, list[str]]:
    def _read():
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        start = max(0, from_line)
        if start >= len(lines):
            return start, start, []
        return start, len(lines), [line.rstrip("\n") for line in lines[start:]]

    return await asyncio.to_thread(_read)


async def build_byte_delta(path: str, from_byte: int, max_buffer: int) -> tuple[int, int, bytes]:
    def _read():
        with open(path, "rb") as fh:
            fh.seek(max(0, from_byte))
            chunk = fh.read(max_buffer)
            end = max(0, from_byte) + len(chunk)
            return max(0, from_byte), end, chunk

    return await asyncio.to_thread(_read)


_limiter: WatchSessionLimiter | None = None


def get_watch_limiter() -> WatchSessionLimiter:
    global _limiter
    if _limiter is None:
        _limiter = WatchSessionLimiter()
    return _limiter


def encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def maybe_create_observer(path: str, queue: asyncio.Queue):
    if Observer is None:
        return None
    watch_dir = os.path.dirname(path) or "."
    handler = _PathEventHandler(path, queue)
    observer = Observer()
    observer.schedule(handler, watch_dir, recursive=False)
    observer.start()
    return observer
