from __future__ import annotations

import threading
from dataclasses import dataclass


@dataclass
class ActiveRunHandle:
    run_id: int
    cancel_event: threading.Event
    process: object | None = None


_LOCK = threading.Lock()
_ACTIVE_RUNS: dict[int, ActiveRunHandle] = {}


def register_run(run_id: int) -> threading.Event:
    with _LOCK:
        handle = ActiveRunHandle(run_id=run_id, cancel_event=threading.Event(), process=None)
        _ACTIVE_RUNS[run_id] = handle
        return handle.cancel_event


def bind_process(run_id: int, process: object) -> None:
    with _LOCK:
        handle = _ACTIVE_RUNS.get(run_id)
        if handle is None:
            return
        handle.process = process


def unregister_run(run_id: int) -> None:
    with _LOCK:
        _ACTIVE_RUNS.pop(run_id, None)


def cancel_run(run_id: int) -> bool:
    with _LOCK:
        handle = _ACTIVE_RUNS.get(run_id)
        if handle is None:
            return False
        handle.cancel_event.set()
        proc = handle.process
    try:
        if proc is not None and getattr(proc, "poll", lambda: None)() is None:
            getattr(proc, "kill")()
    except Exception:
        pass
    return True


def is_run_active(run_id: int) -> bool:
    with _LOCK:
        return run_id in _ACTIVE_RUNS
