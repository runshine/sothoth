from __future__ import annotations

import logging
import socket
import threading
from concurrent.futures import Future, ThreadPoolExecutor

from app.core.config import get_config
from app.services.execution_service import get_execution_service
from app.services.task_service import get_task_service

logger = logging.getLogger(__name__)


class SchedulerService:
    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._executor: ThreadPoolExecutor | None = None
        self._futures: dict[Future[None], str] = {}
        self._futures_lock = threading.Lock()
        self._worker_id = f"{socket.gethostname()}-kernel-scan"
        self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running and self._thread is not None and self._thread.is_alive()

    @property
    def active_attempt_count(self) -> int:
        with self._futures_lock:
            return sum(0 if f.done() else 1 for f in self._futures)

    async def start(self) -> None:
        if self.is_running:
            return
        get_task_service().recover_expired_attempts()
        self._stop_event.clear()
        max_parallel = max(get_config().execution.max_parallel_tasks, 1)
        self._executor = ThreadPoolExecutor(
            max_workers=max_parallel,
            thread_name_prefix="kernel-scan-attempt",
        )
        self._thread = threading.Thread(target=self._loop, name="kernel-scan-scheduler", daemon=True)
        self._thread.start()
        self._is_running = True

    async def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=False)
        self._executor = None
        with self._futures_lock:
            self._futures.clear()
        self._thread = None
        self._is_running = False

    def _loop(self) -> None:
        interval = max(get_config().execution.scheduler_tick_interval_seconds, 0.2)
        while not self._stop_event.is_set():
            try:
                max_parallel = max(get_config().execution.max_parallel_tasks, 1)
                self._reap_futures()
                get_task_service().recover_expired_attempts()
                active = self.active_attempt_count
                while active < max_parallel and not self._stop_event.is_set():
                    attempt_id = get_task_service().claim_next_attempt(self._worker_id)
                    if not attempt_id:
                        break
                    self._submit_attempt(attempt_id)
                    active += 1
            except Exception as exc:
                logger.exception("scheduler loop failed: %s", exc)
            self._stop_event.wait(timeout=interval)

    def _submit_attempt(self, attempt_id: str) -> None:
        if self._executor is None:
            raise RuntimeError("scheduler executor not initialized")
        future = self._executor.submit(get_execution_service().run_attempt, attempt_id)
        with self._futures_lock:
            self._futures[future] = attempt_id

    def _reap_futures(self) -> None:
        completed: list[tuple[Future[None], str]] = []
        with self._futures_lock:
            for future, attempt_id in list(self._futures.items()):
                if future.done():
                    completed.append((future, attempt_id))
                    self._futures.pop(future, None)
        for future, attempt_id in completed:
            try:
                future.result()
            except Exception as exc:
                logger.exception("attempt future failed for %s: %s", attempt_id, exc)


_scheduler_service: SchedulerService | None = None


def get_scheduler_service() -> SchedulerService:
    global _scheduler_service
    if _scheduler_service is None:
        _scheduler_service = SchedulerService()
    return _scheduler_service
