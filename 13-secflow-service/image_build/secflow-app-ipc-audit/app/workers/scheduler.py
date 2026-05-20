from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
import logging
import socket
import threading
import time

from app.core.config import get_config
from app.services.execution_service import get_execution_service
from app.services.task_service import get_task_service

logger = logging.getLogger(__name__)


class SchedulerService:
    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._executor: ThreadPoolExecutor | None = None
        self._executor_max_workers = 0
        self._futures: dict[Future[None], str] = {}
        self._futures_lock = threading.Lock()
        self._config_changed_event = threading.Event()
        self._worker_id = f"{socket.gethostname()}-ipc-audit"
        self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running and self._thread is not None and self._thread.is_alive()

    @property
    def active_attempt_count(self) -> int:
        return self._active_future_count()

    def notify_config_changed(self) -> None:
        self._config_changed_event.set()

    async def start(self) -> None:
        if self.is_running:
            return
        get_task_service().recover_expired_attempts()
        self._stop_event.clear()
        self._config_changed_event.clear()
        initial_max_parallel = self._current_max_parallel_tasks()
        self._executor = ThreadPoolExecutor(
            max_workers=initial_max_parallel,
            thread_name_prefix="ipc-audit-attempt",
        )
        self._executor_max_workers = initial_max_parallel
        self._thread = threading.Thread(target=self._loop, name="ipc-audit-scheduler", daemon=True)
        self._thread.start()
        self._is_running = True

    async def stop(self) -> None:
        self._stop_event.set()
        self._config_changed_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=False)
        self._executor = None
        self._executor_max_workers = 0
        with self._futures_lock:
            self._futures.clear()
        self._thread = None
        self._is_running = False

    def _loop(self) -> None:
        interval = max(get_config().execution.scheduler_tick_interval_seconds, 0.2)
        while not self._stop_event.is_set():
            try:
                max_parallel = self._current_max_parallel_tasks()
                self._ensure_executor_capacity(max_parallel)
                self._reap_futures()
                get_task_service().recover_expired_attempts(excluded_attempt_ids=self._active_attempt_ids())
                while self._active_future_count() < max_parallel and not self._stop_event.is_set():
                    attempt_id = get_task_service().claim_next_attempt(self._worker_id)
                    if not attempt_id:
                        break
                    self._submit_attempt(attempt_id)
                if self._active_future_count() > 0:
                    self._config_changed_event.wait(timeout=min(interval, 0.5))
                    self._config_changed_event.clear()
                    continue
            except Exception as exc:  # noqa: BLE001
                logger.exception("scheduler loop failed: %s", exc)
            self._config_changed_event.wait(timeout=interval)
            self._config_changed_event.clear()

    def _submit_attempt(self, attempt_id: str) -> None:
        if self._executor is None:
            raise RuntimeError("scheduler executor is not initialized")
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
            except Exception as exc:  # noqa: BLE001
                logger.exception("attempt future failed for %s: %s", attempt_id, exc)

    def _active_future_count(self) -> int:
        with self._futures_lock:
            return sum(0 if future.done() else 1 for future in self._futures)

    def _active_attempt_ids(self) -> set[str]:
        with self._futures_lock:
            return {
                attempt_id
                for future, attempt_id in self._futures.items()
                if not future.done()
            }

    @staticmethod
    def _current_max_parallel_tasks() -> int:
        try:
            from app.services.runtime_config_service import get_runtime_config_service

            return max(get_runtime_config_service().get_max_parallel_tasks(), 1)
        except Exception as exc:  # noqa: BLE001
            logger.warning("failed to load runtime max_parallel_tasks, falling back to env config: %s", exc)
            return max(get_config().execution.max_parallel_tasks, 1)

    def _ensure_executor_capacity(self, max_parallel: int) -> None:
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=max_parallel,
                thread_name_prefix="ipc-audit-attempt",
            )
            self._executor_max_workers = max_parallel
            return
        if max_parallel == self._executor_max_workers:
            return
        # ThreadPoolExecutor reads _max_workers when new work is submitted.
        # Lower values stop future over-submission through scheduler gating; running work is not killed.
        self._executor._max_workers = max_parallel  # type: ignore[attr-defined]  # noqa: SLF001
        self._executor_max_workers = max_parallel


_scheduler_service: SchedulerService | None = None


def get_scheduler_service() -> SchedulerService:
    global _scheduler_service
    if _scheduler_service is None:
        _scheduler_service = SchedulerService()
    return _scheduler_service
