"""Shared-DB task scheduling for firmware unpacker service."""

from __future__ import annotations

import logging
import json
import os
import signal
import shutil
import subprocess
import sys
import threading
import time
import uuid
from math import floor
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import suppress
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from sqlalchemy.exc import SQLAlchemyError

from app.config import get_config
from app.services.agent_sanitizer import run_agent_cleanup
from app.services.observability import (
    record_claim_result,
    record_cleanup_job,
    record_db_operation_result,
    record_db_retry,
    record_dispatch_backpressure,
    record_orphan_recovery,
    record_task_duration,
    record_task_error,
    record_task_lifecycle,
    record_task_stage_transition,
)
from app.time_utils import isoformat_local, now_local
from app.unpacker_engine_config import DISPATCHER_RULES_PATH, TOOLS_ACTIVE_DIR, TOOLS_STORE_DIR, get_max_retries_reached_action
from app.unpacker_engine_logs import TASK_RESULT_CACHE_FILENAME, atomic_write_json, scan_output_tree
from app.preprocess import detect_format
from app.tool_dispatcher import activate_tool_version, dispatch_tool_by_magic, find_dispatcher_rule, upsert_dispatcher_rule
from app.tool_store import parse_tool_metadata


logger = logging.getLogger(__name__)

_executor: Optional[ThreadPoolExecutor] = None
_executor_lock = threading.Lock()
_dispatcher_thread: Optional[threading.Thread] = None
_dispatcher_stop = threading.Event()
_scheduler_thread: Optional[threading.Thread] = None
_scheduler_stop = threading.Event()
_futures: Dict[str, Future] = {}
_futures_lock = threading.Lock()
_active_cancel_hooks: Dict[str, object] = {}
_active_cancel_hooks_lock = threading.Lock()
_active_evolution_processes: Dict[str, int] = {}
_active_evolution_processes_lock = threading.Lock()
_active_result_cache_refreshes: set[str] = set()
_active_result_cache_refreshes_lock = threading.Lock()
PROJECT_FILES_ROOT = Path(os.environ.get("PROJECT_FILES_ROOT", "/data/files"))
TASK_WORKSPACE_ROOT = Path("app/secflow-app-firmware-unpacker")
STAGE_LABELS = {
    "pending": "待执行",
    "claimed": "已认领",
    "retry_preparing": "重试准备中",
    "archive_pending": "归档待处理",
    "archiving": "归档中",
    "queued": "排队中",
    "preprocess": "预处理",
    "feature_extract": "特征提取",
    "skill_match": "工具匹配",
    "tool_match": "工具执行",
    "recursive_expand": "递归解包",
    "llm_unpack": "LLM 解包",
    "review": "LLM 评审",
    "cleanup": "清理收尾",
    "completed": "已完成",
    "evolution": "手动进化",
    "tool_execute": "工具执行",
    "evolution_execute": "工具进化执行",
    "evolve": "工具进化",
}
SKILL_GENERATION_PENDING = "pending"
SKILL_GENERATION_RUNNING = "running"
SKILL_GENERATION_SUCCESS = "success"
SKILL_GENERATION_FAILED = "failed"
SKILL_GENERATION_NOT_APPLICABLE = "not_applicable"
EVOLUTION_PENDING = "pending"
EVOLUTION_CLAIMED = "claimed"
EVOLUTION_RUNNING = "running"
EVOLUTION_CANCELLING = "cancelling"
EVOLUTION_SUCCESS = "success"
EVOLUTION_FAILED = "failed"
EVOLUTION_CANCELLED = "cancelled"
EVOLUTION_MAX_ROUNDS = 3
RETRY_PREPARING_TIMEOUT_SECONDS = 300


def _executor_capacity() -> int:
    return max(1, int(get_config().service.max_background_workers))


def _runtime_config_int(key: str, default: int) -> int:
    from app.model import get_config_value, get_db_session

    db = get_db_session()
    try:
        value = get_config_value(db, key, default=default)
        return int(value)
    finally:
        db.close()


def _runtime_config_str(key: str, default: str) -> str:
    from app.model import get_config_value, get_db_session

    db = get_db_session()
    try:
        value = get_config_value(db, key, default=default)
        return str(value or default).strip()
    finally:
        db.close()


def _safe_positive(value: int, fallback: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        return fallback
    return parsed if parsed > 0 else fallback


def _task_origin(task: object) -> str:
    return str(getattr(task, "task_origin_type", "") or "").strip() or "manual"


def _elapsed_seconds(started_at: Optional[datetime], finished_at: Optional[datetime] = None) -> float | None:
    if started_at is None:
        return None
    end = finished_at or now_local()
    try:
        return max(0.0, float((end - started_at).total_seconds()))
    except Exception:
        return None


def _runtime_concurrency_mode() -> str:
    value = _runtime_config_str("concurrency_mode", "auto").lower()
    return value if value in {"auto", "manual"} else "auto"


def _pod_resource_int(env_name: str) -> Optional[int]:
    raw = str(os.environ.get(env_name, "")).strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        logger.warning("invalid pod resource env %s=%s", env_name, raw)
        return None
    return value if value > 0 else None


def get_concurrency_snapshot() -> dict[str, int | str | bool | None]:
    executor_capacity = _executor_capacity()
    mode = _runtime_concurrency_mode()
    manual_default = _runtime_config_int("max_concurrent", default=executor_capacity)
    manual_limit = _safe_positive(
        _runtime_config_int("manual_max_concurrent", default=manual_default),
        manual_default,
    )
    cpu_per_task = _safe_positive(_runtime_config_int("cpu_millis_per_task", 250), 250)
    memory_per_task = _safe_positive(_runtime_config_int("memory_mb_per_task", 512), 512)
    reserved_cpu = max(0, _runtime_config_int("reserved_cpu_millis", 100))
    reserved_memory = max(0, _runtime_config_int("reserved_memory_mb", 256))

    pod_cpu_limit = _pod_resource_int("POD_CPU_LIMIT_MILLICORES")
    pod_memory_limit = _pod_resource_int("POD_MEMORY_LIMIT_MIB")
    pod_cpu_request = _pod_resource_int("POD_CPU_REQUEST_MILLICORES")
    pod_memory_request = _pod_resource_int("POD_MEMORY_REQUEST_MIB")

    resource_based = False
    auto_limit = executor_capacity
    cpu_based_limit: Optional[int] = None
    memory_based_limit: Optional[int] = None

    if pod_cpu_limit and pod_memory_limit:
        usable_cpu = max(0, pod_cpu_limit - reserved_cpu)
        usable_memory = max(0, pod_memory_limit - reserved_memory)
        cpu_based_limit = max(1, floor(usable_cpu / cpu_per_task)) if cpu_per_task > 0 else executor_capacity
        memory_based_limit = max(1, floor(usable_memory / memory_per_task)) if memory_per_task > 0 else executor_capacity
        auto_limit = min(cpu_based_limit, memory_based_limit, executor_capacity)
        auto_limit = max(1, auto_limit)
        resource_based = True

    effective_max = manual_limit if mode == "manual" else auto_limit
    effective_max = max(1, min(executor_capacity, effective_max))

    return {
        "mode": mode,
        "resource_based": resource_based,
        "effective_max_concurrent": effective_max,
        "executor_capacity": executor_capacity,
        "manual_max_concurrent": max(1, min(executor_capacity, manual_limit)),
        "auto_max_concurrent": auto_limit,
        "cpu_based_limit": cpu_based_limit,
        "memory_based_limit": memory_based_limit,
        "cpu_millis_per_task": cpu_per_task,
        "memory_mb_per_task": memory_per_task,
        "reserved_cpu_millis": reserved_cpu,
        "reserved_memory_mb": reserved_memory,
        "pod_cpu_limit_millicores": pod_cpu_limit,
        "pod_memory_limit_mib": pod_memory_limit,
        "pod_cpu_request_millicores": pod_cpu_request,
        "pod_memory_request_mib": pod_memory_request,
    }


def _runtime_max_concurrent() -> int:
    return 1


def _runtime_max_concurrent_for_logs() -> str:
    return "mode=single-slot effective=1 executor=1 source=dispatcher"


def _dispatch_interval_seconds() -> int:
    return max(1, int(get_config().worker.dispatcher_poll_seconds or get_config().worker.claim_interval_seconds))


def _claim_batch_size() -> int:
    return max(1, int(get_config().worker.claim_batch_size))


def _transient_db_retry_attempts() -> int:
    return max(1, int(get_config().worker.transient_db_retry_attempts))


def _transient_db_retry_backoff_seconds() -> float:
    return max(0.05, int(get_config().worker.transient_db_retry_backoff_ms) / 1000.0)


def _is_transient_db_error(exc: BaseException) -> bool:
    orig = getattr(exc, "orig", exc)
    code = None
    with suppress(Exception):
        args = getattr(orig, "args", None) or ()
        if args:
            code = int(args[0])
    message = str(orig or exc).lower()
    if code in {1205, 1213, 1412, 1614, 3572}:
        return True
    markers = (
        "please retry transaction",
        "lock wait timeout exceeded",
        "deadlock found",
        "deadlock detected",
        "serialization failure",
        "could not serialize access",
        "database is locked",
        "database schema has changed",
        "try restarting transaction",
    )
    return any(marker in message for marker in markers)


def _run_db_retry(
    operation_name: str,
    func: Callable[[], Any],
    *,
    context: Optional[dict[str, Any]] = None,
) -> Any:
    max_attempts = _transient_db_retry_attempts()
    delay = _transient_db_retry_backoff_seconds()
    last_exc: BaseException | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            result = func()
            record_db_operation_result(operation_name, "success")
            return result
        except SQLAlchemyError as exc:
            last_exc = exc
            if not _is_transient_db_error(exc) or attempt >= max_attempts:
                record_db_operation_result(operation_name, "failed")
                raise
            record_db_retry(operation_name)
            sleep_seconds = min(2.0, delay * (2 ** (attempt - 1)))
            logger.warning(
                "transient db error during %s, retrying attempt=%s/%s delay=%.2fs context=%s error=%s",
                operation_name,
                attempt,
                max_attempts,
                sleep_seconds,
                context or {},
                exc,
            )
            time.sleep(sleep_seconds)
    if last_exc is not None:
        record_db_operation_result(operation_name, "failed")
        raise last_exc
    raise RuntimeError(f"{operation_name} retry loop exited unexpectedly")


def _task_lease_seconds() -> int:
    return max(
        30,
        _runtime_config_int(
            "task_lease_seconds",
            default=int(get_config().worker.task_lease_seconds),
        ),
    )


def _cancel_timeout_seconds() -> int:
    return max(
        15,
        _runtime_config_int(
            "cancel_timeout_seconds",
            default=int(get_config().worker.cancel_timeout_seconds),
        ),
    )


def _cancel_grace_seconds() -> int:
    return max(
        1,
        _runtime_config_int(
            "cancel_grace_seconds",
            default=int(get_config().worker.cancel_grace_seconds),
        ),
    )


def _cancel_force_seconds() -> int:
    grace = _cancel_grace_seconds()
    return max(
        grace + 1,
        _runtime_config_int(
            "cancel_force_seconds",
            default=int(get_config().worker.cancel_force_seconds),
        ),
    )


def _cleanup_job_lease_seconds() -> int:
    # Compatibility: task_lease_seconds is deprecated for task execution, but
    # still controls workspace cleanup job leases.
    return max(30, _task_lease_seconds())


def _cleanup_job_lease_deadline(now: Optional[datetime] = None) -> datetime:
    return (now or now_local()) + timedelta(seconds=_cleanup_job_lease_seconds())


def _skill_generation_job_lease_deadline(now: Optional[datetime] = None) -> datetime:
    return (now or now_local()) + timedelta(seconds=_cleanup_job_lease_seconds())


def _runner_start_grace_seconds() -> int:
    return 180


def _is_task_in_startup_grace(task: Any, now: Optional[datetime] = None) -> bool:
    current_time = now or now_local()
    grace = timedelta(seconds=_runner_start_grace_seconds())
    dispatch_claimed_at = getattr(task, "dispatch_claimed_at", None)
    started_at = getattr(task, "started_at", None)
    runner_started_at = getattr(task, "runner_started_at", None)
    for candidate in (runner_started_at, started_at, dispatch_claimed_at):
        if candidate and candidate + grace >= current_time:
            return True
    return False


def get_executor() -> ThreadPoolExecutor:
    global _executor
    if _executor is None:
        with _executor_lock:
            if _executor is None:
                _executor = ThreadPoolExecutor(
                    max_workers=_executor_capacity(),
                    thread_name_prefix="fw-unpacker",
                )
    return _executor


def _submit_background(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Future:
    future = get_executor().submit(fn, *args, **kwargs)

    def _log_background_failure(completed_future: Future) -> None:
        try:
            completed_future.result()
        except Exception:
            logger.exception(
                "background task failed: fn=%s",
                getattr(fn, "__name__", repr(fn)),
            )
    future.add_done_callback(_log_background_failure)
    return future


def _cleanup_completed_futures() -> None:
    with _futures_lock:
        done_ids = [task_id for task_id, future in _futures.items() if future.done()]
        for task_id in done_ids:
            _futures.pop(task_id, None)


def _active_future_count() -> int:
    _cleanup_completed_futures()
    with _futures_lock:
        return sum(1 for future in _futures.values() if not future.done())


def _is_process_alive(pid: Optional[int]) -> bool:
    if not pid or int(pid) <= 0:
        return False
    try:
        os.kill(int(pid), 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def _signal_runner_process(pid: Optional[int], sig: int) -> bool:
    if not pid or int(pid) <= 0:
        return False
    try:
        pgid = os.getpgid(int(pid))
        os.killpg(pgid, sig)
        return True
    except ProcessLookupError:
        return False
    except Exception:
        try:
            os.kill(int(pid), sig)
            return True
        except ProcessLookupError:
            return False
        except Exception as exc:
            logger.warning("failed to signal task runner pid=%s sig=%s: %s", pid, sig, exc)
            return False


def _signal_task_runner(task, sig: int, *, event_type: str, summary: str) -> bool:
    sent = _signal_runner_process(getattr(task, "runner_pid", None), sig)
    if sent:
        _record_task_event_from_row(
            task,
            event_type=event_type,
            summary=summary,
            stage_key=getattr(task, "current_stage", None),
            status=getattr(task, "status", None),
            detail={"runner_pid": getattr(task, "runner_pid", None), "signal": sig},
            owner_id=getattr(task, "owner_id", None),
            created_by="task_manager",
        )
    return sent


def _clear_cancel_grace_deadline(task_id: str) -> None:
    from app.model import UnpackTask, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is not None:
            task.cancel_grace_deadline = None
            db.commit()
    finally:
        db.close()


def _active_runner_count() -> int:
    from app.model import TaskStatus, UnpackTask, get_db_session
    from app.services.worker import get_worker_id

    owner_id = get_worker_id()
    db = get_db_session()
    try:
        rows = (
            db.query(UnpackTask.id, UnpackTask.runner_pid)
            .filter(
                UnpackTask.owner_id == owner_id,
                UnpackTask.status.in_([TaskStatus.RUNNING.value, TaskStatus.CANCELLING.value]),
            )
            .all()
        )
    finally:
        db.close()
    return sum(1 for _, pid in rows if _is_process_alive(pid))


def _local_running_evolution_job_count() -> int:
    from app.model import FirmwareEvolutionJob, get_db_session
    from app.services.worker import get_worker_id

    owner_id = get_worker_id()
    db = get_db_session()
    try:
        rows = (
            db.query(FirmwareEvolutionJob.id, FirmwareEvolutionJob.runner_pid)
            .filter(
                FirmwareEvolutionJob.owner_id == owner_id,
                FirmwareEvolutionJob.status.in_([EVOLUTION_RUNNING, EVOLUTION_CANCELLING]),
            )
            .all()
        )
        return sum(1 for _, pid in rows if _is_process_alive(pid))
    finally:
        db.close()


def _register_cancel_hook(task_id: str, hook) -> None:
    with _active_cancel_hooks_lock:
        if hook is None:
            _active_cancel_hooks.pop(task_id, None)
        else:
            _active_cancel_hooks[task_id] = hook


def _register_evolution_pid(job_id: str, pid: int | None) -> None:
    with _active_evolution_processes_lock:
        if not pid or int(pid) <= 0:
            _active_evolution_processes.pop(job_id, None)
        else:
            _active_evolution_processes[job_id] = int(pid)


def _get_registered_evolution_pid(job_id: str) -> int | None:
    with _active_evolution_processes_lock:
        pid = _active_evolution_processes.get(job_id)
    return int(pid) if pid else None


def _clear_registered_evolution_pid(job_id: str) -> None:
    with _active_evolution_processes_lock:
        _active_evolution_processes.pop(job_id, None)


def _signal_evolution_runner(job, sig: int, *, event_type: str, summary: str) -> bool:
    sent = _signal_runner_process(getattr(job, "runner_pid", None), sig)
    if sent:
        _record_task_event(
            str(getattr(job, "task_id", "")),
            project_id=getattr(job, "project_id", None),
            event_type=event_type,
            summary=summary,
            stage_key="evolution",
            status=getattr(job, "status", None),
            detail={
                "job_id": getattr(job, "id", None),
                "runner_pid": getattr(job, "runner_pid", None),
                "signal": sig,
            },
            owner_id=getattr(job, "owner_id", None),
            created_by="task_manager",
        )
    return sent


def _kill_processes_by_path_marker(path_marker: str) -> list[int]:
    marker = str(path_marker or "").strip()
    if not marker:
        return []
    killed: list[int] = []
    try:
        for entry in os.scandir("/proc"):
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            try:
                cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "ignore")
            except Exception:
                continue
            if marker not in cmdline:
                continue
            if _signal_runner_process(pid, signal.SIGTERM):
                killed.append(pid)
        if killed:
            time.sleep(1.0)
            for pid in list(killed):
                if _is_process_alive(pid):
                    _signal_runner_process(pid, signal.SIGKILL)
    except Exception as exc:
        logger.warning("failed to kill processes by path marker %s: %s", marker, exc)
    return killed


def _terminate_evolution_runtime(job_id: str, job_root: Path | None = None) -> dict[str, Any]:
    runtime_root = str(job_root or "").strip()
    killed_pids: list[int] = []
    registered_pid = _get_registered_evolution_pid(job_id)
    if registered_pid:
        if _signal_runner_process(registered_pid, signal.SIGTERM):
            killed_pids.append(int(registered_pid))
            time.sleep(0.5)
            if _is_process_alive(registered_pid):
                _signal_runner_process(registered_pid, signal.SIGKILL)
        _clear_registered_evolution_pid(job_id)
    if runtime_root:
        for pid in _kill_processes_by_path_marker(runtime_root):
            if pid not in killed_pids:
                killed_pids.append(pid)
    return {
        "job_id": job_id,
        "job_root": runtime_root or None,
        "killed_pids": killed_pids,
    }


def _cleanup_evolution_job_workspace(job_root: Path) -> None:
    if not job_root.exists():
        return
    for name in ("round_001", "round_002", "round_003", "sessions", "working_tool", "workspace"):
        target = job_root / name
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
    for name in ("tool_manifest.json", "evolution_result.json"):
        target = job_root / name
        with suppress(Exception):
            if target.exists():
                target.unlink()


def _record_task_event(
    task_id: str,
    *,
    project_id: Optional[str],
    event_type: str,
    summary: str,
    stage_key: Optional[str] = None,
    status: Optional[str] = None,
    detail: Optional[dict] = None,
    owner_id: Optional[str] = None,
    created_by: Optional[str] = None,
) -> None:
    from app.services.task_events import record_task_event

    try:
        record_task_event(
            task_id,
            project_id=project_id,
            event_type=event_type,
            summary=summary,
            stage_key=stage_key,
            status=status,
            detail=detail,
            owner_id=owner_id,
            created_by=created_by,
        )
    except Exception as exc:
        logger.warning("failed to persist task event %s for task %s: %s", event_type, task_id, exc)


def _record_task_event_from_row(
    task,
    *,
    event_type: str,
    summary: str,
    stage_key: Optional[str] = None,
    status: Optional[str] = None,
    detail: Optional[dict] = None,
    owner_id: Optional[str] = None,
    created_by: Optional[str] = None,
) -> None:
    _record_task_event(
        task.id,
        project_id=getattr(task, "project_id", None),
        event_type=event_type,
        summary=summary,
        stage_key=stage_key,
        status=status,
        detail=detail,
        owner_id=owner_id or getattr(task, "owner_id", None),
        created_by=created_by,
    )


def _trigger_cancel_hook(task_id: str) -> None:
    with _active_cancel_hooks_lock:
        hook = _active_cancel_hooks.get(task_id)
    if hook is None:
        return
    try:
        from app.model import UnpackTask, get_db_session

        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
            if task is not None:
                _record_task_event_from_row(
                    task,
                    event_type="cancel_hook_triggered",
                    summary="已触发本地取消钩子",
                    stage_key=task.current_stage,
                    status=task.status,
                    detail={"owner_id": task.owner_id},
                    created_by="task_manager",
                )
        finally:
            db.close()
        hook()
    except Exception as exc:
        logger.warning("failed to trigger cancel hook for task %s: %s", task_id, exc)


def get_local_active_task_count() -> int:
    # Keep manual evolution within the same worker capacity budget as unpack tasks.
    return _active_runner_count() + _local_running_evolution_job_count()


def get_local_running_task_id() -> str | None:
    from app.model import TaskStatus, UnpackTask, get_db_session
    from app.services.worker import get_worker_id

    owner_id = get_worker_id()
    db = get_db_session()
    try:
        row = (
            db.query(UnpackTask.id)
            .filter(
                UnpackTask.assigned_worker_id == owner_id,
                UnpackTask.status.in_([TaskStatus.ASSIGNED.value, TaskStatus.RUNNING.value, TaskStatus.CANCELLING.value]),
            )
            .order_by(UnpackTask.created_at.asc(), UnpackTask.id.asc())
            .first()
        )
        return str(row.id) if row else None
    finally:
        db.close()


def recover_stale_owned_tasks() -> None:
    from app.model import FirmwareEvolutionJob, TaskStatus, UnpackTask, get_db_session
    from app.services.worker import get_worker_id

    owner_id = get_worker_id()
    db = get_db_session()
    try:
        tasks = (
            db.query(UnpackTask)
            .filter(
                UnpackTask.owner_id == owner_id,
                UnpackTask.status.in_(
                    [TaskStatus.CLAIMED.value, TaskStatus.RUNNING.value, TaskStatus.CANCELLING.value]
                ),
            )
            .all()
        )
        evolution_jobs = (
            db.query(FirmwareEvolutionJob)
            .filter(
                FirmwareEvolutionJob.owner_id == owner_id,
                FirmwareEvolutionJob.status.in_([EVOLUTION_CLAIMED, EVOLUTION_RUNNING, EVOLUTION_CANCELLING]),
            )
            .all()
        )
    finally:
        db.close()

    for task in tasks:
        if task.status == TaskStatus.CLAIMED.value:
            _reset_claim(task.id)
            continue
        if _is_process_alive(task.runner_pid):
            continue
        reason = "owner restarted without active runner process"
        if task.status == TaskStatus.CANCELLING.value:
            _mark_task_cancelled(task.id, reason=reason)
        else:
            _finalize_orphaned_task(task.id, reason=reason)
    for job in evolution_jobs:
        if job.status == EVOLUTION_CLAIMED:
            _reset_evolution_claim(job.id)
            continue
        if _is_process_alive(job.runner_pid):
            continue
        reason = "evolution owner restarted without active runner process"
        if job.status == EVOLUTION_CANCELLING:
            _mark_evolution_cancelled(job.id, reason=reason)
        else:
            _finalize_orphaned_evolution_job(job.id, reason=reason)


def _reset_evolution_claim(job_id: str) -> None:
    from app.model import FirmwareEvolutionJob, get_db_session

    db = get_db_session()
    try:
        (
            db.query(FirmwareEvolutionJob)
            .filter(
                FirmwareEvolutionJob.id == job_id,
                FirmwareEvolutionJob.status.in_([EVOLUTION_CLAIMED, EVOLUTION_RUNNING]),
            )
            .update(
                {
                    FirmwareEvolutionJob.status: EVOLUTION_PENDING,
                    FirmwareEvolutionJob.owner_id: None,
                    FirmwareEvolutionJob.dispatch_owner_id: None,
                    FirmwareEvolutionJob.dispatch_token: None,
                    FirmwareEvolutionJob.dispatch_claimed_at: None,
                    FirmwareEvolutionJob.dispatch_lease_expires_at: None,
                    FirmwareEvolutionJob.heartbeat_at: None,
                    FirmwareEvolutionJob.lease_expires_at: None,
                    FirmwareEvolutionJob.cancel_requested_at: None,
                    FirmwareEvolutionJob.last_progress_at: now_local(),
                    FirmwareEvolutionJob.runner_pid: None,
                    FirmwareEvolutionJob.runner_started_at: None,
                    FirmwareEvolutionJob.runner_heartbeat_at: None,
                    FirmwareEvolutionJob.run_token: None,
                    FirmwareEvolutionJob.cancel_grace_deadline: None,
                    FirmwareEvolutionJob.cancel_force_deadline: None,
                    FirmwareEvolutionJob.started_at: None,
                },
                synchronize_session=False,
            )
        )
        db.commit()
    finally:
        db.close()


def _claim_evolution_job(job_id: str) -> bool:
    from app.model import FirmwareEvolutionJob, get_db_session
    from app.services.worker import get_worker_id

    owner_id = get_worker_id()
    now = now_local()
    claim_deadline = now + timedelta(seconds=_dispatch_interval_seconds() * 4)
    dispatch_token = uuid.uuid4().hex

    db = get_db_session()
    try:
        updated = (
            db.query(FirmwareEvolutionJob)
            .filter(FirmwareEvolutionJob.id == job_id, FirmwareEvolutionJob.status == EVOLUTION_PENDING)
            .update(
                {
                    FirmwareEvolutionJob.status: EVOLUTION_CLAIMED,
                    FirmwareEvolutionJob.owner_id: owner_id,
                    FirmwareEvolutionJob.dispatch_owner_id: owner_id,
                    FirmwareEvolutionJob.dispatch_token: dispatch_token,
                    FirmwareEvolutionJob.dispatch_claimed_at: now,
                    FirmwareEvolutionJob.dispatch_lease_expires_at: claim_deadline,
                    FirmwareEvolutionJob.current_stage: "queued",
                    FirmwareEvolutionJob.heartbeat_at: now,
                    FirmwareEvolutionJob.lease_expires_at: None,
                    FirmwareEvolutionJob.cancel_requested_at: None,
                    FirmwareEvolutionJob.last_progress_at: now,
                    FirmwareEvolutionJob.runner_pid: None,
                    FirmwareEvolutionJob.runner_started_at: None,
                    FirmwareEvolutionJob.runner_heartbeat_at: None,
                    FirmwareEvolutionJob.run_token: None,
                    FirmwareEvolutionJob.cancel_grace_deadline: None,
                    FirmwareEvolutionJob.cancel_force_deadline: None,
                    FirmwareEvolutionJob.completed_at: None,
                    FirmwareEvolutionJob.error_message: None,
                },
                synchronize_session=False,
            )
        )
        db.commit()
        return bool(updated)
    finally:
        db.close()


def _claim_pending_evolution_jobs(limit: int) -> list[str]:
    from app.model import FirmwareEvolutionJob, get_db_session
    from app.services.worker import get_worker_id

    fetch_limit = max(1, limit)
    owner_id = get_worker_id()
    use_skip_locked = _supports_skip_locked()

    def _do_claim_pending_jobs() -> list[dict[str, object]]:
        now = now_local()
        claim_deadline = now + timedelta(seconds=_dispatch_interval_seconds() * 4)
        if not use_skip_locked:
            candidate_ids: list[str] = []
            db = get_db_session()
            try:
                candidate_ids = [
                    row.id
                    for row in (
                        db.query(FirmwareEvolutionJob.id)
                        .filter(FirmwareEvolutionJob.status == EVOLUTION_PENDING)
                        .order_by(FirmwareEvolutionJob.created_at.asc(), FirmwareEvolutionJob.id.asc())
                        .limit(fetch_limit)
                        .all()
                    )
                ]
            finally:
                db.close()
            claimed_payloads: list[dict[str, object]] = []
            for job_id in candidate_ids:
                if len(claimed_payloads) >= fetch_limit:
                    break
                if _claim_evolution_job(job_id):
                    claimed_payloads.append(
                        {
                            "job_id": job_id,
                            "status": EVOLUTION_CLAIMED,
                            "owner_id": owner_id,
                            "event_recorded": True,
                        }
                    )
            return claimed_payloads

        db = get_db_session()
        claimed_payloads: list[dict[str, object]] = []
        try:
            query = (
                db.query(FirmwareEvolutionJob)
                .filter(FirmwareEvolutionJob.status == EVOLUTION_PENDING)
                .order_by(FirmwareEvolutionJob.created_at.asc(), FirmwareEvolutionJob.id.asc())
            )
            if use_skip_locked:
                query = query.with_for_update(skip_locked=True)
            candidates = query.limit(fetch_limit).all()
            for job in candidates:
                dispatch_token = uuid.uuid4().hex
                job.status = EVOLUTION_CLAIMED
                job.owner_id = owner_id
                job.dispatch_owner_id = owner_id
                job.dispatch_token = dispatch_token
                job.dispatch_claimed_at = now
                job.dispatch_lease_expires_at = claim_deadline
                job.current_stage = "queued"
                job.heartbeat_at = now
                job.lease_expires_at = None
                job.cancel_requested_at = None
                job.last_progress_at = now
                job.runner_pid = None
                job.runner_started_at = None
                job.runner_heartbeat_at = None
                job.run_token = None
                job.cancel_grace_deadline = None
                job.cancel_force_deadline = None
                job.completed_at = None
                job.error_message = None
                claimed_payloads.append(
                    {
                        "job_id": job.id,
                        "task_id": job.task_id,
                        "project_id": job.project_id,
                        "status": job.status,
                        "owner_id": owner_id,
                    }
                )
            db.commit()
            return claimed_payloads
        except SQLAlchemyError:
            db.rollback()
            raise
        finally:
            db.close()

    claimed_payloads = _run_db_retry(
        "claim_pending_evolution_jobs",
        _do_claim_pending_jobs,
        context={"owner_id": owner_id, "limit": fetch_limit, "skip_locked": use_skip_locked},
    )

    for payload in claimed_payloads:
        if payload.get("event_recorded"):
            continue
        _record_task_event(
            str(payload.get("task_id") or ""),
            project_id=payload.get("project_id"),
            event_type="evolution_claimed",
            summary="进化任务已被当前 owner 认领",
            stage_key="evolution",
            status=str(payload["status"]),
            detail={"job_id": payload["job_id"], "owner_id": payload.get("owner_id"), "dispatch_token_present": True},
            owner_id=str(payload.get("owner_id") or ""),
            created_by="task_manager",
        )
    return [str(item["job_id"]) for item in claimed_payloads]


def _launch_evolution_runner(job_id: str) -> None:
    from app.model import FirmwareEvolutionJob, get_db_session
    from app.services.worker import get_worker_id, refresh_worker_active_tasks

    owner_id = get_worker_id()
    db = get_db_session()
    try:
        job = (
            db.query(FirmwareEvolutionJob)
            .filter(
                FirmwareEvolutionJob.id == job_id,
                FirmwareEvolutionJob.owner_id == owner_id,
                FirmwareEvolutionJob.status == EVOLUTION_CLAIMED,
            )
            .first()
        )
        if job is None or not job.dispatch_token:
            raise RuntimeError(f"进化任务未被当前 owner 正确认领: {job_id}")
        dispatch_token = job.dispatch_token
        run_token = uuid.uuid4().hex
    finally:
        db.close()

    env = os.environ.copy()
    project_root = str(Path(__file__).resolve().parents[2])
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = project_root if not existing_pythonpath else f"{project_root}{os.pathsep}{existing_pythonpath}"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "app.evolution_runner",
            "--job-id",
            job_id,
            "--owner-id",
            owner_id,
            "--run-token",
            run_token,
        ],
        cwd=project_root,
        env=env,
        start_new_session=True,
    )

    now = now_local()
    db = get_db_session()
    try:
        updated = (
            db.query(FirmwareEvolutionJob)
            .filter(
                FirmwareEvolutionJob.id == job_id,
                FirmwareEvolutionJob.owner_id == owner_id,
                FirmwareEvolutionJob.dispatch_token == dispatch_token,
                FirmwareEvolutionJob.status == EVOLUTION_CLAIMED,
            )
            .update(
                {
                    FirmwareEvolutionJob.status: EVOLUTION_RUNNING,
                    FirmwareEvolutionJob.dispatch_lease_expires_at: None,
                    FirmwareEvolutionJob.runner_pid: proc.pid,
                    FirmwareEvolutionJob.runner_started_at: now,
                    FirmwareEvolutionJob.runner_heartbeat_at: now,
                    FirmwareEvolutionJob.heartbeat_at: now,
                    FirmwareEvolutionJob.lease_expires_at: None,
                    FirmwareEvolutionJob.last_progress_at: now,
                    FirmwareEvolutionJob.run_token: run_token,
                    FirmwareEvolutionJob.started_at: now,
                },
                synchronize_session=False,
            )
        )
        db.commit()
        if not updated:
            _signal_runner_process(proc.pid, signal.SIGTERM)
            raise RuntimeError(f"进化任务状态已变化，已停止新 runner: {job_id}")
        job = db.query(FirmwareEvolutionJob).filter(FirmwareEvolutionJob.id == job_id).first()
        if job is not None:
            _record_task_event(
                job.task_id,
                project_id=job.project_id,
                event_type="evolution_runner_started",
                summary="进化任务独立执行进程已启动",
                stage_key="evolution",
                status=job.status,
                detail={"job_id": job.id, "runner_pid": proc.pid, "run_token_present": True, "dispatch_token_present": True},
                owner_id=owner_id,
                created_by="task_manager",
            )
    finally:
        db.close()
    refresh_worker_active_tasks()


def _should_cancel_evolution_run(job_id: str, run_token: Optional[str]) -> bool:
    from app.model import FirmwareEvolutionJob, get_db_session

    db = get_db_session()
    try:
        job = db.query(FirmwareEvolutionJob).filter(FirmwareEvolutionJob.id == job_id).first()
        if job is None:
            return True
        if run_token and job.run_token != run_token:
            return True
        return str(job.status or "") in {EVOLUTION_CANCELLING, EVOLUTION_CANCELLED}
    finally:
        db.close()


def _update_evolution_progress_for_owner(job_id: str, *, owner_id: str, run_token: str, round_id: int, stage: str) -> None:
    from app.model import FirmwareEvolutionJob, UnpackTask, get_db_session

    now = now_local()
    db = get_db_session()
    try:
        job = (
            db.query(FirmwareEvolutionJob)
            .filter(
                FirmwareEvolutionJob.id == job_id,
                FirmwareEvolutionJob.owner_id == owner_id,
                FirmwareEvolutionJob.run_token == run_token,
            )
            .first()
        )
        if job is None:
            return
        job.current_round = int(round_id or 0)
        job.current_stage = stage
        job.runner_heartbeat_at = now
        job.heartbeat_at = now
        job.last_progress_at = now
        task = db.query(UnpackTask).filter(UnpackTask.id == job.task_id).first()
        if task is not None:
            task.latest_evolution_status = job.status
        db.commit()
    finally:
        db.close()


def _mark_evolution_cancelled(job_id: str, reason: str = "Evolution job was cancelled") -> None:
    from app.model import FirmwareEvolutionJob, UnpackTask, get_db_session

    db = get_db_session()
    try:
        job = db.query(FirmwareEvolutionJob).filter(FirmwareEvolutionJob.id == job_id).first()
        if job is None:
            return
        previous_owner_id = job.owner_id
        now = now_local()
        job.status = EVOLUTION_CANCELLED
        job.error_message = reason
        job.owner_id = None
        job.dispatch_owner_id = None
        job.dispatch_token = None
        job.dispatch_claimed_at = None
        job.dispatch_lease_expires_at = None
        job.heartbeat_at = now
        job.lease_expires_at = None
        job.runner_pid = None
        job.runner_started_at = None
        job.runner_heartbeat_at = None
        job.run_token = None
        job.cancel_grace_deadline = None
        job.cancel_force_deadline = None
        job.completed_at = now
        job.last_progress_at = now
        task = db.query(UnpackTask).filter(UnpackTask.id == job.task_id).first()
        if task is not None:
            task.latest_evolution_job_id = job.id
            task.latest_evolution_status = EVOLUTION_CANCELLED
            task.latest_evolution_completed_at = now
        db.commit()
        _record_task_event(
            job.task_id,
            project_id=job.project_id,
            event_type="evolution_cancelled",
            summary=f"手动进化任务已取消：{reason}",
            stage_key="evolution",
            status=job.status,
            detail={"job_id": job.id, "reason": reason},
            owner_id=previous_owner_id,
            created_by="task_manager",
        )
        if task is not None:
            _write_task_result_cache(task.id)
    finally:
        db.close()


def _finalize_orphaned_evolution_job(job_id: str, reason: str) -> None:
    from app.model import FirmwareEvolutionJob, UnpackTask, get_db_session

    db = get_db_session()
    try:
        job = db.query(FirmwareEvolutionJob).filter(FirmwareEvolutionJob.id == job_id).first()
        if job is None or str(job.status or "") not in {EVOLUTION_CLAIMED, EVOLUTION_RUNNING, EVOLUTION_CANCELLING}:
            return
        now = now_local()
        if str(job.status or "") == EVOLUTION_CLAIMED:
            job.status = EVOLUTION_PENDING
            job.current_stage = "pending"
            job.error_message = None
            job.completed_at = None
        elif str(job.status or "") == EVOLUTION_CANCELLING:
            job.status = EVOLUTION_CANCELLED
            job.error_message = reason
            job.completed_at = now
        else:
            job.status = EVOLUTION_FAILED
            job.error_message = reason
            job.completed_at = now
        previous_owner_id = job.owner_id
        job.owner_id = None
        job.dispatch_owner_id = None
        job.dispatch_token = None
        job.dispatch_claimed_at = None
        job.dispatch_lease_expires_at = None
        job.lease_expires_at = None
        job.runner_pid = None
        job.runner_started_at = None
        job.runner_heartbeat_at = None
        job.heartbeat_at = now
        job.run_token = None
        job.cancel_grace_deadline = None
        job.cancel_force_deadline = None
        job.last_progress_at = now
        task = db.query(UnpackTask).filter(UnpackTask.id == job.task_id).first()
        if task is not None:
            task.latest_evolution_job_id = job.id
            task.latest_evolution_status = job.status
            task.latest_evolution_completed_at = job.completed_at
            task.latest_evolution_final_skill_path = job.final_skill_path
        db.commit()
        _record_task_event(
            job.task_id,
            project_id=job.project_id,
            event_type="evolution_orphan_recovered",
            summary="进化孤儿任务已完成状态收敛",
            stage_key="evolution",
            status=job.status,
            detail={"job_id": job.id, "reason": reason},
            owner_id=previous_owner_id,
            created_by="task_manager",
        )
        if task is not None and str(job.status or "") in {EVOLUTION_FAILED, EVOLUTION_CANCELLED}:
            _write_task_result_cache(task.id)
    finally:
        db.close()


def _mark_task_stage(task_id: str, stage: str) -> None:
    from app.model import UnpackTask, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            return
        task.current_stage = stage
        task.last_progress_at = now_local()
        db.commit()
    finally:
        db.close()


def _parse_llm_binding_snapshot(snapshot_raw: str | None) -> dict | None:
    if not snapshot_raw:
        return None
    try:
        payload = json.loads(snapshot_raw)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _agent_runtime_payload_from_snapshot(snapshot: dict | None) -> dict[str, Any]:
    agent_task_key = snapshot.get("agent_task_key") if isinstance(snapshot, dict) and isinstance(snapshot.get("agent_task_key"), dict) else {}
    secret = str(agent_task_key.get("secret") or "").strip()
    return {
        "has_agent_task_key": bool(secret),
        "agent_task_key_id": str(agent_task_key.get("id") or "").strip() or None,
        "agent_task_key_prefix": str(agent_task_key.get("prefix") or "").strip() or None,
        "agent_runtime_mode": "task_scoped" if secret else "global",
    }


def _build_llm_binding_snapshot(db) -> dict:
    from app.services.configcenter import get_configcenter_client
    from app.unpacker_engine import (
        ROLE_CONFIG_FILE_KEYS,
        ROLE_MODEL_CONFIG_KEYS,
        _build_settings_json,
        _resolve_provider_selector,
    )

    from app.model import get_config_value

    roles: dict[str, dict] = {}
    client = get_configcenter_client()
    frozen_at = isoformat_local(now_local()) or ""
    for role, config_key in ROLE_CONFIG_FILE_KEYS.items():
        config_file_key = str(get_config_value(db, config_key, default="") or "").strip()
        if not config_file_key:
            raise ValueError(f"LLM 角色 {role} 未配置 config_file_key")

        config_file = client.get_llm_config_file(config_file_key)
        configured_model = str(get_config_value(db, ROLE_MODEL_CONFIG_KEYS.get(role, ""), default="") or "").strip()
        selected_provider_key, resolved_model, model_selector = _resolve_provider_selector(
            config_file_key,
            str(config_file.get("default_model") or "").strip(),
            configured_model or None,
        )
        roles[role] = {
            "config_file_key": config_file_key,
            "provider_key": selected_provider_key,
            "display_name": str(config_file.get("display_name") or "").strip() or config_file_key,
            "model": resolved_model,
            "model_selector": model_selector,
            "models_json": config_file.get("models_json"),
            "settings_json": _build_settings_json(selected_provider_key, "auto"),
            "frozen_at": frozen_at,
            "updated_at": str(config_file.get("updated_at") or "").strip() or None,
        }

    return {
        "version": 2,
        "frozen_at": frozen_at,
        "roles": roles,
    }


def _freeze_task_llm_binding_snapshot(task_id: str) -> dict:
    from app.model import UnpackTask, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            raise ValueError(f"任务不存在: {task_id}")
        if task.llm_binding_snapshot:
            return json.loads(task.llm_binding_snapshot)

        snapshot = _build_llm_binding_snapshot(db)
        task.llm_binding_snapshot = json.dumps(snapshot, ensure_ascii=False)
        task.last_progress_at = now_local()
        db.commit()
        return snapshot
    finally:
        db.close()


def _update_task_progress(task_id: str, *, stage: Optional[str] = None) -> None:
    from app.services.worker import get_worker_id

    _update_task_progress_for_owner(task_id, owner_id=get_worker_id(), run_token=None, stage=stage)


def _update_task_progress_for_owner(
    task_id: str,
    *,
    owner_id: str,
    run_token: Optional[str],
    stage: Optional[str] = None,
) -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        query = db.query(UnpackTask).filter(
            UnpackTask.id == task_id,
            UnpackTask.owner_id == owner_id,
            UnpackTask.status == TaskStatus.RUNNING.value,
        )
        if run_token:
            query = query.filter(UnpackTask.run_token == run_token)
        task = query.first()
        if task is None:
            return
        previous_stage = str(task.current_stage or "").strip() or None
        task.runner_heartbeat_at = now_local()
        task.heartbeat_at = task.runner_heartbeat_at
        task.dispatch_lease_expires_at = task.runner_heartbeat_at + timedelta(seconds=_task_lease_seconds())
        task.run_lease_expires_at = task.runner_heartbeat_at + timedelta(seconds=_task_lease_seconds())
        task.last_progress_at = now_local()
        if stage:
            task.current_stage = stage
        db.commit()
        if stage and stage != previous_stage:
            record_task_stage_transition(stage=stage, task_origin=_task_origin(task))
            stage_label = STAGE_LABELS.get(stage, stage)
            _record_task_event_from_row(
                task,
                event_type="stage_changed",
                summary=f"进入阶段：{stage_label}",
                stage_key=stage,
                status=task.status,
                detail={"from": previous_stage, "to": stage},
                owner_id=owner_id,
                created_by="task_manager",
            )
    finally:
        db.close()


def _finalize_orphaned_task(task_id: str, reason: str, *, owner_lost: bool = False) -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None or task.status not in (
            TaskStatus.CLAIMED.value,
            TaskStatus.ASSIGNED.value,
            TaskStatus.RUNNING.value,
            TaskStatus.CANCELLING.value,
        ):
            return
        if task.status in (TaskStatus.CLAIMED.value, TaskStatus.ASSIGNED.value):
            task.status = TaskStatus.PENDING.value
            task.current_stage = "pending"
            task.result_status = None
            task.result_message = None
            task.error_message = None
            terminal_event = None
            terminal_summary = None
        elif task.status == TaskStatus.CANCELLING.value:
            task.status = TaskStatus.CANCELLED.value
            task.result_status = "cancelled"
            task.result_message = f"Task cancelled: {reason}"
            terminal_event = "task_cancelled"
            terminal_summary = f"任务已取消：{reason}"
        else:
            task.status = TaskStatus.FAILED.value
            task.result_status = "failed"
            task.error_message = reason
            task.result_message = f"Task failed: {reason}"
            terminal_event = "task_failed"
            terminal_summary = f"任务失败：{reason}"
        previous_owner_id = task.owner_id
        task.owner_id = None
        task.dispatch_owner_id = None
        task.dispatch_token = None
        task.assigned_worker_id = None
        task.assigned_pod_name = None
        task.dispatch_claimed_at = None
        task.dispatch_lease_expires_at = None
        task.lease_expires_at = None
        task.run_lease_expires_at = None
        task.runner_pid = None
        task.runner_started_at = None
        task.runner_heartbeat_at = None
        task.heartbeat_at = None
        task.run_token = None
        task.cancel_grace_deadline = None
        task.cancel_force_deadline = None
        task.completed_at = None if task.status == TaskStatus.PENDING.value else now_local()
        task.last_progress_at = now_local()
        db.commit()
        if owner_lost:
            _record_task_event_from_row(
                task,
                event_type="owner_lost",
                summary="任务 owner 已失活",
                stage_key=task.current_stage,
                status=task.status,
                detail={"reason": reason, "owner_id": previous_owner_id},
                owner_id=previous_owner_id,
                created_by="task_manager",
            )
        _record_task_event_from_row(
            task,
            event_type="orphan_recovered",
            summary="孤儿任务已完成状态收敛",
            stage_key=task.current_stage,
            status=task.status,
            detail={"reason": reason},
            owner_id=previous_owner_id,
            created_by="task_manager",
        )
        if terminal_event and terminal_summary:
            _record_task_event_from_row(
                task,
                event_type=terminal_event,
                summary=terminal_summary,
                stage_key=task.current_stage,
                status=task.status,
                detail={"reason": reason},
                owner_id=previous_owner_id,
                created_by="task_manager",
            )
            _write_task_result_cache(task_id)
    finally:
        db.close()


def build_task_workspace(project_id: str, task_id: str) -> dict[str, Path]:
    base_dir = PROJECT_FILES_ROOT / project_id / TASK_WORKSPACE_ROOT / task_id
    return {
        "base_dir": base_dir,
        "input_dir": base_dir / "input",
        "output_dir": base_dir / "output",
        "run_dir": base_dir / "run",
    }


def _manifest_path(input_dir: Path) -> Path:
    return input_dir / "task.json"


def _write_task_manifest(input_dir: Path, source_firmware_path: str, output_path: str, run_path: str) -> Path:
    manifest_path = _manifest_path(input_dir)
    tool_log_path = str(Path(run_path) / "tool.log") if run_path else ""
    manifest_path.write_text(
        json.dumps(
            {
                "input_path": source_firmware_path,
                "output_path": output_path,
                "run_path": run_path,
                "log_path": tool_log_path,
                "log_file_path": tool_log_path,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return manifest_path


def prepare_task_workspace(
    project_id: str,
    task_id: str,
    source_firmware_path: str,
) -> dict[str, str]:
    workspace = build_task_workspace(project_id, task_id)
    for directory in workspace.values():
        directory.mkdir(parents=True, exist_ok=True)

    source_path = Path(source_firmware_path)
    if not source_path.exists() or not source_path.is_file():
        raise FileNotFoundError(f"固件文件不存在: {source_firmware_path}")

    manifest_path = _write_task_manifest(
        workspace["input_dir"],
        source_firmware_path,
        str(workspace["output_dir"]),
        str(workspace["run_dir"]),
    )
    return {
        "base_dir": str(workspace["base_dir"]),
        "input_path": source_firmware_path,
        "input_dir": str(workspace["input_dir"]),
        "output_path": str(workspace["output_dir"]),
        "run_path": str(workspace["run_dir"]),
        "manifest_path": str(manifest_path),
    }


def reset_task_workspace(
    project_id: str,
    task_id: str,
    source_firmware_path: str,
) -> dict[str, str]:
    workspace = build_task_workspace(project_id, task_id)

    import shutil

    for key in ("input_dir", "output_dir", "run_dir"):
        directory = workspace[key]
        if directory.exists():
            shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True, exist_ok=True)

    manifest_path = _write_task_manifest(
        workspace["input_dir"],
        source_firmware_path,
        str(workspace["output_dir"]),
        str(workspace["run_dir"]),
    )
    return {
        "base_dir": str(workspace["base_dir"]),
        "input_path": source_firmware_path,
        "input_dir": str(workspace["input_dir"]),
        "output_path": str(workspace["output_dir"]),
        "run_path": str(workspace["run_dir"]),
        "manifest_path": str(manifest_path),
    }


def remove_task_workspace(task_id: str, project_id: Optional[str]) -> None:
    normalized_project_id = str(project_id or "").strip()
    if not normalized_project_id:
        return

    workspace = build_task_workspace(normalized_project_id, task_id)
    base_dir = workspace["base_dir"].resolve()
    project_workspace_root = (
        PROJECT_FILES_ROOT / normalized_project_id / TASK_WORKSPACE_ROOT
    ).resolve()
    if not base_dir.exists():
        return
    if base_dir == project_workspace_root or project_workspace_root not in base_dir.parents:
        raise ValueError(
            f"refuse to remove non-task workspace path: {base_dir}"
        )

    import shutil

    shutil.rmtree(base_dir)
    logger.info("task workspace removed: %s", base_dir)


def enqueue_workspace_cleanup(
    task_id: str,
    project_id: Optional[str],
    *,
    reason: str,
    created_by: str = "task_manager",
) -> None:
    from app.model import WorkspaceCleanupJob, generate_id, get_db_session

    db = get_db_session()
    try:
        existing = (
            db.query(WorkspaceCleanupJob)
            .filter(
                WorkspaceCleanupJob.task_id == task_id,
                WorkspaceCleanupJob.project_id == project_id,
                WorkspaceCleanupJob.status.in_(["pending", "running"]),
            )
            .first()
        )
        if existing is not None:
            return
        db.add(
            WorkspaceCleanupJob(
                id=generate_id(),
                task_id=task_id,
                project_id=project_id,
                status="pending",
                reason=reason,
                created_by=created_by,
            )
        )
        db.commit()
    finally:
        db.close()


def process_workspace_cleanup_jobs(limit: int = 2) -> int:
    from app.model import FirmwareEvolutionJob, FirmwareEvolutionRound, SkillGenerationJob, TaskStatus, UnpackTask, WorkspaceCleanupJob, get_db_session, get_worker_id

    owner_id = get_worker_id()
    processed = 0
    while processed < max(1, limit):
        def _claim_cleanup_job() -> dict[str, Any] | None:
            db = get_db_session()
            now = now_local()
            try:
                query = (
                    db.query(WorkspaceCleanupJob)
                    .filter(
                        (
                            (WorkspaceCleanupJob.status == "pending")
                            | (
                                (WorkspaceCleanupJob.status == "running")
                                & (
                                    (WorkspaceCleanupJob.lease_expires_at.is_(None))
                                    | (WorkspaceCleanupJob.lease_expires_at < now)
                                )
                            )
                        )
                    )
                    .order_by(WorkspaceCleanupJob.created_at.asc())
                )
                if _supports_skip_locked():
                    query = query.with_for_update(skip_locked=True)
                job = query.first()
                if job is None:
                    return None
                job.status = "running"
                job.owner_id = owner_id
                job.started_at = job.started_at or now
                job.completed_at = None
                job.error_message = None
                job.attempts = int(job.attempts or 0) + 1
                job.lease_expires_at = _cleanup_job_lease_deadline(now)
                db.commit()
                return {
                    "job_id": job.id,
                    "task_id": job.task_id,
                    "project_id": job.project_id,
                    "reason": job.reason,
                    "attempts": job.attempts,
                }
            except SQLAlchemyError:
                db.rollback()
                raise
            finally:
                db.close()

        job = _run_db_retry(
            "claim_workspace_cleanup_job",
            _claim_cleanup_job,
            context={"owner_id": owner_id},
        )
        if job is None:
            break
        task_id = str(job["task_id"])
        project_id = job.get("project_id")
        job_id = str(job["job_id"])
        reason = str(job.get("reason") or "")
        logger.info(
            "claimed workspace cleanup job job_id=%s task_id=%s reason=%s attempts=%s owner_id=%s",
            job_id,
            task_id,
            reason,
            job.get("attempts"),
            owner_id,
        )

        error_message: Optional[str] = None
        requeue_task_id: Optional[str] = None
        started_at = time.monotonic()
        try:
            if reason == "task_retry_reset":
                db = get_db_session()
                try:
                    task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
                    if task is None:
                        raise RuntimeError("任务不存在，无法执行异步重试重置")
                    normalized_project_id = str(task.project_id or "").strip()
                    if not normalized_project_id:
                        raise RuntimeError("任务缺少 project_id，无法执行异步重试重置")
                    reset_task_workspace(
                        normalized_project_id,
                        task.id,
                        task.firmware_path,
                    )
                    task.status = TaskStatus.PENDING.value
                    task.owner_id = None
                    task.current_stage = "pending"
                    task.lease_expires_at = None
                    task.cancel_requested_at = None
                    task.runner_pid = None
                    task.runner_started_at = None
                    task.runner_heartbeat_at = None
                    task.run_token = None
                    task.cancel_grace_deadline = None
                    task.cancel_force_deadline = None
                    task.last_progress_at = now_local()
                    task.result_status = None
                    task.result_message = None
                    task.rounds = None
                    task.error_message = None
                    task.matched_skill = None
                    task.matched_skill_version = None
                    task.matched_skill_score = None
                    task.fallback_to_llm = False
                    task.generated_skill_path = None
                    task.generated_skill_status = None
                    task.promotion_success_count = None
                    task.skill_generation_status = None
                    task.skill_generation_error = None
                    task.skill_generation_job_id = None
                    task.skill_generation_started_at = None
                    task.skill_generation_completed_at = None
                    task.latest_evolution_job_id = None
                    task.latest_evolution_status = None
                    task.latest_evolution_started_at = None
                    task.latest_evolution_completed_at = None
                    task.latest_evolution_final_skill_path = None
                    task.started_at = None
                    task.completed_at = None
                    db.query(SkillGenerationJob).filter(SkillGenerationJob.task_id == task.id).delete()
                    evolution_jobs = db.query(FirmwareEvolutionJob).filter(FirmwareEvolutionJob.task_id == task.id).all()
                    for evolution_job in evolution_jobs:
                        db.query(FirmwareEvolutionRound).filter(FirmwareEvolutionRound.job_id == evolution_job.id).delete()
                    db.query(FirmwareEvolutionJob).filter(FirmwareEvolutionJob.task_id == task.id).delete()
                    if not task.llm_binding_snapshot:
                        snapshot = _build_llm_binding_snapshot(db)
                        task.llm_binding_snapshot = json.dumps(snapshot, ensure_ascii=False)
                    db.commit()
                    requeue_task_id = task.id
                finally:
                    db.close()
            else:
                remove_task_workspace(task_id, project_id)
        except Exception as exc:
            error_message = str(exc)
            logger.warning(
                "failed to process workspace job %s task %s reason=%s: %s",
                job_id,
                task_id,
                reason,
                exc,
            )

        def _finalize_cleanup_job() -> bool:
            db = get_db_session()
            try:
                current = db.query(WorkspaceCleanupJob).filter(WorkspaceCleanupJob.id == job_id).first()
                if current is None:
                    return False
                current.owner_id = owner_id
                current.lease_expires_at = None
                current.completed_at = now_local()
                if error_message:
                    current.status = "failed"
                    current.error_message = error_message
                else:
                    current.status = "success"
                db.commit()
                return True
            except SQLAlchemyError:
                db.rollback()
                raise
            finally:
                db.close()

        finalized = _run_db_retry(
            "finalize_workspace_cleanup_job",
            _finalize_cleanup_job,
            context={"job_id": job_id, "task_id": task_id, "owner_id": owner_id},
        )
        record_cleanup_job(
            reason=reason,
            result="failed" if error_message else ("success" if finalized else "skipped"),
            duration_seconds=time.monotonic() - started_at,
        )
        if not finalized:
            processed += 1
            continue
        if reason == "task_retry_reset":
            if error_message:
                _fail_retry_preparing_task(task_id, error_message)
            elif requeue_task_id:
                _record_task_event(
                    requeue_task_id,
                    project_id=project_id,
                    event_type="task_requeued",
                    summary="任务工作目录已重置，已重新入队",
                    stage_key="pending",
                    status=TaskStatus.PENDING.value,
                    detail={"retry_mode": "inplace_async"},
                    created_by="task_manager",
                )
        processed += 1
    return processed


def process_skill_generation_jobs(limit: int = 1) -> int:
    from app.model import SkillGenerationJob, UnpackTask, get_db_session, get_worker_id
    from app.unpacker_engine import _generate_candidate_skill

    owner_id = get_worker_id()
    processed = 0
    while processed < max(1, limit):
        db = get_db_session()
        job = None
        now = now_local()
        try:
            job = (
                db.query(SkillGenerationJob)
                .filter(
                    (SkillGenerationJob.status == SKILL_GENERATION_PENDING)
                    | (
                        (SkillGenerationJob.status == SKILL_GENERATION_RUNNING)
                        & (
                            (SkillGenerationJob.lease_expires_at.is_(None))
                            | (SkillGenerationJob.lease_expires_at < now)
                        )
                    )
                )
                .order_by(SkillGenerationJob.created_at.asc())
                .first()
            )
            if job is None:
                db.close()
                break
            job.status = SKILL_GENERATION_RUNNING
            job.owner_id = owner_id
            job.started_at = job.started_at or now
            job.completed_at = None
            job.error_message = None
            job.attempts = int(job.attempts or 0) + 1
            job.lease_expires_at = _skill_generation_job_lease_deadline(now)
            task = db.query(UnpackTask).filter(UnpackTask.id == job.task_id).first()
            if task is not None:
                task.skill_generation_status = SKILL_GENERATION_RUNNING
                task.skill_generation_error = None
                task.skill_generation_job_id = job.id
                task.skill_generation_started_at = job.started_at
                task.skill_generation_completed_at = None
            db.commit()
            if task is not None:
                _record_task_event_from_row(
                    task,
                    event_type="skill_generation_started",
                    summary="候选 SKILL 开始异步生成",
                    stage_key="skill_generation",
                    status=task.status,
                    detail={"job_id": job.id},
                    owner_id=owner_id,
                    created_by="task_manager",
                )
                _write_task_result_cache(task.id)
            task_id = job.task_id
            project_id = job.project_id
            job_id = job.id
        finally:
            db.close()

        error_message: Optional[str] = None
        saved_skill: Optional[dict[str, Any]] = None
        try:
            db = get_db_session()
            try:
                task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
                if task is None:
                    raise RuntimeError("任务不存在，无法执行异步 SKILL 沉淀")
                context_path = _skill_generation_context_path(task.output_path)
                if not context_path.exists():
                    raise RuntimeError(f"缺少 SKILL 沉淀上下文文件: {context_path}")
                context = json.loads(context_path.read_text(encoding="utf-8"))
                features = context.get("features") or {}
                if not isinstance(features, dict) or not features:
                    raise RuntimeError("SKILL 沉淀上下文缺少 features")
                review_result = str(context.get("review_result") or "").strip()
                if not review_result:
                    raise RuntimeError("SKILL 沉淀上下文缺少 review_result")
                llm_binding_snapshot = None
                if task.llm_binding_snapshot:
                    try:
                        llm_binding_snapshot = json.loads(task.llm_binding_snapshot)
                    except Exception:
                        llm_binding_snapshot = None
                saved_skill = _generate_candidate_skill(
                    task_id=task.id,
                    firmware_path=str(context.get("firmware_path") or task.firmware_path),
                    output_path=task.output_path,
                    features=features,
                    review_result=review_result,
                    log_dir=context_path.parent,
                    llm_binding_snapshot=llm_binding_snapshot,
                )
            finally:
                db.close()
        except Exception as exc:
            error_message = str(exc)
            logger.warning("failed to process skill generation job %s task %s: %s", job_id, task_id, exc)

        db = get_db_session()
        try:
            current = db.query(SkillGenerationJob).filter(SkillGenerationJob.id == job_id).first()
            task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
            completed_at = now_local()
            if current is not None:
                current.owner_id = owner_id
                current.lease_expires_at = None
                current.completed_at = completed_at
                current.status = SKILL_GENERATION_FAILED if error_message else SKILL_GENERATION_SUCCESS
                current.error_message = error_message
            if task is not None:
                task.skill_generation_status = SKILL_GENERATION_FAILED if error_message else SKILL_GENERATION_SUCCESS
                task.skill_generation_error = error_message
                task.skill_generation_job_id = job_id
                task.skill_generation_completed_at = completed_at
                if saved_skill:
                    task.generated_skill_path = saved_skill.get("path")
                    task.generated_skill_status = saved_skill.get("skill_status")
                    task.promotion_success_count = saved_skill.get("promotion_success_count")
            db.commit()
            if task is not None:
                _record_task_event_from_row(
                    task,
                    event_type="skill_generation_failed" if error_message else "skill_generation_completed",
                    summary="候选 SKILL 生成失败" if error_message else "候选 SKILL 已异步生成",
                    stage_key="skill_generation",
                    status=task.status,
                    detail={
                        "skill_generation_status": task.skill_generation_status,
                        "generated_skill_path": task.generated_skill_path,
                        "error": error_message,
                    },
                    owner_id=owner_id,
                    created_by="task_manager",
                )
                _write_task_result_cache(task_id)
        finally:
            db.close()
        processed += 1
    return processed


def resolve_task_runtime_paths(
    task_id: str,
    project_id: Optional[str],
    source_firmware_path: str,
    output_path: str,
) -> dict[str, str]:
    normalized_project_id = str(project_id or "").strip()
    if normalized_project_id:
        workspace = build_task_workspace(normalized_project_id, task_id)
        if workspace["base_dir"].exists():
            _write_task_manifest(
                workspace["input_dir"],
                source_firmware_path,
                str(workspace["output_dir"]),
                str(workspace["run_dir"]),
            )
            return {
                "input_path": source_firmware_path,
                "output_path": str(workspace["output_dir"]),
                "run_path": str(workspace["run_dir"]),
            }
        return {
            "input_path": source_firmware_path,
            "output_path": output_path,
            "run_path": str(workspace["run_dir"]) if Path(output_path).name == "output" else "",
        }

    derived_run_path = str(Path(output_path).parent / "run") if Path(output_path).name == "output" else ""
    return {
        "input_path": source_firmware_path,
        "output_path": output_path,
        "run_path": derived_run_path,
    }


def submit_unpack_task(
    firmware_path: str,
    output_path: Optional[str] = None,
    project_id: Optional[str] = None,
    llm_binding_snapshot: Optional[dict] = None,
    task_origin_type: Optional[str] = None,
    parent_project_id: Optional[str] = None,
    parent_task_id: Optional[str] = None,
    parent_task_type: Optional[str] = None,
    parent_stage_name: Optional[str] = None,
    parent_stage_item_id: Optional[str] = None,
    parent_stage_item_key: Optional[str] = None,
) -> dict[str, str]:
    """Insert a pending task into the shared database."""
    from app.model import TaskStatus, UnpackTask, generate_id, get_db_session

    normalized_project_id = str(project_id or "").strip()
    if not normalized_project_id:
        raise ValueError("project_id 不能为空")

    task_id = generate_id()
    normalized_origin_type = str(task_origin_type or "").strip() or "manual"
    prepared = prepare_task_workspace(normalized_project_id, task_id, firmware_path)
    db = get_db_session()
    try:
        effective_snapshot = _build_llm_binding_snapshot(db)
        if isinstance(llm_binding_snapshot, dict) and llm_binding_snapshot:
            effective_snapshot = {
                **effective_snapshot,
                **llm_binding_snapshot,
            }
        db.add(
            UnpackTask(
                id=task_id,
                project_id=normalized_project_id,
                task_origin_type=normalized_origin_type,
                parent_project_id=parent_project_id,
                parent_task_id=parent_task_id,
                parent_task_type=parent_task_type,
                parent_stage_name=parent_stage_name,
                parent_stage_item_id=parent_stage_item_id,
                parent_stage_item_key=parent_stage_item_key,
                firmware_path=firmware_path,
                output_path=prepared["output_path"],
                status=TaskStatus.PENDING.value,
                llm_binding_snapshot=json.dumps(effective_snapshot, ensure_ascii=False),
                current_stage="pending",
                runtime_root=prepared["run_path"] or str(_derive_run_root_from_output_path(prepared["output_path"])),
                archive_root=str(Path(prepared["output_path"]).parent / "archive"),
                archive_status=TaskStatus.ARCHIVE_PENDING.value,
                heartbeat_at=now_local(),
                last_progress_at=now_local(),
            )
        )
        db.commit()
        _record_task_event(
            task_id,
            project_id=normalized_project_id,
            event_type="task_created",
            summary="任务已创建并进入队列",
            stage_key="pending",
            status=TaskStatus.PENDING.value,
            detail={
                "firmware_path": firmware_path,
                "output_path": prepared["output_path"],
                "task_origin_type": normalized_origin_type,
                "llm_binding_snapshot_frozen_at": effective_snapshot.get("frozen_at") if isinstance(effective_snapshot, dict) else None,
            },
            created_by="task_manager",
        )
        record_task_lifecycle(
            event="created",
            status=TaskStatus.PENDING.value,
            task_origin=normalized_origin_type,
        )
    finally:
        db.close()

    logger.info("task queued: %s", task_id)
    return {
        "task_id": task_id,
        "input_path": prepared["input_path"],
        "output_path": prepared["output_path"],
        "run_path": prepared["run_path"],
    }


def cancel_task(task_id: str) -> tuple[bool, str]:
    from app.model import TaskStatus, UnpackTask, get_db_session
    from app.services.worker import get_worker_id

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            return False, "任务不存在"
        trigger_runtime_cancel = False
        if task.status in (TaskStatus.PENDING.value, TaskStatus.CLAIMED.value):
            task.status = TaskStatus.CANCELLED.value
            task.cancel_requested_at = now_local()
            task.result_status = "cancelled"
            task.result_message = "Task was cancelled before execution"
            task.completed_at = now_local()
            task.dispatch_owner_id = None
            task.dispatch_token = None
            task.dispatch_claimed_at = None
            task.dispatch_lease_expires_at = None
            task.cancel_grace_deadline = None
            task.cancel_force_deadline = None
            task.heartbeat_at = None
            task.runner_pid = None
            task.runner_started_at = None
            task.runner_heartbeat_at = None
            task.run_token = None
            db.commit()
            _record_task_event_from_row(
                task,
                event_type="cancel_requested",
                summary="已提交取消请求",
                stage_key=task.current_stage,
                status=TaskStatus.CANCELLING.value,
                detail={"owner_id": task.owner_id},
                created_by="task_manager",
            )
            _record_task_event_from_row(
                task,
                event_type="task_cancelled",
                summary="任务在执行前已取消",
                stage_key=task.current_stage,
                status=task.status,
                detail={"reason": "Task was cancelled before execution"},
                created_by="task_manager",
            )
            record_task_error(category="cancel", status=task.status, task_origin=_task_origin(task))
            record_task_lifecycle(event="finished", status=task.status, task_origin=_task_origin(task))
            record_task_duration(
                phase="total",
                duration_seconds=_elapsed_seconds(task.created_at, task.completed_at),
                status=task.status,
                task_origin=_task_origin(task),
            )
            return True, "取消请求已提交"
        elif task.status in (TaskStatus.RUNNING.value, TaskStatus.CANCELLING.value):
            now = now_local()
            task.status = TaskStatus.CANCELLING.value
            task.cancel_requested_at = task.cancel_requested_at or now
            task.cancel_grace_deadline = task.cancel_grace_deadline or (now + timedelta(seconds=_cancel_grace_seconds()))
            task.cancel_force_deadline = task.cancel_force_deadline or (now + timedelta(seconds=_cancel_force_seconds()))
            task.last_progress_at = now
            trigger_runtime_cancel = True
        elif task.status == TaskStatus.CANCELLED.value:
            return True, "任务已取消"
        else:
            return False, "仅支持取消排队中、已认领或运行中的任务"
        db.commit()
        _record_task_event_from_row(
            task,
            event_type="cancel_requested",
            summary="已提交取消请求",
            stage_key=task.current_stage,
            status=task.status,
            detail={"owner_id": task.owner_id},
            created_by="task_manager",
        )
        if trigger_runtime_cancel:
            if str(task.owner_id or "").strip() == get_worker_id() and task.runner_pid:
                _signal_task_runner(
                    task,
                    signal.SIGTERM,
                    event_type="cancel_sigterm_sent",
                    summary="已向任务执行进程发送 SIGTERM",
                )
            _trigger_cancel_hook(task_id)
        return True, "取消请求已提交"
    finally:
        db.close()


def retry_task(task_id: str) -> tuple[bool, Optional[str], str]:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            return False, None, "任务不存在"
        if task.status not in (
            TaskStatus.SUCCESS.value,
            TaskStatus.FAILED.value,
            TaskStatus.CANCELLED.value,
        ):
            return False, None, "仅支持重试成功、失败或已取消的任务"
        normalized_project_id = str(task.project_id or "").strip()
        if not normalized_project_id:
            return False, None, "任务缺少 project_id，无法重试"
        task.status = TaskStatus.RETRY_PREPARING.value
        task.owner_id = None
        task.dispatch_owner_id = None
        task.dispatch_token = None
        task.dispatch_claimed_at = None
        task.dispatch_lease_expires_at = None
        task.current_stage = "retry_preparing"
        task.lease_expires_at = None
        task.cancel_requested_at = None
        task.heartbeat_at = None
        task.runner_pid = None
        task.runner_started_at = None
        task.runner_heartbeat_at = None
        task.run_token = None
        task.cancel_grace_deadline = None
        task.cancel_force_deadline = None
        task.last_progress_at = now_local()
        task.result_status = None
        task.result_message = "正在后台重置任务目录并准备重试"
        task.error_message = None
        db.commit()
        record_task_error(category="retry", status=task.status, task_origin=_task_origin(task))
        _record_task_event(
            task.id,
            project_id=task.project_id,
            event_type="task_retry_requested",
            summary="任务重试已受理，正在后台重置工作目录",
            stage_key="retry_preparing",
            status=TaskStatus.RETRY_PREPARING.value,
            detail={"retry_mode": "inplace_async"},
            created_by="task_manager",
        )
        try:
            enqueue_workspace_cleanup(
                task.id,
                task.project_id,
                reason="task_retry_reset",
                created_by="task_manager",
            )
            # Opportunistically wake cleanup processing so retry_preparing does not
            # depend on the periodic cleanup loop to make forward progress.
            _submit_background(process_workspace_cleanup_jobs, 1)
        except Exception as exc:
            _fail_retry_preparing_task(task.id, f"异步重试任务入队失败: {exc}")
            return False, None, f"任务重试入队失败: {exc}"
        return True, task.id, "任务重试已受理，后台正在重置工作目录"
    finally:
        db.close()


def delete_tasks(task_ids: list[str]) -> tuple[int, list[str]]:
    from app.model import TaskStatus, UnpackTask, get_db_session

    deleted_count = 0
    skipped_ids: list[str] = []
    deleted_event_payloads: list[dict[str, object]] = []
    cleanup_candidates: list[tuple[str, Optional[str]]] = []
    db = get_db_session()
    try:
        for task_id in task_ids:
            task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
            if task is None:
                skipped_ids.append(task_id)
                continue
            deleted = (
                db.query(UnpackTask)
                .filter(
                    UnpackTask.id == task_id,
                    UnpackTask.status.notin_(
                        [
                            TaskStatus.CLAIMED.value,
                            TaskStatus.RETRY_PREPARING.value,
                            TaskStatus.RUNNING.value,
                            TaskStatus.CANCELLING.value,
                        ]
                    ),
                )
                .delete(synchronize_session=False)
            )
            if not deleted:
                skipped_ids.append(task_id)
                continue
            deleted_event_payloads.append(
                {
                    "task_id": task_id,
                    "project_id": task.project_id,
                    "stage_key": task.current_stage,
                    "status": task.status,
                    "detail": {"output_path": task.output_path},
                    "owner_id": task.owner_id,
                }
            )
            deleted_count += 1
            cleanup_candidates.append((task_id, task.project_id))
        db.commit()
        for payload in deleted_event_payloads:
            _record_task_event(
                str(payload["task_id"]),
                project_id=payload.get("project_id"),
                event_type="task_deleted",
                summary="任务记录已删除",
                stage_key=payload.get("stage_key"),
                status=payload.get("status"),
                detail=payload.get("detail"),
                owner_id=payload.get("owner_id"),
                created_by="task_manager",
            )
        for task_id, project_id in cleanup_candidates:
            enqueue_workspace_cleanup(
                task_id,
                project_id,
                reason="task_deleted",
                created_by="task_manager",
            )
        return deleted_count, skipped_ids
    finally:
        db.close()


def _should_cancel(task_id: str) -> bool:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            return True
        return task.status in (
            TaskStatus.CANCELLING.value,
            TaskStatus.CANCELLED.value,
        )
    finally:
        db.close()


def _should_cancel_run(task_id: str, run_token: Optional[str]) -> bool:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            return True
        if run_token and task.run_token != run_token:
            return True
        return task.status in (
            TaskStatus.CANCELLING.value,
            TaskStatus.CANCELLED.value,
        )
    finally:
        db.close()


def recover_orphaned_tasks() -> None:
    from app.model import FirmwareEvolutionJob, TaskStatus, UnpackTask, WorkerInstance, get_db_session
    from app.services.worker import get_worker_id

    now = now_local()
    heartbeat_cutoff = now - timedelta(seconds=max(15, int(get_config().worker.dead_threshold_seconds)))

    def _load_recovery_snapshot() -> tuple[set[str], list[Any], list[Any]]:
        db = get_db_session()
        try:
            active_owner_ids = {
                str(row.worker_id)
                for row in db.query(WorkerInstance)
                .filter(
                    WorkerInstance.is_alive.is_(True),
                    WorkerInstance.last_heartbeat >= heartbeat_cutoff,
                )
                .all()
            }
            tasks = (
                db.query(UnpackTask)
                .filter(
                    UnpackTask.status.in_(
                        [TaskStatus.CLAIMED.value, TaskStatus.RUNNING.value, TaskStatus.CANCELLING.value]
                    )
                )
                .all()
            )
            evolution_jobs = (
                db.query(FirmwareEvolutionJob)
                .filter(
                    FirmwareEvolutionJob.status.in_([EVOLUTION_CLAIMED, EVOLUTION_RUNNING, EVOLUTION_CANCELLING])
                )
                .all()
            )
            return active_owner_ids, tasks, evolution_jobs
        finally:
            db.close()

    active_owner_ids, tasks, evolution_jobs = _run_db_retry(
        "recover_orphaned_tasks_snapshot",
        _load_recovery_snapshot,
        context={"heartbeat_cutoff": isoformat_local(heartbeat_cutoff)},
    )

    current_owner = get_worker_id()
    action_counts: dict[str, int] = {}
    started_at = time.monotonic()

    for task in tasks:
        try:
            owner_id = str(task.owner_id or "").strip()
            cancel_requested_at = task.cancel_requested_at
            owner_missing = not owner_id or owner_id not in active_owner_ids
            startup_grace = _is_task_in_startup_grace(task, now)
            local_owned = owner_id == current_owner
            runner_pid = getattr(task, "runner_pid", None)
            runner_alive = _is_process_alive(runner_pid) if local_owned and runner_pid else False
            runner_not_started = bool(
                local_owned
                and not runner_pid
                and task.started_at
                and task.started_at + timedelta(seconds=_runner_start_grace_seconds()) < now
            )
            cancel_timed_out = bool(
                cancel_requested_at
                and cancel_requested_at + timedelta(seconds=_cancel_timeout_seconds()) < now
            )
            progress_stale = bool(
                task.last_progress_at
                and task.last_progress_at + timedelta(seconds=_cancel_timeout_seconds()) < now
            )
            claim_stale = bool(
                task.status == TaskStatus.CLAIMED.value
                and task.dispatch_claimed_at
                and task.dispatch_claimed_at + timedelta(seconds=_runner_start_grace_seconds()) < now
            )
            if task.status == TaskStatus.CLAIMED.value:
                if claim_stale or (owner_missing and not startup_grace):
                    _reset_claim(task.id)
                    action_counts["claim_reset"] = int(action_counts.get("claim_reset", 0)) + 1
                continue
            if task.status == TaskStatus.CANCELLING.value and local_owned:
                if runner_not_started:
                    _mark_task_cancelled(task.id, reason="Task runner was not started")
                    action_counts["cancelled_runner_not_started"] = int(action_counts.get("cancelled_runner_not_started", 0)) + 1
                    continue
                if not runner_alive:
                    _mark_task_cancelled(task.id, reason="Task runner exited while cancelling")
                    action_counts["cancelled_runner_exited"] = int(action_counts.get("cancelled_runner_exited", 0)) + 1
                    continue
                if task.cancel_grace_deadline and task.cancel_grace_deadline <= now:
                    sent = _signal_task_runner(
                        task,
                        signal.SIGTERM,
                        event_type="cancel_sigterm_sent",
                        summary="已向任务执行进程发送 SIGTERM",
                    )
                    if sent:
                        _clear_cancel_grace_deadline(task.id)
                        action_counts["cancel_sigterm_sent"] = int(action_counts.get("cancel_sigterm_sent", 0)) + 1
                if (
                    (task.cancel_force_deadline and task.cancel_force_deadline <= now)
                    or cancel_timed_out
                    or progress_stale
                ):
                    record_task_error(category="timeout", status=task.status, task_origin=_task_origin(task))
                    _signal_task_runner(
                        task,
                        signal.SIGKILL,
                        event_type="cancel_sigkill_sent",
                        summary="已向任务执行进程发送 SIGKILL",
                    )
                    _mark_task_cancelled(task.id, reason="Task cancelled after force kill deadline")
                    action_counts["cancel_sigkill_sent"] = int(action_counts.get("cancel_sigkill_sent", 0)) + 1
                continue
            if task.status == TaskStatus.CANCELLING.value:
                if owner_missing and not startup_grace:
                    _finalize_orphaned_task(task.id, reason="Task owner pod lost", owner_lost=True)
                    action_counts["orphaned_cancelled"] = int(action_counts.get("orphaned_cancelled", 0)) + 1
                elif cancel_timed_out or progress_stale:
                    record_task_error(category="timeout", status=task.status, task_origin=_task_origin(task))
                    _mark_task_cancelled(task.id, reason="Task cancelled after owner lost or timeout")
                    action_counts["cancel_timeout"] = int(action_counts.get("cancel_timeout", 0)) + 1
                continue
            if task.status == TaskStatus.RUNNING.value:
                if owner_missing and not startup_grace:
                    _finalize_orphaned_task(task.id, reason="Task owner pod lost", owner_lost=True)
                    action_counts["owner_lost"] = int(action_counts.get("owner_lost", 0)) + 1
                elif local_owned and runner_not_started:
                    _finalize_orphaned_task(task.id, reason="Task runner was not started")
                    action_counts["runner_not_started"] = int(action_counts.get("runner_not_started", 0)) + 1
                elif local_owned and not runner_alive:
                    _finalize_orphaned_task(task.id, reason="Task runner process exited unexpectedly")
                    action_counts["runner_exited"] = int(action_counts.get("runner_exited", 0)) + 1
                elif local_owned and runner_alive:
                    _update_task_progress_for_owner(
                        task.id,
                        owner_id=owner_id,
                        run_token=task.run_token,
                        stage=None,
                    )
                    action_counts["progress_refreshed"] = int(action_counts.get("progress_refreshed", 0)) + 1
        except Exception as exc:
            action_counts["errors"] = int(action_counts.get("errors", 0)) + 1
            logger.warning(
                "recover orphaned task warning task_id=%s status=%s owner_id=%s error=%s",
                task.id,
                task.status,
                getattr(task, "owner_id", None),
                exc,
            )
    for job in evolution_jobs:
        try:
            owner_id = str(job.owner_id or "").strip()
            cancel_requested_at = getattr(job, "cancel_requested_at", None)
            owner_missing = not owner_id or owner_id not in active_owner_ids
            local_owned = owner_id == current_owner
            runner_pid = getattr(job, "runner_pid", None)
            runner_alive = _is_process_alive(runner_pid) if local_owned and runner_pid else False
            registered_pid = _get_registered_evolution_pid(str(job.id))
            registered_runner_alive = _is_process_alive(registered_pid) if local_owned and registered_pid else False
            runner_not_started = bool(
                local_owned
                and not runner_pid
                and job.started_at
                and job.started_at + timedelta(seconds=_runner_start_grace_seconds()) < now
            )
            local_runner_missing = bool(
                local_owned
                and str(job.status or "") == EVOLUTION_RUNNING
                and (
                    (runner_pid and not runner_alive)
                    or (registered_pid and not registered_runner_alive)
                    or (
                        not runner_pid
                        and not registered_pid
                        and job.started_at
                        and job.started_at + timedelta(seconds=_runner_start_grace_seconds()) < now
                    )
                )
            )
            cancel_timed_out = bool(
                cancel_requested_at
                and cancel_requested_at + timedelta(seconds=_cancel_timeout_seconds()) < now
            )
            progress_stale = bool(
                job.last_progress_at
                and job.last_progress_at + timedelta(seconds=_cancel_timeout_seconds()) < now
            )
            claim_stale = bool(
                str(job.status or "") == EVOLUTION_CLAIMED
                and job.dispatch_claimed_at
                and job.dispatch_claimed_at + timedelta(seconds=_runner_start_grace_seconds()) < now
            )
            if str(job.status or "") == EVOLUTION_CLAIMED:
                if owner_missing or claim_stale:
                    _reset_evolution_claim(job.id)
                    action_counts["evolution_claim_reset"] = int(action_counts.get("evolution_claim_reset", 0)) + 1
                continue
            if str(job.status or "") == EVOLUTION_CANCELLING and local_owned:
                if runner_not_started:
                    _mark_evolution_cancelled(job.id, reason="Evolution runner was not started")
                    action_counts["evolution_cancelled_runner_not_started"] = int(action_counts.get("evolution_cancelled_runner_not_started", 0)) + 1
                    continue
                if not runner_alive:
                    _mark_evolution_cancelled(job.id, reason="Evolution runner exited while cancelling")
                    action_counts["evolution_cancelled_runner_exited"] = int(action_counts.get("evolution_cancelled_runner_exited", 0)) + 1
                    continue
                if job.cancel_grace_deadline and job.cancel_grace_deadline <= now:
                    sent = _signal_evolution_runner(
                        job,
                        signal.SIGTERM,
                        event_type="evolution_cancel_sigterm_sent",
                        summary="已向进化任务执行进程发送 SIGTERM",
                    )
                    if sent:
                        db = get_db_session()
                        try:
                            current = db.query(FirmwareEvolutionJob).filter(FirmwareEvolutionJob.id == job.id).first()
                            if current is not None:
                                current.cancel_grace_deadline = None
                                db.commit()
                        finally:
                            db.close()
                        action_counts["evolution_cancel_sigterm_sent"] = int(action_counts.get("evolution_cancel_sigterm_sent", 0)) + 1
                if (
                    (job.cancel_force_deadline and job.cancel_force_deadline <= now)
                    or cancel_timed_out
                    or progress_stale
                ):
                    _signal_evolution_runner(
                        job,
                        signal.SIGKILL,
                        event_type="evolution_cancel_sigkill_sent",
                        summary="已向进化任务执行进程发送 SIGKILL",
                    )
                    task_db = get_db_session()
                    try:
                        current = task_db.query(FirmwareEvolutionJob).filter(FirmwareEvolutionJob.id == job.id).first()
                        task = task_db.query(UnpackTask).filter(UnpackTask.id == job.task_id).first()
                        job_root = _derive_evolution_job_root(str(getattr(task, "output_path", "") or ""), job.id) if task is not None else None
                    finally:
                        task_db.close()
                    _terminate_evolution_runtime(job.id, job_root)
                    _mark_evolution_cancelled(job.id, reason="Evolution task cancelled after force kill deadline")
                    action_counts["evolution_cancel_sigkill_sent"] = int(action_counts.get("evolution_cancel_sigkill_sent", 0)) + 1
                continue
            if str(job.status or "") == EVOLUTION_CANCELLING:
                if owner_missing or cancel_timed_out or progress_stale:
                    _mark_evolution_cancelled(job.id, reason="Evolution task cancelled after owner lost or timeout")
                    action_counts["evolution_cancel_timeout"] = int(action_counts.get("evolution_cancel_timeout", 0)) + 1
                continue
            if str(job.status or "") == EVOLUTION_RUNNING:
                if owner_missing:
                    _finalize_orphaned_evolution_job(job.id, reason="Evolution task owner pod lost")
                    action_counts["evolution_owner_lost"] = int(action_counts.get("evolution_owner_lost", 0)) + 1
                elif local_owned and runner_not_started:
                    _finalize_orphaned_evolution_job(job.id, reason="Evolution runner was not started")
                    action_counts["evolution_runner_not_started"] = int(action_counts.get("evolution_runner_not_started", 0)) + 1
                elif local_owned and not runner_alive and runner_pid:
                    _finalize_orphaned_evolution_job(job.id, reason="Evolution runner process exited unexpectedly")
                    action_counts["evolution_runner_exited"] = int(action_counts.get("evolution_runner_exited", 0)) + 1
                elif local_runner_missing:
                    _finalize_orphaned_evolution_job(job.id, reason="Evolution runner process missing or exited unexpectedly")
                    action_counts["evolution_runner_missing"] = int(action_counts.get("evolution_runner_missing", 0)) + 1
                elif local_owned and runner_alive:
                    _update_evolution_progress_for_owner(
                        job.id,
                        owner_id=owner_id,
                        run_token=job.run_token,
                        round_id=int(job.current_round or 0),
                        stage=str(job.current_stage or "evolution_execute"),
                    )
                    action_counts["evolution_progress_refreshed"] = int(action_counts.get("evolution_progress_refreshed", 0)) + 1
        except Exception as exc:
            action_counts["evolution_errors"] = int(action_counts.get("evolution_errors", 0)) + 1
            logger.warning(
                "recover orphaned evolution warning job_id=%s status=%s owner_id=%s error=%s",
                job.id,
                job.status,
                getattr(job, "owner_id", None),
                exc,
            )
    noisy_keys = {"progress_refreshed", "evolution_progress_refreshed"}
    meaningful_action_counts = {
        key: value for key, value in action_counts.items() if key not in noisy_keys and int(value or 0) > 0
    }
    if meaningful_action_counts:
        logger.info(
            "recover orphaned tasks summary owner_id=%s active_workers=%s scanned_tasks=%s scanned_evolution_jobs=%s actions=%s",
            current_owner,
            len(active_owner_ids),
            len(tasks),
            len(evolution_jobs),
            meaningful_action_counts,
        )
    record_orphan_recovery(
        scanned_tasks=len(tasks),
        action_counts=action_counts,
        duration_seconds=time.monotonic() - started_at,
    )


def _claim_task(task_id: str) -> bool:
    from app.model import TaskStatus, UnpackTask, get_db_session
    from app.services.worker import get_worker_id

    owner_id = get_worker_id()
    run_token = uuid.uuid4().hex
    db = get_db_session()
    try:
        now = now_local()
        updated = (
            db.query(UnpackTask)
            .filter(
                UnpackTask.id == task_id,
                UnpackTask.status == TaskStatus.PENDING.value,
            )
            .update(
                {
                    UnpackTask.status: TaskStatus.CLAIMED.value,
                    UnpackTask.owner_id: owner_id,
                    UnpackTask.dispatch_owner_id: owner_id,
                    UnpackTask.dispatch_token: run_token,
                    UnpackTask.dispatch_claimed_at: now,
                    UnpackTask.dispatch_lease_expires_at: now + timedelta(seconds=_dispatch_interval_seconds() * 4),
                    UnpackTask.current_stage: "queued",
                    UnpackTask.lease_expires_at: None,
                    UnpackTask.cancel_requested_at: None,
                    UnpackTask.heartbeat_at: now,
                    UnpackTask.last_progress_at: now,
                    UnpackTask.runner_pid: None,
                    UnpackTask.runner_started_at: None,
                    UnpackTask.runner_heartbeat_at: None,
                    UnpackTask.run_token: None,
                    UnpackTask.cancel_grace_deadline: None,
                    UnpackTask.cancel_force_deadline: None,
                    UnpackTask.started_at: None,
                    UnpackTask.completed_at: None,
                    UnpackTask.error_message: None,
                    UnpackTask.result_status: None,
                    UnpackTask.result_message: None,
                },
                synchronize_session=False,
            )
        )
        if updated:
            db.commit()
            task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
            if task is not None:
                record_task_lifecycle(event="queued", status=task.status, task_origin=_task_origin(task))
                record_task_duration(
                    phase="queue_wait",
                    duration_seconds=_elapsed_seconds(task.created_at, task.dispatch_claimed_at),
                    status=task.status,
                    task_origin=_task_origin(task),
                )
                _record_task_event_from_row(
                    task,
                    event_type="task_claimed",
                    summary="任务已被当前 owner 认领",
                    stage_key="claimed",
                    status=task.status,
                    detail={"owner_id": owner_id, "dispatch_token_present": True},
                    owner_id=owner_id,
                    created_by="task_manager",
                )
            return True
        db.rollback()
        return False
    finally:
        db.close()


def _supports_skip_locked() -> bool:
    from app.model import get_engine

    try:
        dialect = str(get_engine().dialect.name or "").strip().lower()
    except Exception:
        return False
    return dialect in {"mysql", "postgresql", "postgres", "mariadb"}


def _reset_claim(task_id: str) -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        (
            db.query(UnpackTask)
            .filter(
                UnpackTask.id == task_id,
                UnpackTask.status.in_([TaskStatus.CLAIMED.value, TaskStatus.RUNNING.value]),
            )
            .update(
                {
                    UnpackTask.status: TaskStatus.PENDING.value,
                    UnpackTask.owner_id: None,
                    UnpackTask.dispatch_owner_id: None,
                    UnpackTask.dispatch_token: None,
                    UnpackTask.assigned_worker_id: None,
                    UnpackTask.assigned_pod_name: None,
                    UnpackTask.dispatch_claimed_at: None,
                    UnpackTask.dispatch_lease_expires_at: None,
                    UnpackTask.assignment_generation: 0,
                    UnpackTask.current_stage: "pending",
                    UnpackTask.lease_expires_at: None,
                    UnpackTask.run_lease_expires_at: None,
                    UnpackTask.cancel_requested_at: None,
                    UnpackTask.heartbeat_at: None,
                    UnpackTask.runner_pid: None,
                    UnpackTask.runner_started_at: None,
                    UnpackTask.runner_heartbeat_at: None,
                    UnpackTask.run_token: None,
                    UnpackTask.cancel_grace_deadline: None,
                    UnpackTask.cancel_force_deadline: None,
                    UnpackTask.started_at: None,
                    UnpackTask.last_progress_at: now_local(),
                },
                synchronize_session=False,
            )
        )
        db.commit()
    finally:
        db.close()


def _assign_task_to_worker(task_id: str, worker_id: str, pod_name: str) -> bool:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        now = now_local()
        updated = (
            db.query(UnpackTask)
            .filter(
                UnpackTask.id == task_id,
                UnpackTask.status.in_(
                    [
                        TaskStatus.PENDING.value,
                        TaskStatus.AWAITING_TAKEOVER.value,
                        TaskStatus.RETRY_PREPARING.value,
                    ]
                ),
            )
            .update(
                {
                    UnpackTask.status: TaskStatus.ASSIGNED.value,
                    UnpackTask.owner_id: worker_id,
                    UnpackTask.dispatch_owner_id: worker_id,
                    UnpackTask.assigned_worker_id: worker_id,
                    UnpackTask.assigned_pod_name: pod_name,
                    UnpackTask.dispatch_token: uuid.uuid4().hex,
                    UnpackTask.dispatch_claimed_at: now,
                    UnpackTask.dispatch_lease_expires_at: now + timedelta(seconds=_task_lease_seconds()),
                    UnpackTask.assignment_generation: UnpackTask.assignment_generation + 1,
                    UnpackTask.current_stage: "queued",
                    UnpackTask.heartbeat_at: now,
                    UnpackTask.last_progress_at: now,
                    UnpackTask.runner_pid: None,
                    UnpackTask.runner_started_at: None,
                    UnpackTask.runner_heartbeat_at: None,
                    UnpackTask.run_token: None,
                    UnpackTask.run_lease_expires_at: None,
                    UnpackTask.cancel_grace_deadline: None,
                    UnpackTask.cancel_force_deadline: None,
                    UnpackTask.completed_at: None,
                },
                synchronize_session=False,
            )
        )
        db.commit()
        return bool(updated)
    finally:
        db.close()


def _assign_pending_tasks(limit: int) -> list[str]:
    from app.model import TaskStatus, UnpackTask, WorkerInstance, get_db_session

    db = get_db_session()
    assigned_ids: list[str] = []
    try:
        workers = (
            db.query(WorkerInstance)
            .filter(
                WorkerInstance.role == "dispatcher",
                WorkerInstance.is_alive.is_(True),
                WorkerInstance.drain_requested.is_(False),
                WorkerInstance.active_tasks <= 0,
            )
            .order_by(WorkerInstance.last_heartbeat.asc(), WorkerInstance.started_at.asc())
            .all()
        )
        if not workers:
            return []
        tasks = (
            db.query(UnpackTask)
            .filter(
                UnpackTask.status.in_(
                    [
                        TaskStatus.AWAITING_TAKEOVER.value,
                        TaskStatus.RETRY_PREPARING.value,
                        TaskStatus.PENDING.value,
                    ]
                )
            )
            .order_by(UnpackTask.created_at.asc(), UnpackTask.id.asc())
            .limit(max(1, limit))
            .all()
        )
        worker_index = 0
        for task in tasks:
            if worker_index >= len(workers):
                break
            worker = workers[worker_index]
            if _assign_task_to_worker(str(task.id), str(worker.worker_id), str(worker.pod_name or worker.hostname or worker.worker_id)):
                assigned_ids.append(str(task.id))
                worker.active_tasks = 1
                worker.running_task_id = str(task.id)
                worker.state = "busy"
                worker_index += 1
        db.commit()
    finally:
        db.close()
    return assigned_ids


def _launch_task_runner(task_id: str) -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session
    from app.services.worker import get_worker_id, refresh_worker_active_tasks, update_worker_runtime_state

    owner_id = get_worker_id()
    db = get_db_session()
    try:
        task = (
            db.query(UnpackTask)
            .filter(
                UnpackTask.id == task_id,
                UnpackTask.assigned_worker_id == owner_id,
                UnpackTask.status.in_([TaskStatus.ASSIGNED.value, TaskStatus.CLAIMED.value]),
            )
            .first()
        )
        if task is None or not task.dispatch_token:
            raise RuntimeError(f"任务未被当前 owner 正确认领: {task_id}")
        dispatch_token = task.dispatch_token
        run_token = uuid.uuid4().hex
        if get_config().worker.agent_pre_cleanup_enabled:
            cleanup_summary = run_agent_cleanup(worker_id=owner_id, phase="pre-run", task_id=task_id)
            update_worker_runtime_state(cleanup_summary=cleanup_summary)
            if int(cleanup_summary.get("errors") and len(cleanup_summary["errors"]) or 0) > 0:
                _reset_claim(task_id)
                _record_task_event_from_row(
                    task,
                    event_type="agent_cleanup_failed",
                    summary="任务启动前智能体清理失败，任务重新排队",
                    stage_key="cleanup",
                    status=TaskStatus.RETRY_PREPARING.value,
                    detail=cleanup_summary,
                    owner_id=owner_id,
                    created_by="task_manager",
                )
                raise RuntimeError("pre-run cleanup failed")
    finally:
        db.close()

    env = os.environ.copy()
    project_root = str(Path(__file__).resolve().parents[2])
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = project_root if not existing_pythonpath else f"{project_root}{os.pathsep}{existing_pythonpath}"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "app.task_runner",
            "--task-id",
            task_id,
            "--owner-id",
            owner_id,
            "--run-token",
            run_token,
        ],
        cwd=project_root,
        env=env,
        start_new_session=True,
    )

    now = now_local()
    db = get_db_session()
    try:
        updated = (
            db.query(UnpackTask)
            .filter(
                UnpackTask.id == task_id,
                UnpackTask.assigned_worker_id == owner_id,
                UnpackTask.dispatch_token == dispatch_token,
                UnpackTask.status.in_([TaskStatus.ASSIGNED.value, TaskStatus.CLAIMED.value]),
            )
            .update(
                {
                    UnpackTask.status: TaskStatus.RUNNING.value,
                    UnpackTask.dispatch_lease_expires_at: now + timedelta(seconds=_task_lease_seconds()),
                    UnpackTask.runner_pid: proc.pid,
                    UnpackTask.runner_started_at: now,
                    UnpackTask.runner_heartbeat_at: now,
                    UnpackTask.heartbeat_at: now,
                    UnpackTask.lease_expires_at: None,
                    UnpackTask.run_lease_expires_at: now + timedelta(seconds=_task_lease_seconds()),
                    UnpackTask.last_progress_at: now,
                    UnpackTask.run_token: run_token,
                    UnpackTask.started_at: now,
                },
                synchronize_session=False,
            )
        )
        db.commit()
        if not updated:
            _signal_runner_process(proc.pid, signal.SIGTERM)
            raise RuntimeError(f"任务状态已变化，已停止新 runner: {task_id}")
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is not None:
            record_task_lifecycle(event="started", status=TaskStatus.RUNNING.value, task_origin=_task_origin(task))
            record_task_duration(
                phase="queue_wait",
                duration_seconds=_elapsed_seconds(task.created_at, task.started_at),
                status=TaskStatus.RUNNING.value,
                task_origin=_task_origin(task),
            )
            _record_task_event_from_row(
                task,
                event_type="runner_started",
                summary="任务独立执行进程已启动",
                stage_key=task.current_stage,
                status=task.status,
                detail={"runner_pid": proc.pid, "run_token_present": True, "dispatch_token_present": True},
                owner_id=owner_id,
                created_by="task_manager",
            )
    finally:
        db.close()
    update_worker_runtime_state(state="busy", running_task_id=task_id)
    refresh_worker_active_tasks()


def _claim_pending_tasks(limit: int) -> list[str]:
    from app.model import TaskStatus, UnpackTask, get_db_session
    from app.services.worker import get_worker_id

    fetch_limit = max(1, limit)
    owner_id = get_worker_id()
    use_skip_locked = _supports_skip_locked()

    def _do_claim_pending_tasks() -> list[dict[str, object]]:
        now = now_local()
        claim_deadline = now + timedelta(seconds=_dispatch_interval_seconds() * 4)
        if not use_skip_locked:
            candidate_ids: list[str] = []
            db = get_db_session()
            try:
                candidate_ids = [
                    row.id
                    for row in (
                        db.query(UnpackTask.id)
                        .filter(UnpackTask.status == TaskStatus.PENDING.value)
                        .order_by(UnpackTask.created_at.asc(), UnpackTask.id.asc())
                        .limit(fetch_limit)
                        .all()
                    )
                ]
            finally:
                db.close()
            claimed_payloads: list[dict[str, object]] = []
            for task_id in candidate_ids:
                if len(claimed_payloads) >= fetch_limit:
                    break
                if _claim_task(task_id):
                    claimed_payloads.append(
                        {
                            "task_id": task_id,
                            "project_id": None,
                            "status": TaskStatus.CLAIMED.value,
                            "owner_id": owner_id,
                            "event_recorded": True,
                        }
                    )
            return claimed_payloads

        db = get_db_session()
        claimed_payloads: list[dict[str, object]] = []
        try:
            query = (
                db.query(UnpackTask)
                .filter(UnpackTask.status == TaskStatus.PENDING.value)
                .order_by(UnpackTask.created_at.asc(), UnpackTask.id.asc())
            )
            if use_skip_locked:
                query = query.with_for_update(skip_locked=True)
            candidates = query.limit(fetch_limit).all()
            for task in candidates:
                dispatch_token = uuid.uuid4().hex
                task.status = TaskStatus.CLAIMED.value
                task.owner_id = owner_id
                task.dispatch_owner_id = owner_id
                task.dispatch_token = dispatch_token
                task.dispatch_claimed_at = now
                task.dispatch_lease_expires_at = claim_deadline
                task.current_stage = "queued"
                task.lease_expires_at = None
                task.cancel_requested_at = None
                task.heartbeat_at = now
                task.last_progress_at = now
                task.runner_pid = None
                task.runner_started_at = None
                task.runner_heartbeat_at = None
                task.run_token = None
                task.cancel_grace_deadline = None
                task.cancel_force_deadline = None
                task.started_at = None
                task.completed_at = None
                task.error_message = None
                task.result_status = None
                task.result_message = None
                claimed_payloads.append(
                    {
                        "task_id": task.id,
                        "project_id": task.project_id,
                        "status": task.status,
                        "owner_id": owner_id,
                    }
                )
            db.commit()
            return claimed_payloads
        except SQLAlchemyError:
            db.rollback()
            raise
        finally:
            db.close()

    started_at = time.monotonic()
    try:
        claimed_payloads = _run_db_retry(
            "claim_pending_tasks",
            _do_claim_pending_tasks,
            context={"owner_id": owner_id, "limit": fetch_limit, "skip_locked": use_skip_locked},
        )
    except Exception:
        record_claim_result(
            claimed_count=0,
            duration_seconds=time.monotonic() - started_at,
            result="failed",
        )
        raise

    for payload in claimed_payloads:
        if payload.get("event_recorded"):
            continue
        _record_task_event(
            str(payload["task_id"]),
            project_id=payload.get("project_id"),
            event_type="task_claimed",
            summary="任务已被当前 owner 认领",
            stage_key="claimed",
            status=str(payload["status"]),
            detail={"owner_id": payload.get("owner_id"), "dispatch_token_present": True},
            owner_id=str(payload["owner_id"]),
            created_by="task_manager",
        )
    duration_ms = int((time.monotonic() - started_at) * 1000)
    record_claim_result(
        claimed_count=len(claimed_payloads),
        duration_seconds=duration_ms / 1000.0,
        result="success" if claimed_payloads else "empty",
    )
    if claimed_payloads:
        logger.info(
            "claimed pending tasks owner_id=%s requested=%s claimed=%s skip_locked=%s duration_ms=%s",
            owner_id,
            fetch_limit,
            len(claimed_payloads),
            use_skip_locked,
            duration_ms,
        )
    return [str(item["task_id"]) for item in claimed_payloads]


def _schedule_pending_tasks() -> None:
    available_slots = _runtime_max_concurrent() - _active_runner_count()
    if available_slots <= 0:
        record_dispatch_backpressure()
        logger.debug(
            "task dispatch backpressure owner_active=%s runtime_max=%s",
            _active_runner_count(),
            _runtime_max_concurrent(),
        )
        return

    fetch_limit = max(available_slots, _claim_batch_size())
    for task_id in _claim_pending_tasks(fetch_limit):
        if _runtime_max_concurrent() - _active_runner_count() <= 0:
            _reset_claim(task_id)
            break
        try:
            _launch_task_runner(task_id)
        except Exception:
            _reset_claim(task_id)
            raise


def _scheduler_assign_tasks() -> None:
    available_slots = max(0, _claim_batch_size())
    if available_slots <= 0:
        return
    _assign_pending_tasks(available_slots)


def _dispatcher_start_assigned_task() -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session
    from app.services.worker import get_worker_id

    if get_local_active_task_count() > 0:
        return
    owner_id = get_worker_id()
    db = get_db_session()
    try:
        task = (
            db.query(UnpackTask)
            .filter(
                UnpackTask.assigned_worker_id == owner_id,
                UnpackTask.status == TaskStatus.ASSIGNED.value,
            )
            .order_by(UnpackTask.dispatch_claimed_at.asc(), UnpackTask.created_at.asc())
            .first()
        )
        task_id = str(task.id) if task is not None else ""
    finally:
        db.close()
    if not task_id:
        return
    _launch_task_runner(task_id)


def _fail_retry_preparing_task(task_id: str, error_message: str) -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session

    normalized_error = str(error_message or "").strip() or "异步重试准备失败"
    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None or task.status != TaskStatus.RETRY_PREPARING.value:
            return
        task.status = TaskStatus.FAILED.value
        task.current_stage = "retry_preparing"
        task.completed_at = now_local()
        task.last_progress_at = task.completed_at
        task.result_status = "failed"
        task.result_message = f"任务重试准备失败：{normalized_error}"
        task.error_message = normalized_error
        db.commit()
        _record_task_event_from_row(
            task,
            event_type="task_retry_prepare_failed",
            summary=f"任务重试准备失败：{normalized_error}",
            stage_key="retry_preparing",
            status=task.status,
            detail={"reason": normalized_error},
            created_by="task_manager",
        )
        _write_task_result_cache(task_id)
    finally:
        db.close()


def _recover_stuck_retry_preparing_tasks() -> int:
    from app.model import TaskStatus, UnpackTask, get_db_session

    now = now_local()
    cutoff = now - timedelta(seconds=RETRY_PREPARING_TIMEOUT_SECONDS)
    db = get_db_session()
    recovered = 0
    try:
        tasks = (
            db.query(UnpackTask)
            .filter(
                UnpackTask.status == TaskStatus.RETRY_PREPARING.value,
                ((UnpackTask.last_progress_at.is_(None)) | (UnpackTask.last_progress_at < cutoff)),
            )
            .all()
        )
        task_ids = [str(task.id) for task in tasks]
    finally:
        db.close()

    for task_id in task_ids:
        _fail_retry_preparing_task(
            task_id,
            f"重试准备超时超过 {RETRY_PREPARING_TIMEOUT_SECONDS}s，已自动回退为失败状态",
        )
        recovered += 1
    return recovered


def _derive_run_root_from_output_path(output_path: str) -> Path:
    output_root = Path(str(output_path or "").strip())
    if not str(output_root):
        return Path("/tmp")
    return output_root.parent / "run" if output_root.name == "output" else output_root.parent / "run"


def _derive_evolution_root_from_output_path(output_path: str) -> Path:
    return _derive_run_root_from_output_path(output_path) / "evolution_jobs"


def _derive_evolution_job_root(output_path: str, job_id: str) -> Path:
    return _derive_evolution_root_from_output_path(output_path) / str(job_id).strip()


def _resolve_evolution_source_tool_path(task: Any, latest_job: Any | None = None) -> str | None:
    candidates: list[str] = []
    if latest_job is not None and getattr(task, "output_path", None):
        job_root = _derive_evolution_job_root(str(task.output_path or ""), str(latest_job.id or ""))
        result_path = job_root / "evolution_result.json"
        if result_path.exists():
            try:
                payload = json.loads(result_path.read_text(encoding="utf-8"))
            except Exception:
                payload = {}
            if isinstance(payload, dict):
                for key in ("working_tool_path", "final_tool_path", "working_skill_path", "final_skill_path"):
                    value = str(payload.get(key) or "").strip()
                    if value:
                        candidates.append(value)
                for item in reversed(list(payload.get("rounds") or [])):
                    if not isinstance(item, dict):
                        continue
                    value = str(item.get("tool_path_after") or item.get("tool_skill_path_after") or "").strip()
                    if value:
                        candidates.append(value)
                        break
    base_tool = str(getattr(task, "matched_skill", "") or "").strip()
    if base_tool:
        candidates.append(base_tool)
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    return None


def _resolve_evolution_dispatcher_tool_path(task: Any) -> str | None:
    firmware_path = str(getattr(task, "firmware_path", "") or "").strip()
    if not firmware_path:
        return None
    path = Path(firmware_path)
    if not path.exists():
        return None
    try:
        info = detect_format(firmware_path)
    except Exception:
        return None
    magic_bytes = info.get("magic") or b""
    features = {
        "filename": path.name,
        "fmt": str(info.get("fmt") or "").strip().lower(),
        "ext": str(info.get("ext") or "").strip().lower(),
        "ext2": str(info.get("ext2") or "").strip().lower(),
        "magic_hex": str(magic_bytes.hex() if isinstance(magic_bytes, (bytes, bytearray)) else "").strip().lower()[:8],
    }
    if not features["magic_hex"]:
        return None
    try:
        tool_meta, _ = dispatch_tool_by_magic(features, DISPATCHER_RULES_PATH)
    except Exception:
        return None
    resolved = str((tool_meta or {}).get("path") or "").strip()
    return resolved if resolved and Path(resolved).exists() else None


def _normalize_evolution_token_metrics(payload: Any) -> dict[str, int]:
    data = payload if isinstance(payload, dict) else {}
    return {
        "input": int(data.get("input") or data.get("token_input") or 0),
        "output": int(data.get("output") or data.get("token_output") or 0),
        "cacheRead": int(data.get("cacheRead") or data.get("cache_read") or data.get("token_cache_read") or 0),
        "cacheWrite": int(data.get("cacheWrite") or data.get("cache_write") or data.get("token_cache_write") or 0),
        "total": int(data.get("total") or data.get("token_total") or 0),
    }


def _parse_evolution_metrics_from_summary(summary_path: str | None) -> dict[str, Any]:
    if not summary_path:
        return {}
    path = Path(str(summary_path))
    if not path.exists() or not path.is_file():
        return {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {}
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip().lstrip("-").strip()
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip()
    metrics: dict[str, Any] = {}
    try:
        if "elapsed_seconds" in values:
            metrics["tool_unpack_duration_seconds"] = round(max(0.0, float(values["elapsed_seconds"])), 3)
    except Exception:
        pass
    tokens = _normalize_evolution_token_metrics(
        {
            "token_input": values.get("token_input"),
            "token_output": values.get("token_output"),
            "token_cache_read": values.get("token_cache_read"),
            "token_cache_write": values.get("token_cache_write"),
            "token_total": values.get("token_total"),
        }
    )
    if any(tokens.values()):
        metrics["evolution_executor_tokens"] = tokens
        metrics["total_tokens"] = tokens
    return metrics


def _mtime_iso_text(path: Path) -> str | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime).astimezone().isoformat()
    except Exception:
        return None


def _normalize_evolution_round_metrics(item: dict[str, Any]) -> dict[str, Any]:
    raw_metrics = item.get("metrics") if isinstance(item.get("metrics"), dict) else {}
    summary_metrics = _parse_evolution_metrics_from_summary(str(item.get("summary_path") or "").strip() or None)
    tool_duration = raw_metrics.get("tool_unpack_duration_seconds", summary_metrics.get("tool_unpack_duration_seconds"))
    try:
        tool_duration_value = round(max(0.0, float(tool_duration or 0.0)), 3)
    except Exception:
        tool_duration_value = 0.0
    executor_tokens = _normalize_evolution_token_metrics(
        raw_metrics.get("evolution_executor_tokens") or summary_metrics.get("evolution_executor_tokens")
    )
    reviewer_tokens = _normalize_evolution_token_metrics(raw_metrics.get("reviewer_tokens"))
    total_tokens = _normalize_evolution_token_metrics(raw_metrics.get("total_tokens") or summary_metrics.get("total_tokens"))
    if not any(total_tokens.values()):
        total_tokens = {
            key: int(executor_tokens.get(key, 0)) + int(reviewer_tokens.get(key, 0))
            for key in ("input", "output", "cacheRead", "cacheWrite", "total")
        }
    return {
        "tool_unpack_duration_seconds": tool_duration_value,
        "evolution_executor_tokens": executor_tokens,
        "reviewer_tokens": reviewer_tokens,
        "total_tokens": total_tokens,
    }


def _load_evolution_rounds_from_run_dir(
    job_root: Path,
    *,
    enriched: dict[str, Any],
) -> list[dict[str, Any]]:
    rounds: list[dict[str, Any]] = []
    for round_dir in sorted(job_root.glob("round_*")):
        if not round_dir.is_dir():
            continue
        round_json_path = round_dir / "evolution_round.json"
        if not round_json_path.exists():
            continue
        try:
            loaded = json.loads(round_json_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(loaded, dict):
            continue
        metrics = _normalize_evolution_round_metrics(loaded)
        round_id = int(loaded.get("round") or 0)
        rounds.append(
            {
                "id": str(loaded.get("id") or "").strip() or f"{str(enriched.get('id') or '').strip()}-{round_id}",
                "job_id": str(loaded.get("job_id") or enriched.get("id") or "").strip(),
                "round": round_id,
                "status": str(loaded.get("status") or "failed"),
                "tool_skill_path_before": str(loaded.get("tool_skill_path_before") or "").strip() or None,
                "tool_skill_path_after": str(loaded.get("tool_skill_path_after") or "").strip() or None,
                "tool_path_before": str(loaded.get("tool_path_before") or loaded.get("tool_skill_path_before") or "").strip() or None,
                "tool_path_after": str(loaded.get("tool_path_after") or loaded.get("tool_skill_path_after") or "").strip() or None,
                "tool_changed": bool(loaded.get("tool_changed")),
                "review_result": str(loaded.get("review_result") or "").strip() or None,
                "summary_path": str(loaded.get("summary_path") or "").strip() or None,
                "reason_path": str(loaded.get("reason_path") or "").strip() or None,
                "source_skill_path": str(loaded.get("source_skill_path") or enriched.get("source_skill_path") or "").strip() or None,
                "source_tool_path": str(loaded.get("source_tool_path") or enriched.get("source_tool_path") or "").strip() or None,
                "started_without_matched_skill": bool(loaded.get("started_without_matched_skill")),
                "generated_new_skill": bool(loaded.get("generated_new_skill")),
                "generated_new_tool": bool(loaded.get("generated_new_tool", loaded.get("generated_new_skill"))),
                "executed_tool": bool(loaded.get("executed_tool")),
                "tool_response_preview": str(loaded.get("tool_response_preview") or "").strip() or None,
                "metrics": metrics,
                "tool_unpack_duration_seconds": metrics["tool_unpack_duration_seconds"],
                "evolution_executor_tokens": metrics["evolution_executor_tokens"],
                "reviewer_tokens": metrics["reviewer_tokens"],
                "total_tokens": metrics["total_tokens"],
                "created_at": str(loaded.get("created_at") or "").strip() or _mtime_iso_text(round_json_path),
                "completed_at": str(loaded.get("completed_at") or "").strip() or _mtime_iso_text(round_json_path),
            }
        )
    rounds.sort(key=lambda item: int(item.get("round") or 0))
    return rounds


def _guess_running_working_tool_path(job_root: Path) -> str | None:
    working_dir = job_root / "working_tool"
    if not working_dir.exists() or not working_dir.is_dir():
        return None
    candidates = sorted(
        (path for path in working_dir.glob("*.py") if path.is_file()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return str(candidates[0]) if candidates else None


def _build_running_evolution_round(
    enriched: dict[str, Any],
    *,
    job_root: Path,
) -> dict[str, Any] | None:
    job_status = str(enriched.get("status") or "").strip().lower()
    if job_status not in {EVOLUTION_PENDING, EVOLUTION_CLAIMED, EVOLUTION_RUNNING, EVOLUTION_CANCELLING}:
        return None
    round_id = int(enriched.get("current_round") or 0)
    if round_id <= 0:
        return None
    round_dir = job_root / f"round_{round_id:03d}"
    if not round_dir.exists():
        return None
    workspace_output = job_root / "workspace" / "output"
    summary_path = workspace_output / "summary.md"
    reason_path = workspace_output / "reason.md"
    item = {
        "round": round_id,
        "status": "running",
        "tool_path_before": enriched.get("source_tool_path") or enriched.get("source_skill_path"),
        "tool_path_after": enriched.get("working_tool_path") or enriched.get("working_skill_path") or _guess_running_working_tool_path(job_root),
        "summary_path": str(summary_path) if summary_path.exists() else None,
        "reason_path": str(reason_path) if reason_path.exists() else None,
        "tool_response_preview": None,
        "metrics": {},
    }
    metrics = _normalize_evolution_round_metrics(item)
    review_result = None
    if reason_path.exists():
        review_result = _safe_read_text(reason_path)
    created_at = _mtime_iso_text(round_dir / "evolution_executor.log") or _mtime_iso_text(round_dir)
    return {
        "id": f"{str(enriched.get('id') or '').strip()}-{round_id}",
        "job_id": str(enriched.get("id") or "").strip(),
        "round": round_id,
        "status": "running",
        "tool_skill_path_before": item["tool_path_before"],
        "tool_skill_path_after": item["tool_path_after"],
        "tool_path_before": item["tool_path_before"],
        "tool_path_after": item["tool_path_after"],
        "tool_changed": bool(item["tool_path_before"] and item["tool_path_after"] and item["tool_path_before"] != item["tool_path_after"]),
        "review_result": review_result,
        "summary_path": item["summary_path"],
        "reason_path": item["reason_path"],
        "source_skill_path": enriched.get("source_skill_path"),
        "source_tool_path": enriched.get("source_tool_path"),
        "started_without_matched_skill": bool(enriched.get("started_without_matched_skill")),
        "generated_new_skill": False,
        "generated_new_tool": False,
        "executed_tool": (round_dir / "tool_manifest.json").exists() or (job_root / "tool_manifest.json").exists(),
        "tool_response_preview": None,
        "metrics": metrics,
        "tool_unpack_duration_seconds": metrics["tool_unpack_duration_seconds"],
        "evolution_executor_tokens": metrics["evolution_executor_tokens"],
        "reviewer_tokens": metrics["reviewer_tokens"],
        "total_tokens": metrics["total_tokens"],
        "created_at": created_at,
        "completed_at": None,
    }


def _enrich_evolution_job_payload(
    payload: dict[str, Any],
    *,
    task: Any | None,
    job_root: Path | None,
) -> dict[str, Any]:
    enriched = dict(payload or {})
    runtime_root = job_root
    if runtime_root is not None and not runtime_root.exists():
        runtime_root = Path("/data/secflow-app-firmware-unpacker")
    enriched["run_root"] = str(runtime_root) if runtime_root is not None else None
    enriched["session_root"] = str(job_root / "sessions") if job_root is not None else None
    enriched["task_output_path"] = str(getattr(task, "output_path", "") or "").strip() or None
    dispatcher_source_path = _resolve_evolution_dispatcher_tool_path(task) if task is not None else None
    source_skill_path = dispatcher_source_path or str(getattr(task, "matched_skill", "") or "").strip() or None
    enriched["source_skill_path"] = source_skill_path
    enriched["source_tool_path"] = source_skill_path
    enriched["started_without_matched_skill"] = not bool(source_skill_path)
    enriched["working_skill_path"] = None
    enriched["working_tool_path"] = None
    enriched["generated_new_skill"] = False
    enriched["generated_new_tool"] = False
    enriched["replacement_required"] = False
    enriched["replacement_confirmed"] = True
    enriched["effective_tool_path"] = None
    if job_root is None:
        return enriched
    result_payload: dict[str, Any] = {}
    result_path = job_root / "evolution_result.json"
    if result_path.exists():
        try:
            loaded = json.loads(result_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                result_payload = loaded
        except Exception:
            result_payload = {}
    if isinstance(result_payload, dict):
        enriched["working_skill_path"] = str(result_payload.get("working_skill_path") or "").strip() or None
        enriched["working_tool_path"] = str(result_payload.get("working_tool_path") or enriched["working_skill_path"] or "").strip() or None
        enriched["source_skill_path"] = str(result_payload.get("source_skill_path") or source_skill_path or "").strip() or None
        enriched["source_tool_path"] = str(result_payload.get("source_tool_path") or enriched["source_skill_path"] or "").strip() or None
        enriched["started_without_matched_skill"] = bool(result_payload.get("started_without_matched_skill"))
        enriched["generated_new_skill"] = bool(result_payload.get("generated_new_skill"))
        enriched["generated_new_tool"] = bool(result_payload.get("generated_new_tool", enriched["generated_new_skill"]))
        enriched["final_tool_path"] = str(result_payload.get("final_tool_path") or result_payload.get("final_skill_path") or "").strip() or None
        enriched["replaced_tool_path"] = str(result_payload.get("replaced_tool_path") or result_payload.get("replaced_skill_path") or "").strip() or None
        enriched["replacement_required"] = bool(result_payload.get("replacement_required"))
        enriched["replacement_confirmed"] = bool(result_payload.get("replacement_confirmed", not enriched["replacement_required"]))
        enriched["effective_tool_path"] = str(result_payload.get("effective_tool_path") or "").strip() or None
        rounds = result_payload.get("rounds")
        if isinstance(rounds, list):
            enriched["round_count"] = len(rounds)
            enriched["rounds"] = []
            for item in rounds:
                if not isinstance(item, dict):
                    continue
                metrics = _normalize_evolution_round_metrics(item)
                enriched["rounds"].append(
                    {
                        "id": str(item.get("id") or "").strip() or f"{str(enriched.get('id') or '').strip()}-{int(item.get('round') or 0)}",
                        "job_id": str(item.get("job_id") or enriched.get("id") or "").strip(),
                        "round": int(item.get("round") or 0),
                        "status": str(item.get("status") or "failed"),
                        "tool_skill_path_before": str(item.get("tool_skill_path_before") or "").strip() or None,
                        "tool_skill_path_after": str(item.get("tool_skill_path_after") or "").strip() or None,
                        "tool_path_before": str(item.get("tool_path_before") or item.get("tool_skill_path_before") or "").strip() or None,
                        "tool_path_after": str(item.get("tool_path_after") or item.get("tool_skill_path_after") or "").strip() or None,
                        "tool_changed": bool(item.get("tool_changed")),
                        "review_result": str(item.get("review_result") or "").strip() or None,
                        "summary_path": str(item.get("summary_path") or "").strip() or None,
                        "reason_path": str(item.get("reason_path") or "").strip() or None,
                        "source_skill_path": str(item.get("source_skill_path") or enriched["source_skill_path"] or "").strip() or None,
                        "source_tool_path": str(item.get("source_tool_path") or enriched["source_tool_path"] or "").strip() or None,
                        "started_without_matched_skill": bool(item.get("started_without_matched_skill")),
                        "generated_new_skill": bool(item.get("generated_new_skill")),
                        "generated_new_tool": bool(item.get("generated_new_tool", item.get("generated_new_skill"))),
                        "executed_tool": bool(item.get("executed_tool")),
                        "tool_response_preview": str(item.get("tool_response_preview") or "").strip() or None,
                        "metrics": metrics,
                        "tool_unpack_duration_seconds": metrics["tool_unpack_duration_seconds"],
                        "evolution_executor_tokens": metrics["evolution_executor_tokens"],
                        "reviewer_tokens": metrics["reviewer_tokens"],
                        "total_tokens": metrics["total_tokens"],
                        "created_at": str(item.get("created_at") or "").strip() or None,
                        "completed_at": str(item.get("completed_at") or "").strip() or None,
                    }
                )
    rounds_list = list(enriched.get("rounds") or [])
    if not rounds_list:
        rounds_list = _load_evolution_rounds_from_run_dir(job_root, enriched=enriched)
    running_round = _build_running_evolution_round(enriched, job_root=job_root)
    if running_round is not None and not any(int(item.get("round") or 0) == int(running_round.get("round") or 0) for item in rounds_list):
        rounds_list.append(running_round)
        rounds_list.sort(key=lambda item: int(item.get("round") or 0))
    if rounds_list:
        enriched["rounds"] = rounds_list
        enriched["round_count"] = len(rounds_list)
        first_round = next((item for item in rounds_list if int(item.get("round") or 0) == 1), rounds_list[0])
        runtime_source_tool = str(first_round.get("source_tool_path") or first_round.get("source_skill_path") or "").strip() or None
        if runtime_source_tool is not None or bool(first_round.get("started_without_matched_skill")):
            enriched["source_skill_path"] = runtime_source_tool
            enriched["source_tool_path"] = runtime_source_tool
            enriched["started_without_matched_skill"] = bool(first_round.get("started_without_matched_skill"))
        latest_round = rounds_list[-1]
        runtime_working_tool = str(
            latest_round.get("tool_path_after")
            or latest_round.get("tool_skill_path_after")
            or enriched.get("working_tool_path")
            or enriched.get("working_skill_path")
            or ""
        ).strip() or None
        if runtime_working_tool:
            enriched["working_skill_path"] = runtime_working_tool
            enriched["working_tool_path"] = runtime_working_tool
    return enriched


def _read_session_count(run_root: Path) -> int:
    index_path = run_root / "sessions" / "index.json"
    if not index_path.exists():
        return 0
    try:
        payload = json.loads(index_path.read_text(encoding="utf-8"))
    except Exception:
        return 0
    raw_items = payload.get("items")
    if not isinstance(raw_items, list):
        return 0
    return sum(1 for item in raw_items if isinstance(item, dict))


def _safe_read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip() or None
    except Exception:
        return None


def _latest_evolution_summary(db: Any, task_id: str) -> dict[str, Any] | None:
    from app.model import FirmwareEvolutionJob

    row = (
        db.query(FirmwareEvolutionJob)
        .filter(FirmwareEvolutionJob.task_id == task_id)
        .order_by(FirmwareEvolutionJob.created_at.desc())
        .first()
    )
    return row.to_dict() if row is not None else None


def _evolution_session_index_payload(job_root: Path) -> dict[str, Any]:
    session_root = job_root / "sessions"
    index_path = session_root / "index.json"
    if not index_path.exists():
        return {"version": 1, "session_root": str(session_root), "items": []}
    try:
        payload = json.loads(index_path.read_text(encoding="utf-8"))
    except Exception:
        payload = {"version": 1, "items": []}
    if not isinstance(payload, dict):
        payload = {"version": 1, "items": []}
    payload["session_root"] = str(session_root)
    if not isinstance(payload.get("items"), list):
        payload["items"] = []
    return payload


def _write_task_result_cache(task_id: str) -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            return
        latest_evolution = _latest_evolution_summary(db, task_id)

        output_root = Path(str(task.output_path or "").strip())
        run_root = _derive_run_root_from_output_path(task.output_path or "")
        summary_path = output_root / "summary.md"
        reason_path = output_root / "reason.md"
        tokens_summary_path = run_root / "round_000" / "tokens_summary.json"

        warnings: list[str] = []
        task_status = str(task.status or "").strip() or "unknown"
        available = task_status in {
            TaskStatus.SUCCESS.value,
            TaskStatus.FAILED.value,
            TaskStatus.CANCELLED.value,
        }
        if not output_root.exists() or not output_root.is_dir():
            warnings.append("输出目录不存在")
            available = False

        output_stats = {
            "output_file_count": 0,
            "output_dir_count": 0,
            "output_total_size_bytes": 0,
            "largest_file_path": None,
            "largest_file_size_bytes": 0,
            "top_level_entry_count": 0,
            "top_level_entries": [],
            "file_extension_breakdown": [],
            "largest_files": [],
            "deepest_path": None,
            "avg_file_size_bytes": 0,
            "small_file_count": 0,
            "medium_file_count": 0,
            "large_file_count": 0,
        }
        if output_root.exists() and output_root.is_dir():
            output_stats = scan_output_tree(output_root)

        summary_text = _safe_read_text(summary_path)
        reason_text = _safe_read_text(reason_path)
        if summary_path.exists() and not summary_text:
            warnings.append("summary.md 存在但为空")
        if reason_path.exists() and not reason_text:
            warnings.append("reason.md 存在但为空")

        session_count = _read_session_count(run_root)
        if (run_root / "sessions" / "index.json").exists() and session_count == 0:
            warnings.append("会话索引存在但未解析到任何会话")

        started_at = isoformat_local(task.started_at)
        completed_at = isoformat_local(task.completed_at)
        duration_seconds: Optional[int] = None
        if task.started_at and task.completed_at:
            try:
                duration_seconds = max(0, int((task.completed_at - task.started_at).total_seconds()))
            except Exception:
                duration_seconds = None

        payload = {
            "schema_version": 1,
            "task_id": task.id,
            "available": available,
            "status": task_status,
            "output_root": str(output_root) if str(output_root) else None,
            "run_root": str(run_root),
            "summary_path": str(summary_path) if summary_path.exists() else None,
            "reason_path": str(reason_path) if reason_path.exists() else None,
            "tokens_summary_path": str(tokens_summary_path) if tokens_summary_path.exists() else None,
            "summary_text": summary_text,
            "reason_text": reason_text,
            "warnings": warnings,
            "summary": {
                **output_stats,
                "matched_skill": str(task.matched_skill or "").strip() or None,
                "fallback_to_llm": bool(task.fallback_to_llm),
                "generated_skill_path": str(task.generated_skill_path or "").strip() or None,
                "generated_skill_status": str(task.generated_skill_status or "").strip() or None,
                "promotion_success_count": int(task.promotion_success_count or 0),
                "skill_generation_status": str(task.skill_generation_status or "").strip() or None,
                "skill_generation_error": str(task.skill_generation_error or "").strip() or None,
                "skill_generation_job_id": str(task.skill_generation_job_id or "").strip() or None,
                "skill_generation_started_at": isoformat_local(task.skill_generation_started_at),
                "skill_generation_completed_at": isoformat_local(task.skill_generation_completed_at),
                "latest_evolution_job": str((latest_evolution or {}).get("id") or "").strip() or None,
                "latest_evolution_status": str((latest_evolution or {}).get("status") or "").strip() or None,
                "latest_evolution_started_at": str((latest_evolution or {}).get("started_at") or "").strip() or None,
                "latest_evolution_completed_at": str((latest_evolution or {}).get("completed_at") or "").strip() or None,
                "latest_evolution_final_skill_path": str((latest_evolution or {}).get("final_skill_path") or "").strip() or None,
                "executor_rounds": int(task.rounds or 0),
                "session_count": session_count,
                "event_count": 0,
                "started_at": started_at,
                "completed_at": completed_at,
                "duration_seconds": duration_seconds,
            },
        }
        atomic_write_json(run_root / TASK_RESULT_CACHE_FILENAME, payload)
    finally:
        db.close()


def _skill_generation_context_path(output_path: str) -> Path:
    from app.unpacker_engine import SKILL_GENERATION_CONTEXT_FILENAME

    return _derive_run_root_from_output_path(output_path) / "round_000" / SKILL_GENERATION_CONTEXT_FILENAME


def _enqueue_skill_generation_job(db: Any, task: Any, *, created_by: str = "task_manager") -> Optional[str]:
    from app.model import SkillGenerationJob, generate_id

    if task is None:
        return None
    existing = (
        db.query(SkillGenerationJob)
        .filter(
            SkillGenerationJob.task_id == task.id,
            SkillGenerationJob.status.in_([SKILL_GENERATION_PENDING, SKILL_GENERATION_RUNNING]),
        )
        .first()
    )
    if existing is not None:
        task.skill_generation_status = existing.status
        task.skill_generation_job_id = existing.id
        task.skill_generation_error = None
        task.skill_generation_started_at = existing.started_at
        task.skill_generation_completed_at = existing.completed_at
        return existing.id

    job_id = generate_id()
    db.add(
        SkillGenerationJob(
            id=job_id,
            task_id=task.id,
            project_id=task.project_id,
            status=SKILL_GENERATION_PENDING,
            created_by=created_by,
        )
    )
    task.skill_generation_status = SKILL_GENERATION_PENDING
    task.skill_generation_error = None
    task.skill_generation_job_id = job_id
    task.skill_generation_started_at = None
    task.skill_generation_completed_at = None
    return job_id


def submit_evolution_job(task_id: str, *, created_by: str = "task_manager") -> dict[str, Any]:
    from app.model import FirmwareEvolutionJob, TaskStatus, UnpackTask, generate_id, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            raise ValueError("任务不存在")
        if task.status != TaskStatus.SUCCESS.value:
            raise ValueError("仅主任务 success 后允许发起进化")
        existing = (
            db.query(FirmwareEvolutionJob)
            .filter(
                FirmwareEvolutionJob.task_id == task.id,
                FirmwareEvolutionJob.status.in_([EVOLUTION_PENDING, EVOLUTION_CLAIMED, EVOLUTION_RUNNING, EVOLUTION_CANCELLING]),
            )
            .first()
        )
        if existing is not None:
            raise ValueError("当前任务已有运行中的进化任务")
        latest_job = (
            db.query(FirmwareEvolutionJob)
            .filter(FirmwareEvolutionJob.task_id == task.id)
            .order_by(FirmwareEvolutionJob.created_at.desc())
            .first()
        )
        source_tool_path = _resolve_evolution_dispatcher_tool_path(task) or _resolve_evolution_source_tool_path(task, latest_job)
        job_id = generate_id()
        job = FirmwareEvolutionJob(
            id=job_id,
            task_id=task.id,
            project_id=task.project_id,
            status=EVOLUTION_PENDING,
            current_round=0,
            max_rounds=EVOLUTION_MAX_ROUNDS,
            current_stage="evolution_execute",
            created_by=created_by,
        )
        db.add(job)
        task.latest_evolution_job_id = job_id
        task.latest_evolution_status = EVOLUTION_PENDING
        task.latest_evolution_started_at = None
        task.latest_evolution_completed_at = None
        task.latest_evolution_final_skill_path = None
        db.commit()
        _record_task_event_from_row(
            task,
            event_type="evolution_queued",
            summary="手动进化任务已创建",
            stage_key="evolution",
            status=task.status,
            detail={"job_id": job_id, "max_rounds": EVOLUTION_MAX_ROUNDS, "source_tool_path": source_tool_path},
            created_by=created_by,
        )
        _write_task_result_cache(task.id)
        return {"job_id": job_id, "status": EVOLUTION_PENDING, "max_rounds": EVOLUTION_MAX_ROUNDS}
    finally:
        db.close()


def list_evolution_jobs(task_id: str) -> list[dict[str, Any]]:
    from app.model import FirmwareEvolutionJob, UnpackTask, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        rows = (
            db.query(FirmwareEvolutionJob)
            .filter(FirmwareEvolutionJob.task_id == task_id)
            .order_by(FirmwareEvolutionJob.created_at.desc())
            .all()
        )
        output_path = str(task.output_path or "").strip() if task is not None else ""
        return [
            _enrich_evolution_job_payload(
                row.to_dict(),
                task=task,
                job_root=_derive_evolution_job_root(output_path, row.id) if output_path else None,
            )
            for row in rows
        ]
    finally:
        db.close()


def list_all_evolution_jobs(
    *,
    project_id: str | None = None,
    status: str | None = None,
    search: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    from sqlalchemy import or_

    from app.model import FirmwareEvolutionJob, UnpackTask, get_db_session

    db = get_db_session()
    try:
        query = db.query(FirmwareEvolutionJob, UnpackTask).join(UnpackTask, FirmwareEvolutionJob.task_id == UnpackTask.id)
        if project_id:
            query = query.filter(FirmwareEvolutionJob.project_id == project_id)
        if status:
            query = query.filter(FirmwareEvolutionJob.status == status)
        keyword = str(search or "").strip()
        if keyword:
            like = f"%{keyword}%"
            query = query.filter(
                or_(
                    FirmwareEvolutionJob.id.like(like),
                    FirmwareEvolutionJob.task_id.like(like),
                    UnpackTask.firmware_path.like(like),
                    UnpackTask.output_path.like(like),
                )
            )
        total = query.count()
        rows = (
            query.order_by(FirmwareEvolutionJob.created_at.desc())
            .offset(max(0, int(offset or 0)))
            .limit(max(1, min(500, int(limit or 100))))
            .all()
        )
        items = []
        for job, task in rows:
            output_path = str(task.output_path or "").strip() if task is not None else ""
            payload = _enrich_evolution_job_payload(
                job.to_dict(),
                task=task,
                job_root=_derive_evolution_job_root(output_path, job.id) if output_path else None,
            )
            payload["source_task"] = task.to_dict() if task is not None else None
            items.append(payload)
        return {"total": total, "items": items}
    finally:
        db.close()


def get_evolution_job(job_id: str) -> dict[str, Any] | None:
    from app.model import FirmwareEvolutionJob, FirmwareEvolutionRound, UnpackTask, get_db_session

    db = get_db_session()
    try:
        job = db.query(FirmwareEvolutionJob).filter(FirmwareEvolutionJob.id == job_id).first()
        if job is None:
            return None
        task = db.query(UnpackTask).filter(UnpackTask.id == job.task_id).first()
        rounds = (
            db.query(FirmwareEvolutionRound)
            .filter(FirmwareEvolutionRound.job_id == job.id)
            .order_by(FirmwareEvolutionRound.round.asc())
            .all()
        )
        output_path = str(task.output_path or "").strip() if task is not None else ""
        job_root = _derive_evolution_job_root(output_path, job.id) if output_path else Path("/tmp")
        payload = _enrich_evolution_job_payload(
            job.to_dict(),
            task=task,
            job_root=job_root,
        )
        payload.update(
            {
                "run_root": str(job_root),
                "session_root": str(job_root / "sessions"),
                "task_output_path": output_path or None,
                "round_count": int(payload.get("round_count") or len(rounds)),
                "rounds": payload.get("rounds") or [item.to_dict() for item in rounds],
            }
        )
        return payload
    finally:
        db.close()


def cancel_evolution_job(job_id: str) -> dict[str, Any]:
    from app.model import FirmwareEvolutionJob, UnpackTask, get_db_session

    db = get_db_session()
    try:
        job = db.query(FirmwareEvolutionJob).filter(FirmwareEvolutionJob.id == job_id).first()
        if job is None:
            raise ValueError("进化任务不存在")
        task = db.query(UnpackTask).filter(UnpackTask.id == job.task_id).first()
        status = str(job.status or "")
        if status not in {EVOLUTION_PENDING, EVOLUTION_CLAIMED, EVOLUTION_RUNNING, EVOLUTION_CANCELLING}:
            return {"message": "进化任务已处于终态", "task_id": job.task_id}
        job_root = _derive_evolution_job_root(str(task.output_path or ""), job.id) if task is not None else None
        now = now_local()
        runtime_cleanup: dict[str, Any] = {"job_id": job.id}
        if status in {EVOLUTION_PENDING, EVOLUTION_CLAIMED}:
            runtime_cleanup = _terminate_evolution_runtime(job.id, job_root)
            job.status = EVOLUTION_CANCELLED
            job.owner_id = None
            job.dispatch_owner_id = None
            job.dispatch_token = None
            job.dispatch_claimed_at = None
            job.dispatch_lease_expires_at = None
            job.heartbeat_at = now
            job.lease_expires_at = None
            job.runner_pid = None
            job.runner_started_at = None
            job.runner_heartbeat_at = None
            job.run_token = None
            job.cancel_grace_deadline = None
            job.cancel_force_deadline = None
            job.completed_at = now
            job.last_progress_at = now
        else:
            job.status = EVOLUTION_CANCELLING
            job.cancel_requested_at = now
            job.cancel_grace_deadline = now + timedelta(seconds=_cancel_grace_seconds())
            job.cancel_force_deadline = now + timedelta(seconds=_cancel_force_seconds())
            job.heartbeat_at = now
            job.last_progress_at = now
            if job.runner_pid:
                _signal_evolution_runner(
                    job,
                    signal.SIGTERM,
                    event_type="evolution_runner_sigterm_sent",
                    summary="已向进化任务执行进程发送 SIGTERM",
                )
        if task is not None:
            task.latest_evolution_job_id = job.id
            task.latest_evolution_status = job.status
            task.latest_evolution_completed_at = job.completed_at
            _record_task_event_from_row(
                task,
                event_type="evolution_cancel_requested" if job.status == EVOLUTION_CANCELLING else "evolution_cancelled",
                summary="已提交进化任务结束请求" if job.status == EVOLUTION_CANCELLING else "手动进化任务已结束",
                stage_key="evolution",
                status=task.status,
                detail={"job_id": job.id, **runtime_cleanup},
                created_by="task_manager",
            )
        db.commit()
        if task is not None:
            _write_task_result_cache(task.id)
        return {"message": "进化任务结束请求已提交", "task_id": job.task_id}
    finally:
        db.close()


def retry_evolution_job(job_id: str) -> dict[str, Any]:
    from app.model import FirmwareEvolutionJob, FirmwareEvolutionRound, UnpackTask, get_db_session

    db = get_db_session()
    try:
        job = db.query(FirmwareEvolutionJob).filter(FirmwareEvolutionJob.id == job_id).first()
        if job is None:
            raise ValueError("进化任务不存在")
        if str(job.status or "") in {EVOLUTION_PENDING, EVOLUTION_CLAIMED, EVOLUTION_RUNNING, EVOLUTION_CANCELLING}:
            raise ValueError("运行中的进化任务不能重试")
        task = db.query(UnpackTask).filter(UnpackTask.id == job.task_id).first()
        if task is None:
            raise ValueError("进化任务对应主任务不存在")
        existing = (
            db.query(FirmwareEvolutionJob)
            .filter(
                FirmwareEvolutionJob.task_id == job.task_id,
                FirmwareEvolutionJob.id != job.id,
                FirmwareEvolutionJob.status.in_([EVOLUTION_PENDING, EVOLUTION_CLAIMED, EVOLUTION_RUNNING, EVOLUTION_CANCELLING]),
            )
            .first()
        )
        if existing is not None:
            raise ValueError("当前主任务已有运行中的进化任务")
        job_root = _derive_evolution_job_root(str(task.output_path or ""), job.id)
        runtime_cleanup = _terminate_evolution_runtime(job.id, job_root)
        _cleanup_evolution_job_workspace(job_root)
        db.query(FirmwareEvolutionRound).filter(FirmwareEvolutionRound.job_id == job.id).delete()
        job.status = EVOLUTION_PENDING
        job.current_round = 0
        job.current_stage = "evolution_execute"
        job.owner_id = None
        job.dispatch_owner_id = None
        job.dispatch_token = None
        job.dispatch_claimed_at = None
        job.dispatch_lease_expires_at = None
        job.heartbeat_at = None
        job.lease_expires_at = None
        job.cancel_requested_at = None
        job.last_progress_at = now_local()
        job.runner_pid = None
        job.runner_started_at = None
        job.runner_heartbeat_at = None
        job.run_token = None
        job.cancel_grace_deadline = None
        job.cancel_force_deadline = None
        job.error_message = None
        job.started_at = None
        job.completed_at = None
        job.final_skill_path = None
        job.replaced_skill_path = None
        job.review_passed = False
        task.latest_evolution_job_id = job.id
        task.latest_evolution_status = EVOLUTION_PENDING
        task.latest_evolution_started_at = None
        task.latest_evolution_completed_at = None
        task.latest_evolution_final_skill_path = None
        db.commit()
        _record_task_event_from_row(
            task,
            event_type="evolution_retry_queued",
            summary="手动进化任务已重新排队",
            stage_key="evolution",
            status=task.status,
            detail={"job_id": job.id, **runtime_cleanup},
            created_by="task_manager",
        )
        _write_task_result_cache(task.id)
        return {"message": "进化任务重试已受理", "task_id": job.task_id}
    finally:
        db.close()


def delete_evolution_job(job_id: str) -> dict[str, Any]:
    from app.model import FirmwareEvolutionJob, FirmwareEvolutionRound, UnpackTask, get_db_session

    db = get_db_session()
    try:
        job = db.query(FirmwareEvolutionJob).filter(FirmwareEvolutionJob.id == job_id).first()
        if job is None:
            raise ValueError("进化任务不存在")
        if str(job.status or "") in {EVOLUTION_PENDING, EVOLUTION_CLAIMED, EVOLUTION_RUNNING, EVOLUTION_CANCELLING}:
            raise ValueError("运行中的进化任务不能删除，请先结束")
        task_id = job.task_id
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        job_root = _derive_evolution_job_root(str(task.output_path or ""), job.id) if task is not None else None
        runtime_cleanup = _terminate_evolution_runtime(job.id, job_root)
        db.query(FirmwareEvolutionRound).filter(FirmwareEvolutionRound.job_id == job.id).delete()
        db.delete(job)
        latest = (
            db.query(FirmwareEvolutionJob)
            .filter(FirmwareEvolutionJob.task_id == task_id, FirmwareEvolutionJob.id != job_id)
            .order_by(FirmwareEvolutionJob.created_at.desc())
            .first()
        )
        if task is not None:
            task.latest_evolution_job_id = latest.id if latest is not None else None
            task.latest_evolution_status = latest.status if latest is not None else None
            task.latest_evolution_started_at = latest.started_at if latest is not None else None
            task.latest_evolution_completed_at = latest.completed_at if latest is not None else None
            task.latest_evolution_final_skill_path = latest.final_skill_path if latest is not None else None
        db.commit()
        if job_root is not None:
            shutil.rmtree(job_root, ignore_errors=True)
        if task is not None:
            _record_task_event_from_row(
                task,
                event_type="evolution_deleted",
                summary="手动进化任务已删除",
                stage_key="evolution",
                status=task.status,
                detail={"job_id": job_id, **runtime_cleanup},
                created_by="task_manager",
            )
        if task is not None:
            _write_task_result_cache(task.id)
        return {"message": "进化任务已删除", "task_id": task_id}
    finally:
        db.close()


def list_evolution_rounds(job_id: str) -> list[dict[str, Any]]:
    from app.model import FirmwareEvolutionRound, get_db_session

    fallback_items: list[dict[str, Any]] = []
    fallback = get_evolution_job(job_id)
    if isinstance(fallback, dict):
        raw_rounds = fallback.get("rounds")
        if isinstance(raw_rounds, list):
            for item in raw_rounds:
                if not isinstance(item, dict):
                    continue
                metrics = _normalize_evolution_round_metrics(item)
                payload = dict(item)
                payload["metrics"] = metrics
                payload["tool_unpack_duration_seconds"] = metrics["tool_unpack_duration_seconds"]
                payload["evolution_executor_tokens"] = metrics["evolution_executor_tokens"]
                payload["reviewer_tokens"] = metrics["reviewer_tokens"]
                payload["total_tokens"] = metrics["total_tokens"]
                fallback_items.append(payload)
            if fallback_items:
                fallback_items.sort(key=lambda item: int(item.get("round") or 0))

    db = get_db_session()
    try:
        rows = (
            db.query(FirmwareEvolutionRound)
            .filter(FirmwareEvolutionRound.job_id == job_id)
            .order_by(FirmwareEvolutionRound.round.asc())
            .all()
        )
        items: list[dict[str, Any]] = []
        for row in rows:
            payload = row.to_dict()
            metrics = _normalize_evolution_round_metrics(payload)
            payload["metrics"] = metrics
            payload["tool_unpack_duration_seconds"] = metrics["tool_unpack_duration_seconds"]
            payload["evolution_executor_tokens"] = metrics["evolution_executor_tokens"]
            payload["reviewer_tokens"] = metrics["reviewer_tokens"]
            payload["total_tokens"] = metrics["total_tokens"]
            items.append(payload)
        if fallback_items:
            if not items:
                return fallback_items
            if len(fallback_items) >= len(items):
                return fallback_items
        if items:
            return items
        if fallback_items:
            return fallback_items
        return items
    finally:
        db.close()


def get_evolution_sessions(job_id: str) -> dict[str, Any] | None:
    from app.model import FirmwareEvolutionJob, UnpackTask, get_db_session

    db = get_db_session()
    try:
        job = db.query(FirmwareEvolutionJob).filter(FirmwareEvolutionJob.id == job_id).first()
        if job is None:
            return None
        task = db.query(UnpackTask).filter(UnpackTask.id == job.task_id).first()
        if task is None:
            return None
        job_root = _derive_evolution_job_root(task.output_path, job.id)
        return _evolution_session_index_payload(job_root)
    finally:
        db.close()


def get_evolution_log(job_id: str, round_id: int, role: str) -> dict[str, Any] | None:
    from app.model import FirmwareEvolutionJob, UnpackTask, get_db_session
    from app.unpacker_engine_logs import read_text_tail

    role_file_map = {
        "evolution_executor": ["evolution_executor_transcript.log", "evolution_executor_messages.json"],
        "tool_executor": ["tool_executor_transcript.log", "tool_executor_messages.json"],
        "reviewer": ["reviewer_transcript.log", "reviewer_messages.json"],
        "evolver": ["evolver_transcript.log", "evolver_messages.json"],
    }
    files = role_file_map.get(str(role or "").strip())
    if not files:
        raise ValueError("不支持的 evolution log role")

    db = get_db_session()
    try:
        job = db.query(FirmwareEvolutionJob).filter(FirmwareEvolutionJob.id == job_id).first()
        if job is None:
            return None
        task = db.query(UnpackTask).filter(UnpackTask.id == job.task_id).first()
        if task is None:
            return None
        round_dir = _derive_evolution_job_root(task.output_path, job.id) / f"round_{max(1, int(round_id)):03d}"
        existing_files = [str(round_dir / name) for name in files if (round_dir / name).exists()]
        text_chunks = []
        for name in files:
            path = round_dir / name
            if path.exists():
                text_chunks.append(f"===== {name} =====\n{read_text_tail(path, 128 * 1024)}")
        return {
            "task_id": job.task_id,
            "run_path": str(round_dir),
            "available": bool(text_chunks),
            "log_text": "\n\n".join(text_chunks),
            "files": existing_files,
            "phase": f"evolution:{role}:round_{max(1, int(round_id)):03d}",
            "message": None if text_chunks else "当前轮次日志不存在",
        }
    finally:
        db.close()


def confirm_evolution_tool_replacement(job_id: str) -> dict[str, Any]:
    from app.model import FirmwareEvolutionJob, UnpackTask, get_db_session

    db = get_db_session()
    try:
        job = db.query(FirmwareEvolutionJob).filter(FirmwareEvolutionJob.id == job_id).first()
        if job is None:
            raise ValueError("进化任务不存在")
        task = db.query(UnpackTask).filter(UnpackTask.id == job.task_id).first()
        if task is None:
            raise ValueError("进化任务对应主任务不存在")
        if str(job.status or "").strip() != EVOLUTION_SUCCESS:
            raise ValueError("仅 success 的进化任务允许确认替换")
        job_root = _derive_evolution_job_root(task.output_path, job.id)
        result_path = job_root / "evolution_result.json"
        if not result_path.exists():
            raise ValueError("进化结果不存在")
        payload = json.loads(result_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("进化结果格式非法")

        final_tool_path = Path(str(payload.get("final_tool_path") or payload.get("final_skill_path") or "").strip())
        replacement_required = bool(payload.get("replacement_required"))
        replacement_confirmed = bool(payload.get("replacement_confirmed", not replacement_required))

        if not replacement_required:
            raise ValueError("当前进化结果不需要确认替换")
        if replacement_confirmed:
            raise ValueError("当前进化结果已确认替换")
        if not final_tool_path.exists():
            raise ValueError("新工具文件不存在")
        info = detect_format(str(task.firmware_path or ""))
        magic_hex = str((info.get("magic") or b"").hex())[:8].lower()
        meta = parse_tool_metadata(final_tool_path)
        description = str(meta.get("description") or "").strip()
        family_id = str(meta.get("format_id") or meta.get("name") or final_tool_path.stem or "").strip()
        if not family_id:
            raise ValueError("无法从新工具中解析 family_id")
        active_path = activate_tool_version(
            tools_store_dir=TOOLS_STORE_DIR,
            tools_active_dir=TOOLS_ACTIVE_DIR,
            family_id=family_id,
            target_path=final_tool_path,
            magic_hex=magic_hex,
            source="evolution_confirm",
        )
        current_rule = find_dispatcher_rule(
            dispatcher_rules_path=DISPATCHER_RULES_PATH,
            family_id=family_id,
            magic_hex=magic_hex,
        )
        if current_rule is None and magic_hex:
            upsert_dispatcher_rule(
                dispatcher_rules_path=DISPATCHER_RULES_PATH,
                family_id=family_id,
                magic_hex=magic_hex,
                tool_path=active_path,
                description=description,
            )

        payload["replacement_confirmed"] = True
        payload["replaced_skill_path"] = str(active_path)
        payload["replaced_tool_path"] = str(active_path)
        payload["effective_tool_path"] = str(active_path)
        result_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

        job.replaced_skill_path = str(active_path)
        task.latest_evolution_final_skill_path = str(final_tool_path)
        db.commit()

        _record_task_event_from_row(
            task,
            event_type="evolution_tool_replaced",
            summary="已确认使用新工具替换原工具",
            stage_key="evolution",
            status=task.status,
            detail={
                "job_id": job.id,
                "new_tool_path": str(final_tool_path),
                "replaced_tool_path": str(active_path),
            },
            created_by="task_manager",
        )
        return {
            "message": "已确认替换原工具",
            "task_id": task.id,
        }
    finally:
        db.close()


def process_evolution_jobs(limit: int = 1) -> int:
    processed = 0
    while processed < max(1, limit):
        available_slots = _runtime_max_concurrent() - get_local_active_task_count()
        if available_slots <= 0:
            break
        claimed_job_ids = _claim_pending_evolution_jobs(max(1, min(limit - processed, available_slots)))
        if not claimed_job_ids:
            break
        for job_id in claimed_job_ids:
            if _runtime_max_concurrent() - get_local_active_task_count() <= 0:
                _reset_evolution_claim(job_id)
                break
            try:
                _launch_evolution_runner(job_id)
                processed += 1
            except Exception:
                _reset_evolution_claim(job_id)
                raise
    return processed


def _run_claimed_evolution_job(job_id: str) -> None:
    from app.model import FirmwareEvolutionJob, get_db_session
    from app.services.worker import get_worker_id

    owner_id = get_worker_id()
    db = get_db_session()
    try:
        job = db.query(FirmwareEvolutionJob).filter(FirmwareEvolutionJob.id == job_id).first()
        run_token = job.run_token if job is not None else None
    finally:
        db.close()
    if not run_token:
        return
    run_claimed_evolution_job_process(job_id, owner_id=owner_id, run_token=run_token)


def run_claimed_evolution_job_process(job_id: str, *, owner_id: str, run_token: str) -> None:
    from app.evolution_engine import run_evolution_job
    from app.model import FirmwareEvolutionJob, FirmwareEvolutionRound, UnpackTask, generate_id, get_db_session

    db = get_db_session()
    try:
        job = db.query(FirmwareEvolutionJob).filter(FirmwareEvolutionJob.id == job_id).first()
        if job is None or job.owner_id != owner_id or job.run_token != run_token:
            return
        project_id = job.project_id
        task = db.query(UnpackTask).filter(UnpackTask.id == job.task_id).first()
        if task is None:
            raise RuntimeError("进化任务对应主任务不存在")
        task_id = task.id
        firmware_path = task.firmware_path
        output_path = task.output_path
        latest_job = (
            db.query(FirmwareEvolutionJob)
            .filter(FirmwareEvolutionJob.task_id == task.id)
            .order_by(FirmwareEvolutionJob.created_at.desc())
            .first()
        )
        active_skill_path = _resolve_evolution_dispatcher_tool_path(task) or _resolve_evolution_source_tool_path(task, latest_job) or ""
        llm_binding_snapshot = _parse_llm_binding_snapshot(task.llm_binding_snapshot)
        max_rounds = int(job.max_rounds or EVOLUTION_MAX_ROUNDS)
    finally:
        db.close()

    result: dict[str, Any] | None = None
    error_message: Optional[str] = None
    _register_evolution_pid(job_id, os.getpid())
    try:
        if _should_cancel_evolution_run(job_id, run_token):
            _mark_evolution_cancelled(job_id, reason="cancel requested before execution")
            return

        _record_task_event(
            task_id,
            project_id=project_id,
            event_type="evolution_started",
            summary="手动进化任务开始执行",
            stage_key="evolution",
            status=EVOLUTION_RUNNING,
            detail={"job_id": job_id, "owner_id": owner_id},
            owner_id=owner_id,
            created_by="task_manager",
        )

        result = run_evolution_job(
            task_id=task_id,
            evolution_job_id=job_id,
            firmware_path=firmware_path,
            unpack_output_path=output_path,
            active_skill_path=active_skill_path,
            llm_binding_snapshot=llm_binding_snapshot,
            max_rounds=max_rounds,
            progress_callback=lambda round_id, stage: _update_evolution_progress_for_owner(
                job_id,
                owner_id=owner_id,
                run_token=run_token,
                round_id=round_id,
                stage=stage,
            ),
        )
    except Exception as exc:
        logger.exception("evolution job %s failed with exception: %s", job_id, exc)
        error_message = str(exc)
    finally:
        _clear_registered_evolution_pid(job_id)

    db = get_db_session()
    try:
        current = (
            db.query(FirmwareEvolutionJob)
            .filter(
                FirmwareEvolutionJob.id == job_id,
                FirmwareEvolutionJob.owner_id == owner_id,
                FirmwareEvolutionJob.run_token == run_token,
            )
            .first()
        )
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if current is None or task is None:
            return
        if str(current.status or "") == EVOLUTION_CANCELLING:
            _mark_evolution_cancelled(job_id, reason=error_message or "cancel requested during execution")
            return

        db.query(FirmwareEvolutionRound).filter(FirmwareEvolutionRound.job_id == job_id).delete()
        for item in list((result or {}).get("rounds") or []):
            if not isinstance(item, dict):
                continue
            db.add(
                FirmwareEvolutionRound(
                    id=generate_id(),
                    job_id=job_id,
                    round=int(item.get("round") or 0),
                    status=str(item.get("status") or "failed"),
                    tool_skill_path_before=str(item.get("tool_skill_path_before") or "").strip() or None,
                    tool_skill_path_after=str(item.get("tool_skill_path_after") or "").strip() or None,
                    tool_changed=bool(item.get("tool_changed")),
                    review_result=str(item.get("review_result") or "").strip() or None,
                    summary_path=str(item.get("summary_path") or "").strip() or None,
                    reason_path=str(item.get("reason_path") or "").strip() or None,
                    created_at=now_local(),
                    completed_at=now_local(),
                )
            )

        completed_at = now_local()
        current.status = EVOLUTION_FAILED if error_message else str((result or {}).get("status") or EVOLUTION_FAILED)
        current.owner_id = None
        current.dispatch_owner_id = None
        current.dispatch_token = None
        current.dispatch_claimed_at = None
        current.dispatch_lease_expires_at = None
        current.heartbeat_at = completed_at
        current.lease_expires_at = None
        current.cancel_requested_at = None
        current.last_progress_at = completed_at
        current.runner_pid = None
        current.runner_started_at = None
        current.runner_heartbeat_at = None
        current.run_token = None
        current.cancel_grace_deadline = None
        current.cancel_force_deadline = None
        current.completed_at = completed_at
        current.current_round = int((result or {}).get("current_round") or current.current_round or 0)
        current.current_stage = "review"
        current.error_message = error_message
        current.final_skill_path = str((result or {}).get("final_skill_path") or "").strip() or None
        current.replaced_skill_path = str((result or {}).get("replaced_skill_path") or "").strip() or None
        current.review_passed = bool((result or {}).get("review_passed"))

        task.latest_evolution_job_id = job_id
        task.latest_evolution_status = current.status
        task.latest_evolution_started_at = current.started_at
        task.latest_evolution_completed_at = completed_at
        task.latest_evolution_final_skill_path = current.final_skill_path
        db.commit()
        _record_task_event_from_row(
            task,
            event_type="evolution_failed" if error_message or current.status != EVOLUTION_SUCCESS else "evolution_completed",
            summary="手动进化任务失败" if error_message or current.status != EVOLUTION_SUCCESS else "手动进化任务完成",
            stage_key="evolution",
            status=task.status,
            detail={
                "job_id": job_id,
                "evolution_status": current.status,
                "current_round": current.current_round,
                "final_skill_path": current.final_skill_path,
                "error": error_message,
            },
            owner_id=owner_id,
            created_by="task_manager",
        )
        _write_task_result_cache(task_id)
    finally:
        db.close()


def _run_task_result_cache_refresh(task_id: str) -> None:
    from app.model import UnpackTask, get_db_session

    try:
        _write_task_result_cache(task_id)
        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
            if task is not None:
                _record_task_event_from_row(
                    task,
                    event_type="task_result_cache_refreshed",
                    summary="任务结果缓存已刷新",
                    stage_key=task.current_stage,
                    status=task.status,
                    created_by="task_manager",
                )
        finally:
            db.close()
    except Exception as exc:
        logger.warning("failed to refresh task result cache for %s: %s", task_id, exc)
        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
            if task is not None:
                _record_task_event_from_row(
                    task,
                    event_type="task_result_cache_refresh_failed",
                    summary=f"任务结果缓存刷新失败：{exc}",
                    stage_key=task.current_stage,
                    status=task.status,
                    detail={"reason": str(exc)},
                    created_by="task_manager",
                )
        finally:
            db.close()
        raise
    finally:
        with _active_result_cache_refreshes_lock:
            _active_result_cache_refreshes.discard(task_id)


def request_task_result_cache_refresh(task_id: str) -> tuple[bool, str]:
    from app.model import UnpackTask, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            return False, "任务不存在"
        with _active_result_cache_refreshes_lock:
            if task_id in _active_result_cache_refreshes:
                return True, "结果缓存刷新已在后台执行中"
            _active_result_cache_refreshes.add(task_id)
        _record_task_event_from_row(
            task,
            event_type="task_result_cache_refresh_requested",
            summary="任务结果缓存刷新已受理",
            stage_key=task.current_stage,
            status=task.status,
            created_by="task_manager",
        )
    finally:
        db.close()

    try:
        get_executor().submit(_run_task_result_cache_refresh, task_id)
    except Exception:
        with _active_result_cache_refreshes_lock:
            _active_result_cache_refreshes.discard(task_id)
        raise
    return True, "结果缓存刷新已受理，后台正在更新"


def _run_claimed_task(task_id: str) -> None:
    from app.model import UnpackTask, get_db_session
    from app.services.worker import get_worker_id

    owner_id = get_worker_id()
    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        run_token = task.run_token if task is not None else None
    finally:
        db.close()
    if not run_token:
        return
    run_claimed_task_process(task_id, owner_id=owner_id, run_token=run_token)


def run_claimed_task_process(task_id: str, *, owner_id: str, run_token: str) -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session
    from app.unpacker_engine import run_unpack

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            return
        if task.owner_id != owner_id:
            return
        if task.run_token != run_token:
            return
        runtime_paths = resolve_task_runtime_paths(
            task_id=task.id,
            project_id=task.project_id,
            source_firmware_path=task.firmware_path,
            output_path=task.output_path,
        )
    finally:
        db.close()

    _update_task_progress_for_owner(
        task_id,
        owner_id=owner_id,
        run_token=run_token,
        stage="queued",
    )

    try:
        if _should_cancel_run(task_id, run_token):
            _mark_task_cancelled(task_id, reason="cancel requested before execution")
            return

        llm_binding_snapshot = _freeze_task_llm_binding_snapshot(task_id)
        _record_task_event(
            task_id,
            project_id=task.project_id,
            event_type="task_started",
            summary="任务开始执行",
            stage_key="queued",
            status=TaskStatus.RUNNING.value,
            detail={"owner_id": owner_id},
            owner_id=owner_id,
            created_by="task_manager",
        )

        os.makedirs(runtime_paths["output_path"], exist_ok=True)
        result = run_unpack(
            task_id=task_id,
            firmware_path=runtime_paths["input_path"],
            output_path=runtime_paths["output_path"],
            llm_binding_snapshot=llm_binding_snapshot,
            cancel_check=lambda: _should_cancel_run(task_id, run_token),
            register_cancel_hook=lambda hook: _register_cancel_hook(task_id, hook),
            progress_callback=lambda stage: _update_task_progress_for_owner(
                task_id,
                owner_id=owner_id,
                run_token=run_token,
                stage=stage,
            ),
            event_callback=lambda event_type, summary, **kwargs: _record_task_event(
                task_id,
                project_id=task.project_id,
                event_type=event_type,
                summary=summary,
                stage_key=kwargs.pop("stage_key", None),
                status=kwargs.pop("status", None),
                detail=kwargs.pop("detail", None),
                owner_id=kwargs.pop("owner_id", owner_id),
                created_by=kwargs.pop("created_by", "unpacker_engine"),
            ),
        )
        _update_task_result(task_id, result, run_token=run_token)
    except Exception as exc:
        logger.exception("task %s failed with exception: %s", task_id, exc)
        _update_task_error(task_id, str(exc), run_token=run_token)
    finally:
        _register_cancel_hook(task_id, None)


def _mark_task_cancelled(task_id: str, reason: str = "Task was cancelled") -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            return
        previous_owner_id = task.owner_id
        task.status = TaskStatus.CANCELLED.value
        task.result_status = "cancelled"
        task.result_message = reason
        task.owner_id = None
        task.lease_expires_at = None
        task.runner_pid = None
        task.runner_started_at = None
        task.runner_heartbeat_at = None
        task.run_token = None
        task.cancel_grace_deadline = None
        task.cancel_force_deadline = None
        task.completed_at = now_local()
        task.last_progress_at = now_local()
        db.commit()
        _record_task_event_from_row(
            task,
            event_type="task_cancelled",
            summary=f"任务已取消：{reason}",
            stage_key=task.current_stage,
            status=task.status,
            detail={"reason": reason},
            owner_id=previous_owner_id,
            created_by="task_manager",
        )
        record_task_error(category="cancel", status=task.status, task_origin=_task_origin(task))
        record_task_lifecycle(event="finished", status=task.status, task_origin=_task_origin(task))
        record_task_duration(
            phase="execution",
            duration_seconds=_elapsed_seconds(task.started_at, task.completed_at),
            status=task.status,
            task_origin=_task_origin(task),
        )
        record_task_duration(
            phase="total",
            duration_seconds=_elapsed_seconds(task.created_at, task.completed_at),
            status=task.status,
            task_origin=_task_origin(task),
        )
        _write_task_result_cache(task_id)
    finally:
        db.close()


def _update_task_result(task_id: str, result: dict, *, run_token: Optional[str] = None) -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        query = db.query(UnpackTask).filter(UnpackTask.id == task_id)
        if run_token:
            query = query.filter(UnpackTask.run_token == run_token)
        task = query.first()
        if task is None:
            return
        if task.status not in (TaskStatus.RUNNING.value, TaskStatus.CANCELLING.value):
            return

        result_status = str(result.get("status") or "").lower()
        if task.status == TaskStatus.CANCELLING.value or result_status == "cancelled":
            task.status = TaskStatus.CANCELLED.value
            event_type = "task_cancelled"
            summary = f"任务已取消：{result.get('message') or 'Task was cancelled'}"
        elif result_status == "success":
            task.status = TaskStatus.SUCCESS.value
            task.current_stage = "completed"
            event_type = "task_succeeded"
            summary = "任务执行成功"
        elif result_status == "max_retries_reached" and get_max_retries_reached_action() == "success":
            task.status = TaskStatus.SUCCESS.value
            task.current_stage = "completed"
            event_type = "task_succeeded"
            summary = "任务达到最大重试次数，按配置判定为通过"
        else:
            task.status = TaskStatus.FAILED.value
            task.current_stage = "failed"
            event_type = "task_failed"
            summary = f"任务失败：{result.get('message') or result_status or 'unknown'}"

        previous_owner_id = task.owner_id
        task.owner_id = None
        task.lease_expires_at = None
        task.runner_pid = None
        task.runner_started_at = None
        task.runner_heartbeat_at = None
        task.run_token = None
        task.cancel_grace_deadline = None
        task.cancel_force_deadline = None
        task.result_status = result.get("status")
        task.result_message = result.get("message")
        task.rounds = result.get("rounds")
        task.matched_skill = result.get("matched_skill")
        task.matched_skill_version = result.get("matched_skill_version")
        task.matched_skill_score = result.get("matched_skill_score")
        task.fallback_to_llm = bool(result.get("fallback_to_llm"))
        task.generated_skill_path = result.get("generated_skill_path")
        task.generated_skill_status = result.get("generated_skill_status")
        task.promotion_success_count = result.get("promotion_success_count")
        task.skill_generation_status = SKILL_GENERATION_NOT_APPLICABLE
        task.skill_generation_error = None
        task.skill_generation_job_id = None
        task.skill_generation_started_at = None
        task.skill_generation_completed_at = None
        task.completed_at = now_local()
        task.last_progress_at = now_local()
        db.commit()
        _record_task_event_from_row(
            task,
            event_type=event_type,
            summary=summary,
            stage_key=task.current_stage,
            status=task.status,
            detail={
                "result_status": result.get("status"),
                "rounds": result.get("rounds"),
                "matched_skill": result.get("matched_skill"),
                "fallback_to_llm": bool(result.get("fallback_to_llm")),
            },
            owner_id=previous_owner_id,
            created_by="task_manager",
        )
        if task.status == TaskStatus.CANCELLED.value:
            record_task_error(category="cancel", status=task.status, task_origin=_task_origin(task))
        elif task.status == TaskStatus.FAILED.value:
            record_task_error(category="downstream_error", status=task.status, task_origin=_task_origin(task))
        record_task_lifecycle(event="finished", status=task.status, task_origin=_task_origin(task))
        record_task_duration(
            phase="execution",
            duration_seconds=_elapsed_seconds(task.started_at, task.completed_at),
            status=task.status,
            task_origin=_task_origin(task),
        )
        record_task_duration(
            phase="total",
            duration_seconds=_elapsed_seconds(task.created_at, task.completed_at),
            status=task.status,
            task_origin=_task_origin(task),
        )
        _write_task_result_cache(task_id)
    finally:
        db.close()


def _update_task_error(task_id: str, error: str, *, run_token: Optional[str] = None) -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        query = db.query(UnpackTask).filter(UnpackTask.id == task_id)
        if run_token:
            query = query.filter(UnpackTask.run_token == run_token)
        task = query.first()
        if task is None:
            return
        if task.status not in (TaskStatus.RUNNING.value, TaskStatus.CANCELLING.value):
            return
        task.status = TaskStatus.CANCELLED.value if task.status == TaskStatus.CANCELLING.value else TaskStatus.FAILED.value
        previous_owner_id = task.owner_id
        task.owner_id = None
        task.lease_expires_at = None
        task.runner_pid = None
        task.runner_started_at = None
        task.runner_heartbeat_at = None
        task.run_token = None
        task.cancel_grace_deadline = None
        task.cancel_force_deadline = None
        task.result_status = "cancelled" if task.status == TaskStatus.CANCELLED.value else "failed"
        task.result_message = error if task.status == TaskStatus.CANCELLED.value else task.result_message
        task.error_message = error
        task.completed_at = now_local()
        task.last_progress_at = now_local()
        db.commit()
        _record_task_event_from_row(
            task,
            event_type="task_cancelled" if task.status == TaskStatus.CANCELLED.value else "task_failed",
            summary=f"{'任务已取消' if task.status == TaskStatus.CANCELLED.value else '任务失败'}：{error}",
            stage_key=task.current_stage,
            status=task.status,
            detail={"reason": error},
            owner_id=previous_owner_id,
            created_by="task_manager",
        )
        record_task_error(
            category="cancel" if task.status == TaskStatus.CANCELLED.value else "downstream_error",
            status=task.status,
            task_origin=_task_origin(task),
        )
        record_task_lifecycle(event="finished", status=task.status, task_origin=_task_origin(task))
        record_task_duration(
            phase="execution",
            duration_seconds=_elapsed_seconds(task.started_at, task.completed_at),
            status=task.status,
            task_origin=_task_origin(task),
        )
        record_task_duration(
            phase="total",
            duration_seconds=_elapsed_seconds(task.created_at, task.completed_at),
            status=task.status,
            task_origin=_task_origin(task),
        )
        _write_task_result_cache(task_id)
    finally:
        db.close()


def _dispatch_loop() -> None:
    while not _dispatcher_stop.wait(timeout=_dispatch_interval_seconds()):
        try:
            _dispatcher_start_assigned_task()
            processed_evolution_jobs = process_evolution_jobs(max(1, _claim_batch_size()))
            if processed_evolution_jobs:
                logger.info(
                    "processed pending evolution jobs: count=%s owner_active=%s runtime_max=%s",
                    processed_evolution_jobs,
                    get_local_active_task_count(),
                    _runtime_max_concurrent_for_logs(),
                )
        except Exception as exc:
            logger.warning("task dispatch warning: %s", exc)


def _scheduler_loop() -> None:
    while not _scheduler_stop.wait(timeout=_dispatch_interval_seconds()):
        try:
            recovered_retry_preparing = _recover_stuck_retry_preparing_tasks()
            if recovered_retry_preparing:
                logger.warning(
                    "recovered stuck retry_preparing tasks: count=%s timeout_seconds=%s",
                    recovered_retry_preparing,
                    RETRY_PREPARING_TIMEOUT_SECONDS,
                )
            recover_orphaned_tasks()
            _scheduler_assign_tasks()
        except Exception as exc:
            logger.warning("task scheduler warning: %s", exc)


def start() -> None:
    global _dispatcher_thread

    if _dispatcher_thread and _dispatcher_thread.is_alive():
        return

    get_executor()
    recover_stale_owned_tasks()
    recover_orphaned_tasks()
    logger.info("task dispatcher concurrency: %s", _runtime_max_concurrent_for_logs())
    _dispatcher_stop.clear()
    _dispatcher_thread = threading.Thread(
        target=_dispatch_loop,
        name="fw-task-dispatcher",
        daemon=True,
    )
    _dispatcher_thread.start()
    logger.info("task dispatcher started")


def start_scheduler() -> None:
    global _scheduler_thread

    if _scheduler_thread and _scheduler_thread.is_alive():
        return

    get_executor()
    recover_stale_owned_tasks()
    recover_orphaned_tasks()
    _scheduler_stop.clear()
    _scheduler_thread = threading.Thread(
        target=_scheduler_loop,
        name="fw-task-scheduler",
        daemon=True,
    )
    _scheduler_thread.start()
    logger.info("task scheduler started")


def stop() -> None:
    global _dispatcher_thread

    _dispatcher_stop.set()
    if _dispatcher_thread and _dispatcher_thread.is_alive():
        _dispatcher_thread.join(timeout=5)
    _dispatcher_thread = None
    shutdown()
    logger.info("task dispatcher stopped")


def stop_scheduler() -> None:
    global _scheduler_thread

    _scheduler_stop.set()
    if _scheduler_thread and _scheduler_thread.is_alive():
        _scheduler_thread.join(timeout=5)
    _scheduler_thread = None
    logger.info("task scheduler stopped")


def shutdown() -> None:
    global _executor

    from app.model import FirmwareEvolutionJob, TaskStatus, UnpackTask, get_db_session
    from app.services.worker import get_worker_id

    owner_id = get_worker_id()
    db = get_db_session()
    try:
        tasks = (
            db.query(UnpackTask)
            .filter(
                UnpackTask.owner_id == owner_id,
                UnpackTask.status.in_([TaskStatus.CLAIMED.value, TaskStatus.RUNNING.value, TaskStatus.CANCELLING.value]),
            )
            .all()
        )
        evolution_jobs = (
            db.query(FirmwareEvolutionJob)
            .filter(
                FirmwareEvolutionJob.owner_id == owner_id,
                FirmwareEvolutionJob.status.in_([EVOLUTION_CLAIMED, EVOLUTION_RUNNING, EVOLUTION_CANCELLING]),
            )
            .all()
        )
    finally:
        db.close()
    for task in tasks:
        if task.status == TaskStatus.CLAIMED.value:
            _reset_claim(task.id)
            continue
        if _is_process_alive(task.runner_pid):
            _signal_task_runner(
                task,
                signal.SIGTERM,
                event_type="runner_shutdown_sigterm_sent",
                summary="服务停止，已向任务执行进程发送 SIGTERM",
            )
    for job in evolution_jobs:
        if str(job.status or "") == EVOLUTION_CLAIMED:
            _reset_evolution_claim(job.id)
            continue
        if _is_process_alive(job.runner_pid):
            _signal_evolution_runner(
                job,
                signal.SIGTERM,
                event_type="evolution_runner_shutdown_sigterm_sent",
                summary="服务停止，已向进化任务执行进程发送 SIGTERM",
            )

    _cleanup_completed_futures()
    if _executor is not None:
        _executor.shutdown(wait=False, cancel_futures=False)
        _executor = None
