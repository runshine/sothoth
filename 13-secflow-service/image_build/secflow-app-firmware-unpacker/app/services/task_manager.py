"""Shared-DB task scheduling for firmware unpacker service."""

from __future__ import annotations

import logging
import json
import os
import signal
import subprocess
import sys
import threading
import uuid
from math import floor
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from app.config import get_config
from app.evolution import (
    DEFAULT_EVOLUTION_OPTIMIZER,
    DEFAULT_EVOLUTION_TARGET_AGENT,
    EVOLUTION_FAILED,
    EVOLUTION_NOT_APPLICABLE,
    EVOLUTION_PENDING,
    EVOLUTION_RUNNING,
    EVOLUTION_SUCCESS,
    EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR,
    archive_success_sample,
    ensure_tuner_profile,
    evolution_archive_root,
    evolution_enabled,
    evolution_target_nodes,
    is_generic_success_result,
    max_concurrent_evolution_jobs,
    register_family_tuned_agent,
    tuned_agent_alias,
    tuned_manifest_path,
    tuned_profile_name,
)
from app.time_utils import isoformat_local, now_local
from app.unpacker_engine_config import get_max_retries_reached_action
from app.unpacker_engine_logs import TASK_RESULT_CACHE_FILENAME, atomic_write_json, scan_output_tree


logger = logging.getLogger(__name__)

_executor: Optional[ThreadPoolExecutor] = None
_executor_lock = threading.Lock()
_dispatcher_thread: Optional[threading.Thread] = None
_dispatcher_stop = threading.Event()
_futures: Dict[str, Future] = {}
_futures_lock = threading.Lock()
_active_cancel_hooks: Dict[str, object] = {}
_active_cancel_hooks_lock = threading.Lock()
_active_result_cache_refreshes: set[str] = set()
_active_result_cache_refreshes_lock = threading.Lock()
PROJECT_FILES_ROOT = Path(os.environ.get("PROJECT_FILES_ROOT", "/data/files"))
TASK_WORKSPACE_ROOT = Path("app/secflow-app-firmware-unpacker")
STAGE_LABELS = {
    "pending": "待执行",
    "retry_preparing": "重试准备中",
    "queued": "排队中",
    "preprocess": "预处理",
    "feature_extract": "特征提取",
    "skill_match": "工具匹配",
    "tool_match": "工具执行",
    "llm_unpack": "LLM 解包",
    "review": "LLM 评审",
    "cleanup": "清理收尾",
}

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
    snapshot = get_concurrency_snapshot()
    return int(snapshot["effective_max_concurrent"])


def _runtime_max_concurrent_for_logs() -> str:
    snapshot = get_concurrency_snapshot()
    source = "resource" if snapshot["resource_based"] else "fallback"
    return (
        f"mode={snapshot['mode']} "
        f"effective={snapshot['effective_max_concurrent']} "
        f"executor={snapshot['executor_capacity']} "
        f"source={source}"
    )


def _dispatch_interval_seconds() -> int:
    return max(1, int(get_config().worker.claim_interval_seconds))


def _claim_batch_size() -> int:
    return max(1, int(get_config().worker.claim_batch_size))


def _task_lease_seconds() -> int:
    return max(
        15,
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


def _evolution_job_lease_deadline(now: Optional[datetime] = None) -> datetime:
    return (now or now_local()) + timedelta(seconds=_cleanup_job_lease_seconds())


def _runner_start_grace_seconds() -> int:
    return 60


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


def _register_cancel_hook(task_id: str, hook) -> None:
    with _active_cancel_hooks_lock:
        if hook is None:
            _active_cancel_hooks.pop(task_id, None)
        else:
            _active_cancel_hooks[task_id] = hook


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
    return _active_runner_count()


def recover_stale_owned_tasks() -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session
    from app.services.worker import get_worker_id

    owner_id = get_worker_id()
    db = get_db_session()
    try:
        tasks = (
            db.query(UnpackTask)
            .filter(
                UnpackTask.owner_id == owner_id,
                UnpackTask.status.in_(
                    [TaskStatus.RUNNING.value, TaskStatus.CANCELLING.value]
                ),
            )
            .all()
        )
    finally:
        db.close()

    for task in tasks:
        if _is_process_alive(task.runner_pid):
            continue
        reason = "owner restarted without active runner process"
        if task.status == TaskStatus.CANCELLING.value:
            _mark_task_cancelled(task.id, reason=reason)
        else:
            _finalize_orphaned_task(task.id, reason=reason)


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
        task.last_progress_at = now_local()
        if stage:
            task.current_stage = stage
        db.commit()
        if stage and stage != previous_stage:
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
            TaskStatus.RUNNING.value,
            TaskStatus.CANCELLING.value,
        ):
            return
        if task.status == TaskStatus.CANCELLING.value:
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
    manifest_path.write_text(
        json.dumps(
            {
                "input_path": source_firmware_path,
                "output_path": output_path,
                "log_path": run_path,
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
    from app.model import EvolutionJob, TaskStatus, UnpackTask, WorkspaceCleanupJob, get_db_session, get_worker_id

    owner_id = get_worker_id()
    processed = 0
    while processed < max(1, limit):
        db = get_db_session()
        job = None
        now = now_local()
        try:
            job = (
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
                .first()
            )
            if job is None:
                db.close()
                break
            job.status = "running"
            job.owner_id = owner_id
            job.started_at = job.started_at or now
            job.completed_at = None
            job.error_message = None
            job.attempts = int(job.attempts or 0) + 1
            job.lease_expires_at = _cleanup_job_lease_deadline(now)
            db.commit()
            task_id = job.task_id
            project_id = job.project_id
            job_id = job.id
        finally:
            db.close()

        error_message: Optional[str] = None
        requeue_task_id: Optional[str] = None
        try:
            if job.reason == "task_retry_reset":
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
                    task.evolution_status = None
                    task.evolution_error = None
                    task.evolution_job_id = None
                    task.evolution_started_at = None
                    task.evolution_completed_at = None
                    task.evolution_target_node = None
                    task.evolution_source_run_id = None
                    task.tuned_agent_path = None
                    task.tuned_agent_status = None
                    task.tuned_agent_version = None
                    task.started_at = None
                    task.completed_at = None
                    db.query(EvolutionJob).filter(EvolutionJob.task_id == task.id).delete()
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
                job.reason,
                exc,
            )

        db = get_db_session()
        try:
            current = db.query(WorkspaceCleanupJob).filter(WorkspaceCleanupJob.id == job_id).first()
            if current is None:
                processed += 1
                continue
            current.owner_id = owner_id
            current.lease_expires_at = None
            current.completed_at = now_local()
            if error_message:
                current.status = "failed"
                current.error_message = error_message
            else:
                current.status = "success"
            db.commit()
        finally:
            db.close()
        if job.reason == "task_retry_reset":
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
                _schedule_pending_tasks()
        processed += 1
    return processed


def process_evolution_jobs(limit: int | None = None) -> int:
    from agentflow.tuned_agents import run_evolution_from_payload
    from app.model import EvolutionJob, UnpackTask, get_db_session, get_worker_id

    owner_id = get_worker_id()
    processed = 0
    effective_limit = max(1, int(limit or max_concurrent_evolution_jobs()))
    while processed < effective_limit:
        db = get_db_session()
        job = None
        now = now_local()
        try:
            job = (
                db.query(EvolutionJob)
                .filter(
                    (EvolutionJob.status == EVOLUTION_PENDING)
                    | (
                        (EvolutionJob.status == EVOLUTION_RUNNING)
                        & (
                            (EvolutionJob.lease_expires_at.is_(None))
                            | (EvolutionJob.lease_expires_at < now)
                        )
                    )
                )
                .order_by(EvolutionJob.created_at.asc())
                .first()
            )
            if job is None:
                db.close()
                break
            job.status = EVOLUTION_RUNNING
            job.owner_id = owner_id
            job.started_at = job.started_at or now
            job.completed_at = None
            job.error_message = None
            job.attempts = int(job.attempts or 0) + 1
            job.lease_expires_at = _evolution_job_lease_deadline(now)
            task = db.query(UnpackTask).filter(UnpackTask.id == job.task_id).first()
            if task is not None:
                task.evolution_status = EVOLUTION_RUNNING
                task.evolution_error = None
                task.evolution_job_id = job.id
                task.evolution_started_at = job.started_at
                task.evolution_completed_at = None
                task.evolution_target_node = job.target_node
                task.evolution_source_run_id = job.source_run_id
            db.commit()
            if task is not None:
                _record_task_event_from_row(
                    task,
                    event_type="evolution_started",
                    summary="AgentFlow tuned evolution 开始执行",
                    stage_key="evolution",
                    status=task.status,
                    detail={"job_id": job.id, "target_node": job.target_node},
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
        evolution_result: Optional[dict[str, Any]] = None
        tuned_manifest: Optional[dict[str, Any]] = None
        try:
            db = get_db_session()
            try:
                task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
                if task is None:
                    raise RuntimeError("任务不存在，无法执行 evolution")
                if not task.evolution_source_run_id:
                    raise RuntimeError("缺少 evolution source run id")
                family_id = str(task.evolution_target_node or job.target_node or "").strip() or EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR
                source_family_id = str(job.source_family_id or "").strip() or "generic"
                workspace = Path(task.output_path).expanduser().resolve().parent
                profile = tuned_profile_name(job.target_node or EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR, source_family_id)
                alias = tuned_agent_alias(job.target_node or EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR, source_family_id)
                ensure_tuner_profile(workspace, profile=profile, alias=alias)
                payload = {
                    "profile": profile,
                    "target": DEFAULT_EVOLUTION_TARGET_AGENT,
                    "optimizer": DEFAULT_EVOLUTION_OPTIMIZER,
                    "source_nodes": [job.target_node or EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR],
                    "run_id": task.evolution_source_run_id,
                    "trace_paths": {
                        job.target_node or EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR: str(
                            Path(job.artifact_path or "") / "traces" / f"{job.target_node or EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR}.trace.jsonl"
                        ),
                    },
                    "workspace_dir": str(workspace),
                }
                evolution_result = run_evolution_from_payload(payload)
                version = str(evolution_result.get("version") or "").strip()
                manifest_path = tuned_manifest_path(
                    evolution_archive_root(),
                    job.target_node or EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR,
                    source_family_id,
                    version,
                )
                manifest_path.parent.mkdir(parents=True, exist_ok=True)
                tuned_manifest = {
                    "target_node": job.target_node or EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR,
                    "family_id": source_family_id,
                    "source_run_id": task.evolution_source_run_id,
                    "task_id": task.id,
                    "version": version,
                    "status": "active",
                    "created_at": now_local().isoformat(),
                    "artifact_path": evolution_result.get("repo_path"),
                    "agent_name": evolution_result.get("agent_name") or alias,
                    "executable": evolution_result.get("executable"),
                }
                manifest_path.write_text(json.dumps(tuned_manifest, ensure_ascii=False, indent=2), encoding="utf-8")
                register_family_tuned_agent(
                    root=evolution_archive_root(),
                    target_node=job.target_node or EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR,
                    family_id=source_family_id,
                    agent_name=str(tuned_manifest.get("agent_name") or alias),
                    version=version,
                    task_id=task.id,
                    run_id=task.evolution_source_run_id,
                )
            finally:
                db.close()
        except Exception as exc:
            error_message = str(exc)
            logger.warning("failed to process evolution job %s task %s: %s", job_id, task_id, exc)

        db = get_db_session()
        try:
            current = db.query(EvolutionJob).filter(EvolutionJob.id == job_id).first()
            task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
            completed_at = now_local()
            if current is not None:
                current.owner_id = owner_id
                current.lease_expires_at = None
                current.completed_at = completed_at
                current.status = EVOLUTION_FAILED if error_message else EVOLUTION_SUCCESS
                current.error_message = error_message
                current.result_json = json.dumps(evolution_result or tuned_manifest or {}, ensure_ascii=False)
            if task is not None:
                task.evolution_status = EVOLUTION_FAILED if error_message else EVOLUTION_SUCCESS
                task.evolution_error = error_message
                task.evolution_job_id = job_id
                task.evolution_completed_at = completed_at
                if tuned_manifest:
                    task.tuned_agent_path = str(tuned_manifest.get("artifact_path") or "")
                    task.tuned_agent_status = str(tuned_manifest.get("status") or "")
                    task.tuned_agent_version = str(tuned_manifest.get("version") or "")
            db.commit()
            if task is not None:
                _record_task_event_from_row(
                    task,
                    event_type="evolution_failed" if error_message else "evolution_completed",
                    summary="AgentFlow tuned evolution 失败" if error_message else "AgentFlow tuned evolution 已完成",
                    stage_key="evolution",
                    status=task.status,
                    detail={
                        "evolution_status": task.evolution_status,
                        "tuned_agent_path": task.tuned_agent_path,
                        "tuned_agent_version": task.tuned_agent_version,
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


def process_skill_generation_jobs(limit: int = 1) -> int:
    return process_evolution_jobs(limit=limit)


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
        effective_snapshot = llm_binding_snapshot or _build_llm_binding_snapshot(db)
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
        if task.status == TaskStatus.PENDING.value:
            task.status = TaskStatus.CANCELLED.value
            task.cancel_requested_at = now_local()
            task.result_status = "cancelled"
            task.result_message = "Task was cancelled before execution"
            task.completed_at = now_local()
            task.cancel_grace_deadline = None
            task.cancel_force_deadline = None
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
            return False, "仅支持取消排队中或运行中的任务"
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
        task.current_stage = "retry_preparing"
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
        task.result_message = "正在后台重置任务目录并准备重试"
        task.error_message = None
        db.commit()
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
    from app.model import TaskStatus, UnpackTask, WorkerInstance, get_db_session
    from app.services.worker import get_worker_id

    now = now_local()
    active_owner_ids: set[str] = set()
    heartbeat_cutoff = now - timedelta(seconds=max(15, int(get_config().worker.dead_threshold_seconds)))
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
                    [TaskStatus.RUNNING.value, TaskStatus.CANCELLING.value]
                )
            )
            .all()
        )
    finally:
        db.close()

    current_owner = get_worker_id()

    for task in tasks:
        owner_id = str(task.owner_id or "").strip()
        cancel_requested_at = task.cancel_requested_at
        owner_missing = not owner_id or owner_id not in active_owner_ids
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
        if task.status == TaskStatus.CANCELLING.value and local_owned:
            if runner_not_started:
                _mark_task_cancelled(task.id, reason="Task runner was not started")
                continue
            if not runner_alive:
                _mark_task_cancelled(task.id, reason="Task runner exited while cancelling")
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
            if (
                (task.cancel_force_deadline and task.cancel_force_deadline <= now)
                or cancel_timed_out
                or progress_stale
            ):
                _signal_task_runner(
                    task,
                    signal.SIGKILL,
                    event_type="cancel_sigkill_sent",
                    summary="已向任务执行进程发送 SIGKILL",
                )
                _mark_task_cancelled(task.id, reason="Task cancelled after force kill deadline")
            continue
        if task.status == TaskStatus.CANCELLING.value:
            if owner_missing:
                _finalize_orphaned_task(task.id, reason="Task owner pod lost", owner_lost=True)
            elif cancel_timed_out or progress_stale:
                _mark_task_cancelled(task.id, reason="Task cancelled after owner lost or timeout")
            continue
        if task.status == TaskStatus.RUNNING.value:
            if owner_missing:
                _finalize_orphaned_task(task.id, reason="Task owner pod lost", owner_lost=True)
            elif local_owned and runner_not_started:
                _finalize_orphaned_task(task.id, reason="Task runner was not started")
            elif local_owned and not runner_alive:
                _finalize_orphaned_task(task.id, reason="Task runner process exited unexpectedly")
            elif local_owned and runner_alive:
                _update_task_progress_for_owner(
                    task.id,
                    owner_id=owner_id,
                    run_token=task.run_token,
                    stage=None,
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
                    UnpackTask.status: TaskStatus.RUNNING.value,
                    UnpackTask.owner_id: owner_id,
                    UnpackTask.current_stage: "queued",
                    UnpackTask.lease_expires_at: None,
                    UnpackTask.cancel_requested_at: None,
                    UnpackTask.last_progress_at: now,
                    UnpackTask.runner_pid: None,
                    UnpackTask.runner_started_at: None,
                    UnpackTask.runner_heartbeat_at: None,
                    UnpackTask.run_token: run_token,
                    UnpackTask.cancel_grace_deadline: None,
                    UnpackTask.cancel_force_deadline: None,
                    UnpackTask.started_at: now,
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
                _record_task_event_from_row(
                    task,
                    event_type="task_claimed",
                    summary="任务已被当前 owner 认领",
                    stage_key="queued",
                    status=task.status,
                    detail={"owner_id": owner_id, "run_token_present": True},
                    owner_id=owner_id,
                    created_by="task_manager",
                )
            return True
        db.rollback()
        return False
    finally:
        db.close()


def _reset_claim(task_id: str) -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        (
            db.query(UnpackTask)
            .filter(
                UnpackTask.id == task_id,
                UnpackTask.status == TaskStatus.RUNNING.value,
            )
            .update(
                {
                    UnpackTask.status: TaskStatus.PENDING.value,
                    UnpackTask.owner_id: None,
                    UnpackTask.current_stage: "pending",
                    UnpackTask.lease_expires_at: None,
                    UnpackTask.cancel_requested_at: None,
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


def _launch_task_runner(task_id: str) -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session
    from app.services.worker import get_worker_id, refresh_worker_active_tasks

    owner_id = get_worker_id()
    db = get_db_session()
    try:
        task = (
            db.query(UnpackTask)
            .filter(
                UnpackTask.id == task_id,
                UnpackTask.owner_id == owner_id,
                UnpackTask.status == TaskStatus.RUNNING.value,
            )
            .first()
        )
        if task is None or not task.run_token:
            raise RuntimeError(f"任务未被当前 owner 正确认领: {task_id}")
        run_token = task.run_token
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
                UnpackTask.owner_id == owner_id,
                UnpackTask.run_token == run_token,
                UnpackTask.status == TaskStatus.RUNNING.value,
            )
            .update(
                {
                    UnpackTask.runner_pid: proc.pid,
                    UnpackTask.runner_started_at: now,
                    UnpackTask.runner_heartbeat_at: now,
                    UnpackTask.lease_expires_at: None,
                    UnpackTask.last_progress_at: now,
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
            _record_task_event_from_row(
                task,
                event_type="runner_started",
                summary="任务独立执行进程已启动",
                stage_key=task.current_stage,
                status=task.status,
                detail={"runner_pid": proc.pid, "run_token_present": True},
                owner_id=owner_id,
                created_by="task_manager",
            )
    finally:
        db.close()
    refresh_worker_active_tasks()


def _schedule_pending_tasks() -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session

    available_slots = _runtime_max_concurrent() - _active_runner_count()
    if available_slots <= 0:
        return

    fetch_limit = max(available_slots, _claim_batch_size())
    db = get_db_session()
    try:
        candidate_ids = [
            row.id
            for row in (
                db.query(UnpackTask.id)
                .filter(UnpackTask.status == TaskStatus.PENDING.value)
                .order_by(UnpackTask.created_at.asc())
                .limit(fetch_limit)
                .all()
            )
        ]
    finally:
        db.close()

    for task_id in candidate_ids:
        if _runtime_max_concurrent() - _active_runner_count() <= 0:
            break
        if not _claim_task(task_id):
            continue
        try:
            _launch_task_runner(task_id)
        except Exception:
            _reset_claim(task_id)
            raise


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


def _derive_run_root_from_output_path(output_path: str) -> Path:
    output_root = Path(str(output_path or "").strip())
    if not str(output_root):
        return Path("/tmp")
    return output_root.parent / "run" if output_root.name == "output" else output_root.parent / "run"


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


def _write_task_result_cache(task_id: str) -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            return

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
                "evolution_status": str(task.evolution_status or "").strip() or None,
                "evolution_error": str(task.evolution_error or "").strip() or None,
                "evolution_job_id": str(task.evolution_job_id or "").strip() or None,
                "evolution_started_at": isoformat_local(task.evolution_started_at),
                "evolution_completed_at": isoformat_local(task.evolution_completed_at),
                "evolution_target_node": str(task.evolution_target_node or "").strip() or None,
                "evolution_source_run_id": str(task.evolution_source_run_id or "").strip() or None,
                "tuned_agent_path": str(task.tuned_agent_path or "").strip() or None,
                "tuned_agent_status": str(task.tuned_agent_status or "").strip() or None,
                "tuned_agent_version": str(task.tuned_agent_version or "").strip() or None,
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


def _enqueue_evolution_job(
    db: Any,
    task: Any,
    *,
    created_by: str = "task_manager",
    source_run_id: str,
    source_family_id: str,
    target_node: str = EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR,
    artifact_path: str | None = None,
) -> Optional[str]:
    from app.model import EvolutionJob, generate_id

    if task is None:
        return None
    if not evolution_enabled():
        task.evolution_status = EVOLUTION_NOT_APPLICABLE
        return None
    target_node = str(target_node or "").strip() or EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR
    if target_node not in evolution_target_nodes():
        task.evolution_status = EVOLUTION_NOT_APPLICABLE
        return None
    existing = (
        db.query(EvolutionJob)
        .filter(
            EvolutionJob.task_id == task.id,
            EvolutionJob.status.in_([EVOLUTION_PENDING, EVOLUTION_RUNNING]),
        )
        .first()
    )
    if existing is not None:
        task.evolution_status = existing.status
        task.evolution_job_id = existing.id
        task.evolution_error = None
        task.evolution_started_at = existing.started_at
        task.evolution_completed_at = existing.completed_at
        task.evolution_target_node = existing.target_node
        task.evolution_source_run_id = existing.source_run_id
        return existing.id

    job_id = generate_id()
    db.add(
        EvolutionJob(
            id=job_id,
            task_id=task.id,
            project_id=task.project_id,
            status=EVOLUTION_PENDING,
            created_by=created_by,
            target_node=target_node,
            source_run_id=source_run_id,
            source_family_id=source_family_id,
            source_stage=target_node,
            artifact_path=artifact_path,
        )
    )
    task.evolution_status = EVOLUTION_PENDING
    task.evolution_error = None
    task.evolution_job_id = job_id
    task.evolution_started_at = None
    task.evolution_completed_at = None
    task.evolution_target_node = target_node
    task.evolution_source_run_id = source_run_id
    return job_id


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
    from app.cli import run_unpack_agentflow as run_unpack

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
        _write_task_result_cache(task_id)
    finally:
        db.close()


def _update_task_result(task_id: str, result: dict, *, run_token: Optional[str] = None) -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    queued_evolution_job_id: Optional[str] = None
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
            event_type = "task_succeeded"
            summary = "任务执行成功"
        elif result_status == "max_retries_reached" and get_max_retries_reached_action() == "success":
            task.status = TaskStatus.SUCCESS.value
            event_type = "task_succeeded"
            summary = "任务达到最大重试次数，按配置判定为通过"
        else:
            task.status = TaskStatus.FAILED.value
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
        task.skill_generation_error = None
        task.evolution_target_node = result.get("evolution_target_node")
        task.evolution_source_run_id = result.get("evolution_source_run_id") or result.get("agentflow_run_id")
        if task.status == TaskStatus.SUCCESS.value and is_generic_success_result(result):
            sample_path = result.get("evolution_sample_path")
            if not sample_path:
                run_root = _derive_run_root_from_output_path(task.output_path)
                family_id = str(result.get("family_id") or "").strip() or "generic"
                run_id = str(result.get("agentflow_run_id") or result.get("run_id") or "").strip() or task.id
                tokens = {}
                tokens_path = run_root / "tokens_summary.json"
                if tokens_path.exists():
                    try:
                        tokens = json.loads(tokens_path.read_text(encoding="utf-8"))
                    except Exception:
                        tokens = {}
                archived = archive_success_sample(
                    task_id=task.id,
                    project_id=task.project_id,
                    family_id=family_id,
                    run_id=run_id,
                    run_dir=run_root,
                    final_result=result,
                    tokens_summary=tokens,
                )
                sample_path = str(archived.sample_dir)
            queued_evolution_job_id = _enqueue_evolution_job(
                db,
                task,
                source_run_id=str(result.get("agentflow_run_id") or result.get("run_id") or ""),
                source_family_id=str(result.get("family_id") or "generic"),
                target_node=str(result.get("evolution_target_node") or EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR),
                artifact_path=str(sample_path),
            )
        else:
            task.evolution_status = EVOLUTION_NOT_APPLICABLE
            task.evolution_error = None
            task.evolution_job_id = None
            task.evolution_started_at = None
            task.evolution_completed_at = None
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
        if queued_evolution_job_id:
            _record_task_event_from_row(
                task,
                event_type="evolution_queued",
                summary="AgentFlow tuned evolution 已入队",
                stage_key="evolution",
                status=task.status,
                detail={"job_id": queued_evolution_job_id, "target_node": task.evolution_target_node},
                created_by="task_manager",
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
        _write_task_result_cache(task_id)
    finally:
        db.close()


def _dispatch_loop() -> None:
    while not _dispatcher_stop.wait(timeout=_dispatch_interval_seconds()):
        try:
            recover_orphaned_tasks()
            _schedule_pending_tasks()
        except Exception as exc:
            logger.warning("task dispatch warning: %s", exc)


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


def stop() -> None:
    global _dispatcher_thread

    _dispatcher_stop.set()
    if _dispatcher_thread and _dispatcher_thread.is_alive():
        _dispatcher_thread.join(timeout=5)
    _dispatcher_thread = None
    shutdown()
    logger.info("task dispatcher stopped")


def shutdown() -> None:
    global _executor

    from app.model import TaskStatus, UnpackTask, get_db_session
    from app.services.worker import get_worker_id

    owner_id = get_worker_id()
    db = get_db_session()
    try:
        tasks = (
            db.query(UnpackTask)
            .filter(
                UnpackTask.owner_id == owner_id,
                UnpackTask.status.in_([TaskStatus.RUNNING.value, TaskStatus.CANCELLING.value]),
            )
            .all()
        )
    finally:
        db.close()
    for task in tasks:
        if _is_process_alive(task.runner_pid):
            _signal_task_runner(
                task,
                signal.SIGTERM,
                event_type="runner_shutdown_sigterm_sent",
                summary="服务停止，已向任务执行进程发送 SIGTERM",
            )

    _cleanup_completed_futures()
    if _executor is not None:
        _executor.shutdown(wait=False, cancel_futures=False)
        _executor = None
