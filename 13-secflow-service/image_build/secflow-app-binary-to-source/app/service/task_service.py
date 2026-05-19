"""B2S task orchestration and pi-re-agent status mapping."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timedelta, timezone
import re
from pathlib import Path
from statistics import mean
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import ConflictError, NotFoundError, UpstreamError, ValidationError
from app.model import B2STask, B2STaskItem
from app.observability import get_observability
from app.schemas import (
    AdvancedBatch,
    AdvancedFile,
    AdvancedRun,
    AgentRuntimeEntry,
    AgentRuntimeSummary,
    B2SArtifact,
    B2SArtifactContentResponse,
    B2SOverallProgress,
    RelationshipEdge,
    RelationshipNode,
    ReviewAnalyticsAttempt,
    ReviewAnalyticsDimension,
    ReviewAnalyticsFunction,
    ReviewAnalyticsFunctionAttempt,
    ReviewAnalyticsIssue,
    ReviewAnalyticsMeta,
    ReviewAnalyticsRadar,
    ReviewAnalyticsResponse,
    ReviewAnalyticsSummary,
    ReviewAnalyticsTrendInsight,
    ReviewAnalyticsTrendPoint,
    ReviewAnalyticsTrendSeries,
    SessionFileResponse,
    SessionIndexNode,
    SessionIndexResponse,
    TaskConfigInputItem,
    TaskConfigSnapshot,
    TaskCreate,
    TaskDetailResponse,
    TaskItemAdvancedResponse,
    TaskItemArtifactsResponse,
    TaskItemResponse,
    TaskObservabilityItem,
    TaskObservabilitySummary,
    TaskRelationshipResponse,
    TaskResponse,
    TaskResultItemSummary,
    TaskResultSummary,
)
from app.service.cache_service import get_cache_service
from app.service.config_service import get_config_service, normalize_budget_exhausted_action
from app.service.llm_provider import materialize_llm_provider
from app.service.pi_cluster import get_pi_cluster_monitor
from app.service.pi_re_agent import get_pi_client
from app.service.security import app_task_item_root, app_task_root, ensure_path_in_project, project_root, safe_input_dir, safe_output_dir, validate_task_id
from app.time_utils import isoformat_local, now_local

TERMINAL = {"success", "failed", "cancelled"}
PI_STATUS_MAP = {
    "queued": "queued",
    "running": "running",
    "cancelling": "running",
    "completed": "success",
    "failed": "failed",
    "cancelled": "cancelled",
    "max_rounds_exceeded": "failed",
    "max_retries_reached": "failed",
    "timeout_max_retries_exceeded": "failed",
}

PI_PHASE_MAP = {
    "analyzing": "ida",
    "batching": "batching",
    "header_synthesis": "header",
    "processing": "body",
    "merging": "merge",
}

PHASE_LABELS = {
    "queued": "排队中",
    "ida": "IDA 分析",
    "batching": "函数分批",
    "header": "头文件恢复",
    "body": "函数体恢复",
    "merge": "结果合并",
    "completed": "已完成",
    "failed": "失败",
    "cancelled": "已取消",
}

_BUDGET_EXHAUSTED_MARKERS = (
    "max_rounds_exceeded",
    "max_retries_reached",
    "timeout_max_retries_exceeded",
    "agent_timeout_max_retries",
    "timeout max retries",
    "budget exhausted",
    "review budget exhausted",
    "max turns reached",
)
FUNCTION_STATS_METADATA_KEY = "function_stats"
FUNCTION_STATS_FIELDS = ("total_functions", "completed_functions", "failed_functions", "uncompleted_functions")


def _budget_exhausted_action_for_project(db: Session, project_id: str) -> str:
    cfg = get_config_service().get_config(db, project_id)
    return normalize_budget_exhausted_action(cfg.get("budget_exhausted_action"))


def _budget_exhausted_action_for_item(db: Session, item: B2STaskItem) -> str:
    metadata = item.extra_metadata or {}
    frozen = metadata.get("budget_exhausted_action")
    if frozen:
        return normalize_budget_exhausted_action(str(frozen))
    return _budget_exhausted_action_for_project(db, item.project_id)


def _normalize_llm_provider_key(value: object) -> str | None:
    key = str(value or "").strip()
    return key or None


def _normalize_reuse_cache(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "off", "no"}


def _provider_model_name(provider: dict | None) -> str | None:
    if not provider:
        return None
    provider_key = _normalize_llm_provider_key(provider.get("provider_key"))
    model = _normalize_llm_provider_key(provider.get("model"))
    if not provider_key or not model:
        return None
    if model.startswith(f"{provider_key}/"):
        return model
    return f"{provider_key}/{model}"


def _project_default_llm_provider_key(db: Session, project_id: str) -> str | None:
    cfg = get_config_service().get_config(db, project_id)
    return _normalize_llm_provider_key(cfg.get("llm_provider_key"))


def _frozen_item_llm_provider_key(items: list[B2STaskItem]) -> str | None:
    for item in items:
        key = _normalize_llm_provider_key((item.extra_metadata or {}).get("llm_provider_key"))
        if key:
            return key
    return None


def _restart_llm_provider_key(db: Session, task: B2STask, items: list[B2STaskItem]) -> str | None:
    project_key = _project_default_llm_provider_key(db, task.project_id)
    frozen_key = _frozen_item_llm_provider_key(items)
    if task.status in TERMINAL:
        return project_key or frozen_key
    return frozen_key or project_key


def _is_budget_exhausted_failure(job: dict | None, error_reason: str | None = None) -> bool:
    if isinstance(job, dict):
        raw_status = str(job.get("status") or "").strip().lower()
        if raw_status in {"max_rounds_exceeded", "max_retries_reached", "timeout_max_retries_exceeded"}:
            return True
        payloads = [
            job.get("error"),
            job.get("message"),
            job.get("detail"),
            job.get("status_reason"),
            job.get("failure_type"),
            json.dumps(job.get("progress") or {}, ensure_ascii=False),
            json.dumps(job.get("output") or {}, ensure_ascii=False),
        ]
    else:
        payloads = []
    payloads.append(error_reason or "")
    normalized = "\n".join(str(part or "") for part in payloads).lower()
    return any(marker in normalized for marker in _BUDGET_EXHAUSTED_MARKERS)


def _task_origin_payload(task: B2STask) -> dict:
    task_origin_type = str(task.task_origin_type or "").strip() or "manual"
    parent_task_type = str(task.parent_task_type or "").strip() or None
    origin_label = (
        "二进制安全-源码扫描"
        if task_origin_type == "binary_security" and parent_task_type == "source"
        else "二进制安全-二进制类扫描"
        if task_origin_type == "binary_security"
        else "手动任务"
    )
    return {
        "task_origin_type": task_origin_type,
        "parent_project_id": task.parent_project_id,
        "parent_task_id": task.parent_task_id,
        "parent_task_type": parent_task_type,
        "parent_stage_name": task.parent_stage_name,
        "parent_stage_item_id": task.parent_stage_item_id,
        "parent_stage_item_key": task.parent_stage_item_key,
        "origin_label": origin_label,
        "parent_task_display": task.parent_task_id,
    }


def generate_task_id(db: Session, project_id: str) -> str:
    for _ in range(10):
        task_id = uuid4().hex[:16]
        exists = db.query(B2STask.id).filter(B2STask.project_id == project_id, B2STask.id == task_id).first()
        if not exists:
            return task_id
    raise ConflictError("无法生成唯一B2S任务ID，请重试")


def configured_pi_workers() -> list[str]:
    cfg = get_config().pi_re_agent
    if cfg.worker_urls:
        return [url.rstrip("/") for url in cfg.worker_urls]
    return [cfg.base_url.rstrip("/")]


async def choose_pi_worker(db: Session, task_id: str, sequence_no: int) -> str:
    """Pick a pi-re-agent worker with simple worker affinity.

    The primary signal is the worker's own queued/running job count, which also
    covers jobs created before this B2S release.  The DB count is a cheap local
    supplement, and the stable hash is only a deterministic tie breaker.
    """
    snapshot = await get_pi_cluster_monitor().snapshot()
    workers = [worker.url.rstrip("/") for worker in snapshot.workers if worker.healthy]
    workers = workers or configured_pi_workers()
    if len(workers) == 1:
        return workers[0]
    counts = {worker: 0 for worker in workers}

    if snapshot.workers:
        for worker in snapshot.workers:
            worker_url = worker.url.rstrip("/")
            if worker_url in counts:
                counts[worker_url] += worker.running_jobs + worker.queued_jobs
                if not worker.healthy:
                    counts[worker_url] += 1_000_000
    else:
        for worker in workers:
            try:
                jobs = await get_pi_client(worker).list_jobs()
                counts[worker] += sum(1 for job in jobs if job.get("status") in {"queued", "running"})
            except Exception:
                # Avoid placing new work on an unreachable worker.
                counts[worker] += 1_000_000

    active_items = db.query(B2STaskItem).filter(B2STaskItem.status.in_(["queued", "running"])).all()
    for active_item in active_items:
        worker_url = str((active_item.extra_metadata or {}).get("pi_worker_url") or "").rstrip("/")
        if worker_url in counts:
            counts[worker_url] += 1
    salt = int(hashlib.sha256(f"{task_id}:{sequence_no}".encode("utf-8")).hexdigest(), 16)
    return min(enumerate(workers), key=lambda item: (counts[item[1]], (item[0] - salt) % len(workers)))[1]


def item_pi_worker_url(item: B2STaskItem) -> str | None:
    worker_url = str((item.extra_metadata or {}).get("pi_worker_url") or "").strip()
    return worker_url.rstrip("/") or None


def _normalized_target(path: str | None) -> str:
    try:
        return str(Path(path or "").resolve())
    except Exception:
        return str(path or "")


def _pi_idempotency_key(task_id: str, item: B2STaskItem) -> str:
    return f"b2s:{task_id}:{item.id}:{_normalized_target(item.elf_path)}"


def _new_pi_idempotency_key(task_id: str, item: B2STaskItem) -> str:
    return f"{_pi_idempotency_key(task_id, item)}:attempt:{uuid4().hex[:8]}"


def _item_pi_idempotency_key(item: B2STaskItem) -> str:
    metadata = item.extra_metadata or {}
    key = str(metadata.get("pi_idempotency_key") or "").strip()
    return key or _pi_idempotency_key(item.task_id, item)


def _parse_pi_timestamp(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        raw = str(value).strip()
        if not raw:
            return None
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        return parsed
    return parsed.astimezone(timezone(timedelta(hours=8))).replace(tzinfo=None)


def _pi_job_age_seconds(job: dict, *fields: str) -> float | None:
    candidates = [_parse_pi_timestamp(job.get(field)) for field in fields]
    candidates = [candidate for candidate in candidates if candidate is not None]
    if not candidates:
        return None
    return max(0.0, (now_local() - max(candidates)).total_seconds())


def _record_pi_metadata(item: B2STaskItem, **updates: object) -> None:
    metadata = item.extra_metadata or {}
    metadata.update({key: value for key, value in updates.items() if value is not None})
    item.extra_metadata = metadata


def _record_pi_runtime_metrics(item: B2STaskItem, job: dict) -> bool:
    progress = job.get("progress") if isinstance(job, dict) else None
    metrics = progress.get("runtime_metrics") if isinstance(progress, dict) else None
    metadata = dict(item.extra_metadata or {})
    if not isinstance(metrics, dict):
        reason = _pi_runtime_metric_missing_reason(item, job)
        if metadata.get("pi_runtime_metric_missing_reason") == reason:
            return False
        metadata["pi_runtime_metric_missing_reason"] = reason
        metadata["pi_runtime_metric_last_checked_at"] = isoformat_local(now_local())
        item.extra_metadata = metadata
        return False
    if (
        metadata.get("pi_runtime_metrics") == metrics
        and metadata.get("pi_runtime_metric_missing_reason") is None
    ):
        return False
    metadata["pi_runtime_metrics"] = metrics
    metadata.pop("pi_runtime_metric_missing_reason", None)
    metadata["pi_runtime_metric_last_seen_at"] = isoformat_local(now_local())
    item.extra_metadata = metadata
    return True


def _pi_runtime_metric_missing_reason(item: B2STaskItem, job: dict | None = None) -> str:
    status = str((job or {}).get("status") or item.status or "").strip().lower()
    pi_job_id = str(item.pi_job_id or "").strip()
    if not pi_job_id:
        return "pi_job_missing"
    if status in {"queued", "pending"}:
        return "queued_or_pending"
    if status in {"running", "cancelling"} or str(item.status or "").lower() == "running":
        return "running_not_reported"
    if item.failure_type == "upstream_lost":
        return "upstream_missing"
    return "legacy_or_unavailable"


def _merge_item_progress(item: B2STaskItem, **updates: object) -> bool:
    progress = item.progress or {}
    changed = False
    for key, value in updates.items():
        if value is None:
            continue
        if progress.get(key) != value:
            progress[key] = value
            changed = True
    if changed:
        item.progress = progress
    return changed


def _pi_job_payload(
    item: B2STaskItem,
    *,
    pi_cfg,
    job_model: str | None,
    timeout_seconds: int,
    timeout_retry_enabled: bool,
    timeout_max_retries: int,
    engine: str,
    concurrency: int,
    clean: bool,
) -> dict:
    return {
        "target": item.elf_path,
        "output_dir": item.output_dir,
        "idempotency_key": _item_pi_idempotency_key(item),
        "batch_size": pi_cfg.batch_size,
        "max_retries": pi_cfg.max_retries,
        "timeout_seconds": timeout_seconds,
        "timeout_retry_enabled": timeout_retry_enabled,
        "timeout_max_retries": timeout_max_retries,
        "model": job_model,
        "functions": (item.extra_metadata or {}).get("file_list") or None,
        "clean": clean,
        "engine": engine,
        "concurrency": concurrency,
    }


async def _submit_or_reuse_pi_job(item: B2STaskItem, worker_url: str, payload: dict) -> dict:
    job = await get_pi_client(worker_url).create_job(payload)
    if not isinstance(job, dict) or not job.get("_conflict"):
        return job
    existing = job.get("existing_job") if isinstance(job.get("existing_job"), dict) else None
    if existing and _normalized_target(existing.get("target")) == _normalized_target(item.elf_path):
        _record_pi_metadata(
            item,
            pi_conflict_job_id=existing.get("id"),
            pi_recover_reason="reuse_active_target_job",
        )
        return existing
    _record_pi_metadata(
        item,
        pi_conflict_job_id=(existing or {}).get("id") if existing else None,
        pi_recover_reason="active_target_conflict",
    )
    raise ConflictError("pi-re-agent存在同名活跃任务，等待上游释放后重试")


def _apply_pi_job_to_item(db: Session, item: B2STaskItem, job: dict, *, worker_url: str) -> None:
    item.pi_job_id = job.get("id")
    _record_pi_metadata(
        item,
        pi_worker_url=worker_url,
        pi_job_id=item.pi_job_id,
        pi_idempotency_key=_item_pi_idempotency_key(item),
        pi_last_seen_status=job.get("status"),
        pi_last_seen_at=isoformat_local(now_local()),
        pi_recover_reason=(item.extra_metadata or {}).get("pi_recover_reason"),
    )
    item.status = map_pi_status(job.get("status"))
    item.phase = map_pi_phase(job.get("phase"), job.get("status"))
    item.progress = build_item_progress(item, job)
    _record_pi_runtime_metrics(item, job)
    refresh_item_function_stats(item, inspect_files=False)
    if item.status == "running" and item.started_at is None:
        item.started_at = now_local()
    if item.status == "success":
        item.generated_files = build_generated_files(item, job.get("output") or {})
        refresh_item_function_stats(item, inspect_files=True)
        item.failure_type = None
        item.error_reason = None
    elif item.status == "failed":
        item.phase = "failed"
        item.failure_type = _classify_pi_failure(job.get("error"))
        item.error_reason = job.get("error")
    elif item.status in {"queued", "running"}:
        item.failure_type = None
        item.error_reason = None


def _queue_item_for_dispatch(item: B2STaskItem, *, clean: bool = False, fresh_pi_job: bool = False) -> None:
    metadata = item.extra_metadata or {}
    metadata["pi_idempotency_key"] = _new_pi_idempotency_key(item.task_id, item) if fresh_pi_job else _pi_idempotency_key(item.task_id, item)
    metadata["dispatch_clean"] = clean
    metadata.pop("pi_last_seen_status", None)
    metadata.pop("pi_last_seen_at", None)
    metadata.pop("pi_last_recover_error", None)
    metadata.pop("pi_conflict_job_id", None)
    metadata.pop("pi_recover_reason", None)
    item.extra_metadata = metadata
    item.pi_job_id = None
    item.status = "pending"
    item.dispatch_status = "pending"
    item.phase = "queued"
    item.progress = build_item_progress(item, {"status": "queued", "phase": "queued", "progress": {}})
    item.failure_type = None
    item.error_reason = None
    item.generated_files = []
    item.started_at = None
    item.finished_at = None
    item.scheduler_owner = None
    item.scheduler_lease_until = None


def _sync_observation_is_still_current(db: Session, item: B2STaskItem, observed_pi_job_id: str | None) -> bool:
    """Guard sync_task against stale in-memory item state after rerun/retry/reset.

    sync_task() may race with rerun_task()/retry_task(), which reset ``pi_job_id``
    and queue the item again. Refresh the row before writing any upstream status
    back; if the observed job id no longer matches, the current sync view is stale
    and must not overwrite the newer state.
    """
    db.refresh(item)
    current_pi_job_id = str(item.pi_job_id or "").strip() or None
    observed = str(observed_pi_job_id or "").strip() or None
    return current_pi_job_id == observed


async def _requeue_stale_pi_job(
    db: Session,
    item: B2STaskItem,
    job: dict,
    *,
    reason: str,
    observed_pi_job_id: str | None,
) -> bool:
    if not _sync_observation_is_still_current(db, item, observed_pi_job_id):
        return False
    if item.pi_job_id:
        try:
            await get_pi_client(item_pi_worker_url(item)).cancel_job(item.pi_job_id)
        except Exception as exc:
            _record_pi_metadata(
                item,
                pi_last_recover_error=str(exc),
                pi_recover_reason=reason,
            )
    _queue_item_for_dispatch(item, clean=True, fresh_pi_job=True)
    _record_pi_metadata(
        item,
        pi_last_seen_status=job.get("status"),
        pi_last_seen_at=isoformat_local(now_local()),
        pi_recover_reason=reason,
        pi_previous_job_id=observed_pi_job_id,
    )
    item.failure_type = "upstream_stale"
    item.error_reason = "pi-re-agent任务长时间未推进，已取消旧job并重新排队"
    return True


async def _recover_stale_pi_job(db: Session, item: B2STaskItem, job: dict, observed_pi_job_id: str | None) -> bool:
    raw_status = str(job.get("status") or "").strip().lower()
    pi_cfg = get_config().pi_re_agent
    if raw_status == "cancelling":
        age = _pi_job_age_seconds(job, "cancel_requested_at", "updated_at")
        if age is not None and age >= max(30, int(pi_cfg.cancelling_stale_after_seconds)):
            return await _requeue_stale_pi_job(
                db,
                item,
                job,
                reason="stale_cancelling_requeued",
                observed_pi_job_id=observed_pi_job_id,
            )
    if raw_status == "queued":
        age = _pi_job_age_seconds(job, "heartbeat_at", "updated_at", "created_at")
        if age is not None and age >= max(60, int(pi_cfg.queued_stale_after_seconds)):
            return await _requeue_stale_pi_job(
                db,
                item,
                job,
                reason="stale_queued_requeued",
                observed_pi_job_id=observed_pi_job_id,
            )
    return False


async def dispatch_item_to_pi(db: Session, item: B2STaskItem, *, owner_id: str) -> bool:
    pi_cfg = get_config().pi_re_agent
    metadata = item.extra_metadata or {}
    worker_url = await choose_pi_worker(db, item.task_id, item.sequence_no)
    metadata["pi_worker_url"] = worker_url
    metadata["pi_endpoint_url"] = worker_url
    metadata["pi_idempotency_key"] = str(metadata.get("pi_idempotency_key") or "").strip() or _pi_idempotency_key(item.task_id, item)
    item.extra_metadata = metadata
    item.dispatch_status = "dispatching"
    item.dispatch_attempts = int(item.dispatch_attempts or 0) + 1
    item.last_dispatch_at = now_local()
    item.scheduler_owner = owner_id
    item.scheduler_lease_until = None
    item.status = "queued"
    item.phase = "queued"
    item.progress = build_item_progress(item, {"status": "queued", "phase": "queued", "progress": {}})
    db.flush()

    try:
        job = await _submit_or_reuse_pi_job(
            item,
            worker_url,
            _pi_job_payload(
                item,
                pi_cfg=pi_cfg,
                job_model=_job_model_for_item(item),
                timeout_seconds=int(metadata.get("agent_run_timeout_seconds") or pi_cfg.agent_run_timeout_seconds),
                timeout_retry_enabled=bool(metadata.get("agent_timeout_retry_enabled") if metadata.get("agent_timeout_retry_enabled") is not None else pi_cfg.agent_timeout_retry_enabled),
                timeout_max_retries=int(metadata.get("agent_timeout_max_retries") if metadata.get("agent_timeout_max_retries") is not None else pi_cfg.agent_timeout_max_retries),
                engine=str(metadata.get("engine") or pi_cfg.engine),
                concurrency=int(metadata.get("concurrency") or pi_cfg.concurrency),
                clean=bool(metadata.get("dispatch_clean")),
            ),
        )
        item.dispatch_status = "dispatched"
        _apply_pi_job_to_item(db, item, job, worker_url=worker_url)
        if item.status == "success":
            get_cache_service().store_success_cache(
                db,
                item,
                upsert=not _normalize_reuse_cache((item.extra_metadata or {}).get("reuse_cache")),
            )
        get_observability().record_item_submit(item, worker_url)
        return True
    except Exception as exc:
        item.pi_job_id = None
        item.status = "pending" if isinstance(exc, ConflictError) else "failed"
        item.dispatch_status = "pending" if isinstance(exc, ConflictError) else "failed"
        item.phase = "queued" if isinstance(exc, ConflictError) else "failed"
        item.progress = build_item_progress(item, {"status": "queued" if isinstance(exc, ConflictError) else "failed", "phase": item.phase, "progress": {}, "error": str(exc)})
        item.failure_type = "upstream_conflict" if isinstance(exc, ConflictError) else _classify_pi_failure(str(exc))
        item.error_reason = str(exc)
        item.scheduler_owner = None
        item.scheduler_lease_until = None
        if item.status == "failed":
            item.finished_at = now_local()
            get_observability().record_item_finished(item)
        return False
def _classify_pi_failure(error: str | None) -> str:
    text = str(error or "").lower()
    if "job not found" in text:
        return "upstream_lost"
    if "already running" in text or "active_job_exists" in text:
        return "upstream_conflict"
    if "timeout" in text:
        return "upstream_timeout"
    if "unauthorized" in text or "401" in text or "permission" in text:
        return "provider_auth_error"
    if "token" in text and ("context" in text or "length" in text or "quota" in text):
        return "token_limit_error"
    return "pi-re-agent"


def _job_model_for_item(item: B2STaskItem) -> str | None:
    metadata = item.extra_metadata or {}
    key = _normalize_llm_provider_key(metadata.get("llm_provider_key"))
    model = _normalize_llm_provider_key(metadata.get("llm_provider_model"))
    if key and model:
        if model.startswith(f"{key}/"):
            return model
        return f"{key}/{model}"
    return model or get_config().pi_re_agent.model


async def _recover_missing_pi_job(db: Session, item: B2STaskItem) -> dict | None:
    worker_url = item_pi_worker_url(item) or get_config().pi_re_agent.base_url.rstrip("/")
    client = get_pi_client(worker_url)
    try:
        found = await client.get_job_by_target(item.elf_path, active=True)
    except Exception as exc:
        _record_pi_metadata(
            item,
            pi_recover_reason="by_target_lookup_failed",
            pi_last_recover_error=str(exc),
        )
        found = None
    if found:
        _record_pi_metadata(
            item,
            pi_worker_url=worker_url,
            pi_job_id=found.get("id"),
            pi_recover_reason="recovered_by_target",
        )
        item.pi_job_id = found.get("id")
        return found

    metadata = item.extra_metadata or {}
    attempts = int(metadata.get("pi_recover_attempt") or 0)
    if attempts >= 3:
        item.status = "failed"
        item.phase = "failed"
        item.failure_type = "upstream_lost"
        item.error_reason = "pi-re-agent job not found after recovery attempts"
        item.finished_at = now_local()
        item.progress = build_item_progress(item, {
            "status": "failed",
            "phase": "failed",
            "progress": item.progress or {},
            "error": item.error_reason,
        })
        refresh_item_function_stats(item, inspect_files=True)
        get_observability().record_item_finished(item)
        return None

    _record_pi_metadata(item, pi_recover_attempt=attempts + 1, pi_recover_reason="queue_missing_job_for_dispatch")
    _queue_item_for_dispatch(item, clean=False)
    item.failure_type = "upstream_lost"
    item.error_reason = "pi-re-agent job not found; 已回到B2S队列等待重新派发"
    return None


def prepare_input_file(project_id: str, task_id: str, sequence_no: int, source_path: Path) -> Path:
    input_dir = safe_input_dir(project_id, task_id, sequence_no)
    target_path = input_dir.joinpath(source_path.name).resolve()
    if not target_path.is_relative_to(input_dir):
        raise ValidationError("输入文件路径不合法")
    if source_path.resolve() != target_path:
        shutil.copy2(source_path, target_path)
    return target_path


async def create_task(db: Session, project_id: str, req: TaskCreate, created_by: str | None) -> TaskResponse:
    if not req.elf_tasks:
        raise ValidationError("elf_tasks不能为空")

    task_id = validate_task_id(req.task_id) if req.task_id else generate_task_id(db, project_id)
    if db.query(B2STask).filter(B2STask.project_id == project_id, B2STask.id == task_id).first():
        raise ConflictError("B2S任务ID已存在")

    task = B2STask(
        id=task_id,
        project_id=project_id,
        task_origin_type=str(req.task_origin_type or "").strip() or "manual",
        parent_project_id=req.parent_project_id,
        parent_task_id=req.parent_task_id,
        parent_task_type=req.parent_task_type,
        parent_stage_name=req.parent_stage_name,
        parent_stage_item_id=req.parent_stage_item_id,
        parent_stage_item_key=req.parent_stage_item_key,
        name=req.name,
        description=req.description,
        priority=req.priority,
        status="pending",
        created_by=created_by,
    )
    task.tags = req.tags
    db.add(task)
    db.flush()

    cfg = get_config()
    pi_cfg = cfg.pi_re_agent
    request_provider_key = _normalize_llm_provider_key(req.llm_provider_key)
    project_provider_key = _project_default_llm_provider_key(db, project_id)
    effective_provider_key = request_provider_key or project_provider_key
    provider = await materialize_llm_provider(effective_provider_key) if cfg.configcenter_service.enabled else None
    job_model = _provider_model_name(provider) or pi_cfg.model
    frozen_provider_key = _normalize_llm_provider_key(provider.get("provider_key") if provider else effective_provider_key)
    frozen_provider_model = _normalize_llm_provider_key(provider.get("model") if provider else job_model)
    job_concurrency = req.concurrency if req.concurrency and req.concurrency > 0 else pi_cfg.concurrency
    job_timeout_seconds = req.agent_run_timeout_seconds if req.agent_run_timeout_seconds is not None else pi_cfg.agent_run_timeout_seconds
    job_timeout_retry_enabled = req.agent_timeout_retry_enabled if req.agent_timeout_retry_enabled is not None else pi_cfg.agent_timeout_retry_enabled
    job_timeout_max_retries = req.agent_timeout_max_retries if req.agent_timeout_max_retries is not None else pi_cfg.agent_timeout_max_retries
    budget_exhausted_action = _budget_exhausted_action_for_project(db, project_id)
    mode_engine_map = {"fast": "hybrid", "deep": "agent"}
    job_mode = req.mode or ({"hybrid": "fast", "agent": "deep"}.get(req.engine or "") if req.engine else None)
    job_engine = mode_engine_map.get(job_mode or "") or req.engine or pi_cfg.engine
    job_mode = job_mode or {"hybrid": "fast", "agent": "deep"}.get(job_engine)
    reuse_cache = _normalize_reuse_cache(req.reuse_cache)
    for idx, elf in enumerate(req.elf_tasks, start=1):
        source_elf_path = ensure_path_in_project(project_id, elf.elf_path, must_be_file=True)
        input_elf_path = prepare_input_file(project_id, task.id, idx, source_elf_path)
        item = B2STaskItem(
            id=uuid4().hex[:16],
            task_id=task.id,
            project_id=project_id,
            sequence_no=idx,
            elf_path=str(input_elf_path),
            output_dir=str(safe_output_dir(project_id, task.id, idx, elf.output_subdir)),
            status="pending",
        )
        item.extra_metadata = {
            **(elf.metadata or {}),
            "task_origin_type": str(req.task_origin_type or "").strip() or "manual",
            "parent_project_id": req.parent_project_id,
            "parent_task_id": req.parent_task_id,
            "parent_task_type": req.parent_task_type,
            "parent_stage_name": req.parent_stage_name,
            "parent_stage_item_id": req.parent_stage_item_id,
            "parent_stage_item_key": req.parent_stage_item_key,
            "file_list": elf.file_list or [],
            "source_elf_path": str(source_elf_path),
            "llm_provider_key": frozen_provider_key,
            "llm_provider_model": frozen_provider_model,
            "llm_provider_display_name": str(provider.get("display_name") or "").strip() if provider else None,
            "llm_provider_type": str(provider.get("provider_type") or "").strip() if provider else None,
            "concurrency": job_concurrency,
            "agent_run_timeout_seconds": job_timeout_seconds,
            "agent_timeout_retry_enabled": job_timeout_retry_enabled,
            "agent_timeout_max_retries": job_timeout_max_retries,
            "budget_exhausted_action": budget_exhausted_action,
            "mode": job_mode,
            "engine": job_engine,
            "reuse_cache": reuse_cache,
            "pi_idempotency_key": _pi_idempotency_key(task.id, item),
            "dispatch_clean": False,
        }
        cache_service = get_cache_service()
        cache_result = None
        if reuse_cache:
            cache_result = cache_service.try_apply_cache_hit(db, item, input_elf_path)
        else:
            cache_service.prepare_cache_metadata(item, input_elf_path)
            get_observability().record_cache_request(mode=str(job_mode or "fast"), reuse_cache=False)
            get_observability().record_cache_bypassed(mode=str(job_mode or "fast"))
        if not cache_result or not cache_result.hit:
            _queue_item_for_dispatch(item, clean=False)
        refresh_item_function_stats(item, inspect_files=bool(cache_result and cache_result.hit))
        db.add(item)
        db.flush()
    recompute_task_status(db, task)
    db.commit()
    db.refresh(task)
    get_observability().record_task_created(len(req.elf_tasks))
    return build_task_response(db, task)


async def sync_task(db: Session, task: B2STask) -> None:
    changed = False
    previous_status = str(task.status or "")
    items = query_items(db, task.id)
    for item in items:
        observed_pi_job_id = str(item.pi_job_id or "").strip() or None
        if not item.pi_job_id and item.status == "queued":
            _queue_item_for_dispatch(item, clean=bool((item.extra_metadata or {}).get("dispatch_clean")))
            item.failure_type = "upstream_lost"
            item.error_reason = "pi-re-agent job id missing; 已回到B2S队列等待重新派发"
            changed = True
            continue
        if not item.pi_job_id:
            continue
        terminal_metrics_backfill_only = item.status in TERMINAL
        if terminal_metrics_backfill_only:
            metadata = item.extra_metadata if isinstance(item.extra_metadata, dict) else {}
            if isinstance(metadata.get("pi_runtime_metrics"), dict):
                continue
        try:
            job = await get_pi_client(item_pi_worker_url(item)).get_job(item.pi_job_id)
        except UpstreamError as exc:
            if not _sync_observation_is_still_current(db, item, observed_pi_job_id):
                continue
            if terminal_metrics_backfill_only:
                _record_pi_metadata(
                    item,
                    pi_runtime_metric_missing_reason="upstream_unreachable",
                    pi_runtime_metric_last_checked_at=isoformat_local(now_local()),
                    pi_runtime_metric_last_error=str(exc),
                )
                changed = True
                continue
            # Do not let one stale/unreachable worker make the whole task detail
            # API return 502. Keep the item visible and let users rerun/delete it.
            item.failure_type = "pi-re-agent"
            item.error_reason = str(exc)
            item.progress = build_item_progress(item, {
                "status": item.status,
                "phase": item.phase,
                "progress": item.progress or {},
                "error": str(exc),
            })
            changed = True
            continue
        if not _sync_observation_is_still_current(db, item, observed_pi_job_id):
            continue
        if terminal_metrics_backfill_only:
            if job is None:
                _record_pi_metadata(
                    item,
                    pi_runtime_metric_missing_reason="upstream_missing",
                    pi_runtime_metric_last_checked_at=isoformat_local(now_local()),
                )
                changed = True
                continue
            if _record_pi_runtime_metrics(item, job):
                changed = True
            continue
        if job is None:
            recovered = await _recover_missing_pi_job(db, item)
            if recovered is not None:
                job = recovered
            elif item.status == "failed":
                changed = True
                continue
            elif item.status == "pending":
                changed = True
                continue
            else:
                item.status = "queued"
                item.phase = "queued"
                item.failure_type = "upstream_lost"
                item.error_reason = "pi-re-agent job not found; 已重新排队等待恢复"
                item.progress = build_item_progress(item, {
                    "status": "queued",
                    "phase": "queued",
                    "progress": item.progress or {},
                    "error": item.error_reason,
                })
                item.pi_job_id = None
                _record_pi_metadata(
                    item,
                    pi_recover_reason="job_not_found_waiting_resubmit",
                    pi_last_seen_status="missing",
                    pi_last_seen_at=isoformat_local(now_local()),
                )
                changed = True
                continue
            changed = True
        if await _recover_stale_pi_job(db, item, job, observed_pi_job_id):
            changed = True
            continue
        new_status = map_pi_status(job.get("status"))
        new_phase = map_pi_phase(job.get("phase"), job.get("status"))
        new_progress = build_item_progress(item, job)
        if _record_pi_runtime_metrics(item, job):
            changed = True
        if new_status == "failed" and _is_budget_exhausted_failure(job, item.error_reason):
            action = _budget_exhausted_action_for_item(db, item)
            if action == "treat_as_passed":
                new_status = "success"
                new_phase = "completed"
        if item.status != new_status:
            item.status = new_status
            changed = True
        if item.phase != new_phase:
            item.phase = new_phase
            changed = True
        if item.progress != new_progress:
            item.progress = new_progress
            changed = True
        if refresh_item_function_stats(item, inspect_files=False):
            changed = True
        started_now = False
        if new_status == "running" and item.started_at is None:
            item.started_at = now_local()
            started_now = True
        if new_status == "success":
            output = job.get("output") or {}
            item.generated_files = build_generated_files(item, output)
            if refresh_item_function_stats(item, inspect_files=True):
                changed = True
            if get_cache_service().store_success_cache(
                db,
                item,
                upsert=not _normalize_reuse_cache((item.extra_metadata or {}).get("reuse_cache")),
            ):
                changed = True
        if new_status == "failed":
            item.phase = "failed"
            item.failure_type = "pi-re-agent"
            item.error_reason = job.get("error")
            if refresh_item_function_stats(item, inspect_files=True):
                changed = True
        elif new_status == "success":
            item.failure_type = None
            item.error_reason = None
        if started_now:
            get_observability().record_item_submit(item, item_pi_worker_url(item) or "unknown")
        if new_status in TERMINAL and item.finished_at is None:
            item.finished_at = now_local()
            get_observability().record_item_finished(item)
        changed = True
    recompute_task_status(db, task)
    if changed or str(task.status or "") != previous_status:
        db.commit()
        db.refresh(task)


async def terminate_task(db: Session, task: B2STask) -> None:
    for item in query_items(db, task.id):
        if item.status in TERMINAL:
            continue
        if item.pi_job_id:
            await get_pi_client(item_pi_worker_url(item)).cancel_job(item.pi_job_id)
        item.status = "cancelled"
        item.phase = "cancelled"
        item.progress = build_item_progress(item, {"status": "cancelled", "phase": "cancelled", "progress": item.progress})
        refresh_item_function_stats(item, inspect_files=True)
        item.finished_at = now_local()
        get_observability().record_item_finished(item)
    recompute_task_status(db, task)
    db.commit()


def clean_item_output_dir(project_id: str, task_id: str, sequence_no: int, output_dir: str) -> Path:
    """Remove and recreate an item's output directory, preserving input files."""
    item_root = app_task_item_root(project_id, task_id, sequence_no)
    root = project_root(project_id)
    expected_output_root = item_root.joinpath("output").resolve()
    resolved_output = Path(output_dir).resolve()
    if not resolved_output.is_relative_to(root):
        raise ValidationError("输出目录不在项目目录内，拒绝清理")
    if not resolved_output.is_relative_to(item_root):
        raise ValidationError("输出目录不在任务项目录内，拒绝清理")
    if not resolved_output.is_relative_to(expected_output_root):
        raise ValidationError("仅允许清理output目录，拒绝清理input或其他目录")
    if resolved_output.exists():
        if not resolved_output.is_dir():
            raise ValidationError("输出路径不是目录，拒绝清理")
        shutil.rmtree(resolved_output)
    os.makedirs(resolved_output, exist_ok=True)
    return resolved_output


async def delete_task(db: Session, task: B2STask) -> None:
    """Delete a B2S task record and its complete task-id filesystem tree.

    Files are stored under ``<project_root>/<app_root_name>/<task_id>``.  Only
    that directory is removed; source files selected from elsewhere in the
    project are intentionally preserved.
    """
    items = query_items(db, task.id)
    for item in items:
        if item.pi_job_id and item.status not in TERMINAL:
            try:
                await get_pi_client(item_pi_worker_url(item)).cancel_job(item.pi_job_id)
            except Exception:
                # Deletion should not be blocked by a stale/unreachable upstream
                # job.  DB rows and the task workspace are still removed below.
                pass

    task_dir = app_task_root(task.project_id, task.id)
    root = project_root(task.project_id)
    if not task_dir.is_relative_to(root):
        raise ValidationError("B2S任务目录不合法")
    if task_dir.exists():
        if not task_dir.is_dir():
            raise ValidationError("B2S任务路径不是目录，拒绝删除")
        shutil.rmtree(task_dir)

    for item in items:
        db.delete(item)
    db.delete(task)
    db.commit()


async def rerun_task(db: Session, task: B2STask, *, clean_output: bool = True, cancel_running: bool = True) -> None:
    """Fully rerun all items of a task while keeping taskId and input files."""
    if not clean_output:
        raise ValidationError("rerun仅支持清空output后从头重跑")
    if not cancel_running:
        raise ValidationError("rerun仅支持先终止未完成job后再重跑")
    items = query_items(db, task.id)
    if not items:
        raise NotFoundError("任务没有可重跑的任务项")
    selected_provider_key = _restart_llm_provider_key(db, task, items)
    provider = await materialize_llm_provider(selected_provider_key) if get_config().configcenter_service.enabled else None

    for item in items:
        if cancel_running and item.pi_job_id and item.status not in TERMINAL:
            try:
                await get_pi_client(item_pi_worker_url(item)).cancel_job(item.pi_job_id)
            except Exception as exc:
                raise ValidationError(
                    f"无法安全重跑：终止旧job失败，item={item.sequence_no} job_id={item.pi_job_id} error={exc}"
                ) from exc

        if clean_output:
            item.output_dir = str(clean_item_output_dir(task.project_id, task.id, item.sequence_no, item.output_dir))

        metadata = item.extra_metadata or {}
        metadata.pop("pi_worker_url", None)
        metadata.pop("pi_endpoint_url", None)
        metadata["pi_idempotency_key"] = _new_pi_idempotency_key(task.id, item)
        if provider:
            metadata["llm_provider_key"] = _normalize_llm_provider_key(provider.get("provider_key"))
            metadata["llm_provider_model"] = _normalize_llm_provider_key(provider.get("model"))
            metadata["llm_provider_display_name"] = str(provider.get("display_name") or "").strip() or None
            metadata["llm_provider_type"] = str(provider.get("provider_type") or "").strip() or None
        item.extra_metadata = metadata
        _queue_item_for_dispatch(item, clean=True, fresh_pi_job=True)
        db.flush()
    recompute_task_status(db, task)
    db.commit()
    get_observability().record_retry("rerun", len(items))


async def retry_task(db: Session, task: B2STask, item_ids: list[str] | None = None) -> None:
    items = query_items(db, task.id)
    selected = [i for i in items if item_ids is None or i.id in item_ids]
    if not selected:
        raise NotFoundError("未找到可重试的任务项")
    selected_provider_key = _restart_llm_provider_key(db, task, selected)
    provider = await materialize_llm_provider(selected_provider_key) if get_config().configcenter_service.enabled else None
    for item in selected:
        if item.status not in {"failed", "cancelled"}:
            continue
        metadata = item.extra_metadata or {}
        metadata.pop("pi_worker_url", None)
        metadata.pop("pi_endpoint_url", None)
        metadata["pi_idempotency_key"] = _new_pi_idempotency_key(task.id, item)
        if provider:
            metadata["llm_provider_key"] = _normalize_llm_provider_key(provider.get("provider_key"))
            metadata["llm_provider_model"] = _normalize_llm_provider_key(provider.get("model"))
            metadata["llm_provider_display_name"] = str(provider.get("display_name") or "").strip() or None
            metadata["llm_provider_type"] = str(provider.get("provider_type") or "").strip() or None
        item.extra_metadata = metadata
        _queue_item_for_dispatch(item, clean=True, fresh_pi_job=True)
    recompute_task_status(db, task)
    db.commit()
    get_observability().record_retry("retry", len(selected))


def get_task_or_404(db: Session, project_id: str, task_id: str) -> B2STask:
    task = db.query(B2STask).filter(B2STask.project_id == project_id, B2STask.id == task_id).first()
    if not task:
        raise NotFoundError("B2S任务不存在")
    return task


def query_items(db: Session, task_id: str) -> list[B2STaskItem]:
    return db.query(B2STaskItem).filter(B2STaskItem.task_id == task_id).order_by(B2STaskItem.sequence_no.asc()).all()


def map_pi_status(status: str | None) -> str:
    return PI_STATUS_MAP.get(status or "queued", status or "queued")


def map_pi_phase(raw_phase: str | None, status: str | None = None) -> str:
    mapped_status = map_pi_status(status)
    if mapped_status in {"success", "failed", "cancelled"}:
        return {"success": "completed", "failed": "failed", "cancelled": "cancelled"}[mapped_status]
    if mapped_status == "queued":
        return "queued"
    return PI_PHASE_MAP.get(raw_phase or "", "body" if mapped_status == "running" else "queued")


def phase_label(phase: str | None) -> str:
    return PHASE_LABELS.get(phase or "", phase or "-")


def _safe_existing_file(path: Path, root: Path) -> str | None:
    try:
        resolved = path.resolve()
        resolved_root = root.resolve()
    except Exception:
        return None
    if not resolved.is_relative_to(resolved_root):
        return None
    if not resolved.is_file():
        return None
    return str(resolved)


def ida_decompiled_c_path(item: B2STaskItem, reference_path: str | None = None) -> str | None:
    """Return IDA's direct decompiled C output for an item if present."""
    output_root = Path(item.output_dir)
    stems: list[str] = []
    if reference_path:
        stems.append(Path(reference_path).stem)
    if item.elf_path:
        stems.append(Path(item.elf_path).stem)
    seen: set[str] = set()
    for stem in stems:
        if not stem or stem in seen:
            continue
        seen.add(stem)
        candidate = output_root / f".re_work_{stem}" / "ida_cache" / "ida_export" / "decompiled.c"
        existing = _safe_existing_file(candidate, output_root)
        if existing:
            return existing
    return None


def build_generated_files(item: B2STaskItem, output: dict | None) -> list[str]:
    output = output or {}
    ida_c = output.get("ida_c") or ida_decompiled_c_path(item, output.get("c"))
    return [p for p in [output.get("c"), output.get("h"), ida_c] if p]


def normalize_generated_files(item: B2STaskItem) -> list[str]:
    """Replace legacy .asm entries with IDA's direct decompiled.c for responses."""
    normalized: list[str] = []
    for path in item.generated_files:
        if Path(path).suffix.lower() == ".asm":
            ida_c = ida_decompiled_c_path(item, path)
            if ida_c:
                normalized.append(ida_c)
            continue
        normalized.append(path)
    return normalized


def _safe_percent(done: int | float | None, total: int | float | None) -> float | None:
    if total in (None, 0) or done is None:
        return None
    return round(max(0.0, min(100.0, float(done) * 100.0 / float(total))), 2)


def _file_size(path: str | None) -> int | None:
    try:
        if path and os.path.isfile(path):
            return os.path.getsize(path)
    except OSError:
        return None
    return None


def build_item_progress(item: B2STaskItem, job: dict) -> dict:
    raw_progress = job.get("progress") if isinstance(job.get("progress"), dict) else {}
    raw_phase = job.get("phase")
    status = map_pi_status(job.get("status"))
    phase = map_pi_phase(raw_phase, job.get("status"))
    total_batches = raw_progress.get("total_batches")
    completed_batches = raw_progress.get("completed_batches") or 0
    total_functions = raw_progress.get("total_functions")
    completed_functions = raw_progress.get("completed_functions")
    total_bytes = raw_progress.get("total_bytes") or raw_progress.get("total_binary_bytes") or _file_size(item.elf_path)

    if status == "success":
        if total_batches is not None:
            completed_batches = total_batches
        elif completed_batches == 0:
            completed_batches = 1
        if total_functions is not None:
            completed_functions = total_functions

    if completed_functions is None and total_functions and total_batches:
        completed_functions = int(float(total_functions) * float(completed_batches) / float(total_batches))
    completed_bytes = raw_progress.get("completed_bytes")
    batch_percent = _safe_percent(completed_batches, total_batches)
    if status == "success" and total_bytes is not None:
        completed_bytes = total_bytes
    elif completed_bytes is None and total_bytes and batch_percent is not None:
        completed_bytes = int(float(total_bytes) * batch_percent / 100.0)
    percent = _safe_percent(completed_functions, total_functions) or batch_percent or _safe_percent(completed_bytes, total_bytes)
    if status == "success":
        percent = 100.0
    message = raw_progress.get("message") or job.get("error") or phase_label(phase)
    return {
        "phase": phase,
        "raw_phase": raw_phase,
        "phase_label": phase_label(phase),
        "message": message,
        "total_functions": total_functions,
        "completed_functions": completed_functions,
        "total_bytes": total_bytes,
        "completed_bytes": completed_bytes,
        "total_batches": total_batches,
        "completed_batches": completed_batches,
        "current_batch": raw_progress.get("current_batch"),
        "current_attempt": raw_progress.get("current_attempt"),
        "current_function": raw_progress.get("current_function"),
        "percent": percent,
        "bytes_percent": _safe_percent(completed_bytes, total_bytes),
        "batches_percent": batch_percent,
        "updated_at": isoformat_local(now_local()),
    }


def recompute_task_status(db: Session, task: B2STask) -> None:
    items = query_items(db, task.id)
    counts = count_status(items)
    total = len(items)
    terminal_total = (
        counts["success_items"]
        + counts["failed_items"]
        + counts["cancelled_items"]
        + counts["partial_items"]
    )
    active_total = counts["queued_items"] + counts["running_items"]
    waiting_total = counts["pending_items"]
    if total == 0:
        task.status = "pending"
    elif counts["success_items"] == total:
        task.status = "completed"
    elif counts["cancelled_items"] == total:
        task.status = "cancelled"
    elif counts["failed_items"] == total:
        task.status = "failed"
    elif terminal_total == total:
        task.status = "partial" if counts["success_items"] > 0 or counts["partial_items"] > 0 else "failed"
    elif active_total > 0:
        task.status = "running"
    elif waiting_total == total:
        task.status = "pending"
    elif waiting_total > 0 and terminal_total > 0:
        # Once any item has reached a terminal result, the task has already
        # started even if the remaining items are still waiting in the local
        # dispatch queue for downstream capacity.
        task.status = "running"
    elif counts["success_items"] > 0 and counts["failed_items"] + counts["cancelled_items"] > 0:
        task.status = "partial"
    else:
        task.status = "pending"
    task.updated_at = now_local()


def count_status(items: list[B2STaskItem]) -> dict[str, int]:
    return {
        "pending_items": sum(1 for i in items if i.status == "pending"),
        "queued_items": sum(1 for i in items if i.status == "queued"),
        "running_items": sum(1 for i in items if i.status == "running"),
        "success_items": sum(1 for i in items if i.status == "success"),
        "partial_items": sum(1 for i in items if i.status == "partial"),
        "failed_items": sum(1 for i in items if i.status == "failed"),
        "cancelled_items": sum(1 for i in items if i.status == "cancelled"),
    }


def task_mode_summary(items: list[B2STaskItem]) -> tuple[str | None, str | None]:
    modes: list[str] = []
    engine_mode_map = {"hybrid": "fast", "agent": "deep"}
    for item in items:
        metadata = item.extra_metadata or {}
        mode = str(metadata.get("mode") or "").strip()
        if not mode:
            mode = engine_mode_map.get(str(metadata.get("engine") or "").strip(), "")
        if mode and mode not in modes:
            modes.append(mode)
    if not modes:
        return None, None
    if len(modes) == 1:
        mode = modes[0]
        if mode == "deep":
            return mode, "深度模式"
        if mode == "fast":
            return mode, "快速模式"
        return mode, mode
    return "mixed", "混合模式"


def task_input_filenames(items: list[B2STaskItem]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for item in items:
        metadata = item.extra_metadata or {}
        filename = (
            str(metadata.get("uploaded_filename") or "").strip()
            or str(metadata.get("source_filename") or "").strip()
            or Path(str(metadata.get("source_elf_path") or item.elf_path or "")).name
        )
        if not filename or filename in seen:
            continue
        seen.add(filename)
        names.append(filename)
    return names


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _json_file(path: Path) -> dict[str, Any] | None:
    try:
        if path.is_file():
            data = json.loads(path.read_text("utf-8") or "{}")
            if isinstance(data, dict):
                return data
    except Exception:
        return None
    return None


def _latest_run_dir(item: B2STaskItem) -> Path | None:
    output_dir = Path(item.output_dir)
    work_dirs = sorted([p for p in output_dir.glob(".re_work_*") if p.is_dir()], key=lambda p: p.name)
    work_dir = work_dirs[-1] if work_dirs else None
    runs_root = work_dir / "runs" if work_dir else None
    if not runs_root or not runs_root.exists():
        return None
    run_dirs = sorted([p for p in runs_root.iterdir() if p.is_dir()], key=lambda p: p.name)
    return run_dirs[-1] if run_dirs else None


def _normalize_function_stats(stats: dict[str, Any] | None) -> dict[str, int | None]:
    stats = stats or {}
    total = _safe_int(stats.get("total_functions"))
    completed = _safe_int(stats.get("completed_functions"))
    failed = _safe_int(stats.get("failed_functions"))
    if total is not None and completed is not None:
        completed = min(max(0, completed), max(0, total))
    if total is not None and failed is not None:
        failed = min(max(0, failed), max(0, total))
    uncompleted = _safe_int(stats.get("uncompleted_functions"))
    if total is not None and completed is not None:
        uncompleted = max(0, total - completed)
    return {
        "total_functions": total,
        "completed_functions": completed,
        "failed_functions": failed,
        "uncompleted_functions": uncompleted,
    }


def _cached_item_function_stats(item: B2STaskItem) -> dict[str, int | None] | None:
    metadata = item.extra_metadata or {}
    cached = metadata.get(FUNCTION_STATS_METADATA_KEY)
    if not isinstance(cached, dict):
        return None
    stats = _normalize_function_stats(cached)
    if any(stats[field] is not None for field in FUNCTION_STATS_FIELDS):
        return stats
    return None


def _store_item_function_stats(item: B2STaskItem, stats: dict[str, int | None], *, source: str) -> bool:
    normalized = _normalize_function_stats(stats)
    metadata = item.extra_metadata or {}
    existing = metadata.get(FUNCTION_STATS_METADATA_KEY) if isinstance(metadata.get(FUNCTION_STATS_METADATA_KEY), dict) else {}
    comparable = {**normalized, "source": source}
    existing_comparable = {key: existing.get(key) for key in (*FUNCTION_STATS_FIELDS, "source")} if isinstance(existing, dict) else {}
    if existing_comparable == comparable:
        return _merge_item_progress(
            item,
            total_functions=normalized["total_functions"],
            completed_functions=normalized["completed_functions"],
            failed_functions=normalized["failed_functions"],
            uncompleted_functions=normalized["uncompleted_functions"],
        )
    payload = {
        **(existing or {}),
        **comparable,
        "updated_at": isoformat_local(now_local()),
    }
    metadata[FUNCTION_STATS_METADATA_KEY] = payload
    item.extra_metadata = metadata
    _merge_item_progress(
        item,
        total_functions=normalized["total_functions"],
        completed_functions=normalized["completed_functions"],
        failed_functions=normalized["failed_functions"],
        uncompleted_functions=normalized["uncompleted_functions"],
    )
    return True


def _compute_item_function_stats(item: B2STaskItem, *, inspect_files: bool) -> tuple[dict[str, int | None], str]:
    progress = item.progress or {}
    run_dir = _latest_run_dir(item) if inspect_files else None
    results = _json_file(run_dir / "results.json") if run_dir else None
    manifest = _json_file(run_dir / "batch_manifest.json") if run_dir else None

    total = _safe_int(progress.get("total_functions"))
    completed = _safe_int(progress.get("completed_functions"))
    failed: int | None = None
    source = "progress"

    result_rows = results.get("results") if isinstance(results, dict) else None
    if isinstance(result_rows, list):
        result_total = 0
        result_completed = 0
        result_failed = 0
        has_result_functions = False
        for row in result_rows:
            if not isinstance(row, dict):
                continue
            count = _safe_int(row.get("func_count"))
            if count is None:
                continue
            has_result_functions = True
            result_total += count
            verdict = str(row.get("verdict") or "").strip().upper()
            if verdict == "PASS":
                result_completed += count
            elif verdict == "FAIL":
                result_failed += count
        if has_result_functions:
            total = max(total or 0, result_total)
            completed = max(completed or 0, result_completed)
            failed = result_failed
            source = "results"

    manifest_total = _safe_int(manifest.get("function_count")) if isinstance(manifest, dict) else None
    if manifest_total is not None:
        total = max(total or 0, manifest_total)
        if source == "progress":
            source = "manifest"

    file_list = (item.extra_metadata or {}).get("file_list")
    if isinstance(file_list, list) and file_list:
        total = max(total or 0, len(file_list))
        if source == "progress":
            source = "file_list"

    if item.status == "success" and total is not None:
        completed = total
        failed = 0 if failed is None else failed
    elif item.status in TERMINAL and total is not None and completed is None:
        completed = 0

    if total is not None and completed is not None:
        completed = min(max(0, completed), max(0, total))

    return {
        "total_functions": total,
        "completed_functions": completed,
        "failed_functions": failed,
        "uncompleted_functions": max(0, total - completed) if total is not None and completed is not None else None,
    }, source


def refresh_item_function_stats(item: B2STaskItem, *, inspect_files: bool = True, only_missing: bool = False) -> bool:
    if only_missing and _cached_item_function_stats(item) is not None:
        return False
    stats, source = _compute_item_function_stats(item, inspect_files=inspect_files)
    if not any(stats[field] is not None for field in FUNCTION_STATS_FIELDS):
        return False
    return _store_item_function_stats(item, stats, source=source)


def refresh_task_function_stats(
    db: Session,
    task: B2STask,
    *,
    inspect_files: bool = True,
    only_missing: bool = False,
    commit: bool = True,
) -> bool:
    changed = False
    for item in query_items(db, task.id):
        if refresh_item_function_stats(item, inspect_files=inspect_files, only_missing=only_missing):
            changed = True
    if changed and commit:
        db.commit()
        db.refresh(task)
    return changed


def _item_function_stats(item: B2STaskItem) -> dict[str, int | None]:
    cached = _cached_item_function_stats(item)
    if cached is not None:
        return cached
    stats, _ = _compute_item_function_stats(item, inspect_files=False)
    return _normalize_function_stats(stats)


def build_task_function_stats(items: list[B2STaskItem]) -> dict[str, int | None]:
    totals = completed = failed = 0
    has_total = has_completed = has_failed = False
    for item in items:
        stats = _item_function_stats(item)
        if stats["total_functions"] is not None:
            has_total = True
            totals += int(stats["total_functions"] or 0)
        if stats["completed_functions"] is not None:
            has_completed = True
            completed += int(stats["completed_functions"] or 0)
        if stats["failed_functions"] is not None:
            has_failed = True
            failed += int(stats["failed_functions"] or 0)

    total_value = totals if has_total else None
    completed_value = completed if has_completed else None
    failed_value = failed if has_failed else None
    uncompleted_value = None
    if total_value is not None and completed_value is not None:
        uncompleted_value = max(0, total_value - completed_value)
    return {
        "total_functions": total_value,
        "completed_functions": completed_value,
        "failed_functions": failed_value,
        "uncompleted_functions": uncompleted_value,
    }


def build_task_timing_summary(items: list[B2STaskItem]) -> dict[str, datetime | int | None]:
    started_values = [item.started_at for item in items if item.started_at is not None]
    if not started_values:
        return {"started_at": None, "finished_at": None, "run_duration_ms": None}

    started_at = min(started_values)
    open_items = [item for item in items if item.started_at is not None and item.status not in TERMINAL]
    finished_values = [item.finished_at for item in items if item.finished_at is not None]
    finished_at = max(finished_values) if finished_values else None
    duration_end = now_local() if open_items else finished_at
    run_duration_ms = None
    if duration_end is not None:
        run_duration_ms = max(0, int((duration_end - started_at).total_seconds() * 1000))
    return {
        "started_at": started_at,
        "finished_at": None if open_items else finished_at,
        "run_duration_ms": run_duration_ms,
    }


def build_task_response(db: Session, task: B2STask) -> TaskResponse:
    items = query_items(db, task.id)
    counts = count_status(items)
    mode, mode_label = task_mode_summary(items)
    function_stats = build_task_function_stats(items)
    timing_summary = build_task_timing_summary(items)
    return TaskResponse(
        id=task.id,
        project_id=task.project_id,
        **_task_origin_payload(task),
        mode=mode,
        mode_label=mode_label,
        input_filenames=task_input_filenames(items),
        name=task.name,
        status=task.status,
        total_items=len(items),
        total_functions=function_stats["total_functions"],
        completed_functions=function_stats["completed_functions"],
        failed_functions=function_stats["failed_functions"],
        uncompleted_functions=function_stats["uncompleted_functions"],
        started_at=timing_summary["started_at"],
        finished_at=timing_summary["finished_at"],
        run_duration_ms=timing_summary["run_duration_ms"],
        created_at=task.created_at,
        updated_at=task.updated_at,
        **counts,
    )


def get_task_item_or_404(db: Session, task: B2STask, item_id: str) -> B2STaskItem:
    item = db.query(B2STaskItem).filter(B2STaskItem.task_id == task.id, B2STaskItem.id == item_id).first()
    if item:
        return item
    if item_id.isdigit():
        item = db.query(B2STaskItem).filter(B2STaskItem.task_id == task.id, B2STaskItem.sequence_no == int(item_id)).first()
        if item:
            return item
    raise NotFoundError("B2S任务项不存在")


def build_task_detail(db: Session, task: B2STask) -> TaskDetailResponse:
    base = build_task_response(db, task).model_dump()
    raw_items = query_items(db, task.id)
    items = [
        TaskItemResponse(
            id=i.id,
            sequence_no=i.sequence_no,
            elf_path=i.elf_path,
            output_dir=i.output_dir,
            status=i.status,
            phase=i.phase,
            phase_label=phase_label(i.phase),
            phase_message=(i.progress or {}).get("message"),
            progress=i.progress or None,
            failure_type=i.failure_type,
            error_reason=i.error_reason,
            pi_job_id=i.pi_job_id,
            pi_worker_url=str((i.extra_metadata or {}).get("pi_worker_url") or (i.extra_metadata or {}).get("pi_endpoint_url") or "") or None,
            generated_files=normalize_generated_files(i),
            started_at=i.started_at,
            finished_at=i.finished_at,
        )
        for i in raw_items
    ]
    return TaskDetailResponse(
        **base,
        overall_progress=build_overall_progress(raw_items),
        items=items,
        task_config_snapshot=build_task_config_snapshot(task, raw_items),
        effective_llm_provider=build_effective_llm_provider(raw_items),
        agent_runtime_summary=build_agent_runtime_summary(raw_items),
        result_summary=build_task_result_summary(raw_items),
        observability_summary=build_task_observability_summary(raw_items),
    )


def _item_metadata_value(item: B2STaskItem, key: str):
    return (item.extra_metadata or {}).get(key)


def _first_non_empty(items: list[B2STaskItem], key: str):
    for item in items:
        value = _item_metadata_value(item, key)
        if value not in (None, "", []):
            return value
    return None


def _item_output_subdir(item: B2STaskItem) -> str | None:
    source = str((_item_metadata_value(item, "source_elf_path") or "")).strip()
    try:
        output_path = Path(item.output_dir)
        source_name = Path(source).stem if source else ""
        if source_name and output_path.name == source_name:
            return source_name
        return output_path.name or None
    except Exception:
        return None


def build_task_config_snapshot(task: B2STask, items: list[B2STaskItem]) -> TaskConfigSnapshot:
    mode, mode_label = task_mode_summary(items)
    input_items = [
        TaskConfigInputItem(
            item_id=item.id,
            sequence_no=item.sequence_no,
            elf_path=item.elf_path,
            source_elf_path=str(_item_metadata_value(item, "source_elf_path") or "").strip() or None,
            output_dir=item.output_dir,
            output_subdir=_item_output_subdir(item),
            file_list=list(_item_metadata_value(item, "file_list") or []),
        )
        for item in items
    ]
    return TaskConfigSnapshot(
        name=task.name,
        description=task.description,
        priority=task.priority,
        tags=task.tags,
        **_task_origin_payload(task),
        mode=mode,
        mode_label=mode_label,
        engine=str(_first_non_empty(items, "engine") or "").strip() or None,
        llm_provider_key=str(_first_non_empty(items, "llm_provider_key") or "").strip() or None,
        llm_provider_display_name=str(_first_non_empty(items, "llm_provider_display_name") or "").strip() or None,
        llm_provider_type=str(_first_non_empty(items, "llm_provider_type") or "").strip() or None,
        llm_provider_model=str(_first_non_empty(items, "llm_provider_model") or "").strip() or None,
        concurrency=int(_first_non_empty(items, "concurrency") or 0) or None,
        agent_run_timeout_seconds=int(_first_non_empty(items, "agent_run_timeout_seconds") or 0) or None,
        agent_timeout_retry_enabled=bool(_first_non_empty(items, "agent_timeout_retry_enabled")) if _first_non_empty(items, "agent_timeout_retry_enabled") is not None else None,
        agent_timeout_max_retries=int(_first_non_empty(items, "agent_timeout_max_retries") or 0) or None,
        reuse_cache=_normalize_reuse_cache(_first_non_empty(items, "reuse_cache")),
        budget_exhausted_action=str(_first_non_empty(items, "budget_exhausted_action") or "").strip() or None,
        input_count=len(input_items),
        input_items=input_items,
    )


def build_effective_llm_provider(items: list[B2STaskItem]) -> dict | None:
    provider_key = str(_first_non_empty(items, "llm_provider_key") or "").strip()
    if not provider_key:
        return None
    return {
        "provider_key": provider_key,
        "display_name": str(_first_non_empty(items, "llm_provider_display_name") or "").strip() or None,
        "provider_type": str(_first_non_empty(items, "llm_provider_type") or "").strip() or None,
        "enabled": True,
        "is_default": False,
        "model": str(_first_non_empty(items, "llm_provider_model") or "").strip() or None,
    }


ADVANCED_TEXT_EXTENSIONS = {".c", ".h", ".json", ".jsonl", ".md", ".txt", ".log", ".yaml", ".yml"}
ADVANCED_MAX_BYTES = 512 * 1024


def _advanced_kind(path: Path) -> str:
    name = path.name.lower()
    if name.startswith("batch_") and name.endswith(".c"):
        return "batch_source"
    if name.startswith("disasm_batch_") and name.endswith(".c"):
        return "batch_disasm"
    if "verdict" in name or "review" in name:
        return "review"
    if "session" in str(path).lower() or "prompt" in name:
        return "agent_session"
    if name.endswith(".json"):
        return "json"
    return path.suffix.lstrip(".") or "file"


def _safe_read_advanced_file(path: Path, base: Path, include_content: bool, metadata: dict | None = None) -> AdvancedFile | None:
    try:
        resolved = path.resolve()
        resolved.relative_to(base.resolve())
        if not resolved.is_file():
            return None
        size = resolved.stat().st_size
        content = None
        truncated = False
        if include_content and resolved.suffix.lower() in ADVANCED_TEXT_EXTENSIONS:
            raw = resolved.read_bytes()[:ADVANCED_MAX_BYTES + 1]
            truncated = len(raw) > ADVANCED_MAX_BYTES
            content = raw[:ADVANCED_MAX_BYTES].decode("utf-8", errors="replace")
        return AdvancedFile(
            name=resolved.name,
            path=str(resolved),
            kind=_advanced_kind(resolved),
            size=size,
            content=content,
            truncated=truncated,
            **(metadata or {}),
        )
    except Exception:
        return None


def _batch_no(path: Path) -> int | None:
    match = re.search(r"batch_(\d+)", str(path))
    return int(match.group(1)) if match else None


def _attempt_no(path: Path | str) -> int | None:
    match = re.search(r"attempt[_-]?(\d+)", str(path), re.IGNORECASE)
    return int(match.group(1)) if match else None


def _batch_label(no: int | None) -> str:
    return f"Batch {no:03d}" if no else "Batch"


def _stage4_meta(batch_no: int | None, *, section: str, section_order: int, round_label: str, round_order: int = 0, agent: str | None = None, role: str | None = None, attempt_no: int | None = None) -> dict:
    if batch_no:
        stage = f"阶段 4 · {_batch_label(batch_no)} 函数"
        stage_order = 4000 + batch_no
    else:
        stage = "阶段 4 · 全局执行会话"
        stage_order = 4998
    return {
        "stage": stage,
        "stage_order": stage_order,
        "section": section,
        "section_order": section_order,
        "round": round_label,
        "round_order": round_order,
        "agent": agent,
        "role": role,
        "batch_no": batch_no,
        "attempt_no": attempt_no,
    }


def _session_meta(path: Path, run_dir: Path, default_batch_no: int | None) -> dict:
    rel = str(path.relative_to(run_dir)) if path.is_relative_to(run_dir) else str(path)
    lower = rel.lower()
    batch_no = _batch_no(rel) or default_batch_no
    attempt_no = _attempt_no(rel)
    is_prompt = "system-prompt" in lower or path.name.lower().endswith("system-prompt.md")
    role = "System Prompt" if is_prompt else "JSONL 会话"
    if "header" in lower or "synth" in lower:
        return {
            "stage": "阶段 3 · 共享头文件合成",
            "stage_order": 3000,
            "section": "Header Agent",
            "section_order": 0,
            "round": f"第 {attempt_no} 轮" if attempt_no else "Header 会话",
            "round_order": attempt_no or 0,
            "agent": "header agent",
            "role": role,
            "batch_no": None,
            "attempt_no": attempt_no,
        }
    if "validator" in lower:
        return _stage4_meta(batch_no, section="评审", section_order=20, round_label=f"第 {attempt_no} 次评审" if attempt_no else "评审会话", round_order=attempt_no or 0, agent="validator agent", role=role, attempt_no=attempt_no)
    if "executor" in lower:
        return _stage4_meta(batch_no, section="执行", section_order=10, round_label="执行会话", round_order=0, agent="executor agent", role=role)
    return _stage4_meta(batch_no, section="其他会话", section_order=90, round_label=f"第 {attempt_no} 轮" if attempt_no else "Agent 会话", round_order=attempt_no or 0, agent="agent", role=role, attempt_no=attempt_no)


def _run_file_meta(path: Path) -> dict:
    name = path.name.lower()
    if name == "run_manifest.json":
        return {"stage": "阶段 0 · 运行配置", "stage_order": 0, "section": "文件", "section_order": 0, "round": "产物", "round_order": 0, "role": "运行配置"}
    if name == "batch_manifest.json":
        return {"stage": "阶段 2 · Batch 划分清单", "stage_order": 2000, "section": "文件", "section_order": 0, "round": "产物", "round_order": 0, "role": "Batch 清单"}
    if name == "results.json":
        return {"stage": "结果汇总", "stage_order": 6000, "section": "文件", "section_order": 0, "round": "产物", "round_order": 0, "role": "结果汇总"}
    if name == "preamble.h":
        return {"stage": "阶段 3 · 共享头文件", "stage_order": 3000, "section": "文件", "section_order": 0, "round": "产物", "round_order": 0, "role": "共享头文件"}
    return {"stage": "运行文件", "stage_order": 500, "section": "文件", "section_order": 0, "round": "产物", "round_order": 0}


def _ida_file_meta(path: Path) -> dict:
    return {"stage": "阶段 1 · IDA 分析缓存", "stage_order": 1000, "section": "文件", "section_order": 0, "round": "产物", "round_order": 0, "role": "IDA 缓存"}


def _collect_advanced_files(paths: list[Path], base: Path, include_content: bool) -> list[AdvancedFile]:
    files: list[AdvancedFile] = []
    for path in paths:
        file = _safe_read_advanced_file(path, base, include_content)
        if file:
            files.append(file)
    return files


ISSUE_LABELS = {"Length Logic": "长度校验逻辑反转", "Return Code": "accepted 返回值错误", "Extra Check": "多余校验条件", "Semantic": "语义问题", "Validation": "输入校验", "Return": "返回语义", "Call": "调用关系", "Type": "类型结构"}
ISSUE_DETAILS = {
    "Length Logic": "序列号长度判断方向错误，导致有效输入路径被错误处理。",
    "Return Code": "accepted 分支返回值与原始二进制语义不一致。",
    "Extra Check": "输出中出现原始逻辑不存在的 hex_len == 0 校验。",
    "Semantic": "还原代码与原始二进制语义存在偏差。",
}
CATEGORY_LABELS = {"Validation": "输入校验", "Return": "返回语义", "Call": "调用关系", "Type": "类型结构", "Semantic": "语义一致性"}
SEVERITY_LABELS = {"blocking": "阻断", "major": "重要", "warning": "警告"}
STATUS_LABELS = {"resolved": "已解决", "remaining": "未解决"}
RISK_LABELS = {"low": "低", "low-medium": "低-中", "medium": "中", "high": "高", "unknown": "未知"}

QUALITY_DIMENSION_GROUPS = [
    {
        "key": "logic_accuracy",
        "label": "代码逻辑准确性",
        "color_hint": "logic",
        "description": "控制流、返回值和关键条件高度匹配原始程序",
        "formula": "0.15*completeness + 0.25*control_flow + 0.20*return_semantics + 0.25*input_validation + 0.15*call_fidelity",
        "terms": [("completeness", 0.15), ("control_flow", 0.25), ("return_semantics", 0.2), ("input_validation", 0.25), ("call_fidelity", 0.15)],
    },
    {
        "key": "data_structure_accuracy",
        "label": "数据结构准确性",
        "color_hint": "structure",
        "description": "类型、结构体和参数含义还原合理",
        "formula": "0.55*type_struct_fidelity + 0.25*call_fidelity + 0.20*completeness",
        "terms": [("type_struct_fidelity", 0.55), ("call_fidelity", 0.25), ("completeness", 0.2)],
    },
    {
        "key": "readability",
        "label": "可读性",
        "color_hint": "readability",
        "description": "命名、代码结构和表达便于人工审查",
        "formula": "0.45*completeness + 0.35*type_struct_fidelity + 0.20*call_fidelity",
        "terms": [("completeness", 0.45), ("type_struct_fidelity", 0.35), ("call_fidelity", 0.2)],
    },
]


def _quality_level(score: int) -> tuple[str, str]:
    if score >= 90:
        return "excellent", "优秀"
    if score >= 80:
        return "good", "良好"
    if score >= 70:
        return "usable", "可用"
    return "needs_work", "待优化"


def _verdict_label(verdict: str) -> str:
    verdict = (verdict or "UNKNOWN").upper()
    return "通过" if verdict == "PASS" else "失败" if verdict == "FAIL" else "未知"


def _dimension_score(radar: ReviewAnalyticsRadar, terms: list[tuple[str, float]]) -> int:
    total_weight = sum(weight for _, weight in terms)
    weighted = sum(float(getattr(radar, key, 0) or 0) * weight for key, weight in terms)
    return round(weighted / total_weight) if total_weight else 0


def _build_review_dimensions(radar: list[ReviewAnalyticsRadar]) -> list[ReviewAnalyticsDimension]:
    if not radar:
        return []
    dimensions: list[ReviewAnalyticsDimension] = []
    final_radar = radar[-1]
    for group in QUALITY_DIMENSION_GROUPS:
        points = [ReviewAnalyticsTrendPoint(attempt_no=round_.attempt_no, label=f"第{round_.attempt_no}轮", score=_dimension_score(round_, group["terms"])) for round_ in radar]
        initial_score = points[0].score if points else 0
        final_score = points[-1].score if points else 0
        delta = max(0, final_score - initial_score)
        delta_percent = round(delta / initial_score * 100) if initial_score > 0 else 0
        level, level_label = _quality_level(final_score)
        components = {key: int(getattr(final_radar, key, 0) or 0) for key, _ in group["terms"]}
        dimensions.append(ReviewAnalyticsDimension(
            key=group["key"], label=group["label"], score=final_score, initial_score=initial_score,
            delta=delta, delta_percent=delta_percent, level=level, level_label=level_label,
            description=group["description"], formula=group["formula"], color_hint=group["color_hint"],
            points=points, components=components,
        ))
    return dimensions


def _quality_scores_from_dimensions(dimensions: list[ReviewAnalyticsDimension], fallback_initial: int = 0, fallback_final: int = 0) -> tuple[int, int, int, int, str, str]:
    if dimensions:
        initial = round(sum(item.initial_score for item in dimensions) / len(dimensions))
        final = round(sum(item.score for item in dimensions) / len(dimensions))
    else:
        initial, final = fallback_initial, fallback_final
    delta = max(0, final - initial)
    delta_percent = round(delta / initial * 100) if initial > 0 else 0
    level, label = _quality_level(final)
    return initial, final, delta, delta_percent, level, label


def _build_review_trend_insight(attempts: list[ReviewAnalyticsAttempt], dimensions: list[ReviewAnalyticsDimension] | None = None) -> ReviewAnalyticsTrendInsight:
    if not attempts:
        return ReviewAnalyticsTrendInsight()
    first = attempts[0]
    final = attempts[-1]
    if dimensions:
        first_score, final_score, delta, _, _, _ = _quality_scores_from_dimensions(dimensions, int(first.semantic_score or first.confidence or 0), int(final.semantic_score or final.confidence or 0))
    else:
        first_score = int(first.quality_score or first.semantic_score or first.confidence or 0)
        final_score = int(final.quality_score or final.semantic_score or final.confidence or 0)
        delta = final_score - first_score
    series = [ReviewAnalyticsTrendSeries(key=item.key, label=item.label, color_hint=item.color_hint, points=item.points) for item in dimensions or []]
    if len(attempts) < 2:
        title = "等待下一轮评审"
        conclusion = "当前仅有 1 轮评审数据，建议结合后续轮次观察质量变化。"
        tone = "neutral"
    elif delta >= 20:
        title = "质量显著提升"
        conclusion = f"经过 {len(attempts)} 轮评审修复，语义质量从 {first_score} 提升至 {final_score}，累计提升 {delta} 分。"
        tone = "positive"
    elif delta >= 8:
        title = "质量稳步提升"
        conclusion = f"经过 {len(attempts)} 轮评审修复，语义质量提升 {delta} 分，整体趋势向好。"
        tone = "positive"
    elif delta >= 0:
        title = "质量基本稳定"
        conclusion = f"{len(attempts)} 轮评审后质量保持稳定，最终语义质量为 {final_score}。"
        tone = "neutral"
    else:
        title = "质量出现回落"
        conclusion = f"最近轮次语义质量较初始下降 {abs(delta)} 分，建议优先复核新引入的问题。"
        tone = "warning"
    return ReviewAnalyticsTrendInsight(title=title, conclusion=conclusion, tone=tone, primary_metric="质量分", first_score=first_score, final_score=final_score, delta=delta, series=series)


def _finalize_review_analytics(task_id: str, item_id: str, attempts: list[ReviewAnalyticsAttempt], issues: list[ReviewAnalyticsIssue], matrix: list[ReviewAnalyticsFunction], radar: list[ReviewAnalyticsRadar], *, final_verdict: str, final_confidence: int, closure: float, residual: str) -> ReviewAnalyticsResponse:
    for issue in issues:
        issue.display_label = issue.display_label or ISSUE_LABELS.get(issue.label, issue.label)
        issue.description = issue.description or ISSUE_DETAILS.get(issue.label, f"{issue.category} · {issue.severity}")
        issue.category_label = issue.category_label or CATEGORY_LABELS.get(issue.category, issue.category)
        issue.severity_label = issue.severity_label or SEVERITY_LABELS.get(issue.severity, issue.severity)
        issue.status_label = issue.status_label or STATUS_LABELS.get(issue.status, issue.status)

    dimensions = _build_review_dimensions(radar)
    fallback_initial = attempts[0].semantic_score if attempts else 0
    fallback_final = attempts[-1].semantic_score if attempts else final_confidence
    initial_quality, final_quality, quality_delta, quality_delta_percent, _, final_quality_label = _quality_scores_from_dimensions(dimensions, fallback_initial, fallback_final)

    for attempt in attempts:
        discovered = sum(1 for issue in issues if issue.introduced_attempt == attempt.attempt_no)
        resolved_at = sum(1 for issue in issues if issue.resolved_attempt == attempt.attempt_no)
        open_after = sum(1 for issue in issues if issue.introduced_attempt <= attempt.attempt_no and (not issue.resolved_attempt or issue.resolved_attempt > attempt.attempt_no))
        round_radar = next((item for item in radar if item.attempt_no == attempt.attempt_no), None)
        round_dimensions = _build_review_dimensions([round_radar]) if round_radar else []
        round_quality = round(sum(item.score for item in round_dimensions) / len(round_dimensions)) if round_dimensions else (attempt.semantic_score or attempt.confidence or 0)
        attempt.label = attempt.label or f"第 {attempt.attempt_no} 轮"
        attempt.verdict_label = attempt.verdict_label or _verdict_label(attempt.verdict)
        attempt.quality_score = round_quality
        attempt.issues_discovered = discovered
        attempt.issues_resolved = resolved_at
        attempt.issues_open_after_attempt = open_after
        attempt.status_label = attempt.status_label or ("最终轮" if attempt is attempts[-1] else "已通过" if attempt.verdict == "PASS" else "需修复")

    resolved_count = sum(1 for issue in issues if issue.status == "resolved")
    remaining_count = sum(1 for issue in issues if issue.status != "resolved")
    trend = _build_review_trend_insight(attempts, dimensions)
    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return ReviewAnalyticsResponse(
        task_id=task_id,
        item_id=item_id,
        status="ready",
        meta=ReviewAnalyticsMeta(generated_at=generated_at),
        summary=ReviewAnalyticsSummary(
            attempts=len(attempts), attempt_count=len(attempts), final_verdict=final_verdict,
            final_verdict_label=_verdict_label(final_verdict), final_confidence=final_confidence,
            final_quality_score=final_quality, final_quality_label=final_quality_label,
            initial_quality_score=initial_quality, quality_delta=quality_delta, quality_delta_percent=quality_delta_percent,
            issue_total=len(issues), issue_resolved=resolved_count, issue_remaining=remaining_count,
            issue_closure_rate=closure, residual_risk=residual, residual_risk_label=RISK_LABELS.get(residual, residual),
        ),
        attempts=attempts,
        issues=issues,
        dimensions=dimensions,
        trend=trend,
        function_matrix=matrix,
        radar=radar,
        trend_insight=trend,
    )
def _parse_review_file(file: AdvancedFile) -> dict:
    try:
        data = json.loads(file.content or "{}")
    except Exception:
        data = {}
    verdict = str(data.get("verdict") or "UNKNOWN").upper()
    issues = [str(issue) for issue in data.get("issues") or [] if str(issue).strip()]
    total = int(data.get("total_functions") or 0)
    verified = int(data.get("verified_functions") or 0)
    attempt_no = file.attempt_no or _attempt_no(file.name) or 0
    ratio = verified / total if total else (1 if verdict == "PASS" else 0)
    score = max(0, min(100, round(ratio * 100) - len(issues) * 8 + (0 if verdict == "PASS" else -8)))
    return {"attempt_no": attempt_no, "verdict": verdict, "issues": issues, "total": total, "verified": verified, "score": score}


def _review_issue_key(issue: str) -> tuple[str, str, str]:
    function_match = re.search(r"\b([A-Za-z_.][\w.]*)\s*:", issue)
    function_name = function_match.group(1) if function_match else "global"
    lower = issue.lower()
    if "return" in lower:
        category, label = "Return", "Return Code"
    elif "length" in lower:
        category, label = "Validation", "Length Logic"
    elif "hex_len" in lower or "validation" in lower:
        category, label = "Validation", "Extra Check"
    elif "call" in lower:
        category, label = "Call", "Call"
    elif "struct" in lower or "type" in lower:
        category, label = "Type", "Type"
    else:
        category, label = "Semantic", "Semantic"
    return function_name, category, label


def build_task_item_review_analytics(item: B2STaskItem) -> ReviewAnalyticsResponse:
    advanced = build_task_item_advanced(item, include_content=True)
    review_files = [review for run in advanced.runs for batch in run.batches for review in batch.reviews]
    parsed = [_parse_review_file(file) for file in review_files]
    parsed = [entry for entry in parsed if entry["attempt_no"]]
    parsed.sort(key=lambda entry: entry["attempt_no"])
    if not parsed:
        return _empty_review_analytics(item)
    attempts = [ReviewAnalyticsAttempt(attempt_no=entry["attempt_no"], verdict=entry["verdict"], total_functions=entry["total"], verified_functions=entry["verified"], blocking_issues=len(entry["issues"]), semantic_score=entry["score"], confidence=max(0, min(100, entry["score"] + (10 if entry["verdict"] == "PASS" else -4)))) for entry in parsed]
    final = parsed[-1]
    final_keys = {_review_issue_key(issue) for issue in final["issues"]}
    first_seen: dict[tuple[str, str, str], tuple[str, int]] = {}
    for entry in parsed:
        for issue in entry["issues"]:
            first_seen.setdefault(_review_issue_key(issue), (issue, entry["attempt_no"]))
    issues: list[ReviewAnalyticsIssue] = []
    for idx, (key, (_, first_attempt)) in enumerate(first_seen.items(), start=1):
        function_name, category, label = key
        remaining = key in final_keys
        resolved_attempt = None if remaining else next((entry["attempt_no"] for entry in parsed if entry["attempt_no"] > first_attempt and key not in {_review_issue_key(candidate) for candidate in entry["issues"]}), None)
        issues.append(ReviewAnalyticsIssue(id=f"I{idx}", label=label, function=function_name, category=category, severity="blocking", introduced_attempt=first_attempt, resolved_attempt=resolved_attempt, status="remaining" if remaining else "resolved"))
    function_names = {issue.function for issue in issues}
    for run in advanced.runs:
        for batch in run.batches:
            source = (batch.source.content if batch.source else None) or (batch.review_snapshots[-1].content if batch.review_snapshots else "") or ""
            for match in re.finditer(r"(?:^|\n)(?:[\w\s_*]+\s+)?([A-Za-z_.][\w.]*)\s*\([^;{}]*\)\s*\{", source):
                function_names.add(match.group(1))
    matrix = []
    for name in list(function_names)[:24]:
        cells = []
        for entry in parsed:
            hits = sum(1 for issue in entry["issues"] if _review_issue_key(issue)[0] == name)
            cells.append(ReviewAnalyticsFunctionAttempt(attempt_no=entry["attempt_no"], risk="critical" if hits else ("passed" if entry["verdict"] == "PASS" else "unknown"), score=max(0, 42 - hits * 8) if hits else (95 if entry["verdict"] == "PASS" else 82)))
        matrix.append(ReviewAnalyticsFunction(function=name, attempts=cells))
    radar = []
    for entry in parsed:
        categories = {_review_issue_key(issue)[1] for issue in entry["issues"]}
        radar.append(ReviewAnalyticsRadar(attempt_no=entry["attempt_no"], completeness=round((entry["verified"] / entry["total"] * 100) if entry["total"] else (100 if entry["verdict"] == "PASS" else 0)), control_flow=94 if entry["verdict"] == "PASS" else 72, return_semantics=45 if "Return" in categories else 94, input_validation=42 if "Validation" in categories else 94, call_fidelity=92, type_struct_fidelity=88))
    resolved = sum(1 for issue in issues if issue.status == "resolved")
    closure = resolved / len(issues) if issues else (1.0 if final["verdict"] == "PASS" else 0.0)
    confidence = max(0, min(100, round(final["score"] * 0.42 + closure * 38 + (14 if final["verdict"] == "PASS" else 0) + min(len(parsed), 3) * 2)))
    residual = "high" if final["verdict"] != "PASS" or final["issues"] else ("low" if confidence >= 92 else "low-medium" if confidence >= 82 else "medium")
    return _finalize_review_analytics(item.task_id, item.id, attempts, issues, matrix, radar, final_verdict=final["verdict"], final_confidence=confidence, closure=closure, residual=residual)


def build_task_item_advanced(item: B2STaskItem, include_content: bool = True) -> TaskItemAdvancedResponse:
    output_dir = Path(item.output_dir)
    base = output_dir.resolve()
    work_dirs = sorted([p for p in output_dir.glob(".re_work_*") if p.is_dir()], key=lambda p: p.name)
    work_dir = work_dirs[-1] if work_dirs else None
    runs: list[AdvancedRun] = []
    ida_files: list[AdvancedFile] = []
    if work_dir:
        ida_root = work_dir / "ida_cache"
        if ida_root.exists():
            ida_paths = [p for p in ida_root.rglob("*") if p.is_file() and p.suffix.lower() in ADVANCED_TEXT_EXTENSIONS]
            ida_files = [file for path in sorted(ida_paths) if (file := _safe_read_advanced_file(path, base, include_content, _ida_file_meta(path)))]
        runs_root = work_dir / "runs"
        run_dirs = sorted([p for p in runs_root.iterdir() if p.is_dir()], key=lambda p: p.name) if runs_root.exists() else []
        for run_dir in run_dirs:
            batch_map: dict[int, AdvancedBatch] = {}
            for batch_path in sorted(run_dir.glob("batch_*.c")):
                no = _batch_no(batch_path) or 0
                batch_map.setdefault(no, AdvancedBatch(name=f"batch_{no:03d}", batch_no=no)).source = _safe_read_advanced_file(batch_path, base, include_content, _stage4_meta(no or None, section="执行", section_order=10, round_label="执行输出", round_order=0, agent="executor agent", role="batch 输出"))
            for disasm_path in sorted(run_dir.glob("disasm_batch_*.c")):
                no = _batch_no(disasm_path) or 0
                batch_map.setdefault(no, AdvancedBatch(name=f"batch_{no:03d}", batch_no=no)).disasm = _safe_read_advanced_file(disasm_path, base, include_content, {"stage": "阶段 2 · Batch 上下文切片", "stage_order": 2000, "section": "文件", "section_order": 0, "round": _batch_label(no or None), "round_order": no, "role": "反编译上下文", "batch_no": no or None})
            review_dir = run_dir / "review_snapshots"
            if review_dir.exists():
                for review_path in sorted(review_dir.iterdir()):
                    if not review_path.is_file():
                        continue
                    no = _batch_no(review_path) or 0
                    attempt_no = _attempt_no(review_path) or 0
                    role = "评审输出" if review_path.name.endswith(".verdict.json") else "评审输入"
                    file = _safe_read_advanced_file(review_path, base, include_content, _stage4_meta(no or None, section="评审", section_order=20, round_label=f"第 {attempt_no} 次评审" if attempt_no else "评审轮次", round_order=attempt_no, agent="validator agent", role=role, attempt_no=attempt_no or None))
                    if not file:
                        continue
                    batch = batch_map.setdefault(no, AdvancedBatch(name=f"batch_{no:03d}", batch_no=no))
                    if review_path.name.endswith(".verdict.json"):
                        batch.reviews.append(file)
                    else:
                        batch.review_snapshots.append(file)
            session_dir = run_dir / "agent_sessions"
            session_paths = sorted([p for p in session_dir.rglob("*") if p.is_file()]) if session_dir.exists() else []
            single_batch_no = next(iter(batch_map.keys())) if len(batch_map) == 1 else None
            session_files = [file for path in session_paths if (file := _safe_read_advanced_file(path, base, include_content, _session_meta(path, run_dir, single_batch_no)))]
            misc_paths = [p for p in run_dir.iterdir() if p.is_file() and p.name not in {"preamble.h"} and not p.name.startswith("batch_") and not p.name.startswith("disasm_batch_")]
            preamble = run_dir / "preamble.h"
            if preamble.exists():
                misc_paths.insert(0, preamble)
            runs.append(AdvancedRun(
                name=run_dir.name,
                path=str(run_dir),
                batches=[batch_map[key] for key in sorted(batch_map)],
                agent_sessions=session_files,
                files=[file for path in misc_paths if (file := _safe_read_advanced_file(path, base, include_content, _run_file_meta(path)))],
            ))
    mode, mode_label = task_mode_summary([item])
    return TaskItemAdvancedResponse(
        task_id=item.task_id,
        item_id=item.id,
        sequence_no=item.sequence_no,
        mode=mode,
        mode_label=mode_label,
        output_dir=item.output_dir,
        work_dir=str(work_dir) if work_dir else None,
        runs=runs,
        ida_files=ida_files,
    )


def _artifact_id(path: str) -> str:
    return hashlib.sha256(path.encode("utf-8")).hexdigest()[:24]


def _artifact_mime_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "application/json"
    if suffix == ".jsonl":
        return "application/x-jsonlines"
    if suffix in {".c", ".h"}:
        return "text/x-c"
    if suffix == ".md":
        return "text/markdown"
    return "text/plain"


def _iter_advanced_files(advanced: TaskItemAdvancedResponse) -> list[AdvancedFile]:
    files: list[AdvancedFile] = []
    files.extend(advanced.ida_files)
    for run in advanced.runs:
        files.extend(run.files)
        files.extend(run.agent_sessions)
        for batch in run.batches:
            for file in [batch.disasm, batch.source]:
                if file:
                    files.append(file)
            files.extend(batch.review_snapshots)
            files.extend(batch.reviews)
    return files


def build_task_item_artifacts(item: B2STaskItem) -> TaskItemArtifactsResponse:
    advanced = build_task_item_advanced(item, include_content=False)
    base = Path(advanced.output_dir).resolve()
    artifacts: list[B2SArtifact] = []
    for file in _iter_advanced_files(advanced):
        try:
            relative_path = str(Path(file.path).resolve().relative_to(base))
        except Exception:
            relative_path = file.name
        artifact_id = _artifact_id(file.path)
        content_url = f"/api/app/binary-to-source/projects/{item.project_id}/tasks/{item.task_id}/items/{item.id}/artifacts/{artifact_id}/content"
        artifacts.append(B2SArtifact(
            id=artifact_id, name=file.name, path=file.path, relative_path=relative_path, kind=file.kind, size=file.size,
            stage=file.stage, stage_order=file.stage_order, section=file.section, section_order=file.section_order,
            round=file.round, round_order=file.round_order, agent=file.agent, role=file.role, batch_no=file.batch_no,
            attempt_no=file.attempt_no, content_url=content_url,
        ))
    return TaskItemArtifactsResponse(
        task_id=item.task_id,
        item_id=item.id,
        output_dir=advanced.output_dir,
        work_dir=advanced.work_dir,
        artifacts=sorted(artifacts, key=lambda file: ((file.stage_order or 0), (file.section_order or 0), (file.round_order or 0), file.relative_path)),
        counts={
            "artifacts": len(artifacts),
            "batches": sum(len(run.batches) for run in advanced.runs),
            "reviews": sum(len(batch.reviews) + len(batch.review_snapshots) for run in advanced.runs for batch in run.batches),
            "sessions": sum(len(run.agent_sessions) for run in advanced.runs),
            "ida_files": len(advanced.ida_files),
        },
    )


def build_task_item_artifact_content(item: B2STaskItem, artifact_id: str, offset: int = 0, limit: int = ADVANCED_MAX_BYTES) -> B2SArtifactContentResponse:
    advanced = build_task_item_advanced(item, include_content=False)
    file = next((candidate for candidate in _iter_advanced_files(advanced) if _artifact_id(candidate.path) == artifact_id), None)
    if not file:
        raise NotFoundError("产物文件不存在")
    path = Path(file.path).resolve()
    base = Path(advanced.output_dir).resolve()
    try:
        path.relative_to(base)
    except Exception as exc:
        raise ValidationError("产物路径越界") from exc
    if not path.is_file():
        raise NotFoundError("产物文件不存在")
    safe_offset = max(0, int(offset or 0))
    safe_limit = max(1, min(int(limit or ADVANCED_MAX_BYTES), ADVANCED_MAX_BYTES))
    size = path.stat().st_size
    with path.open("rb") as fp:
        fp.seek(safe_offset)
        raw = fp.read(safe_limit + 1)
    truncated = len(raw) > safe_limit
    content = raw[:safe_limit].decode("utf-8", errors="replace")
    next_offset = safe_offset + safe_limit if truncated or safe_offset + len(raw[:safe_limit]) < size else None
    return B2SArtifactContentResponse(
        artifact_id=artifact_id,
        name=file.name,
        path=str(path),
        kind=file.kind,
        mime_type=_artifact_mime_type(path),
        size=size,
        offset=safe_offset,
        limit=safe_limit,
        content=content,
        truncated=bool(next_offset),
        next_offset=next_offset,
    )


def _safe_iso(dt: datetime | None) -> str | None:
    return isoformat_local(dt) if dt else None


def _session_relative_to_output(item: B2STaskItem, full_path: str) -> str:
    try:
        return str(Path(full_path).resolve().relative_to(Path(item.output_dir).resolve()))
    except Exception:
        return Path(full_path).name


def build_task_session_index(items: list[B2STaskItem]) -> SessionIndexResponse:
    nodes: list[SessionIndexNode] = []
    warnings: list[str] = []
    for item in items:
        try:
            advanced = build_task_item_advanced(item, include_content=False)
            is_active = item.status not in TERMINAL
            item_name = Path(item.elf_path).name
            for run in advanced.runs:
                for session in run.agent_sessions:
                    nodes.append(SessionIndexNode(
                        node_id=f"{item.id}:{hashlib.md5(session.path.encode('utf-8')).hexdigest()[:12]}",
                        item_id=item.id,
                        sequence_no=item.sequence_no,
                        item_name=item_name,
                        run_name=run.name,
                        stage=session.stage or "Agent 会话",
                        stage_order=int(session.stage_order or 0),
                        section=session.section,
                        round=session.round,
                        round_order=session.round_order,
                        agent=session.agent,
                        role=session.role,
                        batch_no=session.batch_no,
                        attempt_no=session.attempt_no,
                        relative_path=_session_relative_to_output(item, session.path),
                        full_path=session.path,
                        size=session.size,
                        updated_at=_safe_iso(item.updated_at),
                        is_active=is_active,
                        kind=session.kind,
                    ))
        except Exception as exc:
            warnings.append(f"item #{item.sequence_no} 会话索引构建失败: {exc}")
    nodes.sort(key=lambda node: (node.sequence_no, node.stage_order, node.run_name, node.batch_no or 0, node.attempt_no or 0, node.relative_path))
    return SessionIndexResponse(
        task_id=items[0].task_id if items else "",
        nodes=nodes,
        warnings=warnings,
        generated_at=isoformat_local(now_local()),
    )


def build_task_session_file(items: list[B2STaskItem], relative_path: str, offset: int = 0, limit: int = ADVANCED_MAX_BYTES) -> SessionFileResponse:
    normalized = str(relative_path or "").replace("\\", "/").lstrip("/")
    if not normalized:
        raise NotFoundError("会话文件路径不能为空")
    for item in items:
        candidate = Path(item.output_dir).joinpath(normalized).resolve()
        try:
            candidate.relative_to(Path(item.output_dir).resolve())
        except Exception:
            continue
        if not candidate.is_file():
            continue
        size = candidate.stat().st_size
        safe_offset = max(0, int(offset or 0))
        safe_limit = max(1, min(int(limit or ADVANCED_MAX_BYTES), ADVANCED_MAX_BYTES))
        with candidate.open("rb") as fp:
            fp.seek(safe_offset)
            raw = fp.read(safe_limit + 1)
        truncated = len(raw) > safe_limit
        content = raw[:safe_limit].decode("utf-8", errors="replace")
        next_offset = safe_offset + safe_limit if truncated or safe_offset + len(raw[:safe_limit]) < size else None
        suffix = candidate.suffix.lower()
        mime_type = "application/json" if suffix in {".json", ".jsonl"} else "text/markdown" if suffix == ".md" else "text/plain"
        return SessionFileResponse(
            task_id=item.task_id,
            relative_path=normalized,
            full_path=str(candidate),
            size=size,
            content=content,
            truncated=bool(next_offset),
            next_offset=next_offset,
            offset=safe_offset,
            limit=safe_limit,
            mime_type=mime_type,
        )
    raise NotFoundError("会话文件不存在")


def _count_item_sessions(advanced: TaskItemAdvancedResponse) -> int:
    return sum(len(run.agent_sessions) for run in advanced.runs)


def _count_item_reviews(advanced: TaskItemAdvancedResponse) -> int:
    return sum(len(batch.reviews) for run in advanced.runs for batch in run.batches)


def _count_item_batches(advanced: TaskItemAdvancedResponse) -> int:
    return sum(len(run.batches) for run in advanced.runs)


def _item_duration_ms(item: B2STaskItem) -> int | None:
    if not item.started_at:
        return None
    end = item.finished_at or now_local()
    delta = end - item.started_at
    return max(0, int(delta.total_seconds() * 1000))


def _empty_review_analytics(item: B2STaskItem) -> ReviewAnalyticsResponse:
    return ReviewAnalyticsResponse(
        task_id=item.task_id,
        item_id=item.id,
        status="empty",
        meta=ReviewAnalyticsMeta(generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), data_quality="empty"),
        summary=ReviewAnalyticsSummary(
            attempts=0,
            attempt_count=0,
            final_verdict="UNKNOWN",
            final_verdict_label="未评审",
            final_confidence=0,
            final_quality_score=0,
            final_quality_label="暂无",
            initial_quality_score=0,
            quality_delta=0,
            quality_delta_percent=0,
            issue_total=0,
            issue_resolved=0,
            issue_remaining=0,
            issue_closure_rate=0,
            residual_risk="unknown",
            residual_risk_label="未知",
        ),
        attempts=[],
        issues=[],
        dimensions=[],
        trend=None,
        function_matrix=[],
        radar=[],
        trend_insight=None,
    )


def _task_level_review_analytics(item: B2STaskItem, advanced: TaskItemAdvancedResponse | None = None) -> ReviewAnalyticsResponse:
    loaded = advanced or build_task_item_advanced(item, include_content=True)
    has_reviews = any(batch.reviews for run in loaded.runs for batch in run.batches)
    if not has_reviews:
        return _empty_review_analytics(item)
    return build_task_item_review_analytics(item)


def build_task_result_summary(items: list[B2STaskItem]) -> TaskResultSummary:
    summaries: list[TaskResultItemSummary] = []
    total_result_files = 0
    total_sessions = 0
    total_review_rounds = 0
    success_items = partial_items = failed_items = cancelled_items = 0
    for item in items:
        advanced = build_task_item_advanced(item, include_content=False)
        analytics = _task_level_review_analytics(item)
        artifact_paths = normalize_generated_files(item)
        result_file_count = len(artifact_paths)
        total_result_files += result_file_count
        session_count = _count_item_sessions(advanced)
        total_sessions += session_count
        review_round_count = int(analytics.summary.attempt_count or analytics.summary.attempts or 0)
        total_review_rounds += review_round_count
        if item.status == "success":
            success_items += 1
        elif item.status == "failed":
            failed_items += 1
        elif item.status == "cancelled":
            cancelled_items += 1
        elif item.status == "completed":
            partial_items += 1
        summaries.append(TaskResultItemSummary(
            item_id=item.id,
            sequence_no=item.sequence_no,
            item_name=Path(item.elf_path).name,
            elf_path=item.elf_path,
            output_dir=item.output_dir,
            status=item.status,
            result_file_count=result_file_count,
            key_result_files=artifact_paths[:6],
            session_file_count=session_count,
            review_round_count=review_round_count,
            final_verdict=analytics.summary.final_verdict,
            final_verdict_label=analytics.summary.final_verdict_label,
        ))
    return TaskResultSummary(
        task_id=items[0].task_id if items else "",
        success_items=success_items,
        partial_items=partial_items,
        failed_items=failed_items,
        cancelled_items=cancelled_items,
        result_file_count=total_result_files,
        session_file_count=total_sessions,
        review_round_count=total_review_rounds,
        items=sorted(summaries, key=lambda entry: entry.sequence_no),
    )


def build_agent_runtime_summary(items: list[B2STaskItem]) -> AgentRuntimeSummary:
    active_agents: list[AgentRuntimeEntry] = []
    total_sessions = 0
    for item in items:
        if item.status in TERMINAL:
            continue
        advanced = build_task_item_advanced(item, include_content=False)
        item_name = Path(item.elf_path).name
        for run in advanced.runs:
            for session in run.agent_sessions:
                total_sessions += 1
                active_agents.append(AgentRuntimeEntry(
                    key=f"{item.id}:{session.path}",
                    label=session.agent or session.role or session.name,
                    item_id=item.id,
                    sequence_no=item.sequence_no,
                    item_name=item_name,
                    run_name=run.name,
                    stage=session.stage,
                    agent=session.agent,
                    role=session.role,
                    batch_no=session.batch_no,
                    attempt_no=session.attempt_no,
                    relative_path=_session_relative_to_output(item, session.path),
                    full_path=session.path,
                    updated_at=_safe_iso(item.updated_at),
                    is_active=True,
                    size=session.size,
                ))
    def _count_by(keyword: str) -> int:
        return sum(1 for entry in active_agents if keyword in str(entry.agent or "").lower())
    return AgentRuntimeSummary(
        total_sessions=total_sessions,
        active_agent_count=len(active_agents),
        header_agent_count=_count_by("header"),
        executor_agent_count=_count_by("executor"),
        validator_agent_count=_count_by("validator"),
        active_agents=active_agents[:24],
    )


def build_business_runtime_metrics_summary(items: list[B2STaskItem]) -> dict[str, Any]:
    available = 0
    missing = 0
    terminal_available = 0
    running_available = 0
    missing_reasons: dict[str, int] = {}
    status_distribution: dict[str, int] = {}
    phase_totals: dict[str, float] = {}
    phase_counts: dict[str, int] = {}
    running_phase_totals: dict[str, float] = {}
    running_phase_counts: dict[str, int] = {}
    artifact_totals: dict[str, float] = {}
    engines: dict[str, int] = {}
    batch_count = passed_batches = failed_batches = 0
    total_attempts = 0
    total_functions = completed_functions = failed_functions = 0
    throughput_values: list[float] = []
    token_totals: dict[str, float] = {"input": 0.0, "output": 0.0, "cache_read": 0.0, "cache_write": 0.0, "cost": 0.0}

    for item in items:
        metadata = item.extra_metadata if isinstance(item.extra_metadata, dict) else {}
        metrics = metadata.get("pi_runtime_metrics")
        if not isinstance(metrics, dict):
            missing += 1
            reason = str(metadata.get("pi_runtime_metric_missing_reason") or _pi_runtime_metric_missing_reason(item))
            missing_reasons[reason] = missing_reasons.get(reason, 0) + 1
            continue
        available += 1
        engine = str(metrics.get("engine") or "unknown")
        engines[engine] = engines.get(engine, 0) + 1
        metric_status = str(metrics.get("status") or item.status or "unknown").strip().lower()
        if metric_status == "completed":
            metric_status = "success"
        if metric_status not in TERMINAL and str(item.status or "").lower() in TERMINAL:
            metric_status = str(item.status or "unknown").lower()
        status_distribution[metric_status] = status_distribution.get(metric_status, 0) + 1
        is_terminal_metric = metric_status in TERMINAL
        if is_terminal_metric:
            terminal_available += 1
        elif metric_status == "running":
            running_available += 1
        phases = metrics.get("phase_durations_seconds") if isinstance(metrics.get("phase_durations_seconds"), dict) else {}
        for phase, value in phases.items():
            try:
                duration = float(value or 0)
            except Exception:
                duration = 0.0
            if duration <= 0:
                continue
            if is_terminal_metric:
                phase_totals[str(phase)] = phase_totals.get(str(phase), 0.0) + duration
                phase_counts[str(phase)] = phase_counts.get(str(phase), 0) + 1
            elif metric_status == "running":
                running_phase_totals[str(phase)] = running_phase_totals.get(str(phase), 0.0) + duration
                running_phase_counts[str(phase)] = running_phase_counts.get(str(phase), 0) + 1

        batch_summary = metrics.get("batch_summary") if isinstance(metrics.get("batch_summary"), dict) else {}
        if is_terminal_metric:
            batch_count += int(batch_summary.get("batch_count") or 0)
            passed_batches += int(batch_summary.get("passed_batches") or 0)
            failed_batches += int(batch_summary.get("failed_batches") or 0)
            total_attempts += int(batch_summary.get("total_attempts") or 0)

        function_summary = metrics.get("function_summary") if isinstance(metrics.get("function_summary"), dict) else {}
        if is_terminal_metric:
            total_functions += int(function_summary.get("total_functions") or 0)
            completed_functions += int(function_summary.get("completed_functions") or 0)
            failed_functions += int(function_summary.get("failed_functions") or 0)
        try:
            throughput = float(function_summary.get("functions_per_second") or 0)
        except Exception:
            throughput = 0.0
        if is_terminal_metric and throughput > 0:
            throughput_values.append(throughput)

        artifact_summary = metrics.get("artifact_summary") if isinstance(metrics.get("artifact_summary"), dict) else {}
        for kind, value in artifact_summary.items():
            try:
                artifact_totals[str(kind)] = artifact_totals.get(str(kind), 0.0) + float(value or 0)
            except Exception:
                artifact_totals[str(kind)] = artifact_totals.get(str(kind), 0.0)

        llm_summary = metrics.get("llm_summary") if isinstance(metrics.get("llm_summary"), dict) else {}
        for key in token_totals:
            try:
                token_totals[key] += float(llm_summary.get(key) or 0)
            except Exception:
                pass

    phase_averages = {
        phase: round(total / max(1, phase_counts.get(phase, 0)), 6)
        for phase, total in sorted(phase_totals.items())
    }
    running_phase_averages = {
        phase: round(total / max(1, running_phase_counts.get(phase, 0)), 6)
        for phase, total in sorted(running_phase_totals.items())
    }
    return {
        "available_items": available,
        "missing_items": missing,
        "coverage": {
            "total_items": len(items),
            "available_items": available,
            "missing_items": missing,
            "coverage_rate": round(available / len(items), 6) if items else 0,
            "terminal_available_items": terminal_available,
            "running_available_items": running_available,
        },
        "missing_reasons": missing_reasons,
        "sample_status_distribution": status_distribution,
        "engines": engines,
        "phase_average_seconds": phase_averages,
        "running_phase_average_seconds": running_phase_averages,
        "header_recovery_avg_seconds": phase_averages.get("header_synthesis", 0),
        "body_recovery_avg_seconds": phase_averages.get("body_generation", 0),
        "batch_summary": {
            "batch_count": batch_count,
            "passed_batches": passed_batches,
            "failed_batches": failed_batches,
            "total_attempts": total_attempts,
            "retry_rate": round(max(0, total_attempts - batch_count) / total_attempts, 6) if total_attempts else 0,
            "validation_pass_rate": round(passed_batches / batch_count, 6) if batch_count else 0,
            "failure_rate": round(failed_batches / batch_count, 6) if batch_count else 0,
            "avg_attempts_per_batch": round(total_attempts / batch_count, 6) if batch_count else 0,
        },
        "function_summary": {
            "total_functions": total_functions,
            "completed_functions": completed_functions,
            "failed_functions": failed_functions,
            "avg_functions_per_second": round(mean(throughput_values), 6) if throughput_values else 0,
        },
        "llm_summary": token_totals,
        "artifact_summary": artifact_totals,
    }


def build_task_observability_summary(items: list[B2STaskItem]) -> TaskObservabilitySummary:
    rows: list[TaskObservabilityItem] = []
    durations: list[int] = []
    total_batches = total_sessions = total_attempts = 0
    passed_items = issue_total = issue_resolved = issue_remaining = 0
    confidence_scores: list[int] = []
    quality_scores: list[int] = []
    risk_distribution: dict[str, int] = {}
    overall_progress = build_overall_progress(items)
    for item in items:
        advanced = build_task_item_advanced(item, include_content=False)
        analytics = _task_level_review_analytics(item)
        duration_ms = _item_duration_ms(item)
        if duration_ms is not None:
            durations.append(duration_ms)
        batch_count = _count_item_batches(advanced)
        session_count = _count_item_sessions(advanced)
        attempt_count = int(analytics.summary.attempt_count or analytics.summary.attempts or 0)
        total_batches += batch_count
        total_sessions += session_count
        total_attempts += attempt_count
        if str(analytics.summary.final_verdict or "").upper() == "PASS":
            passed_items += 1
        issue_total += int(analytics.summary.issue_total or 0)
        issue_resolved += int(analytics.summary.issue_resolved or 0)
        issue_remaining += int(analytics.summary.issue_remaining or 0)
        confidence_scores.append(int(analytics.summary.final_confidence or 0))
        quality_scores.append(int(analytics.summary.final_quality_score or 0))
        risk_key = str(analytics.summary.residual_risk or "unknown")
        risk_distribution[risk_key] = risk_distribution.get(risk_key, 0) + 1
        rows.append(TaskObservabilityItem(
            item_id=item.id,
            sequence_no=item.sequence_no,
            item_name=Path(item.elf_path).name,
            status=item.status,
            duration_ms=duration_ms,
            batch_count=batch_count,
            session_count=session_count,
            attempt_count=attempt_count,
            final_verdict=analytics.summary.final_verdict,
            final_confidence=int(analytics.summary.final_confidence or 0),
            final_quality_score=int(analytics.summary.final_quality_score or 0),
            issue_total=int(analytics.summary.issue_total or 0),
            issue_resolved=int(analytics.summary.issue_resolved or 0),
            issue_remaining=int(analytics.summary.issue_remaining or 0),
        ))
    total_duration_ms = sum(durations) if durations else None
    return TaskObservabilitySummary(
        task_id=items[0].task_id if items else "",
        total_duration_ms=total_duration_ms,
        avg_item_duration_ms=round(mean(durations)) if durations else None,
        total_batches=total_batches,
        avg_batches_per_item=round(total_batches / len(items), 2) if items else 0,
        total_sessions=total_sessions,
        active_agent_count=sum(1 for item in items if item.status not in TERMINAL),
        total_review_attempts=total_attempts,
        avg_review_attempts=round(total_attempts / len(items), 2) if items else 0,
        passed_items=passed_items,
        not_passed_items=max(0, len(items) - passed_items),
        issue_total=issue_total,
        issue_resolved=issue_resolved,
        issue_remaining=issue_remaining,
        issue_closure_rate=(issue_resolved / issue_total) if issue_total else 0,
        completed_functions=int(overall_progress.completed_functions or 0),
        total_functions=int(overall_progress.total_functions or 0),
        completed_bytes=int(overall_progress.completed_bytes or 0),
        total_bytes=int(overall_progress.total_bytes or 0),
        avg_confidence=round(mean(confidence_scores), 1) if confidence_scores else 0,
        avg_quality_score=round(mean(quality_scores), 1) if quality_scores else 0,
        residual_risk_distribution=risk_distribution,
        business_runtime_metrics=build_business_runtime_metrics_summary(items),
        items=sorted(rows, key=lambda entry: entry.sequence_no),
    )


def build_task_relationship(items: list[B2STaskItem]) -> TaskRelationshipResponse:
    nodes: list[RelationshipNode] = []
    edges: list[RelationshipEdge] = []
    warnings: list[str] = []
    node_ids: set[str] = set()
    edge_ids: set[str] = set()
    def add_node(node: RelationshipNode):
        if node.node_id in node_ids:
            return
        node_ids.add(node.node_id)
        nodes.append(node)
    def add_edge(source: str, target: str, kind: str, label: str | None = None):
        edge_id = f"{source}->{target}:{kind}"
        if edge_id in edge_ids:
            return
        edge_ids.add(edge_id)
        edges.append(RelationshipEdge(edge_id=edge_id, source_node_id=source, target_node_id=target, kind=kind, label=label))
    for item in items:
        try:
            advanced = build_task_item_advanced(item, include_content=False)
            item_node_id = f"item:{item.id}"
            add_node(RelationshipNode(
                node_id=item_node_id,
                node_type="item",
                item_id=item.id,
                sequence_no=item.sequence_no,
                title=Path(item.elf_path).name,
                subtitle=f"ELF #{item.sequence_no}",
                status=item.status,
                is_active=item.status not in TERMINAL,
            ))
            for run in advanced.runs:
                run_node_id = f"{item_node_id}:run:{run.name}"
                add_node(RelationshipNode(
                    node_id=run_node_id,
                    node_type="run",
                    item_id=item.id,
                    sequence_no=item.sequence_no,
                    title=run.name,
                    subtitle="执行 Run",
                    status=item.status,
                    is_active=item.status not in TERMINAL,
                ))
                add_edge(item_node_id, run_node_id, "run", "执行")
                for batch in run.batches:
                    batch_no = batch.batch_no or 0
                    batch_node_id = f"{run_node_id}:batch:{batch_no}"
                    add_node(RelationshipNode(
                        node_id=batch_node_id,
                        node_type="batch",
                        item_id=item.id,
                        sequence_no=item.sequence_no,
                        title=_batch_label(batch_no),
                        subtitle="函数批次",
                        status=item.status,
                        batch_no=batch_no or None,
                        is_active=item.status not in TERMINAL,
                    ))
                    add_edge(run_node_id, batch_node_id, "batch", "批次")
                    if batch.source:
                        artifact_node_id = f"{batch_node_id}:artifact:{hashlib.md5(batch.source.path.encode('utf-8')).hexdigest()[:10]}"
                        add_node(RelationshipNode(node_id=artifact_node_id, node_type="artifact", item_id=item.id, sequence_no=item.sequence_no, title=batch.source.name, subtitle="还原源码", status=item.status))
                        add_edge(batch_node_id, artifact_node_id, "artifact", "输出")
                    for review in batch.reviews:
                        review_node_id = f"{batch_node_id}:review:{review.attempt_no or 0}"
                        add_node(RelationshipNode(
                            node_id=review_node_id,
                            node_type="review",
                            item_id=item.id,
                            sequence_no=item.sequence_no,
                            title=review.round or f"第 {review.attempt_no or 0} 轮评审",
                            subtitle=review.name,
                            status=item.status,
                            batch_no=review.batch_no,
                            attempt_no=review.attempt_no,
                        ))
                        add_edge(batch_node_id, review_node_id, "review", "评审")
                    for session in run.agent_sessions:
                        session_node_id = f"{run_node_id}:session:{hashlib.md5(session.path.encode('utf-8')).hexdigest()[:10]}"
                        add_node(RelationshipNode(
                            node_id=session_node_id,
                            node_type="agent",
                            item_id=item.id,
                            sequence_no=item.sequence_no,
                            title=session.agent or session.role or session.name,
                            subtitle=session.round or session.section,
                            status=item.status,
                            relative_path=_session_relative_to_output(item, session.path),
                            full_path=session.path,
                            batch_no=session.batch_no,
                            attempt_no=session.attempt_no,
                            group_key=session.agent,
                            is_active=item.status not in TERMINAL,
                        ))
                        if session.batch_no and batch_no and session.batch_no == batch_no:
                            add_edge(batch_node_id, session_node_id, "session", session.role or "会话")
                        else:
                            add_edge(run_node_id, session_node_id, "session", session.role or "会话")
        except Exception as exc:
            warnings.append(f"item #{item.sequence_no} 关系图构建失败: {exc}")
    return TaskRelationshipResponse(task_id=items[0].task_id if items else "", nodes=nodes, edges=edges, warnings=warnings)


def build_overall_progress(items: list[B2STaskItem]) -> B2SOverallProgress:
    total_items = len(items)
    completed_items = sum(1 for item in items if item.status in TERMINAL)
    phase_summary: dict[str, int] = {}
    total_functions = 0
    completed_functions = 0
    total_bytes = 0
    completed_bytes = 0
    total_batches = 0
    completed_batches = 0
    has_functions = has_bytes = has_batches = False
    for item in items:
        phase = item.phase or (item.progress or {}).get("phase") or item.status
        phase_summary[phase] = phase_summary.get(phase, 0) + 1
        progress = item.progress or {}
        if progress.get("total_functions") is not None:
            has_functions = True
            total_functions += int(progress.get("total_functions") or 0)
            completed_functions += int(progress.get("completed_functions") or 0)
        if progress.get("total_bytes") is not None:
            has_bytes = True
            total_bytes += int(progress.get("total_bytes") or 0)
            completed_bytes += int(progress.get("completed_bytes") or 0)
        if progress.get("total_batches") is not None:
            has_batches = True
            total_batches += int(progress.get("total_batches") or 0)
            completed_batches += int(progress.get("completed_batches") or 0)
    percent = _safe_percent(completed_functions, total_functions) if has_functions else None
    if percent is None and has_batches:
        percent = _safe_percent(completed_batches, total_batches)
    if percent is None and has_bytes:
        percent = _safe_percent(completed_bytes, total_bytes)
    if percent is None:
        percent = _safe_percent(completed_items, total_items)
    return B2SOverallProgress(
        total_items=total_items,
        completed_items=completed_items,
        total_functions=total_functions if has_functions else None,
        completed_functions=completed_functions if has_functions else None,
        total_bytes=total_bytes if has_bytes else None,
        completed_bytes=completed_bytes if has_bytes else None,
        total_batches=total_batches if has_batches else None,
        completed_batches=completed_batches if has_batches else None,
        percent=percent,
        phase_summary=phase_summary,
    )
