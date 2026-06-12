"""Runtime schedule configuration service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import ValidationError
from app.model import ScheduleRuntimeConfig
from app.schemas import (
    ScheduleRuntimeConfigResponse,
    ScheduleRuntimeConfigUpdate,
    ScheduleRuntimeEffectiveConfig,
    ScheduleRuntimeSchedulerPolicy,
    ScheduleRuntimeTimeWindow,
    ScheduleRuntimeToolDefault,
    ScheduleRuntimeUserTaskSyncPolicy,
)


TASK_TYPE_LABELS: dict[str, str] = {
    "binary_firmware_e2e": "二进制固件端到端",
    "source_scan_e2e": "源码端到端",
    "binary_module_e2e": "二进制模块端到端",
    "ai4red": "AI4Red",
    "ai4apk": "AI4APK",
}
CONFIG_KEY_GLOBAL_DEFAULT = "global_default"
CONFIG_TIMEZONE = "Asia/Shanghai"


@dataclass
class RuntimeConfigSnapshot:
    source: str
    timezone: str
    scheduler_policy: ScheduleRuntimeSchedulerPolicy
    user_task_sync_policy: ScheduleRuntimeUserTaskSyncPolicy
    tool_defaults: list[ScheduleRuntimeToolDefault]
    time_windows: list[ScheduleRuntimeTimeWindow]
    active_time_window_name: str | None
    version: int
    updated_by: str | None
    updated_at: datetime | None


def _time_to_minutes(value: str) -> int:
    hour, minute = value.split(":", 1)
    return int(hour) * 60 + int(minute)


def _time_window_matches(now_minutes: int, start: int, end: int) -> bool:
    if start == end:
        return True
    if start < end:
        return start <= now_minutes < end
    return now_minutes >= start or now_minutes < end


def _tool_default_map(rows: list[ScheduleRuntimeToolDefault]) -> dict[str, ScheduleRuntimeToolDefault]:
    return {str(item.task_type): item for item in rows}


class ScheduleRuntimeConfigService:
    def __init__(self) -> None:
        self._cfg = get_config()
        self._cache_lock = Lock()
        self._cached_snapshot: RuntimeConfigSnapshot | None = None
        self._cached_at_epoch: float = 0.0
        self._cache_ttl_seconds = 5.0

    def invalidate_cache(self) -> None:
        with self._cache_lock:
            self._cached_snapshot = None
            self._cached_at_epoch = 0.0

    def default_scheduler_policy(self) -> ScheduleRuntimeSchedulerPolicy:
        return ScheduleRuntimeSchedulerPolicy(
            project_default_concurrency=int(self._cfg.limits.project_default_concurrency),
            target_default_concurrency=int(self._cfg.limits.target_default_concurrency),
            worker_concurrency=int(self._cfg.worker.concurrency),
            ready_backfill_batch_size=int(self._cfg.scheduler.ready_backfill_batch_size),
            db_fallback_batch_size=int(self._cfg.worker.db_fallback_batch_size),
        )

    def default_user_task_sync_policy(self) -> ScheduleRuntimeUserTaskSyncPolicy:
        cfg = self._cfg.user_task_sync
        return ScheduleRuntimeUserTaskSyncPolicy(
            enabled=bool(cfg.enabled),
            lease_seconds=int(cfg.lease_seconds),
            heartbeat_interval_seconds=int(cfg.heartbeat_interval_seconds),
            db_fallback_batch_size=int(cfg.db_fallback_batch_size),
            queue_pop_timeout_seconds=int(cfg.queue_pop_timeout_seconds),
            reclaim_batch_size=int(cfg.reclaim_batch_size),
            dispatching_seconds=int(cfg.dispatching_seconds),
            running_seconds=int(cfg.running_seconds),
            paused_seconds=int(cfg.paused_seconds),
            terminal_verify_seconds=int(cfg.terminal_verify_seconds),
            retry_initial_seconds=int(cfg.retry_initial_seconds),
            retry_max_seconds=int(cfg.retry_max_seconds),
            failure_threshold=int(cfg.failure_threshold),
        )

    def default_tool_defaults(self) -> list[ScheduleRuntimeToolDefault]:
        policies = get_config().user_task_dispatch_policy
        rows: list[ScheduleRuntimeToolDefault] = []
        for task_type, label in TASK_TYPE_LABELS.items():
            policy = getattr(policies, task_type, None)
            capacity_pool_ids = list(getattr(policy, "capacity_pool_ids", []) or []) if policy is not None else []
            root_task_key_max_concurrency = int(getattr(policy, "root_task_key_max_concurrency", 0) or 0) if policy is not None else 0
            root_task_key_expires_at = getattr(policy, "root_task_key_expires_at", None) if policy is not None else None
            rows.append(
                ScheduleRuntimeToolDefault(
                    task_type=task_type,
                    label=label,
                    default_concurrency=1,
                    root_task_key_max_concurrency=root_task_key_max_concurrency,
                    capacity_pool_ids=capacity_pool_ids,
                    root_task_key_expires_at=root_task_key_expires_at,
                )
            )
        return rows

    def default_snapshot(self) -> RuntimeConfigSnapshot:
        return RuntimeConfigSnapshot(
            source="default",
            timezone=CONFIG_TIMEZONE,
            scheduler_policy=self.default_scheduler_policy(),
            user_task_sync_policy=self.default_user_task_sync_policy(),
            tool_defaults=self.default_tool_defaults(),
            time_windows=[],
            active_time_window_name=None,
            version=1,
            updated_by="system",
            updated_at=None,
        )

    def _validate_time_windows(self, rows: list[ScheduleRuntimeTimeWindow]) -> None:
        normalized = [row for row in rows if row.enabled]
        windows: list[tuple[str, int, int]] = []
        for row in normalized:
            start = _time_to_minutes(row.start_time)
            end = _time_to_minutes(row.end_time)
            if start == end:
                raise ValidationError(f"时段不能覆盖整天: {row.name}")
            intervals = [(start, end)] if start < end else [(start, 24 * 60), (0, end)]
            for current_start, current_end in intervals:
                for existing_name, existing_start, existing_end in windows:
                    if max(current_start, existing_start) < min(current_end, existing_end):
                        raise ValidationError(f"时段规则存在重叠: {row.name} 与 {existing_name}")
                windows.append((row.name, current_start, current_end))

    def _normalize_update(self, payload: ScheduleRuntimeConfigUpdate) -> ScheduleRuntimeConfigUpdate:
        tool_types = set()
        for item in payload.tool_defaults:
            task_type = str(item.task_type or "")
            if task_type not in TASK_TYPE_LABELS:
                raise ValidationError(f"未识别的 task_type: {task_type}")
            if task_type in tool_types:
                raise ValidationError(f"重复的 task_type 配置: {task_type}")
            tool_types.add(task_type)
        missing = set(TASK_TYPE_LABELS.keys()) - tool_types
        if missing:
            raise ValidationError(f"缺少 task_type 配置: {', '.join(sorted(missing))}")
        for window in payload.time_windows:
            seen_window_task_types: set[str] = set()
            for item in window.tool_defaults:
                task_type = str(item.task_type or "")
                if task_type not in TASK_TYPE_LABELS:
                    raise ValidationError(f"未识别的 task_type: {task_type}")
                if task_type in seen_window_task_types:
                    raise ValidationError(f"时段 {window.name} 存在重复的 task_type 配置: {task_type}")
                seen_window_task_types.add(task_type)
        self._validate_time_windows(payload.time_windows)
        return payload

    def _serialize_row(self, row: ScheduleRuntimeConfig | None) -> RuntimeConfigSnapshot:
        if row is None:
            return self.default_snapshot()
        scheduler_payload = dict(row.scheduler_policy_json or {})
        sync_policy_payload = dict(scheduler_payload.pop("user_task_sync_policy", None) or self.default_user_task_sync_policy().model_dump())
        scheduler_policy = ScheduleRuntimeSchedulerPolicy.model_validate(scheduler_payload)
        user_task_sync_policy = ScheduleRuntimeUserTaskSyncPolicy.model_validate(sync_policy_payload)
        tool_defaults = [
            ScheduleRuntimeToolDefault.model_validate(item)
            for item in list(row.tool_defaults_json or [])
            if isinstance(item, dict)
        ]
        time_windows = [
            ScheduleRuntimeTimeWindow.model_validate(item)
            for item in list(row.time_windows_json or [])
            if isinstance(item, dict)
        ]
        snapshot = RuntimeConfigSnapshot(
            source="database",
            timezone=str(row.timezone or CONFIG_TIMEZONE),
            scheduler_policy=scheduler_policy,
            user_task_sync_policy=user_task_sync_policy,
            tool_defaults=tool_defaults or self.default_tool_defaults(),
            time_windows=time_windows,
            active_time_window_name=None,
            version=int(row.version or 1),
            updated_by=str(row.updated_by or "system"),
            updated_at=row.updated_at,
        )
        return self._apply_effective_time_window(snapshot)

    def _apply_effective_time_window(self, snapshot: RuntimeConfigSnapshot) -> RuntimeConfigSnapshot:
        local_now = datetime.now(timezone.utc).astimezone(ZoneInfo(snapshot.timezone))
        now_minutes = local_now.hour * 60 + local_now.minute
        active_window = next(
            (
                window
                for window in snapshot.time_windows
                if window.enabled
                and _time_window_matches(now_minutes, _time_to_minutes(window.start_time), _time_to_minutes(window.end_time))
            ),
            None,
        )
        if active_window is None:
            return snapshot
        scheduler_policy = snapshot.scheduler_policy
        user_task_sync_policy = snapshot.user_task_sync_policy
        if active_window.scheduler_policy is not None:
            scheduler_policy = ScheduleRuntimeSchedulerPolicy.model_validate(
                {
                    **scheduler_policy.model_dump(),
                    **active_window.scheduler_policy.model_dump(),
                }
            )
        if active_window.user_task_sync_policy is not None:
            user_task_sync_policy = ScheduleRuntimeUserTaskSyncPolicy.model_validate(
                {
                    **user_task_sync_policy.model_dump(),
                    **active_window.user_task_sync_policy.model_dump(),
                }
            )
        tool_defaults = snapshot.tool_defaults
        if active_window.tool_defaults:
            base_map = _tool_default_map(snapshot.tool_defaults)
            for item in active_window.tool_defaults:
                base = base_map.get(str(item.task_type))
                base_map[str(item.task_type)] = ScheduleRuntimeToolDefault.model_validate(
                    {
                        **(base.model_dump() if base is not None else {}),
                        **item.model_dump(),
                    }
                )
            tool_defaults = [base_map[task_type] for task_type in TASK_TYPE_LABELS.keys()]
        return RuntimeConfigSnapshot(
            source=snapshot.source,
            timezone=snapshot.timezone,
            scheduler_policy=scheduler_policy,
            user_task_sync_policy=user_task_sync_policy,
            tool_defaults=tool_defaults,
            time_windows=snapshot.time_windows,
            active_time_window_name=active_window.name,
            version=snapshot.version,
            updated_by=snapshot.updated_by,
            updated_at=snapshot.updated_at,
        )

    def get_snapshot(self, db: Session, *, use_cache: bool = True) -> RuntimeConfigSnapshot:
        import time

        if use_cache:
            with self._cache_lock:
                if self._cached_snapshot is not None and (time.time() - self._cached_at_epoch) <= self._cache_ttl_seconds:
                    return self._cached_snapshot
        row = db.query(ScheduleRuntimeConfig).filter(ScheduleRuntimeConfig.config_key == CONFIG_KEY_GLOBAL_DEFAULT).first()
        snapshot = self._serialize_row(row)
        with self._cache_lock:
            self._cached_snapshot = snapshot
            self._cached_at_epoch = time.time()
        return snapshot

    def has_database_config(self, db: Session) -> bool:
        row = db.query(ScheduleRuntimeConfig.id).filter(ScheduleRuntimeConfig.config_key == CONFIG_KEY_GLOBAL_DEFAULT).first()
        return row is not None

    def get_config_response(self, db: Session) -> ScheduleRuntimeConfigResponse:
        row = db.query(ScheduleRuntimeConfig).filter(ScheduleRuntimeConfig.config_key == CONFIG_KEY_GLOBAL_DEFAULT).first()
        snapshot = self._serialize_row(row)
        base = self.default_snapshot() if row is None else RuntimeConfigSnapshot(
            source="database",
            timezone=str(row.timezone or CONFIG_TIMEZONE),
            scheduler_policy=ScheduleRuntimeSchedulerPolicy.model_validate(
                {key: value for key, value in dict(row.scheduler_policy_json or {}).items() if key != "user_task_sync_policy"}
            ),
            user_task_sync_policy=ScheduleRuntimeUserTaskSyncPolicy.model_validate(
                dict((row.scheduler_policy_json or {}).get("user_task_sync_policy") or self.default_user_task_sync_policy().model_dump())
            ),
            tool_defaults=[
                ScheduleRuntimeToolDefault.model_validate(item)
                for item in list(row.tool_defaults_json or [])
                if isinstance(item, dict)
            ] or self.default_tool_defaults(),
            time_windows=[
                ScheduleRuntimeTimeWindow.model_validate(item)
                for item in list(row.time_windows_json or [])
                if isinstance(item, dict)
            ],
            active_time_window_name=None,
            version=int(row.version or 1),
            updated_by=str(row.updated_by or "system"),
            updated_at=row.updated_at,
        )
        return ScheduleRuntimeConfigResponse(
            config_key=CONFIG_KEY_GLOBAL_DEFAULT,
            timezone=base.timezone,
            scheduler_policy=base.scheduler_policy,
            user_task_sync_policy=base.user_task_sync_policy,
            tool_defaults=base.tool_defaults,
            time_windows=base.time_windows,
            version=base.version,
            updated_by=base.updated_by,
            updated_at=base.updated_at,
            source=base.source,  # type: ignore[arg-type]
            effective_now=ScheduleRuntimeEffectiveConfig(
                source=snapshot.source,  # type: ignore[arg-type]
                active_time_window_name=snapshot.active_time_window_name,
                timezone=snapshot.timezone,
                scheduler_policy=snapshot.scheduler_policy,
                user_task_sync_policy=snapshot.user_task_sync_policy,
                tool_defaults=snapshot.tool_defaults,
            ),
        )

    def save_config(self, db: Session, payload: ScheduleRuntimeConfigUpdate, *, actor: str) -> ScheduleRuntimeConfigResponse:
        normalized = self._normalize_update(payload)
        row = db.query(ScheduleRuntimeConfig).filter(ScheduleRuntimeConfig.config_key == CONFIG_KEY_GLOBAL_DEFAULT).first()
        if row is None:
            row = ScheduleRuntimeConfig(config_key=CONFIG_KEY_GLOBAL_DEFAULT)
            db.add(row)
        row.timezone = normalized.timezone
        row.scheduler_policy_json = normalized.scheduler_policy.model_dump()
        row.scheduler_policy_json["user_task_sync_policy"] = normalized.user_task_sync_policy.model_dump()
        row.tool_defaults_json = [item.model_dump() for item in normalized.tool_defaults]
        row.time_windows_json = [item.model_dump() for item in normalized.time_windows]
        row.updated_by = actor
        row.version = int(row.version or 0) + 1
        db.commit()
        db.refresh(row)
        self.invalidate_cache()
        return self.get_config_response(db)

    def reset_config(self, db: Session, *, actor: str) -> ScheduleRuntimeConfigResponse:
        row = db.query(ScheduleRuntimeConfig).filter(ScheduleRuntimeConfig.config_key == CONFIG_KEY_GLOBAL_DEFAULT).first()
        if row is not None:
            db.delete(row)
            db.commit()
        self.invalidate_cache()
        response = self.get_config_response(db)
        if response.updated_by is None:
            response.updated_by = actor
        return response


_runtime_config_service: ScheduleRuntimeConfigService | None = None


def get_runtime_config_service() -> ScheduleRuntimeConfigService:
    global _runtime_config_service
    if _runtime_config_service is None:
        _runtime_config_service = ScheduleRuntimeConfigService()
    return _runtime_config_service
