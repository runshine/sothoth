from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy.exc import ProgrammingError

from app.config import Config, get_config
from app.models.database import ServiceRuntimeConfig

SERVICE_RUNTIME_CONFIG_KEY = "global"


def _deep_merge(base: Any, override: Any) -> Any:
    if isinstance(base, dict) and isinstance(override, dict):
        merged = dict(base)
        for key, value in override.items():
            merged[key] = _deep_merge(merged.get(key), value)
        return merged
    return override if override is not None else base


def _default_payload() -> dict[str, Any]:
    config: Config = get_config()
    return {
        "scheduler": {
            "enabled": config.scheduler.enabled,
            "role": config.scheduler.role,
            "worker_capacity": config.scheduler.worker_capacity,
            "poll_interval_seconds": config.scheduler.poll_interval_seconds,
            "heartbeat_interval_seconds": config.scheduler.heartbeat_interval_seconds,
            "worker_timeout_seconds": config.scheduler.worker_timeout_seconds,
            "worker_retention_seconds": config.scheduler.worker_retention_seconds,
            "cleanup_interval_seconds": config.scheduler.cleanup_interval_seconds,
            "reservation_lease_seconds": config.scheduler.reservation_lease_seconds,
            "worker_queue_depth": config.scheduler.worker_queue_depth,
            "dispatch_batch_size": config.scheduler.dispatch_batch_size,
            "requeue_stuck_dispatch_after_seconds": config.scheduler.requeue_stuck_dispatch_after_seconds,
            "cluster_capacity_summary_refresh_interval_seconds": 5,
            "cluster_capacity_summary_stale_after_seconds": 15,
        },
        "dataflow_worker": {
            "worker_url_template": config.dataflow_worker.worker_url_template,
            "advertise_url_template": config.dataflow_worker.advertise_url_template,
            "timeout": config.dataflow_worker.timeout,
            "dispatch_retry_interval_seconds": config.dataflow_worker.dispatch_retry_interval_seconds,
            "dispatch_max_retries": config.dataflow_worker.dispatch_max_retries,
        },
    }


class RuntimeConfigService:
    def get_config(self, db: Session) -> dict[str, Any]:
        try:
            row = db.get(ServiceRuntimeConfig, SERVICE_RUNTIME_CONFIG_KEY)
        except ProgrammingError as exc:
            if "doesn't exist" in str(exc).lower() and ServiceRuntimeConfig.__tablename__ in str(exc):
                db.rollback()
                return _default_payload()
            raise
        payload = row.config_json if row and isinstance(row.config_json, dict) else {}
        return _deep_merge(_default_payload(), payload)

    def save_config(self, db: Session, config_data: dict[str, Any]) -> dict[str, Any]:
        merged = _deep_merge(_default_payload(), config_data or {})
        row = db.get(ServiceRuntimeConfig, SERVICE_RUNTIME_CONFIG_KEY)
        if row is None:
            row = ServiceRuntimeConfig(config_key=SERVICE_RUNTIME_CONFIG_KEY, config_json=merged)
        else:
            row.config_json = merged
        db.add(row)
        db.commit()
        db.refresh(row)
        return dict(row.config_json or {})


_service: RuntimeConfigService | None = None


def get_runtime_config_service() -> RuntimeConfigService:
    global _service
    if _service is None:
        _service = RuntimeConfigService()
    return _service
