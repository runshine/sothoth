"""Celery instance + config for poc-gen-verify (mirrors dvs celery_app).

- broker / result backend = the scheduler pod's Redis (non-persistent; DB is the
  source of truth). Redis loss is recovered by dispatcher `_startup_reset`.
- worker pod: `celery -A app.celery_app worker -P prefork -c 1 --queues=poc ...`
- DB is initialized on import (celery worker / dispatcher processes do not go
  through runtime_bootstrap).
"""
from __future__ import annotations

import logging
import os

from celery import Celery

logger = logging.getLogger("poc.celery")

REDIS_HOST = os.environ.get("POC_SCHEDULER_HOST", "secflow-app-poc-gen-verify-redis")
REDIS_PORT = int(os.environ.get("POC_SCHEDULER_REDIS_PORT", "6379"))
BROKER_DB = int(os.environ.get("POC_CELERY_BROKER_DB", "0"))
BACKEND_DB = int(os.environ.get("POC_CELERY_BACKEND_DB", "1"))

broker_url = f"redis://{REDIS_HOST}:{REDIS_PORT}/{BROKER_DB}"
result_backend = f"redis://{REDIS_HOST}:{REDIS_PORT}/{BACKEND_DB}"

app = Celery("poc", broker_url=broker_url, result_backend=result_backend, include=["app.celery_tasks"])

# Long tasks (PoC gen can run hours): do not rely on visibility_timeout to
# reclaim; the dispatcher's stale scan + DB lease is the recovery mechanism.
_VIS_TIMEOUT = int(os.environ.get("POC_CELERY_VISIBILITY_TIMEOUT", str(86400 * 7)))
app.conf.update(
    task_acks_late=True,                   # worker death/rollout → unacked message re-delivered
    task_reject_on_worker_lost=True,       # worker process lost → message re-delivered
    task_track_started=True,
    broker_transport_options={"visibility_timeout": _VIS_TIMEOUT},
    result_backend_transport_options={"visibility_timeout": _VIS_TIMEOUT},
    worker_prefetch_multiplier=1,          # long tasks, no prefetch of extra messages
    worker_max_tasks_per_child=int(os.environ.get("POC_CELERY_MAX_TASKS_PER_CHILD", "10")),
    worker_send_task_events=True,
    task_send_sent_events=True,
    broker_connection_retry_on_startup=True,
    result_expires=86400,
    task_default_queue="poc",
    task_routes={"app.celery_tasks.run_poc_task": {"queue": "poc"}},
)


def _ensure_db() -> None:
    """celery worker / dispatcher processes have no runtime_bootstrap; init DB here.

    Retried lazily by get_db() on first use if MySQL was not ready at import."""
    try:
        from app.db import ensure_db
        ensure_db()
        logger.info("DB initialized for celery/dispatcher process")
    except Exception:
        logger.exception("celery_app: DB init failed (get_db will retry on first use)")


_ensure_db()
