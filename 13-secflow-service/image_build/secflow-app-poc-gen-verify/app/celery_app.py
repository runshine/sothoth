"""Celery instance + config for poc-gen-verify.

Design: tasks run ONCE. No re-delivery, no retry, no automatic re-run.
- broker / result backend = the scheduler pod's Redis.
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

# PoC tasks run ONCE — no automatic re-delivery on worker death.
# If a worker dies, the task stays in "running" and the user can manually restart.
app.conf.update(
    task_acks_late=False,                  # ack immediately on receipt — no re-delivery
    task_reject_on_worker_lost=False,      # worker lost = task gone, not re-delivered
    task_track_started=True,
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
    """celery worker / dispatcher processes have no runtime_bootstrap; init DB here."""
    try:
        from app.db import ensure_db
        ensure_db()
        logger.info("DB initialized for celery/dispatcher process")
    except Exception:
        logger.exception("celery_app: DB init failed (get_db will retry on first use)")


_ensure_db()
