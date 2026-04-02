"""Celery app factory."""

from celery import Celery
from celery.signals import worker_process_init

from app.config import get_config
from app.model import reset_db_engine


cfg = get_config().celery
celery_app = Celery("binary_to_source", broker=cfg.broker_url, backend=cfg.result_backend)
celery_app.conf.update(
    task_track_started=cfg.task_track_started,
    task_time_limit=cfg.task_time_limit_seconds,
    task_soft_time_limit=cfg.task_soft_time_limit_seconds,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)


@worker_process_init.connect
def _reset_db_for_forked_workers(**_kwargs):
    # Celery prefork children must not reuse the parent's pooled DB connections.
    reset_db_engine()
