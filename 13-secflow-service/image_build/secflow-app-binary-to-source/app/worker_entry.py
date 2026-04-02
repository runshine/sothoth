"""Worker process entry."""

import atexit
import logging
import os
import threading

from app.celery_app import celery_app
from app.celery_tasks import process_single_elf  # ensure task registration
from app.config import load_config
from app.model import apply_table_prefix_if_needed, init_database
from app.services.worker_registry import get_worker_id_and_queue, heartbeat_worker, set_worker_offline, upsert_worker


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _heartbeat_loop(stop_event: threading.Event):
    interval = 5
    while not stop_event.is_set():
        try:
            heartbeat_worker()
        except Exception as exc:
            logger.warning("worker heartbeat failed: %s", exc)
        stop_event.wait(interval)


def main():
    load_config()
    apply_table_prefix_if_needed()
    init_database()

    worker_id, queue = get_worker_id_and_queue()
    worker_concurrency = max(1, int(os.environ.get("WORKER_CONCURRENCY", "1")))
    worker_pool = os.environ.get("WORKER_POOL", "prefork")
    logger.info("starting worker worker_id=%s queue=%s", worker_id, queue)
    upsert_worker("idle")

    stop_event = threading.Event()
    t = threading.Thread(target=_heartbeat_loop, args=(stop_event,), daemon=True)
    t.start()

    def _on_exit():
        stop_event.set()
        set_worker_offline()

    atexit.register(_on_exit)

    celery_app.worker_main([
        "worker",
        "--loglevel=INFO",
        f"--pool={worker_pool}",
        f"--concurrency={worker_concurrency}",
        "--queues",
        queue,
        "--hostname",
        f"{worker_id}@%h",
    ])


if __name__ == "__main__":
    main()
