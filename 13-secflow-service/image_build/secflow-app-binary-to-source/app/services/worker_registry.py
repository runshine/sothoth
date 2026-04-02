"""Worker registry and status on Redis."""

import json
import os
import re
import time
from dataclasses import dataclass
from typing import List, Optional

import redis

from app.config import get_config


@dataclass
class WorkerInfo:
    worker_id: str
    queue: str
    status: str
    last_seen: int
    capacity: int
    running_count: int
    current_task_item_id: Optional[str] = None


_redis_client: Optional[redis.Redis] = None


def get_redis_client() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(get_config().redis.url, decode_responses=True)
    return _redis_client


def _worker_hash_key() -> str:
    cfg = get_config().redis
    return f"{cfg.key_prefix}:workers"


def _sanitize(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9-]", "-", name)


def get_worker_id_and_queue() -> tuple[str, str]:
    pod_name = os.environ.get("POD_NAME") or os.environ.get("HOSTNAME", "worker-local")
    worker_id = _sanitize(pod_name)
    queue = f"{get_config().celery.worker_queue_prefix}-{worker_id}"
    return worker_id, queue


def get_worker_capacity() -> int:
    raw = os.environ.get("WORKER_CONCURRENCY", "1")
    try:
        val = int(raw)
        return max(1, val)
    except Exception:
        return 1


def _load_worker(worker_id: str) -> dict:
    raw = get_redis_client().hget(_worker_hash_key(), worker_id)
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _save_worker(worker_id: str, payload: dict):
    get_redis_client().hset(_worker_hash_key(), worker_id, json.dumps(payload, ensure_ascii=False))


def upsert_worker(status: str, current_task_item_id: Optional[str] = None):
    worker_id, queue = get_worker_id_and_queue()
    existing = _load_worker(worker_id)
    running_count = int(existing.get("running_count", 0))
    capacity = int(existing.get("capacity", get_worker_capacity()))
    payload = {
        "worker_id": worker_id,
        "queue": queue,
        "status": status,
        "last_seen": int(time.time()),
        "capacity": capacity,
        "running_count": running_count,
        "current_task_item_id": current_task_item_id,
    }
    _save_worker(worker_id, payload)


def heartbeat_worker():
    worker_id, queue = get_worker_id_and_queue()
    existing = _load_worker(worker_id)
    running_count = int(existing.get("running_count", 0))
    capacity = int(existing.get("capacity", get_worker_capacity()))
    status = "busy" if running_count >= capacity else "idle"
    payload = {
        "worker_id": worker_id,
        "queue": queue,
        "status": status,
        "last_seen": int(time.time()),
        "capacity": capacity,
        "running_count": running_count,
        "current_task_item_id": existing.get("current_task_item_id"),
    }
    _save_worker(worker_id, payload)


def worker_start_task(current_task_item_id: Optional[str] = None):
    worker_id, queue = get_worker_id_and_queue()
    existing = _load_worker(worker_id)
    capacity = int(existing.get("capacity", get_worker_capacity()))
    running_count = int(existing.get("running_count", 0)) + 1
    status = "busy" if running_count >= capacity else "idle"
    payload = {
        "worker_id": worker_id,
        "queue": queue,
        "status": status,
        "last_seen": int(time.time()),
        "capacity": capacity,
        "running_count": running_count,
        "current_task_item_id": current_task_item_id,
    }
    _save_worker(worker_id, payload)


def worker_finish_task():
    worker_id, queue = get_worker_id_and_queue()
    existing = _load_worker(worker_id)
    capacity = int(existing.get("capacity", get_worker_capacity()))
    running_count = max(0, int(existing.get("running_count", 0)) - 1)
    status = "busy" if running_count >= capacity else "idle"
    payload = {
        "worker_id": worker_id,
        "queue": queue,
        "status": status,
        "last_seen": int(time.time()),
        "capacity": capacity,
        "running_count": running_count,
        "current_task_item_id": None,
    }
    _save_worker(worker_id, payload)


def set_worker_offline():
    worker_id, queue = get_worker_id_and_queue()
    payload = {
        "worker_id": worker_id,
        "queue": queue,
        "status": "offline",
        "last_seen": int(time.time()),
        "capacity": get_worker_capacity(),
        "running_count": 0,
        "current_task_item_id": None,
    }
    _save_worker(worker_id, payload)


def list_available_workers(limit: int = 20) -> List[WorkerInfo]:
    cfg = get_config().redis
    now = int(time.time())
    raw = get_redis_client().hgetall(_worker_hash_key())
    workers: List[WorkerInfo] = []
    for _, value in raw.items():
        try:
            data = json.loads(value)
        except Exception:
            continue
        if now - int(data.get("last_seen", 0)) > cfg.worker_ttl_seconds:
            continue
        if data.get("status") == "offline":
            continue
        capacity = max(1, int(data.get("capacity", 1)))
        running_count = max(0, int(data.get("running_count", 0)))
        available_slots = capacity - running_count
        if available_slots <= 0:
            continue
        for _ in range(available_slots):
            workers.append(
                WorkerInfo(
                    worker_id=data.get("worker_id", ""),
                    queue=data.get("queue", ""),
                    status=data.get("status", "offline"),
                    last_seen=int(data.get("last_seen", 0)),
                    capacity=capacity,
                    running_count=running_count,
                    current_task_item_id=data.get("current_task_item_id"),
                )
            )
    workers.sort(key=lambda x: x.last_seen, reverse=True)
    return workers[:limit]
