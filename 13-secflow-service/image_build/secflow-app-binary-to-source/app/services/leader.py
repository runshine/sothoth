"""Redis leader election helper."""

import os

from app.config import get_config
from app.services.worker_registry import get_redis_client


class LeaderElector:
    def __init__(self):
        cfg = get_config().redis
        self.ttl = cfg.lock_ttl_seconds
        self.pod_id = os.environ.get("POD_NAME") or os.environ.get("HOSTNAME", "manager-local")
        self.lock_key = f"{cfg.key_prefix}:manager:leader"

    def acquire(self) -> bool:
        client = get_redis_client()
        try:
            acquired = bool(client.set(self.lock_key, self.pod_id, ex=self.ttl, nx=True))
            if acquired:
                return True
            current = client.get(self.lock_key)
            if current == self.pod_id:
                client.expire(self.lock_key, self.ttl)
                return True
            return False
        except Exception:
            return False
