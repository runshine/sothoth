"""Redis-backed reducer metrics snapshot store."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from redis.asyncio import Redis

from app.config import get_config
from app.observability import CONTENT_TYPE_LATEST


_SNAPSHOT_TTL_SECONDS = 180
_SNAPSHOT_STALE_AFTER_SECONDS = 30.0
_SNAPSHOT_KEY = "secflow:binary-security:reducer:metrics-snapshot:v1"


class ReducerMetricsSnapshotStore:
    def __init__(self) -> None:
        self._redis_url = get_config().queue.redis_url
        self._client: Redis | None = None
        self._lock = asyncio.Lock()

    async def _client_or_create(self) -> Redis:
        async with self._lock:
            if self._client is None:
                self._client = Redis.from_url(self._redis_url, decode_responses=True)
            return self._client

    async def write_snapshot(
        self,
        *,
        metrics_payload: str,
        source_pod: str,
        generated_at: float | None = None,
    ) -> None:
        client = await self._client_or_create()
        created_at = float(generated_at or time.time())
        payload = {
            "metrics_payload": str(metrics_payload or ""),
            "source_pod": str(source_pod or "unknown"),
            "generated_at": created_at,
        }
        await client.set(_SNAPSHOT_KEY, json.dumps(payload, ensure_ascii=True), ex=_SNAPSHOT_TTL_SECONDS)

    async def read_snapshot(self) -> dict[str, Any] | None:
        client = await self._client_or_create()
        raw = await client.get(_SNAPSHOT_KEY)
        if not raw:
            return None
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        return payload

    async def render_metrics(self, *, fallback_payload: str | None = None) -> tuple[bytes, str]:
        snapshot = await self.read_snapshot()
        now_value = time.time()
        generated_at = 0.0
        source_pod = "unknown"
        stale = 1.0
        available = 0.0
        snapshot_payload = str(fallback_payload or "").strip()

        if snapshot:
            try:
                generated_at = float(snapshot.get("generated_at") or 0.0)
            except (TypeError, ValueError):
                generated_at = 0.0
            source_pod = str(snapshot.get("source_pod") or "unknown")
            candidate_payload = str(snapshot.get("metrics_payload") or "").strip()
            if candidate_payload:
                snapshot_payload = candidate_payload
                available = 1.0
                stale = 1.0 if max(0.0, now_value - generated_at) > _SNAPSHOT_STALE_AFTER_SECONDS else 0.0
        elif snapshot_payload:
            available = 1.0
            stale = 0.0
            generated_at = now_value

        age_seconds = max(0.0, now_value - generated_at) if generated_at > 0 else 0.0
        lines: list[str] = []
        if snapshot_payload:
            lines.append(snapshot_payload)
        lines.extend(
            [
                "# HELP secflow_binary_security_reducer_snapshot_available Whether a reducer metrics snapshot is available.",
                "# TYPE secflow_binary_security_reducer_snapshot_available gauge",
                f"secflow_binary_security_reducer_snapshot_available {available}",
                "# HELP secflow_binary_security_reducer_snapshot_age_seconds Age in seconds of the reducer metrics snapshot.",
                "# TYPE secflow_binary_security_reducer_snapshot_age_seconds gauge",
                f"secflow_binary_security_reducer_snapshot_age_seconds {age_seconds}",
                "# HELP secflow_binary_security_reducer_snapshot_stale Whether the reducer metrics snapshot is stale.",
                "# TYPE secflow_binary_security_reducer_snapshot_stale gauge",
                f"secflow_binary_security_reducer_snapshot_stale {stale}",
                "# HELP secflow_binary_security_reducer_snapshot_generated_at_timestamp_seconds Unix timestamp for the reducer metrics snapshot generation time.",
                "# TYPE secflow_binary_security_reducer_snapshot_generated_at_timestamp_seconds gauge",
                f"secflow_binary_security_reducer_snapshot_generated_at_timestamp_seconds {generated_at}",
                "# HELP secflow_binary_security_reducer_snapshot_source_info Reducer pod that produced the latest snapshot.",
                "# TYPE secflow_binary_security_reducer_snapshot_source_info gauge",
                f'secflow_binary_security_reducer_snapshot_source_info{{pod="{_escape_label_value(source_pod)}"}} 1',
            ]
        )
        return ("\n".join(line for line in lines if line).strip() + "\n").encode("utf-8"), CONTENT_TYPE_LATEST

    async def close(self) -> None:
        async with self._lock:
            client = self._client
            self._client = None
        if client is not None:
            await client.aclose()


def _escape_label_value(value: str) -> str:
    return str(value or "unknown").replace("\\", r"\\").replace("\n", r"\n").replace('"', r"\"")


_snapshot_store: ReducerMetricsSnapshotStore | None = None


def get_reducer_metrics_snapshot_store() -> ReducerMetricsSnapshotStore:
    global _snapshot_store
    if _snapshot_store is None:
        _snapshot_store = ReducerMetricsSnapshotStore()
    return _snapshot_store


async def close_reducer_metrics_snapshot_store() -> None:
    global _snapshot_store
    store = _snapshot_store
    _snapshot_store = None
    if store is not None:
        await store.close()
