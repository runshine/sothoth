"""Redis-backed state event inbox metrics snapshot store."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from app.config import get_config
from app.observability import CONTENT_TYPE_LATEST
from app.service.task_queue import (
    DEFAULT_QUEUE_CONTEXT,
    RedisSelfHealingClientHelper,
)


logger = logging.getLogger(__name__)


_SNAPSHOT_TTL_SECONDS = 1800
_SNAPSHOT_STALE_AFTER_SECONDS = 30.0
_SNAPSHOT_KEY = "secflow:binary-security:state-event-inbox:metrics-snapshot:v1"
class StateEventInboxMetricsSnapshotStore:
    def __init__(self) -> None:
        self._redis_url = get_config().queue.redis_url
        self._redis_helper = RedisSelfHealingClientHelper(
            redis_url=self._redis_url,
            client_log_name="state event inbox metrics redis client",
            client_type="state_event_inbox_metrics_snapshot",
        )

    async def write_snapshot(
        self,
        *,
        metrics_payload: str,
        source_pod: str,
        generated_at: float | None = None,
    ) -> None:
        created_at = float(generated_at or time.time())
        payload = {
            "metrics_payload": str(metrics_payload or ""),
            "source_pod": str(source_pod or "unknown"),
            "generated_at": created_at,
        }

        async def _write(client):
            encoded = json.dumps(payload, ensure_ascii=True)
            await client.set(_SNAPSHOT_KEY, encoded, ex=_SNAPSHOT_TTL_SECONDS)

        await self._redis_helper.execute_with_rebuild_forever(
            "state_event_inbox_metrics_snapshot_write",
            context="state_event_inbox_metrics_snapshot",
            fn=_write,
        )

    async def read_snapshot(self) -> dict[str, Any] | None:

        async def _read(client):
            raw = await client.get(_SNAPSHOT_KEY)
            return raw

        raw = await self._redis_helper.execute_with_rebuild_forever(
            "state_event_inbox_metrics_snapshot_read",
            context="state_event_inbox_metrics_snapshot",
            fn=_read,
        )
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
                "# HELP secflow_binary_security_state_event_inbox_snapshot_available Whether a state event inbox metrics snapshot is available.",
                "# TYPE secflow_binary_security_state_event_inbox_snapshot_available gauge",
                f"secflow_binary_security_state_event_inbox_snapshot_available {available}",
                "# HELP secflow_binary_security_state_event_inbox_snapshot_age_seconds Age in seconds of the state event inbox metrics snapshot.",
                "# TYPE secflow_binary_security_state_event_inbox_snapshot_age_seconds gauge",
                f"secflow_binary_security_state_event_inbox_snapshot_age_seconds {age_seconds}",
                "# HELP secflow_binary_security_state_event_inbox_snapshot_stale Whether the state event inbox metrics snapshot is stale.",
                "# TYPE secflow_binary_security_state_event_inbox_snapshot_stale gauge",
                f"secflow_binary_security_state_event_inbox_snapshot_stale {stale}",
                "# HELP secflow_binary_security_state_event_inbox_snapshot_generated_at_timestamp_seconds Unix timestamp for the state event inbox metrics snapshot generation time.",
                "# TYPE secflow_binary_security_state_event_inbox_snapshot_generated_at_timestamp_seconds gauge",
                f"secflow_binary_security_state_event_inbox_snapshot_generated_at_timestamp_seconds {generated_at}",
                "# HELP secflow_binary_security_state_event_inbox_snapshot_source_info Owner pod that produced the latest state event inbox snapshot.",
                "# TYPE secflow_binary_security_state_event_inbox_snapshot_source_info gauge",
                f'secflow_binary_security_state_event_inbox_snapshot_source_info{{pod="{_escape_label_value(source_pod)}"}} 1',
            ]
        )
        return ("\n".join(line for line in lines if line).strip() + "\n").encode("utf-8"), CONTENT_TYPE_LATEST

    async def close(self) -> None:
        await self._redis_helper.close()


def _escape_label_value(value: str) -> str:
    return str(value or "unknown").replace("\\", r"\\").replace("\n", r"\n").replace('"', r"\"")


_snapshot_store: StateEventInboxMetricsSnapshotStore | None = None


def get_state_event_inbox_metrics_snapshot_store() -> StateEventInboxMetricsSnapshotStore:
    global _snapshot_store
    if _snapshot_store is None:
        _snapshot_store = StateEventInboxMetricsSnapshotStore()
    return _snapshot_store


async def close_state_event_inbox_metrics_snapshot_store() -> None:
    global _snapshot_store
    store = _snapshot_store
    _snapshot_store = None
    if store is not None:
        await store.close()
