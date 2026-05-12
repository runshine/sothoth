from __future__ import annotations

from datetime import datetime, timezone


def now_local() -> datetime:
    return datetime.now(timezone.utc)


def isoformat_local(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()
