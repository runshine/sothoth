from __future__ import annotations

from datetime import UTC, datetime


def now_local() -> datetime:
    return datetime.now(UTC)


def format_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.isoformat()