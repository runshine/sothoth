from __future__ import annotations

from datetime import datetime, timezone, timedelta

LOCAL_TZ = timezone(timedelta(hours=8))


def now_local() -> datetime:
    return datetime.now(LOCAL_TZ).replace(tzinfo=None)


def isoformat_local(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat(timespec="seconds")
