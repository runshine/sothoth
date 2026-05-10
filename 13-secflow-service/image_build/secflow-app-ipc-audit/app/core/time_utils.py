from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_z() -> str:
    return utc_now().isoformat(timespec="seconds").replace("+00:00", "Z")

