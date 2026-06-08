from __future__ import annotations

import functools
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Callable


# ── JSONL formatter ──────────────────────────────────────────────

class JsonLinesFormatter(logging.Formatter):
    """Fixed top-level schema: ts, level, mod, event, data."""

    def format(self, record: logging.LogRecord) -> str:
        extra_fields: dict | None = getattr(record, "_extra", None)
        obj = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "Z",
            "level": record.levelname,
            "mod": record.name.removeprefix("vuln_dispatch.").removeprefix("vuln_verify."),
            "event": record.getMessage(),
            "data": extra_fields or {},
        }
        return json.dumps(obj, default=str)


def setup(level: int = logging.INFO, stream=sys.stderr, loggers: list[str] | None = None) -> None:
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonLinesFormatter())
    handler.setLevel(level)
    for name in (loggers or ["vuln_dispatch"]):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.setLevel(level)


# ── Logger adapter ───────────────────────────────────────────────

class _StructuredLogger:
    def __init__(self, logger: logging.Logger) -> None:
        self._l = logger

    def debug(self, msg: str, **extra_fields) -> None:
        self._l.debug(msg, extra={"_extra": extra_fields})

    def info(self, msg: str, **extra_fields) -> None:
        self._l.info(msg, extra={"_extra": extra_fields})

    def warning(self, msg: str, **extra_fields) -> None:
        self._l.warning(msg, extra={"_extra": extra_fields})

    def exception(self, msg: str, **extra_fields) -> None:
        self._l.exception(msg, extra={"_extra": extra_fields})

    def log(self, level: int, msg: str, **extra_fields) -> None:
        self._l.log(level, msg, extra={"_extra": extra_fields})


def get_logger(name: str) -> _StructuredLogger:
    return _StructuredLogger(logging.getLogger(name))


# ── Automatic call logging decorator ─────────────────────────────

def logged(func: Callable | None = None, *, level: int = logging.INFO):
    """Decorator: automatically log every call with *event* = function name.

    On exit the decorator logs the function's return value (or a summary of
    it when the return type is a known dataclass / container).

    Usage::

        @logged
        def parse_report(file_path): ...

        @logged(level=logging.DEBUG)
        def deduplicate(reports): ...
    """
    if func is not None:
        # called without parentheses: @logged
        return _logged(func, logging.INFO)

    # called with parentheses: @logged(level=...)
    def wrapper(f: Callable) -> Callable:
        return _logged(f, level)
    return wrapper


def _logged(func: Callable, level: int) -> Callable:
    logger = get_logger(func.__module__)

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
        except Exception as exc:
            logger.exception(func.__name__, error=str(exc))
            raise

        data = _summarise_result(result)
        if data is None and hasattr(result, "to_log_dict"):
            data = result.to_log_dict()
        logger.log(level, func.__name__, **(data or {}))
        return result

    return wrapper


def _summarise_result(result) -> dict | None:
    """Extract a compact summary dict from generic return conventions."""
    if all(hasattr(result, name) for name in ("report_id", "file", "function", "fingerprint")):
        return {
            "report_id": result.report_id,
            "file": result.file,
            "function": result.function,
            "fingerprint": result.fingerprint,
        }
    if isinstance(result, tuple) and len(result) == 2:
        reports, records = result  # deduplicate return
        if isinstance(reports, list) and isinstance(records, list):
            removed = sum(
                len(r.removed_report_ids)
                for r in records
                if hasattr(r, "removed_report_ids")
            )
            return {"input_count": len(reports), "removed_count": removed}
    if isinstance(result, dict):
        return result
    return None
