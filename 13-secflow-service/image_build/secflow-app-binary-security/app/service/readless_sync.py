from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Awaitable, Callable, Iterable


logger = logging.getLogger(__name__)


@dataclass
class ReadlessSyncStats:
    candidates: int = 0
    attempted: int = 0
    succeeded: int = 0
    changed: int = 0
    failed: int = 0


async def run_readless_sync_loop(
    *,
    should_stop: Callable[[], bool],
    interval_seconds: int,
    before_tick: Callable[[], Awaitable[bool]] | None,
    candidate_ids_loader: Callable[[], Iterable[str]],
    process_one: Callable[[str], Awaitable[tuple[bool, bool]]],
    observe: Callable[[ReadlessSyncStats], None],
    loop_context: Callable[[str], object] | None = None,
    loop_name: str = "readless_sync",
) -> None:
    while not should_stop():
        context = loop_context(loop_name) if loop_context is not None else None
        if context is None:
            class _NullContext:
                def __enter__(self):
                    return None

                def __exit__(self, exc_type, exc, tb):
                    return False

            context = _NullContext()
        with context:
            stats = ReadlessSyncStats()
            try:
                if before_tick is None or await before_tick():
                    task_ids = [str(task_id) for task_id in candidate_ids_loader()]
                    stats.candidates = len(task_ids)
                    for task_id in task_ids:
                        try:
                            succeeded, changed = await process_one(task_id)
                            stats.attempted += 1
                            if succeeded:
                                stats.succeeded += 1
                            if changed:
                                stats.changed += 1
                        except Exception:
                            stats.failed += 1
                            logger.exception("%s failed for task %s", loop_name, task_id)
                observe(stats)
            except Exception:
                stats.failed += 1
                logger.exception("%s loop failed", loop_name)
                observe(stats)
        await asyncio.sleep(interval_seconds)
