"""Backfill cached B2S function statistics for existing tasks.

Run with:
    python scripts/backfill_function_stats.py --project-id <project_id>
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.model import B2STaskItem, get_session_factory
from app.service.task_service import refresh_item_function_stats


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill cached B2S function statistics.")
    parser.add_argument("--project-id", help="Only backfill a single project.")
    parser.add_argument("--task-id", help="Only backfill a single task.")
    parser.add_argument("--force", action="store_true", help="Recompute even when cached stats already exist.")
    parser.add_argument("--batch-size", type=int, default=100, help="Commit every N changed items.")
    args = parser.parse_args()

    session = get_session_factory()()
    scanned = changed = 0
    try:
        query = session.query(B2STaskItem)
        if args.project_id:
            query = query.filter(B2STaskItem.project_id == args.project_id)
        if args.task_id:
            query = query.filter(B2STaskItem.task_id == args.task_id)
        for item in query.order_by(B2STaskItem.created_at.asc(), B2STaskItem.sequence_no.asc()).yield_per(200):
            scanned += 1
            if refresh_item_function_stats(item, inspect_files=True, only_missing=not args.force):
                changed += 1
                if changed % max(1, args.batch_size) == 0:
                    session.commit()
        session.commit()
    finally:
        session.close()

    print(f"scanned={scanned} changed={changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
