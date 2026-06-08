from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import text

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.model import get_engine


def main() -> None:
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                """
            UPDATE secflow_binary_security_task t
            LEFT JOIN secflow_binary_security_task_runtime_lease l
              ON l.task_id = t.id
            SET t.runtime_phase = 'owned_execution'
            WHERE t.runtime_phase = 'tail_reconciliation'
              AND (l.task_id IS NULL OR l.lease_expires_at < NOW())
                """
            )
        )
    print("tail reconciliation repair completed")


if __name__ == "__main__":
    main()
