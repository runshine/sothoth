"""One-job subprocess runner for firmware evolution jobs."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
os.environ["PYTHONPATH"] = str(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "app"))


logger = logging.getLogger(__name__)
_cancel_event = threading.Event()


def _install_signal_handlers(job_id: str) -> None:
    def _handle_signal(signum, _frame) -> None:
        logger.warning("evolution runner %s received signal %s", job_id, signum)
        _cancel_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a single firmware evolution job")
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--owner-id", required=True)
    parser.add_argument("--run-token", required=True)
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    _install_signal_handlers(args.job_id)

    from app.services.task_manager import run_claimed_evolution_job_process

    run_claimed_evolution_job_process(
        args.job_id,
        owner_id=args.owner_id,
        run_token=args.run_token,
    )
    return 130 if _cancel_event.is_set() else 0


if __name__ == "__main__":
    raise SystemExit(main())
