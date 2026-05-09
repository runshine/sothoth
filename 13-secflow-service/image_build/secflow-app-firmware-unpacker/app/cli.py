"""AgentFlow-only command line entry point for firmware unpacking."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.agentflow_runner import run_unpack_agentflow
from app.config import load_config
from app.logging_utils import configure_container_logging


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the firmware unpack AgentFlow pipeline.")
    parser.add_argument("--firmware", default=None, help="Firmware file path. Defaults to FIRMWARE_PATH.")
    parser.add_argument("--output", default=None, help="Output directory. Defaults to OUTPUT_PATH/FIRMWARE_OUTPUT.")
    parser.add_argument("--task-id", default=None, help="Optional task id for logs.")
    parser.add_argument("--project-id", default=None, help="Optional project id for logs.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    firmware = args.firmware or _env("FIRMWARE_PATH", "firmware")
    output = args.output or _env("OUTPUT_PATH", "FIRMWARE_OUTPUT", "output")
    if not firmware or not output:
        print("FIRMWARE_PATH/--firmware and OUTPUT_PATH/--output are required", file=sys.stderr)
        return 2

    configure_container_logging("secflow-app-firmware-unpacker")
    load_config()
    Path(output).mkdir(parents=True, exist_ok=True)
    result = run_unpack_agentflow(firmware, output, task_id=args.task_id, project_id=args.project_id)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("status") == "success" else 1


def _env(*names: str) -> str | None:
    import os

    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


if __name__ == "__main__":
    raise SystemExit(main())

