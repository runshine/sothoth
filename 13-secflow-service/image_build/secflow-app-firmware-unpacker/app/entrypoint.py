#!/usr/bin/env python3
"""Container entrypoint selector for API and background runtime roles."""

from __future__ import annotations

import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent.parent

os.environ["PYTHONPATH"] = str(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "app"))

from app.config import get_runtime_roles


def resolve_runtime_mode() -> str:
    roles = get_runtime_roles()
    if "all" in roles or "api" in roles:
        return "api"
    return "background"


def main() -> int:
    mode = resolve_runtime_mode()
    if mode == "api":
        from app.start import main as start_api

        return int(start_api())

    from app.background import main as start_background

    return int(start_background())


if __name__ == "__main__":
    raise SystemExit(main())
