"""Stage: remove empty output artifacts after a successful generic run."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def run(payload: dict[str, Any], nodes: dict[str, Any] | None = None) -> None:
    output = Path(payload["output_path"])
    print(f"AGENTFLOW_PROGRESS stage=cleanup event=start output={output}", flush=True)
    removed_files: list[str] = []
    removed_dirs: list[str] = []

    for path in sorted(output.rglob("*")):
        try:
            if path.is_file() and path.stat().st_size == 0:
                path.unlink()
                removed_files.append(str(path.relative_to(output)))
        except OSError:
            continue

    for path in sorted([item for item in output.rglob("*") if item.is_dir()], reverse=True):
        try:
            if any(path.iterdir()):
                continue
            path.rmdir()
            removed_dirs.append(str(path.relative_to(output)))
        except OSError:
            continue

    print(
        f"AGENTFLOW_PROGRESS stage=cleanup event=finish "
        f"removed_files={len(removed_files)} removed_dirs={len(removed_dirs)}",
        flush=True,
    )
    print(json.dumps({"removed_files": removed_files, "removed_dirs": removed_dirs}, ensure_ascii=False))

