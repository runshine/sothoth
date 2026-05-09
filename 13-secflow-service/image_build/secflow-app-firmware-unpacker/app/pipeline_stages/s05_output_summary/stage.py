"""Stage: ensure the output directory has a useful summary.txt."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def run(payload: dict[str, Any], nodes: dict[str, Any] | None = None) -> None:
    output = Path(payload["output_path"])
    summary = Path(payload["summary_file"])
    print(f"AGENTFLOW_PROGRESS stage=output_summary event=start output={output} summary={summary}", flush=True)
    summary.parent.mkdir(parents=True, exist_ok=True)
    if summary.exists() and summary.stat().st_size > 0:
        print(f"AGENTFLOW_PROGRESS stage=output_summary event=finish reused=true bytes={summary.stat().st_size}", flush=True)
        print(json.dumps({"summary_written": False, "summary_path": str(summary)}, ensure_ascii=False))
        return

    files = sorted(path for path in output.rglob("*") if path.is_file() and path.name != "summary.txt")
    lines = [f"Firmware: {payload['firmware_path']}", "Observed artifacts:"]
    if files:
        for path in files:
            lines.append(f"- {path.relative_to(output)} ({path.stat().st_size} bytes)")
        lines.extend(
            [
                "",
                "Summary: extraction artifacts were produced and recorded by the unpacking pipeline.",
                "Skill Reuse Notes: reuse the detected offsets, archive type, and artifact layout for similar firmware images.",
            ]
        )
    else:
        lines.extend(
            [
                "- no extraction artifacts were produced by the executor",
                "",
                "Summary: the run did not produce recoverable components.",
                "Skill Reuse Notes: if the unpacker emits no artifacts, record the blocker in summary.txt instead of leaving the output directory empty.",
            ]
        )
    summary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(
        f"AGENTFLOW_PROGRESS stage=output_summary event=finish "
        f"reused=false artifacts={len(files)} bytes={summary.stat().st_size}",
        flush=True,
    )
    print(json.dumps({"summary_written": True, "summary_path": str(summary), "artifact_count": len(files)}, ensure_ascii=False))

