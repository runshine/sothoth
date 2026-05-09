"""Stage 1: deterministic firmware pre-processing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.preprocess import run_preprocess


def run(payload: dict[str, Any], nodes: dict[str, Any] | None = None) -> None:
    log_dir = Path(payload["log_dir"]) if payload.get("log_dir") else None
    print(
        f"AGENTFLOW_PROGRESS stage=preprocess event=start "
        f"firmware={payload['firmware_path']} output={payload['output_path']}",
        flush=True,
    )
    try:
        result = run_preprocess(payload["firmware_path"], payload["output_path"], log_dir=log_dir)
    except Exception as exc:
        result = {"success": False, "method": None, "error": str(exc)}

    output_file = Path(payload["output_file"])
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    artifacts = result.get("artifacts") or result.get("files") or []
    artifact_count = len(artifacts) if isinstance(artifacts, list) else 0
    print(
        f"AGENTFLOW_PROGRESS stage=preprocess event=finish "
        f"success={bool(result.get('success'))} method={result.get('method')} "
        f"artifacts={artifact_count} output_file={output_file}",
        flush=True,
    )
    print(json.dumps(result, ensure_ascii=False))

