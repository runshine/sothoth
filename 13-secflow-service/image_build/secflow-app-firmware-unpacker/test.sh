#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

TARGETS_DIR="${TARGETS_DIR:-$ROOT_DIR/targets}"
OUTPUT_ROOT="${OUTPUT_ROOT:-$ROOT_DIR/unpacked}"
TOOLS_ROOT="${TOOLS_ROOT:-$ROOT_DIR/tools}"

export PYTHONPATH="${PYTHONPATH:-.:app:agentflow}"
export AGENTFLOW_RUNS_DIR="${AGENTFLOW_RUNS_DIR:-$ROOT_DIR/.agentflow/runs}"
export UNPACKER_TOOLS_DIR="${UNPACKER_TOOLS_DIR:-$TOOLS_ROOT}"

rm -rf "$OUTPUT_ROOT/server"
mkdir -p "$OUTPUT_ROOT"

python3 - <<'PY'
import json
from pathlib import Path

from app.config import get_config
import app.unpacker_engine as engine
from app.agentflow_runner import run_unpack_agentflow

cfg = get_config()
cfg.agentflow.node_timeout_seconds = 360
engine._get_max_retries = lambda: 1

repo = Path.cwd()
targets_dir = Path(__import__("os").environ["TARGETS_DIR"]) if "TARGETS_DIR" in __import__("os").environ else repo / "targets"
output_root = Path(__import__("os").environ["OUTPUT_ROOT"]) if "OUTPUT_ROOT" in __import__("os").environ else repo / "unpacked"

files = sorted(path for path in targets_dir.iterdir() if path.is_file())
print(json.dumps({"targets_dir": str(targets_dir), "files": [str(path) for path in files]}, ensure_ascii=False), flush=True)

results = []
for firmware in files:
    output_path = output_root / firmware.name / "output"
    output_path.mkdir(parents=True, exist_ok=True)
    print(f"RUN_START {firmware} -> {output_path}", flush=True)
    try:
        result = run_unpack_agentflow(
            str(firmware),
            str(output_path),
            task_id=f"local-{firmware.name}",
            project_id="local-targets",
        )
    except Exception as exc:
        result = {
            "status": "error",
            "firmware_path": str(firmware),
            "output_path": str(output_path),
            "error": repr(exc),
        }
    results.append(result)
    print("RUN_RESULT " + json.dumps(result, ensure_ascii=False), flush=True)

summary_path = output_root / "agentflow_results.json"
summary_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
print("SUMMARY " + str(summary_path), flush=True)
print(json.dumps(results, ensure_ascii=False, indent=2), flush=True)
PY

echo
echo "Results: $OUTPUT_ROOT/agentflow_results.json"
