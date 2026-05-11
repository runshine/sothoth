#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
DEFAULT_RUNS_DIR="$ROOT_DIR/unpacked-demo2-direct/.agentflow-test-runs"

if [ -x "$ROOT_DIR/.venv/bin/python" ] && "$ROOT_DIR/.venv/bin/python" -c "import agentflow" >/dev/null 2>&1; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
fi

mkdir -p "$DEFAULT_RUNS_DIR"

PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
FIRMWARE_PATH="${FIRMWARE_PATH:-$ROOT_DIR/targets/demo2/S6730_V200R024C00SPC500.cc}" \
OUTPUT_PATH="${OUTPUT_PATH:-$ROOT_DIR/unpacked-demo2-direct/output}" \
RUN_PATH="${RUN_PATH:-$ROOT_DIR/unpacked-demo2-direct/run}" \
TOOLS_DIR="${TOOLS_DIR:-$ROOT_DIR/tools}" \
UNPACKER_TOOLS_DIR="${UNPACKER_TOOLS_DIR:-$ROOT_DIR/tools}" \
AGENTFLOW_RUNS_DIR="${AGENTFLOW_RUNS_DIR:-$DEFAULT_RUNS_DIR}" \
"$PYTHON_BIN" -m app.cli "$@"
