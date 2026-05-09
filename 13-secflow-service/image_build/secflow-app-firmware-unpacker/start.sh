#!/usr/bin/env bash
set -euo pipefail

echo "========================================="
echo "  SecFlow Firmware Unpacker AgentFlow"
echo "  Node: $(node --version)"
echo "  Python: $(python3 --version 2>&1)"
echo "  Pi: $(pi --version 2>/dev/null || echo N/A)"
echo "========================================="

export CONFIG_PATH="${CONFIG_PATH:-/app/config.yaml}"
export FIRMWARE_UNPACKER_CONFIG="${FIRMWARE_UNPACKER_CONFIG:-${CONFIG_PATH}}"
export UNPACKER_AGENT_DIR="${UNPACKER_AGENT_DIR:-/app/app/agent}"
export UNPACKER_TOOLS_DIR="${UNPACKER_TOOLS_DIR:-/data/secflow-app-firmware-unpacker/tools}"
echo ""
echo "Config: ${FIRMWARE_UNPACKER_CONFIG}"
echo "Agent Dir: ${UNPACKER_AGENT_DIR}"
echo "Tools Dir: ${UNPACKER_TOOLS_DIR}"
echo "Firmware: ${FIRMWARE_PATH:-${firmware:-}}"
echo "Output: ${OUTPUT_PATH:-${FIRMWARE_OUTPUT:-${output:-}}}"
echo "Starting AgentFlow pipeline ..."

mkdir -p /app/data
mkdir -p "${UNPACKER_TOOLS_DIR}"

cd /app
exec python3 -m app.cli "$@"
