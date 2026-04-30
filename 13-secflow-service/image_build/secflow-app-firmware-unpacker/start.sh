#!/usr/bin/env bash
set -euo pipefail

echo "========================================="
echo "  SecFlow Firmware Unpacker Service (K8S)"
echo "  Node: $(node --version)"
echo "  Python: $(python3 --version 2>&1)"
echo "  Pi: $(pi --version 2>/dev/null || echo N/A)"
echo "========================================="

export CONFIG_PATH="${CONFIG_PATH:-/app/config.yaml}"
export FIRMWARE_UNPACKER_CONFIG="${FIRMWARE_UNPACKER_CONFIG:-${CONFIG_PATH}}"
export UNPACKER_AGENT_DIR="${UNPACKER_AGENT_DIR:-/app/app/agent}"
echo ""
echo "Config: ${FIRMWARE_UNPACKER_CONFIG}"
echo "Agent Dir: ${UNPACKER_AGENT_DIR}"
echo "Starting FastAPI service ..."

mkdir -p /app/data

cd /app
exec python3 /app/app/start.py
