#!/bin/bash
set -e

PI_DIR="${PI_CODING_AGENT_DIR:-/root/.pi/agent}"
mkdir -p "$PI_DIR"

if [ -f /data/config/models.json ]; then
    ln -sf /data/config/models.json "$PI_DIR/models.json"
    echo "[entrypoint] linked /data/config/models.json -> $PI_DIR/models.json"
fi

if [ -f /data/config/settings.json ]; then
    ln -sf /data/config/settings.json "$PI_DIR/settings.json"
    echo "[entrypoint] linked /data/config/settings.json -> $PI_DIR/settings.json"
fi

exec "$@"
