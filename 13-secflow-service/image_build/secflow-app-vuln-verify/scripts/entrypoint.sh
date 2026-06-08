#!/bin/bash
set -e

PI_DIR="${PI_CODING_AGENT_DIR:-/root/.pi/agent}"
mkdir -p "$PI_DIR"

if [ -f /data/pi-re-agent-config/models.json ]; then
    ln -sf /data/pi-re-agent-config/models.json "$PI_DIR/models.json"
    echo "[entrypoint] linked /data/pi-re-agent-config/models.json -> $PI_DIR/models.json"
elif [ -f /data/config/models.json ]; then
    ln -sf /data/config/models.json "$PI_DIR/models.json"
    echo "[entrypoint] linked /data/config/models.json -> $PI_DIR/models.json"
fi

if [ -f /data/pi-re-agent-config/settings.json ]; then
    ln -sf /data/pi-re-agent-config/settings.json "$PI_DIR/settings.json"
    echo "[entrypoint] linked /data/pi-re-agent-config/settings.json -> $PI_DIR/settings.json"
elif [ -f /data/config/settings.json ]; then
    ln -sf /data/config/settings.json "$PI_DIR/settings.json"
    echo "[entrypoint] linked /data/config/settings.json -> $PI_DIR/settings.json"
fi

if [ -f /data/pi-re-agent-config/auth.json ]; then
    ln -sf /data/pi-re-agent-config/auth.json "$PI_DIR/auth.json"
    echo "[entrypoint] linked /data/pi-re-agent-config/auth.json -> $PI_DIR/auth.json"
elif [ -f /data/config/auth.json ]; then
    ln -sf /data/config/auth.json "$PI_DIR/auth.json"
    echo "[entrypoint] linked /data/config/auth.json -> $PI_DIR/auth.json"
fi

exec "$@"
