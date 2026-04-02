#!/usr/bin/env bash
set -euo pipefail

ROLE="${ROLE:-manager}"

if [ "$ROLE" = "worker" ]; then
  exec python -m app.worker_entry
fi

exec python -m app.main
