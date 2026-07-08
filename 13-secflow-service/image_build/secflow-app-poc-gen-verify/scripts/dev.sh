#!/usr/bin/env bash
# Local dev / testing helper for secflow-app-poc-gen-verify.
# Brings up the full Celery stack (Redis + MySQL + API + worker + scheduler) via
# docker compose, then runs curl smoke tests against the API.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "[dev] WARNING: .env not found — copy .env.example and set ANTHROPIC_AUTH_TOKEN"
  echo "[dev] the worker cannot run claude without it (API/dispatcher still work)."
fi

echo "[dev] building + starting the stack (this builds the image once, ~minutes)…"
docker compose up --build -d

echo "[dev] waiting for API to be ready…"
for i in $(seq 1 60); do
  if curl -sf http://127.0.0.1:8080/api/app/poc-gen-verify/ready >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo "[dev] health:"; curl -s http://127.0.0.1:8080/api/app/poc-gen-verify/health; echo
echo "[dev] ready:";  curl -s http://127.0.0.1:8080/api/app/poc-gen-verify/ready;  echo
echo "[dev] stats:";  curl -s 'http://127.0.0.1:8080/api/app/poc-gen-verify/tasks/stats?project_id=dev'; echo

cat <<'EOF'

[dev] create a task (example):
  curl -s -X POST http://127.0.0.1:8080/api/app/poc-gen-verify/tasks \
    -H 'Content-Type: application/json' \
    -d '{"project_id":"dev","task_name":"smoke","entry_function":"IPSEC_SOCKI_PipeMsg","vuln_report_path":"/workspace/reports/r.md","binary_dir":"/workspace/firmware"}'

[dev] tail logs:    docker compose logs -f worker scheduler api
[dev] stop:         docker compose down
EOF
