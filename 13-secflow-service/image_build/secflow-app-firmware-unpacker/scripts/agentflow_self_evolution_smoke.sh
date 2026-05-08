#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export PYTHONPATH="${PYTHONPATH:-.:app:agentflow}"

pytest \
  tests/test_agentflow_migration.py \
  tests/test_skill_store.py \
  tests/test_agentflow_runs_api.py \
  tests/test_task_manager.py \
  -q

scripts/agentflow_regression_eval.py --manifest plan/agentflow-regression-samples.json >/tmp/agentflow-regression-summary.json
scripts/agentflow_evolve_skill_from_run.py --help >/tmp/agentflow-evolve-skill-help.txt

python3 -m compileall app scripts >/tmp/agentflow-compileall.log

echo "SELF_EVOLUTION_SMOKE_OK"
