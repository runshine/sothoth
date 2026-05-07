#!/usr/bin/env bash
set -euo pipefail

IMAGE="${IMAGE:-secflow-app-firmware-unpacker:agentflow-migration}"
PORT="${PORT:-18080}"
PROJECT_ID="${PROJECT_ID:-agentflow-smoke}"

TMPDIR="$(mktemp -d)"
CID=""

cleanup() {
  if [ -n "${CID}" ]; then
    docker rm -f "${CID}" >/dev/null 2>&1 || true
  fi
  if [ -d "${TMPDIR}" ]; then
    docker run --rm -v "${TMPDIR}:/hosttmp" "${IMAGE}" sh -lc 'chmod -R 777 /hosttmp' >/dev/null 2>&1 || true
    rm -rf "${TMPDIR}" || true
  fi
}
trap cleanup EXIT

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

require_cmd curl
require_cmd docker
require_cmd python3

mkdir -p "${TMPDIR}/bin" "${TMPDIR}/files" "${TMPDIR}/input"

cat > "${TMPDIR}/bin/pi" <<'PY'
#!/usr/bin/env python3
import json
import sys

prompt = sys.stdin.read()
if "Review the matched-skill extraction result" in prompt:
    text = "AGENTFLOW_REVIEW_SKIPPED reason=SKIPPED_BY_PREPROCESS"
elif "Review the generic unpack result" in prompt:
    text = "AGENTFLOW_REVIEW_SKIPPED reason=SKIPPED_BY_PREPROCESS"
elif "Author a reusable skill candidate" in prompt:
    text = "SKIPPED_NO_SUCCESS"
elif "Clean and normalize the output directory" in prompt:
    text = "cleanup complete"
elif "If Preprocess contains JSON with success=true" in prompt:
    text = "AGENTFLOW_EXECUTOR_SKIPPED reason=SKIPPED_BY_PREPROCESS"
else:
    text = "ok"

message = {"role": "assistant", "content": [{"type": "text", "text": text}]}
print(json.dumps({"type": "message_end", "message": message}))
print(json.dumps({"type": "agent_end", "messages": [message]}))
PY
chmod +x "${TMPDIR}/bin/pi"

python3 - <<PY
import zipfile
from pathlib import Path

firmware = Path("${TMPDIR}/input/fw.zip")
with zipfile.ZipFile(firmware, "w") as archive:
    archive.writestr("etc/version.txt", "1.0")
PY

cat > "${TMPDIR}/config.yaml" <<YAML
database:
  type: sqlite
  path: /tmp/service.db
auth_service:
  enabled: false
project_service:
  enabled: false
registry:
  enabled: false
service:
  max_background_workers: 1
worker:
  claim_interval_seconds: 1
  claim_batch_size: 1
agentflow:
  enabled: true
  runs_dir: /data/files/.agentflow/runs
  max_concurrent_runs: 2
  node_timeout_seconds: 30
  use_worktree: false
app:
  host: 0.0.0.0
  port: 8080
YAML

CID="$(
  docker run -d --rm \
    -p "${PORT}:8080" \
    -v "${TMPDIR}/config.yaml:/tmp/config.yaml:ro" \
    -v "${TMPDIR}/bin/pi:/tmp/bin/pi:ro" \
    -v "${TMPDIR}/files:/data/files" \
    -v "${TMPDIR}/input:/tmp/input:ro" \
    -e CONFIG_PATH=/tmp/config.yaml \
    -e FIRMWARE_UNPACKER_CONFIG=/tmp/config.yaml \
    -e PROJECT_FILES_ROOT=/data/files \
    -e PATH=/tmp/bin:/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    "${IMAGE}"
)"

for attempt in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${PORT}/api/app/firmware-unpacker/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if [ "${attempt}" = "30" ]; then
    docker logs "${CID}" >&2 || true
    echo "service did not become healthy" >&2
    exit 1
  fi
done

curl -fsS -X POST "http://127.0.0.1:${PORT}/api/app/firmware-unpacker/projects/${PROJECT_ID}/tasks" \
  -H "Content-Type: application/json" \
  -d "{\"firmware_path\":\"/tmp/input/fw.zip\",\"project_id\":\"${PROJECT_ID}\"}" \
  > "${TMPDIR}/submit.json"

TASK_ID="$(
  python3 - <<PY
import json
print(json.load(open("${TMPDIR}/submit.json", encoding="utf-8"))["task_id"])
PY
)"

for attempt in $(seq 1 60); do
  curl -fsS "http://127.0.0.1:${PORT}/api/app/firmware-unpacker/projects/${PROJECT_ID}/tasks/${TASK_ID}" \
    > "${TMPDIR}/detail.json"
  STATUS="$(
    python3 - <<PY
import json
print(json.load(open("${TMPDIR}/detail.json", encoding="utf-8"))["status"])
PY
  )"
  if [ "${STATUS}" = "success" ] || [ "${STATUS}" = "failed" ] || [ "${STATUS}" = "cancelled" ]; then
    break
  fi
  sleep 1
  if [ "${attempt}" = "60" ]; then
    docker logs "${CID}" >&2 || true
    cat "${TMPDIR}/detail.json" >&2
    echo "task did not reach a terminal status" >&2
    exit 1
  fi
done

curl -fsS "http://127.0.0.1:${PORT}/api/app/firmware-unpacker/projects/${PROJECT_ID}/tasks/${TASK_ID}/agentflow" \
  > "${TMPDIR}/agentflow.json"

python3 - <<PY
import json
from pathlib import Path

root = Path("${TMPDIR}")
detail = json.load(open(root / "detail.json", encoding="utf-8"))
agentflow = json.load(open(root / "agentflow.json", encoding="utf-8"))
assert detail["status"] == "success", detail
assert detail["result_status"] == "success", detail
assert detail["rounds"] == 0, detail
assert detail["agentflow_run_id"], detail
assert agentflow["status"] == "completed", agentflow

run_path = root / "files" / Path(detail["run_path"]).relative_to("/data/files")
output_path = root / "files" / Path(detail["output_path"]).relative_to("/data/files")
assert (run_path / "final_result.json").is_file(), run_path
assert (run_path / "agentflow" / "runs" / detail["agentflow_run_id"] / "run.json").is_file(), run_path
assert (output_path / "etc" / "version.txt").is_file(), output_path

print(json.dumps({
    "task_id": detail["id"],
    "status": detail["status"],
    "result_status": detail["result_status"],
    "rounds": detail["rounds"],
    "agentflow_status": agentflow["status"],
    "agentflow_run_id": detail["agentflow_run_id"],
    "final_result_exists": True,
    "run_json_exists": True,
    "version_exists": True,
}, indent=2))
PY
