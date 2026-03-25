#!/bin/bash

set -euo pipefail

AUTH_URL="${AUTH_URL:-http://127.0.0.1:18080}"
PROJECT_URL="${PROJECT_URL:-http://127.0.0.1:18081}"
FILESERVER_URL="${FILESERVER_URL:-http://127.0.0.1:18082}"
USERNAME="${USERNAME:-admin}"
PASSWORD="${PASSWORD:-Huawei12#$}"

echo "[1/7] health check"
curl -fsS "${FILESERVER_URL}/api/fileserver/health" >/tmp/fileserver-health.json
cat /tmp/fileserver-health.json
echo

echo "[2/7] login"
TOKEN=$(
python3 - <<PY
import json, urllib.request
req = urllib.request.Request(
    "${AUTH_URL}/api/auth/login",
    data=json.dumps({"username": "${USERNAME}", "password": "${PASSWORD}"}).encode(),
    method="POST",
)
req.add_header("Content-Type", "application/json")
with urllib.request.urlopen(req, timeout=20) as resp:
    print(json.loads(resp.read().decode())["access_token"])
PY
)

echo "[3/7] pvc info"
PVC_RESP=$(curl -fsS "${FILESERVER_URL}/api/fileserver/storage/pvc" \
  -H "Authorization: Bearer ${TOKEN}")
echo "${PVC_RESP}"
PVC_NAME=$(printf '%s' "$PVC_RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["pvc_name"])')
if [[ -z "${PVC_NAME}" || "${PVC_NAME}" == "null" ]]; then
  echo "storage pvc lookup failed" >&2
  exit 1
fi

echo "[4/7] resolve project"
PROJECT_ID=$(
TOKEN="$TOKEN" python3 - <<PY
import json, os, urllib.request
req = urllib.request.Request("${PROJECT_URL}/api/project", method="GET")
req.add_header("Authorization", "Bearer " + os.environ["TOKEN"])
with urllib.request.urlopen(req, timeout=20) as resp:
    print(json.loads(resp.read().decode())["projects"][0]["id"])
PY
)
echo "project_id=${PROJECT_ID}"

SUB_NAME="smoke-$(date +%s)"
TEST_FILE="$(mktemp /tmp/fileserver-smoke-XXXXXX.txt)"
DOWNLOAD_FILE="${TEST_FILE}.download"
echo "fileserver smoke test $(date -u +%FT%TZ)" > "${TEST_FILE}"

echo "[5/7] create subproject + directory"
SUB_RESP=$(
TOKEN="$TOKEN" PROJECT_ID="$PROJECT_ID" SUB_NAME="$SUB_NAME" python3 - <<PY
import json, os, urllib.request
payload = {
    "project_id": os.environ["PROJECT_ID"],
    "name": os.environ["SUB_NAME"],
    "description": "smoke-test"
}
req = urllib.request.Request("${FILESERVER_URL}/api/fileserver/subprojects", data=json.dumps(payload).encode(), method="POST")
req.add_header("Content-Type", "application/json")
req.add_header("Authorization", "Bearer " + os.environ["TOKEN"])
with urllib.request.urlopen(req, timeout=20) as resp:
    print(resp.read().decode())
PY
)
SUB_ID=$(printf '%s' "$SUB_RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
DIR_RESP=$(
TOKEN="$TOKEN" PROJECT_ID="$PROJECT_ID" SUB_ID="$SUB_ID" python3 - <<PY
import json, os, urllib.request
payload = {
    "project_id": os.environ["PROJECT_ID"],
    "subproject_id": int(os.environ["SUB_ID"]),
    "name": "docs"
}
req = urllib.request.Request("${FILESERVER_URL}/api/fileserver/directories", data=json.dumps(payload).encode(), method="POST")
req.add_header("Content-Type", "application/json")
req.add_header("Authorization", "Bearer " + os.environ["TOKEN"])
with urllib.request.urlopen(req, timeout=20) as resp:
    print(resp.read().decode())
PY
)
DIR_ID=$(printf '%s' "$DIR_RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
echo "subproject_id=${SUB_ID}, directory_id=${DIR_ID}"

echo "[6/7] upload + list"
UPLOAD_RESP=$(curl -fsS -X POST "${FILESERVER_URL}/api/fileserver/files/upload" \
  -H "Authorization: Bearer ${TOKEN}" \
  -F "project_id=${PROJECT_ID}" \
  -F "subproject_id=${SUB_ID}" \
  -F "directory_id=${DIR_ID}" \
  -F "file=@${TEST_FILE};type=text/plain")
FILE_ID=$(printf '%s' "$UPLOAD_RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
LIST_RESP=$(curl -fsS "${FILESERVER_URL}/api/fileserver/files?project_id=${PROJECT_ID}&subproject_id=${SUB_ID}&directory_id=${DIR_ID}" \
  -H "Authorization: Bearer ${TOKEN}")
echo "${LIST_RESP}"

echo "[7/7] download"
curl -fsS "${FILESERVER_URL}/api/fileserver/files/${FILE_ID}/download" \
  -H "Authorization: Bearer ${TOKEN}" \
  -o "${DOWNLOAD_FILE}"
cat "${DOWNLOAD_FILE}"
echo
echo "pvc_name=${PVC_NAME}"
echo "smoke test passed"
