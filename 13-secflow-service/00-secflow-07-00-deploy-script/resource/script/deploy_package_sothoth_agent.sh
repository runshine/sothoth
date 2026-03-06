#!/bin/sh

set -e

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
cd "$(cd "$(dirname $0)";pwd)"
. "${ROOT_DIR}/script/common.sh"

deploy_package.sh sothothv1_agent


SERVER_IP=$(${ROOT_DIR}/usr/bin/busybox nslookup nginx-server.sothoth.svc.cluster.local 10.96.0.10 2>/dev/null | grep -E '^Address: ' | grep -v '#' | awk '{print $2}' | head -n1)

cat  <<EOF > ${ROOT_DIR}/service_config/99_sothothv1_service.json
{
  "name": "sothoth",
  "description": "sothoth v1 service",
  "start_cmd": "${ROOT_DIR}/usr/bin/sothothv1_agent -server=http://${SERVER_IP}:80 -projectId=${PROJECT_ID} -nodeId=${NODE_ID} -gaiasecDir=${ROOT_DIR}/usr/sothoth -autohook",
  "pid_file": "${ROOT_DIR}/var/sothoth/nodeagent.pid",
  "stdout_log": "${ROOT_DIR}/var/log/monitor_sothothv1_stdout.log",
  "stderr_log": "${ROOT_DIR}/var/log/monitor_sothothv1_stderr.log",
  "work_dir": "${ROOT_DIR}/usr/sothoth",
  "monitor_mode": "monitor",
  "check_interval": 30,
  "max_failures": 2,
  "depends_on": [],
  "shell": false
}
EOF
