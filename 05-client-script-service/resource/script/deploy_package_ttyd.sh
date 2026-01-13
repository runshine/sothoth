#!/bin/sh

set -e

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
cd "$(cd "$(dirname $0)";pwd)"
. "${ROOT_DIR}/script/common.sh"

deploy_package.sh ttyd

chmod +x "${ROOT_DIR}/usr/bin/ttyd"

cat  <<EOF > ${ROOT_DIR}/service_config/02_ttyd_service.json
{
  "name": "ttyd",
  "description": "ttyd service",
  "start_cmd": "${ROOT_DIR}/usr/bin/ttyd -p 11198 -w  \"${ROOT_DIR}\" -W  \"${ROOT_DIR}/usr/bin/bash\" ",
  "pid_file": "${ROOT_DIR}/var/run/ttyd.pid",
  "stdout_log": "${ROOT_DIR}/var/log/monitor_ttyd_stdout.log",
  "stderr_log": "${ROOT_DIR}/var/log/monitor_ttyd_stderr.log",
  "work_dir": "${ROOT_DIR}",
  "monitor_mode": "monitor",
  "check_interval": 30,
  "max_failures": 2,
  "depends_on": []
}
EOF