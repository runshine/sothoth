#!/bin/sh

set -e

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
cd "$(cd "$(dirname $0)";pwd)"
. "${ROOT_DIR}/script/common.sh"

deploy_package.sh rpcapd

cat  <<EOF > ${ROOT_DIR}/service_config/04_rpcapd_service.json
{
  "name": "rpcapd",
  "description": "rpcapd service",
  "start_cmd": "${ROOT_DIR}/usr/bin/rpcapd -b 0.0.0.0 -p 11187 -4 -n -D",
  "pid_file": "${ROOT_DIR}/var/run/rpcapd.pid",
  "stdout_log": "${ROOT_DIR}/var/log/monitor_rpcapd_stdout.log",
  "stderr_log": "${ROOT_DIR}/var/log/monitor_rpcapd_stderr.log",
  "work_dir": "${ROOT_DIR}",
  "monitor_mode": "monitor",
  "check_interval": 30,
  "max_failures": 2,
  "depends_on": [],
  "shell": false
}
EOF

