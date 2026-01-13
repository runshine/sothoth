#!/bin/sh

set -e

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
cd "$(cd "$(dirname $0)";pwd)"
. "${ROOT_DIR}/script/common.sh"

deploy_package.sh frida_server

cat  <<EOF > ${ROOT_DIR}/service_config/06_frida_server_service.json
{
  "name": "frida_server",
  "description": "frida_server service",
  "start_cmd": "${ROOT_DIR}/usr/bin/frida-server -l 0.0.0.0:11189 --directory=${ROOT_DIR}/usr/lib -v",
  "pid_file": "${ROOT_DIR}/var/run/frida-server.pid",
  "stdout_log": "${ROOT_DIR}/var/log/monitor_frida-server_stdout.log",
  "stderr_log": "${ROOT_DIR}/var/log/monitor_frida-server_stderr.log",
  "work_dir": "${ROOT_DIR}",
  "monitor_mode": "monitor",
  "check_interval": 30,
  "max_failures": 2,
  "depends_on": []
}
EOF

#"${ROOT_DIR}/utils/frida_server" -l 0.0.0.0:11189 "--directory=${FRIDA_ROOT_DIR}/lib -v"  >> "${FRIDA_ROOT_DIR}/log/frida_server.log" 2>&1 &