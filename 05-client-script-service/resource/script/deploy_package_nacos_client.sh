#!/bin/sh

set -e

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
cd "$(cd "$(dirname $0)";pwd)"
. "${ROOT_DIR}/script/common.sh"

deploy_package.sh cpython
deploy_package.sh nacos_client

cat  <<EOF > ${ROOT_DIR}/service_config/99_nacos_client_service.json
{
  "name": "nacos_client",
  "description": "nacos_client service",
  "start_cmd": "ROOT_DIR=$ROOT_DIR UPSTREAM_SERVER=${UPSTREAM_SERVER} ${ROOT_DIR}/usr/bin/python ${ROOT_DIR}/usr/nacos/nacos_client.py",
  "pid_file": "${ROOT_DIR}/var/run/nacos_client.pid",
  "stdout_log": "${ROOT_DIR}/var/log/monitor_nacos_client_stdout.log",
  "stderr_log": "${ROOT_DIR}/var/log/monitor_nacos_client_stderr.log",
  "work_dir": "${ROOT_DIR}",
  "monitor_mode": "monitor",
  "check_interval": 30,
  "max_failures": 2,
  "depends_on": []
}
EOF