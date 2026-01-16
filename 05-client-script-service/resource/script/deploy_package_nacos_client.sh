#!/bin/sh

set -e

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
cd "$(cd "$(dirname $0)";pwd)"
. "${ROOT_DIR}/script/common.sh"

deploy_package.sh cpython
deploy_package.sh nacos_client


cat  <<EOF > ${ROOT_DIR}/usr/nacos/config.json
{
  "port": 11197,
  "host": "0.0.0.0",
  "api_prefix": "/api",
  "token": "your_secure_token_here",
  "daemon": false,
  "log_dir": "${ROOT_DIR}/var/log/nacos_client",
  "log_level": "INFO",
  "compose_root": "${ROOT_DIR}/usr/nacos/services",
  "docker_compose_bin": "${ROOT_DIR}/usr/bin/docker-compose",
  "docker_bin": "${ROOT_DIR}/usr/bin/docker",
  "docker_socket": "unix://${ROOT_DIR}/var/run/docker.sock",
  "max_upload_size": 104857600,
  "database_file": "${ROOT_DIR}/usr/nacos/nacos_client.db",
  "nacos_server_url": "http://192.168.12.90:8848",
  "root_dir": "${ROOT_DIR}",
  "workspace_id": "$WORKSPACE"
}
EOF


cat  <<EOF > ${ROOT_DIR}/service_config/99_nacos_client_service.json
{
  "name": "nacos_client",
  "description": "nacos_client service",
  "start_cmd": "ROOT_DIR=$ROOT_DIR UPSTREAM_SERVER=${UPSTREAM_SERVER} ${ROOT_DIR}/usr/bin/python ${ROOT_DIR}/usr/nacos/nacos_client.py -c ${ROOT_DIR}/usr/nacos/config.json",
  "pid_file": "${ROOT_DIR}/var/run/nacos_client.pid",
  "stdout_log": "${ROOT_DIR}/var/log/monitor_nacos_client_stdout.log",
  "stderr_log": "${ROOT_DIR}/var/log/monitor_nacos_client_stderr.log",
  "work_dir": "${ROOT_DIR}/usr/nacos",
  "monitor_mode": "monitor",
  "check_interval": 30,
  "max_failures": 2,
  "depends_on": [],
  "shell": true
}
EOF