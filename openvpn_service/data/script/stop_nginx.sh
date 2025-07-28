#!/bin/sh

NGINX_ROOT_DIR="$(cd "$(dirname $0)";pwd)/../nginx"
ARCH="$(uname -m)"
OS="linux"
WORKSPACE="$1"
UPSTREAM="$2"
UPSTREAM_SERVER="$(echo $2 | awk -F':' '{print $1}')"
UPSTREAM_PORT="$(echo $2 | awk -F':' '{print $2}')"
cd "$(cd "$(dirname $0)";pwd)"
if [ ! -d "${NGINX_ROOT_DIR}" ];then
  mkdir -p "${NGINX_ROOT_DIR}"
fi
. "${NGINX_ROOT_DIR}/../script/common.sh"

kill_pid_file "${NGINX_ROOT_DIR}/run/nginx.pid"