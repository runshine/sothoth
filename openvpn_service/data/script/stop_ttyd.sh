#!/bin/sh

TTYD_ROOT_DIR="$(cd "$(dirname $0)";pwd)/../ttyd"
ARCH="$(uname -m)"
OS="linux"
WORKSPACE="$1"
UPSTREAM="$2"
UPSTREAM_SERVER="$(echo $2 | awk -F':' '{print $1}')"
UPSTREAM_PORT="$(echo $2 | awk -F':' '{print $2}')"
cd "$(cd "$(dirname $0)";pwd)"
if [ -d "${TTYD_ROOT_DIR}" ];then
  mkdir -p "${TTYD_ROOT_DIR}"
fi
. "${TTYD_ROOT_DIR}/../script/common.sh"

kill_pid_file "${TTYD_ROOT_DIR}/run/ttyd.pid"

