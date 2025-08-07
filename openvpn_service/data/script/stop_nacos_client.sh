#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
NACOS_ROOT_DIR="${ROOT_DIR}/nacos"
cd "$(cd "$(dirname $0)";pwd)"
if [ ! -d "${NACOS_ROOT_DIR}" ];then
  mkdir -p "${NACOS_ROOT_DIR}"
fi
. "${NACOS_ROOT_DIR}/../script/common.sh"


kill_pid_file "$NACOS_ROOT_DIR/run/client.pid"
