#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
TTYD_ROOT_DIR="${ROOT_DIR}/ttyd"
cd "$(cd "$(dirname $0)";pwd)"
if [ ! -d "${TTYD_ROOT_DIR}" ];then
  mkdir -p "${TTYD_ROOT_DIR}"
fi
. "${TTYD_ROOT_DIR}/../script/common.sh"


kill_pid_file "${TTYD_ROOT_DIR}/run/ttyd.pid"

