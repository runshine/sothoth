#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
RPCAPD_ROOT_DIR="${ROOT_DIR}/rpcapd"
cd "$(cd "$(dirname $0)";pwd)"
if [ ! -d "${RPCAPD_ROOT_DIR}" ];then
  mkdir -p "${RPCAPD_ROOT_DIR}"
fi
. "${RPCAPD_ROOT_DIR}/../script/common.sh"


kill_pid_file "${RPCAPD_ROOT_DIR}/run/rpcapd.pid"