#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
FRIDA_ROOT_DIR="${ROOT_DIR}/frida"
cd "$(cd "$(dirname $0)";pwd)"
if [ ! -d "${FRIDA_ROOT_DIR}" ];then
  mkdir -p "${FRIDA_ROOT_DIR}"
fi
. "${FRIDA_ROOT_DIR}/../script/common.sh"


kill_pid_file "${FRIDA_ROOT_DIR}/run/frida_server.pid"