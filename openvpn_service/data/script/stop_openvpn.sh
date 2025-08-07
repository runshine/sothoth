#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
OPENVPN_ROOT_DIR="${ROOT_DIR}/openvpn"
cd "$(cd "$(dirname $0)";pwd)"
if [ ! -d "${OPENVPN_ROOT_DIR}" ];then
  mkdir -p "${OPENVPN_ROOT_DIR}"
fi
. "${OPENVPN_ROOT_DIR}/../script/common.sh"


kill_pid_file "${OPENVPN_ROOT_DIR}/run/client.pid"