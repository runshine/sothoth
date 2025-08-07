#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
OPENSSH_ROOT_DIR="${ROOT_DIR}/openssh"
cd "$(cd "$(dirname $0)";pwd)"
if [ ! -d "${OPENSSH_ROOT_DIR}" ];then
  mkdir -p "${OPENSSH_ROOT_DIR}"
fi
. "${OPENSSH_ROOT_DIR}/../script/common.sh"


kill_pid_file "${OPENSSH_ROOT_DIR}/run/sshd.pid"