#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
RPCAPD_ROOT_DIR="${ROOT_DIR}/rpcapd"
cd "$(cd "$(dirname $0)";pwd)"
if [ ! -d "${RPCAPD_ROOT_DIR}" ];then
  mkdir -p "${RPCAPD_ROOT_DIR}"
fi
. "${RPCAPD_ROOT_DIR}/../script/common.sh"

if [ ! -f "${ROOT_DIR}/utils/rpcapd" ];then
  logger "rpcapd not exist, unable to start"
  exit 0
fi

pre_build_dirs="${RPCAPD_ROOT_DIR}/log ${RPCAPD_ROOT_DIR}/run"
prepare_dir "$pre_build_dirs"

if ! is_pid_file_running "${RPCAPD_ROOT_DIR}/run/rpcapd.pid";then
  chmod +x "${ROOT_DIR}/utils/rpcapd"
  "${ROOT_DIR}/utils/rpcapd"  -b 0.0.0.0 -p 11188 -4 -n -D >> "${RPCAPD_ROOT_DIR}/log/rpcapd.log" 2>&1 &
  echo "$!" > "${RPCAPD_ROOT_DIR}/run/rpcapd.pid"
  logger "start rpcapd: ${ROOT_DIR}/utils/rpcapd  -b 0.0.0.0 -p 11188 -4 -n -D, pid:$(cat ${RPCAPD_ROOT_DIR}/run/rpcapd.pid)"
else
  logger "rpcapd already run, ignore re-run, pid: $(cat ${RPCAPD_ROOT_DIR}/run/rpcapd.pid)"
fi

