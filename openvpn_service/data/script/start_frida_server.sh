#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
FRIDA_ROOT_DIR="${ROOT_DIR}/frida"
cd "$(cd "$(dirname $0)";pwd)"
if [ ! -d "${FRIDA_ROOT_DIR}" ];then
  mkdir -p "${FRIDA_ROOT_DIR}"
fi
. "${FRIDA_ROOT_DIR}/../script/common.sh"

if [ ! -f "${ROOT_DIR}/utils/frida_server" ];then
  logger "frida_server not exist, unable to start"
  exit 0
fi

pre_build_dirs="${FRIDA_ROOT_DIR}/log ${FRIDA_ROOT_DIR}/lib ${FRIDA_ROOT_DIR}/conf ${FRIDA_ROOT_DIR}/run"
prepare_dir "$pre_build_dirs"

if ! is_pid_file_running "${FRIDA_ROOT_DIR}/run/frida_server.pid";then
  logger "start frida_server: ${ROOT_DIR}/utils/frida_server -l 0.0.0.0:11189 --directory=${FRIDA_ROOT_DIR}/lib -v"
  chmod +x "${ROOT_DIR}/utils/frida_server"
  "${ROOT_DIR}/utils/frida_server" -l 0.0.0.0:11189 "--directory=${FRIDA_ROOT_DIR}/lib -v"  >> "${FRIDA_ROOT_DIR}/log/frida_server.log" 2>&1 &
  echo "$!" > "${FRIDA_ROOT_DIR}/run/frida_server.pid"
else
  logger "frida_server already run, ignore re-run, pid: $(cat ${FRIDA_ROOT_DIR}/run/frida_server.pid)"
fi

