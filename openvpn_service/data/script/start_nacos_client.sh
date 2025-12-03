#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
NACOS_ROOT_DIR="${ROOT_DIR}/nacos"
cd "$(cd "$(dirname $0)";pwd)"
if [ ! -d "${NACOS_ROOT_DIR}" ];then
  mkdir -p "${NACOS_ROOT_DIR}"
fi
. "${NACOS_ROOT_DIR}/../script/common.sh"


pre_build_dirs="$NACOS_ROOT_DIR/log $NACOS_ROOT_DIR/script $NACOS_ROOT_DIR/run"
prepare_dir "$pre_build_dirs"

if [ ! -f "${NACOS_ROOT_DIR}/script/nacos_client.py" ] || [ "x${FORCE_DOWNLOAD}" != "x" ];then
  download "$UPSTREAM/download/script/nacos/nacos_client.py" "${NACOS_ROOT_DIR}/script/nacos_client.py"
  download "$UPSTREAM/download/script/nacos/common_utils.py" "${NACOS_ROOT_DIR}/script/common_utils.py"
fi

if ! is_pid_file_running "${NACOS_ROOT_DIR}/run/client.pid";then
  chmod +x "${NACOS_ROOT_DIR}/script/nacos_client.py"
  NACOS_ROOT_DIR="${NACOS_ROOT_DIR}" UPSTREAM_SERVER="${UPSTREAM_SERVER}" "${NACOS_ROOT_DIR}/../python/bin/python" "${NACOS_ROOT_DIR}/script/nacos_client.py" &
  echo "$!" > "${NACOS_ROOT_DIR}/run/client.pid"
  logger "start nacos_client, pid: $(cat ${NACOS_ROOT_DIR}/run/client.pid)"
else
  logger "nacos_client already run, ignore re-run, pid: $(cat ${NACOS_ROOT_DIR}/run/client.pid)"
fi

