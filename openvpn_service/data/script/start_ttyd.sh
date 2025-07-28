#!/bin/sh

TTYD_ROOT_DIR="$(cd "$(dirname $0)";pwd)/../ttyd"
ARCH="$(uname -m)"
OS="linux"
WORKSPACE="$1"
UPSTREAM="$2"
UPSTREAM_SERVER="$(echo $2 | awk -F':' '{print $1}')"
UPSTREAM_PORT="$(echo $2 | awk -F':' '{print $2}')"
cd "$(cd "$(dirname $0)";pwd)"
. "${TTYD_ROOT_DIR}/../script/common.sh"

pre_build_dirs="$TTYD_ROOT_DIR/log $TTYD_ROOT_DIR/run"
prepare_dir "$pre_build_dirs"

if ! is_pid_file_running "${TTYD_ROOT_DIR}/run/ttyd.pid";then
  logger "start ttyd: \"${TTYD_ROOT_DIR}/../utils/ttyd\" -p 11198 -w / -W /bin/bash 2>&1 >> \"$TTYD_ROOT_DIR/log/ttyd.log\""
  chmod +x "${TTYD_ROOT_DIR}/../utils/ttyd"
  "${TTYD_ROOT_DIR}/../utils/ttyd" -p 11198 -w / -W /bin/bash >> "$TTYD_ROOT_DIR/log/ttyd.log" 2>&1 &
  echo "$!" > "$TTYD_ROOT_DIR/run/ttyd.pid"
else
  logger "ttyd already run, ignore re-run, pid: $(cat ${TTYD_ROOT_DIR}/run/ttyd.pid)"
fi
