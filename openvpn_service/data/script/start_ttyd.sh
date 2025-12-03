#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
TTYD_ROOT_DIR="${ROOT_DIR}/ttyd"
cd "$(cd "$(dirname $0)";pwd)"
if [ ! -d "${TTYD_ROOT_DIR}" ];then
  mkdir -p "${TTYD_ROOT_DIR}"
fi
. "${TTYD_ROOT_DIR}/../script/common.sh"


pre_build_dirs="$TTYD_ROOT_DIR/log $TTYD_ROOT_DIR/run"
prepare_dir "$pre_build_dirs"

if ! is_pid_file_running "${TTYD_ROOT_DIR}/run/ttyd.pid";then
  chmod +x "${TTYD_ROOT_DIR}/../utils/ttyd"
  "${TTYD_ROOT_DIR}/../utils/ttyd" -p 11198 -w / -W /bin/bash >> "$TTYD_ROOT_DIR/log/ttyd.log" 2>&1 &
  echo "$!" > "$TTYD_ROOT_DIR/run/ttyd.pid"
  logger "start ttyd: \"${TTYD_ROOT_DIR}/../utils/ttyd\" -p 11198 -w / -W /bin/bash 2>&1 >> \"$TTYD_ROOT_DIR/log/ttyd.log\", pid:$(cat $TTYD_ROOT_DIR/run/ttyd.pid)"
else
  logger "ttyd already run, ignore re-run, pid: $(cat ${TTYD_ROOT_DIR}/run/ttyd.pid)"
fi
