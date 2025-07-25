#!/bin/sh

TTYD_ROOT_DIR="$(cd "$(dirname $0)";pwd)/../ttyd"
ARCH="$(uname -m)"
OS="linux"
WORKSPACE="$1"
UPSTREAM="$2"
UPSTREAM_SERVER="$(echo $2 | awk -F':' '{print $1}')"
UPSTREAM_PORT="$(echo $2 | awk -F':' '{print $2}')"

pre_build_dirs="$TTYD_ROOT_DIR/log $TTYD_ROOT_DIR/run"
for dir in ${pre_build_dirs};
do
  if [ ! -d "${dir}" ];then
    echo "$(date): start create dir: ${dir}"
    mkdir -p "$dir"
  fi
done

echo "start ttyd: \"${TTYD_ROOT_DIR}/utils/ttyd\" -p 11198 -w / -W /bin/bash 2>&1 >> \"$TTYD_ROOT_DIR/log/ttyd.log\""
chmod +x "${TTYD_ROOT_DIR}/../utils/ttyd"
"${TTYD_ROOT_DIR}/../utils/ttyd" -p 11198 -w / -W /bin/bash 2>&1 >> "$TTYD_ROOT_DIR/log/ttyd.log" &
echo "$!" > "$TTYD_ROOT_DIR/run/ttyd.pid"
