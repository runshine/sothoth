#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
cd "$(cd "$(dirname $0)";pwd)"
. "${ROOT_DIR}/script/common.sh"

if [ ! -d "${ROOT_DIR}/utils" ];then
  mkdir -p "${ROOT_DIR}/utils"
fi

bin="$1"
if [ "x${bin}" = "x" ];then
  logger "Usage: $0 utils_name"
  exit 255
fi

download "$UPSTREAM/utils/$bin/$OS/$ARCH" "${ROOT_DIR}/utils/$bin"
if [ -f  "${ROOT_DIR}/utils/$bin" ];then
  chmod +x  "${ROOT_DIR}/utils/$bin"
fi