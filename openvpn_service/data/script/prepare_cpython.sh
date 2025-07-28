#!/bin/sh

PYTHON_ROOT_DIR="$(cd "$(dirname $0)";pwd)/../python"
ARCH="$(uname -m)"
OS="linux"
WORKSPACE="$1"
UPSTREAM="$2"
UPSTREAM_SERVER="$(echo $2 | awk -F':' '{print $1}')"
UPSTREAM_PORT="$(echo $2 | awk -F':' '{print $2}')"
cd "$(cd "$(dirname $0)";pwd)"
if [ ! -d "${PYTHON_ROOT_DIR}" ];then
  mkdir -p "${PYTHON_ROOT_DIR}"
fi
. "${PYTHON_ROOT_DIR}/../script/common.sh"

pre_build_dirs="$PYTHON_ROOT_DIR"
prepare_dir "$pre_build_dirs"

if [ ! -f "${PYTHON_ROOT_DIR}/bin/python" ];then
  download "$UPSTREAM/package/cpython/$OS/$ARCH" "${PYTHON_ROOT_DIR}/cpython.tar.gz"
  tar -zxvf "${PYTHON_ROOT_DIR}/cpython.tar.gz" -C "${PYTHON_ROOT_DIR}/../" 1>/dev/null
  if [ $? -eq 0 ];then
    logger "cpython decompress process success!"
  else
    logger "cpython decompress process failed!"
  fi
fi