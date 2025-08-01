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

if [ ! -f "${PYTHON_ROOT_DIR}/bin/python" ] || [ "x${FORCE_DOWNLOAD}" != "x" ];then
  download "$UPSTREAM/package/cpython/$OS/$ARCH" "${PYTHON_ROOT_DIR}/cpython.tar.gz"
  if [ "x$(command -v tar)" != "x" ];then
    tar -zxvf "${PYTHON_ROOT_DIR}/cpython.tar.gz" -C "${PYTHON_ROOT_DIR}/../" 1>/dev/null
  else
    "${PYTHON_ROOT_DIR}/../utils/7zz" x -y -so "${PYTHON_ROOT_DIR}/cpython.tar.gz" | "${PYTHON_ROOT_DIR}/../utils/7zz" x -y -ttar -si -o"${PYTHON_ROOT_DIR}/../" > /dev/null
  fi
  if [ $? -eq 0 ];then
    logger "cpython decompress process success!"
  else
    logger "cpython decompress process failed!"
  fi
  rm -rf "${PYTHON_ROOT_DIR}/cpython.tar.gz"
fi