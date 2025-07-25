#!/bin/sh

PYTHON_ROOT_DIR="$(cd "$(dirname $0)";pwd)/../python"
ARCH="$(uname -m)"
OS="linux"
WORKSPACE="$1"
UPSTREAM="$2"
UPSTREAM_SERVER="$(echo $2 | awk -F':' '{print $1}')"
UPSTREAM_PORT="$(echo $2 | awk -F':' '{print $2}')"

cd "$(cd "$(dirname $0)";pwd)"

download() {
    url=$1
    target=$2
    if [ -f "$target" ];then
      return
    fi
    wget "${url}" -O "$target" || curl "${url}" -o "$target"
    if [ ! -f "$target" ];then
      echo "$(date): file: $target download failed --> $url"
    else
      echo "$(date): file: $target download success"
    fi
}

pre_build_dirs="$PYTHON_ROOT_DIR"
for dir in ${pre_build_dirs};
do
  if [ ! -d "${dir}" ];then
    echo "$(date): start create dir: ${dir}"
    mkdir -p "$dir"
  fi
done

if [ ! -f "${PYTHON_ROOT_DIR}/bin/python" ];then
  download "$UPSTREAM/package/cpython/$OS/$ARCH" "${PYTHON_ROOT_DIR}/cpython.tar.gz"
  tar -zxvf "${PYTHON_ROOT_DIR}/cpython.tar.gz" -C "${PYTHON_ROOT_DIR}/../"
fi