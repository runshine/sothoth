#!/bin/sh

set -e

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
cd "$(cd "$(dirname $0)";pwd)"
. "${ROOT_DIR}/script/common.sh"

package="$1"

if [ -z "$package" ];then
  logger "arg 0 is package name, must input"
  exit 255
fi

[ -d "${ROOT_DIR}/tmp/" ] || mkdir -p "${ROOT_DIR}/tmp/"
[ -d "${ROOT_DIR}/usr/" ] || mkdir -p "${ROOT_DIR}/usr/"

download_package "${package}" "${ROOT_DIR}/tmp/${package}.tar.gz"
tar -xf "${ROOT_DIR}/tmp/${package}.tar.gz" -C "${ROOT_DIR}/usr/"
rm -rf "${ROOT_DIR}/tmp/${package}.tar.gz"

logger "deploy ${package} success"