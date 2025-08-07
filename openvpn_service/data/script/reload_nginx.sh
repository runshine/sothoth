#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
NGINX_ROOT_DIR="${ROOT_DIR}/nginx"
cd "$(cd "$(dirname $0)";pwd)"
if [ ! -d "${NGINX_ROOT_DIR}" ];then
  mkdir -p "${NGINX_ROOT_DIR}"
fi
. "${NGINX_ROOT_DIR}/../script/common.sh"

