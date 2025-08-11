#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
CLIENT_SERVICE_ROOT_DIR="${ROOT_DIR}/client_service"
cd "${ROOT_DIR}"
if [ ! -d "${CLIENT_SERVICE_ROOT_DIR}" ];then
  mkdir -p "${CLIENT_SERVICE_ROOT_DIR}"
fi
. "${ROOT_DIR}/script/common.sh"


"${CLIENT_SERVICE_ROOT_DIR}/tetragon/stop_tetragon.sh"
"${CLIENT_SERVICE_ROOT_DIR}/opentelemetry_java/stop_opentelemetry.sh"