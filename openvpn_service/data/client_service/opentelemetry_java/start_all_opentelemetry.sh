#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../../";pwd)"
OPEN_TELEMETRY_ROOT_DIR="${ROOT_DIR}/client_service/opentelemetry_java"
DOCKER_ROOT_DIR="${ROOT_DIR}/docker"
cd "${ROOT_DIR}"
if [ ! -d "${OPEN_TELEMETRY_ROOT_DIR}" ];then
  mkdir -p "${OPEN_TELEMETRY_ROOT_DIR}"
fi
. "${ROOT_DIR}/script/common.sh"

