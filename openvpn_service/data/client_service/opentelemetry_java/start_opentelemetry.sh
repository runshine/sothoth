#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../../";pwd)"
OPEN_TELEMETRY_ROOT_DIR="${ROOT_DIR}/client_service/opentelemetry_java"
DOCKER_ROOT_DIR="${ROOT_DIR}/docker"
cd "${ROOT_DIR}"
if [ ! -d "${OPEN_TELEMETRY_ROOT_DIR}" ];then
  mkdir -p "${OPEN_TELEMETRY_ROOT_DIR}"
fi
. "${ROOT_DIR}/script/common.sh"


pre_build_dirs="${OPEN_TELEMETRY_ROOT_DIR}/log"
prepare_dir "$pre_build_dirs"

if [ ! -f "${OPEN_TELEMETRY_ROOT_DIR}/docker-compose.yml" ] ;then
  download_script "$UPSTREAM/download/client_service/opentelemetry_java/stop_opentelemetry.sh"            "${OPEN_TELEMETRY_ROOT_DIR}/stop_opentelemetry.sh"
  download       "$UPSTREAM/download/client_service/opentelemetry_java/docker-compose.yml"                "${OPEN_TELEMETRY_ROOT_DIR}/docker-compose.yml"
fi

echo "start up opentelemetry_java service"
cd "${OPEN_TELEMETRY_ROOT_DIR}"
export TARGET_DIR="${TARGET_DIR}"
"${DOCKER_ROOT_DIR}/../utils/docker-compose" -H "unix:///${DOCKER_ROOT_DIR}/run/docker.sock" pull
"${DOCKER_ROOT_DIR}/../utils/docker-compose" -H "unix:///${DOCKER_ROOT_DIR}/run/docker.sock" up -d
