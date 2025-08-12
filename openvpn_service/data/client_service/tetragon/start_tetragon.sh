#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../../";pwd)"
TETRAGON_ROOT_DIR="${ROOT_DIR}/client_service/tetragon"
DOCKER_ROOT_DIR="${ROOT_DIR}/docker"
cd "${ROOT_DIR}"
if [ ! -d "${TETRAGON_ROOT_DIR}" ];then
  mkdir -p "${TETRAGON_ROOT_DIR}"
fi
. "${ROOT_DIR}/script/common.sh"


pre_build_dirs="${TETRAGON_ROOT_DIR}/filebeat ${TETRAGON_ROOT_DIR}/log ${TETRAGON_ROOT_DIR}/policy"
prepare_dir "$pre_build_dirs"

if [ ! -f "${TETRAGON_ROOT_DIR}/docker-compose.yml" ] ;then
  download_script "$UPSTREAM/download/client_service/tetragon/stop_tetragon.sh"            "${TETRAGON_ROOT_DIR}/stop_tetragon.sh"
  download       "$UPSTREAM/download/client_service/tetragon/docker-compose.yml"          "${TETRAGON_ROOT_DIR}/docker-compose.yml"
  download       "$UPSTREAM/download/client_service/tetragon/filebeat/filebeat.yml"       "${TETRAGON_ROOT_DIR}/filebeat/filebeat.yml"
  download       "$UPSTREAM/download/client_service/tetragon/policy/file_monitoring.yaml" "${TETRAGON_ROOT_DIR}/policy/file_monitoring.yaml"
  sed -i "s/NODE_ID/$NODE_ID/g"      "${TETRAGON_ROOT_DIR}/filebeat/filebeat.yml"
  sed -i "s/NODE_NAME/$NODE_NAME/g"  "${TETRAGON_ROOT_DIR}/filebeat/filebeat.yml"
fi

echo "start up tetragon service"
cd "${TETRAGON_ROOT_DIR}"
"${DOCKER_ROOT_DIR}/../utils/docker-compose" -H "unix:///${DOCKER_ROOT_DIR}/run/docker.sock" pull
"${DOCKER_ROOT_DIR}/../utils/docker-compose" -H "unix:///${DOCKER_ROOT_DIR}/run/docker.sock" up -d
