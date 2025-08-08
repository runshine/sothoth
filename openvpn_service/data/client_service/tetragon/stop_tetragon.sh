#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../../";pwd)"
TETRAGON_ROOT_DIR="${ROOT_DIR}/client_service/tetragon"
DOCKER_ROOT_DIR="${ROOT_DIR}/docker"
cd "${ROOT_DIR}"
if [ ! -d "${TETRAGON_ROOT_DIR}" ];then
  mkdir -p "${TETRAGON_ROOT_DIR}"
fi
. "${ROOT_DIR}/script/common.sh"


alias docker="${DOCKER_ROOT_DIR}/bin/docker -H 'unix:///${DOCKER_ROOT_DIR}/run/docker.sock'"
alias docker-compose="${DOCKER_ROOT_DIR}/../utils/docker-compose -H 'unix:///${DOCKER_ROOT_DIR}/run/docker.sock'"

echo "start down tetragon service"
cd "${TETRAGON_ROOT_DIR}"
"${DOCKER_ROOT_DIR}/../utils/docker-compose" -H "unix:///${DOCKER_ROOT_DIR}/run/docker.sock" down -v
