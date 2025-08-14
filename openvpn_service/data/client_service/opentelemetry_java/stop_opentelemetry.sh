#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../../";pwd)"
OPEN_TELEMETRY_ROOT_DIR="${ROOT_DIR}/client_service/opentelemetry_java"
DOCKER_ROOT_DIR="${ROOT_DIR}/docker"
cd "${ROOT_DIR}"
if [ ! -d "${OPEN_TELEMETRY_ROOT_DIR}" ];then
  mkdir -p "${OPEN_TELEMETRY_ROOT_DIR}"
fi
. "${ROOT_DIR}/script/common.sh"


alias docker="${DOCKER_ROOT_DIR}/bin/docker -H 'unix:///${DOCKER_ROOT_DIR}/run/docker.sock'"
alias docker-compose="${DOCKER_ROOT_DIR}/../utils/docker-compose -H 'unix:///${DOCKER_ROOT_DIR}/run/docker.sock'"

echo "start down opentelemetry_java service"
cd "${OPEN_TELEMETRY_ROOT_DIR}"

pid="$1"
if [ "x${pid}" = "x" ];then
  echo "No input pid, we stop all opentelemetry"
  for container in $(docker ps -a | grep opentelemetry_helper |  awk '{print $1}')
  do
    echo "start opentelemetry_helper container: $container"
    docker stop "$container"
  done
else
  echo "Pid input, we stop opentelemetry_helper_$pid"
  docker stop "opentelemetry_helper_$pid"
fi