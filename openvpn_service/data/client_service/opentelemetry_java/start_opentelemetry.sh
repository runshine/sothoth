#!/bin/sh

pid="$1"
if [ "x${pid}" = "x" ] || [ ! -f "/proc/$pid/status" ];then
  echo "PID not exist or not input: $pid, You must input pid for target"
  exit 255
fi

ROOT_DIR="$(cd "$(dirname $0)/../../";pwd)"
OPEN_TELEMETRY_ROOT_DIR="${ROOT_DIR}/client_service/opentelemetry_java"
DOCKER_ROOT_DIR="${ROOT_DIR}/docker"
cd "${ROOT_DIR}"
if [ ! -d "${OPEN_TELEMETRY_ROOT_DIR}" ];then
  mkdir -p "${OPEN_TELEMETRY_ROOT_DIR}"
fi
. "${ROOT_DIR}/script/common.sh"


#pre_build_dirs="${OPEN_TELEMETRY_ROOT_DIR}/log"
#prepare_dir "$pre_build_dirs"


download_script       "$UPSTREAM/download/client_service/opentelemetry_java/stop_opentelemetry.sh"            "${OPEN_TELEMETRY_ROOT_DIR}/stop_opentelemetry.sh"
download_script       "$UPSTREAM/download/client_service/opentelemetry_java/start.sh"                         "${OPEN_TELEMETRY_ROOT_DIR}/start.sh"


echo "start up opentelemetry_java service"
cd "${OPEN_TELEMETRY_ROOT_DIR}"
${DOCKER_ROOT_DIR}/bin/docker -H "unix:///${DOCKER_ROOT_DIR}/run/docker.sock" pull runshine0819/opentelemetry_helper:latest
${DOCKER_ROOT_DIR}/bin/docker -H "unix:///${DOCKER_ROOT_DIR}/run/docker.sock" run -d \
  --name opentelemetry_helper_$pid \
  --network host \
  --privileged \
  --pid host \
  --cgroupns host \
  --stop-signal SIGTERM \
  -e TZ=Asia/Shanghai \
  -e SOTHOTH_DIR=${ROOT_DIR:-/sothothv2} \
  -v $(pwd)/start.sh:/opt/source/start.sh \
  -v /:/host \
  --restart no \
  --log-driver json-file \
  --log-opt max-size=20m \
  --log-opt max-file=1 \
  runshine0819/opentelemetry_helper:latest \
  /opt/source/start.sh $pid

