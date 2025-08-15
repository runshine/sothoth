#!/bin/sh

pid="$1"
if [ "x${pid}" = "x" ] || [ ! -f "/proc/$pid/status" ];then
  echo "PID not exist or not input: $pid, You must input pid for target"
  exit 255
fi

ROOT_DIR="$(cd "$(dirname $0)/../../";pwd)"
OPEN_TELEMETRY_ROOT_DIR="${ROOT_DIR}/client_service/opentelemetry_go"
DOCKER_ROOT_DIR="${ROOT_DIR}/docker"
cd "${ROOT_DIR}"
if [ ! -d "${OPEN_TELEMETRY_ROOT_DIR}" ];then
  mkdir -p "${OPEN_TELEMETRY_ROOT_DIR}"
fi
. "${ROOT_DIR}/script/common.sh"


#pre_build_dirs="${OPEN_TELEMETRY_ROOT_DIR}/log"
#prepare_dir "$pre_build_dirs"


download_script       "$UPSTREAM/download/client_service/opentelemetry_go/stop_opentelemetry.sh"            "${OPEN_TELEMETRY_ROOT_DIR}/stop_opentelemetry.sh"
download_script       "$UPSTREAM/download/client_service/opentelemetry_go/start.sh"                         "${OPEN_TELEMETRY_ROOT_DIR}/start.sh"


echo "start up opentelemetry_go service"
cd "${OPEN_TELEMETRY_ROOT_DIR}"

${DOCKER_ROOT_DIR}/bin/docker -H "unix:///${DOCKER_ROOT_DIR}/run/docker.sock" pull otel/autoinstrumentation-go:latest
${DOCKER_ROOT_DIR}/bin/docker -H "unix:///${DOCKER_ROOT_DIR}/run/docker.sock" run -d \
  --name opentelemetry_go_helper_$pid \
  --network host \
  --privileged \
  --pid host \
  --cgroupns host \
  --stop-signal SIGTERM \
  -e TZ=Asia/Shanghai \
  -e OTEL_EXPORTER_OTLP_ENDPOINT=http://200.64.0.1:4318 \
  -e OTEL_GO_AUTO_TARGET_EXE=/proc/$pid/exe \
  -e OTEL_SERVICE_NAME= $(hostname)-go-${pid}-$(cat /dev/urandom | od -x | head -1 | awk '{print $2$3}') \
  -e OTEL_PROPAGATORS=tracecontext,baggage \
  -e SOTHOTH_DIR=${ROOT_DIR:-/sothothv2} \
  -v /proc:/host/proc \
  --restart no \
  --log-driver json-file \
  --log-opt max-size=20m \
  --log-opt max-file=1 \
  otel/autoinstrumentation-go:latest
