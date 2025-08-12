#!/bin/sh

cd "$(dirname $0)"

pid="$1"
if [ "x${pid}" = "x" ];then
  echo "You must input pid"
  exit 255
fi

if [ "x${SOTHOTH_DIR}" = "x" ] || [ ! -d "${SOTHOTH_DIR}" ] || [ ! -f "${SOTHOTH_DIR}/sothoth.conf" ];then
  echo "Env SOTHOTH_DIR must set and exist, and must ok"
  exit 255
fi

if [ ! -d "${SOTHOTH_DIR}/share/" ];then
  mkdir -p "${SOTHOTH_DIR}/share/"
fi

if [ ! -f "${SOTHOTH_DIR}/share/libreboot_helper.so" ];then
  cp /libreboot_helper.so         "${SOTHOTH_DIR}/share/libreboot_helper.so"
  cp /attach_helper.jar           "${SOTHOTH_DIR}/share/attach_helper.jar"
  cp /opentelemetry-javaagent.jar "${SOTHOTH_DIR}/share/opentelemetry-javaagent.jar"
  cp /add_mount                   "${SOTHOTH_DIR}/share/add_mount"
else
  echo "file already exist, ignore copy"
fi

nspid="$(cat "/proc/${pid}/status" | grep NSpid | awk '{print $2}')"
if [ "x${nspid}" = "x" ];then
  echo "Pid error, not exist: ${pid}"
  exit 255
fi

host_pid_ns=$(readlink /proc/1/ns/pid)
process_pid_ns=$(readlink /proc/$pid/ns/pid)

if [ "$host_pid_ns" != "$process_pid_ns" ]; then
  echo "Process $pid is running inside a container."
  /addmount 1 "${SOTHOTH_DIR}" "$pid" "${SOTHOTH_DIR}"
else
  echo "Process $pid is not running inside a container."
fi


options="-javaagent:${SOTHOTH_DIR}/share/opentelemetry-javaagent.jar \
            -Dotel.resource.attributes=service.name=,service.version=,deployment.environment= \
            -Dotel.exporter.otlp.protocol=http/protobuf \
            -Dotel.exporter.otlp.traces.endpoint=http://200.64.0.1:4318/api/otlp/traces \
            -Dotel.exporter.otlp.metrics.endpoint=http://200.64.0.1:4318/api/otlp/metrics \
            -Dotel.logs.exporter=none"

echo "java -jar /attach_helper.jar -displayName attach_helper.jar -agent-so \"${SOTHOTH_DIR}/share/libreboot_helper.so\" -pid \"$pid\" -options \"${options}\""
java -jar /attach_helper.jar  -displayName attach_helper.jar -agent-so "${SOTHOTH_DIR}/share/libreboot_helper.so" -pid "$pid" -options "${options}"

if [ $? -eq 0 ];then
  echo "run load agent success"
else
  echo "run load agent failed"
fi

while [ "x" = "x" ]
do
  if [ ! -f "/proc/${pid}/status" ];then
    break
  else
    sleep 10
  fi
done
