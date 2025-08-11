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
  exec ./start_docker.sh "$pid"
else
  echo "Process $pid is not running inside a container."
  exec ./start_normal.sh "$pid"
fi

