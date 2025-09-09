#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
DOCKER_ROOT_DIR="${ROOT_DIR}/docker"
cd "$(cd "$(dirname $0)";pwd)"
if [ ! -d "${DOCKER_ROOT_DIR}" ];then
  mkdir -p "${DOCKER_ROOT_DIR}"
fi
. "${DOCKER_ROOT_DIR}/../script/common.sh"


if [ -S "${DOCKER_ROOT_DIR}/run/docker.sock" ];then
  for i in $("${DOCKER_ROOT_DIR}/bin/docker" -H "unix://${DOCKER_ROOT_DIR}/run/docker.sock" ps -a | grep -v CONTAINER | awk '{print $1}')
  do
    logger "stop container: $i"
    "${DOCKER_ROOT_DIR}/bin/docker" -H "unix://${DOCKER_ROOT_DIR}/run/docker.sock" stop "$i"
    "${DOCKER_ROOT_DIR}/bin/docker" -H "unix://${DOCKER_ROOT_DIR}/run/docker.sock" rm "$i"
  done
else
  logger "dockerd is not run, ignore stop container"
fi

kill_pid_file "${DOCKER_ROOT_DIR}/run/dockerd.pid"
kill_pid_file "${DOCKER_ROOT_DIR}/run/containerd.pid"
remove_bridge_if_exists br-sothoth
for point in $(mount | grep "${ROOT_DIR}" | awk '{print $3}')
do
  logger "try umount point: ${point}"
  umount "$point"
done
if [ -f "${DOCKER_ROOT_DIR}/run/docker.sock" ];then
  rm -rf "${DOCKER_ROOT_DIR}/run/docker.sock"
fi