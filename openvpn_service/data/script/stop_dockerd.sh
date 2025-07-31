#!/bin/sh

DOCKER_ROOT_DIR="$(cd "$(dirname $0)";pwd)/../docker"
ARCH="$(uname -m)"
OS="linux"
WORKSPACE="$1"
UPSTREAM="$2"
UPSTREAM_SERVER="$(echo $2 | awk -F':' '{print $1}')"
UPSTREAM_PORT="$(echo $2 | awk -F':' '{print $2}')"
cd "$(cd "$(dirname $0)";pwd)"
if [ ! -d "${DOCKER_ROOT_DIR}" ];then
  mkdir -p "${DOCKER_ROOT_DIR}"
fi
. "${DOCKER_ROOT_DIR}/../script/common.sh"

if [ -f "${DOCKER_ROOT_DIR}/run/docker.sock" ];then
  for i in $("${DOCKER_ROOT_DIR}/bin/docker" -H "unix://${DOCKER_ROOT_DIR}/run/docker.sock" ps -a | grep -v CONTAINER | awk '{print $1}')
  do
    logger "stop container: $i"
    "${DOCKER_ROOT_DIR}/bin/docker" -H "unix://${DOCKER_ROOT_DIR}/run/docker.sock" stop "$i"
    "${DOCKER_ROOT_DIR}/bin/docker" -H "unix://${DOCKER_ROOT_DIR}/run/docker.sock" rm "$i"
  done
fi

kill_pid_file "${DOCKER_ROOT_DIR}/run/dockerd.pid"
kill_pid_file "${DOCKER_ROOT_DIR}/run/containerd.pid"
remove_bridge_if_exists br-sothoth