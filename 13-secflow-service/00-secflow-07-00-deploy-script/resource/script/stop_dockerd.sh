#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
cd "$(cd "$(dirname $0)";pwd)"
. "${ROOT_DIR}/script/common.sh"


if [ -S "${ROOT_DIR}/var/run/docker.sock" ];then
  for i in $("${ROOT_DIR}/usr/bin/docker" -H "unix://${ROOT_DIR}/var/run/docker.sock" ps -a | grep -v CONTAINER | awk '{print $1}')
  do
    logger "stop container: $i"
    "${ROOT_DIR}/usr/bin/docker" -H "unix://${ROOT_DIR}/var/run/docker.sock" stop "$i"
    #"${ROOT_DIR}/usr/bin/docker" -H "unix://${ROOT_DIR}/var/run/docker.sock" rm "$i"
  done
else
  logger "dockerd is not run, ignore stop container"
fi

kill_pid_file "${ROOT_DIR}/var/run/dockerd.pid"
kill_pid_file "${ROOT_DIR}/var/run/containerd.pid"
remove_bridge_if_exists br-sothoth
for point in $(mount | grep "${ROOT_DIR}" | awk '{print $3}')
do
  logger "try umount point: ${point}"
  umount "$point"
done
if [ -f "${ROOT_DIR}/var/run/docker.sock" ];then
  rm -rf "${ROOT_DIR}/var/run/docker.sock"
fi