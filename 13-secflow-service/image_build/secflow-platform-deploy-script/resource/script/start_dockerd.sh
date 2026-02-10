#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
cd "$(cd "$(dirname $0)";pwd)"
. "${ROOT_DIR}/script/common.sh"

pre_build_dirs="${ROOT_DIR}/var/lib/data-root ${ROOT_DIR}/var/lib/containerd "
prepare_dir "$pre_build_dirs"

if [ "x$(command -v iptables)" = "x" ] || [ "x$(ps -ef|grep -v grep | grep -v sothothv2 |grep dockerd)" != "x" ];then
  logger "disable docker iptables support"
  sed -i '/"iptables":/ s/true/false/' "${ROOT_DIR}/usr/conf/daemon.json"
fi

if ! is_pid_file_running "${ROOT_DIR}/var/run/containerd.pid";then
  logger "start containerd: \"${ROOT_DIR}/usr/bin/containerd\" --config \"${ROOT_DIR}/usr/conf/config.toml\"  >> \"${ROOT_DIR}/var/log/containerd.log\" 2>&1"
  PATH="${ROOT_DIR}/bin:${ROOT_DIR}/usr/bin:${PATH}" "${ROOT_DIR}/usr/bin/containerd" --config "${ROOT_DIR}/usr/conf/config.toml" >> "${ROOT_DIR}/var/log/containerd.log" 2>&1 &
  echo "$!" > "${ROOT_DIR}/var/run/containerd.pid"
else
  logger "containerd already run, ignore re-run, pid: $(cat ${ROOT_DIR}/var/run/containerd.pid)"
fi

if ! is_pid_file_running "${ROOT_DIR}/var/run/dockerd.pid";then
  logger "start dockerd: \"${ROOT_DIR}/usr/bin/dockerd\" --config-file \"${ROOT_DIR}/usr/conf/daemon.json\" >> \"${ROOT_DIR}/var/log/dockerd.log\" 2>&1 "
  if create_bridge br-sothoth ;then
    DOCKER_GWBRIDGE=gw-sothoth PATH="${ROOT_DIR}/bin:${ROOT_DIR}/usr/bin:${PATH}" "${ROOT_DIR}/usr/bin/dockerd" --config-file "${ROOT_DIR}/usr/conf/daemon.json" >> "${ROOT_DIR}/var/log/dockerd.log" 2>&1 &
  else
    logger "disable bridige support with dockerd"
    sed -i 's/br-sothoth/none/g' "${ROOT_DIR}/usr/conf/daemon.json"
    PATH="${ROOT_DIR}/bin:${ROOT_DIR}/usr/bin:${PATH}" "${ROOT_DIR}/usr/bin/dockerd" --config-file "${ROOT_DIR}/usr/conf/daemon.json" >> "${ROOT_DIR}/var/log/dockerd.log" 2>&1 &
  fi
else
  logger "dockerd already run, ignore re-run, pid: $(cat ${ROOT_DIR}/var/run/dockerd.pid)"
fi

#if [ ! -f "${DOCKER_ROOT_DIR}/conf/docker-swarm.conf" ] || [ "x${FORCE_DOWNLOAD}" != "x" ];then
#  download "$UPSTREAM/download/package/docker/docker-swarm.conf" "${DOCKER_ROOT_DIR}/conf/docker-swarm.conf"
#  if [ -f "${DOCKER_ROOT_DIR}/conf/docker-swarm.conf" ];then
#    . "${DOCKER_ROOT_DIR}/conf/docker-swarm.conf" ]
#  fi
#  if [ "x${DOCKER_SWARM_TOKEN}" != "x" ] && [ "x${DOCKER_SWARM_SERVER}" != "x" ] && is_valid_ip_port "${DOCKER_SWARM_SERVER}";then
#    logger "docker swarm info is not none, try to join it:  \"${DOCKER_ROOT_DIR}/bin/docker\" -H \"unix:///${DOCKER_ROOT_DIR}/run/docker.sock\" swarm join --token ${DOCKER_SWARM_TOKEN} ${DOCKER_SWARM_SERVER}"
#    max_retries=30
#    retry_delay=4
#    for ((attempt=1; attempt<=max_retries; attempt++)); do
#        if [[ -S "${DOCKER_ROOT_DIR}/run/docker.sock" ]]; then
#            "${DOCKER_ROOT_DIR}/bin/docker" -H "unix://${DOCKER_ROOT_DIR}/run/docker.sock" swarm join --token ${DOCKER_SWARM_TOKEN} ${DOCKER_SWARM_SERVER}  &
#            break
#        else
#            logger "第 $attempt 次检查:${DOCKER_ROOT_DIR}/run/docker.sock 失败，等待 ${retry_delay}秒后重试..."
#            sleep $retry_delay
#        fi
#    done
#  else
#    logger "docker-swarm.conf exist build not set, ignore swarm mode init"
#  fi
#else
#  logger "docker-swarm.conf not exist, ignore swarm mode init"
#fi