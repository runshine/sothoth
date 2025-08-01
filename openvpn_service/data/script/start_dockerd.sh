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

pre_build_dirs="${DOCKER_ROOT_DIR}/conf ${DOCKER_ROOT_DIR}/run ${DOCKER_ROOT_DIR}/run/containerd ${DOCKER_ROOT_DIR}/log ${DOCKER_ROOT_DIR}/data-root ${DOCKER_ROOT_DIR}/tmp ${DOCKER_ROOT_DIR}/var/lib/containerd ${DOCKER_ROOT_DIR}/var/run"
prepare_dir "$pre_build_dirs"

if [ ! -f "${DOCKER_ROOT_DIR}/bin/dockerd" ] || [ "x${FORCE_DOWNLOAD}" != "x" ];then
  download "$UPSTREAM/docker/docker/$OS/$ARCH" "${DOCKER_ROOT_DIR}/docker.tar.gz"
  download "$UPSTREAM/download/package/docker/daemon.json" "${DOCKER_ROOT_DIR}/conf/daemon.json"
  download "$UPSTREAM/download/package/docker/config.toml" "${DOCKER_ROOT_DIR}/conf/config.toml"
  if [ "x$(command -v tar)" != "x" ];then
    tar -zxvf "${DOCKER_ROOT_DIR}/docker.tar.gz" -C "${DOCKER_ROOT_DIR}/tmp" 1>/dev/null
  else
    "${DOCKER_ROOT_DIR}/../utils/7zz" x -y -so "${DOCKER_ROOT_DIR}/docker.tar.gz" | "${DOCKER_ROOT_DIR}/../utils/7zz" x -y -ttar -si -o"${DOCKER_ROOT_DIR}/tmp" > /dev/null
  fi
  if [ $? -eq 0 ];then
    mv "${DOCKER_ROOT_DIR}/tmp/docker" "${DOCKER_ROOT_DIR}/bin"
    logger "docker decompress process success!"
  else
    logger "docker decompress process failed!"
    exit 255
  fi
  download "$UPSTREAM/download/package/docker/docker_env.sh" "${DOCKER_ROOT_DIR}/bin/docker_env.sh" && chmod +x "${DOCKER_ROOT_DIR}/bin/docker_env.sh"
  rm -rf "${DOCKER_ROOT_DIR}/docker.tar.gz"
fi

if [ "x$(command -v iptables)" = "x" ] || [ "x$(ps -ef|grep -v grep | grep -v sothothv2 |grep dockerd)" != "x" ]; then
  logger "disable iptables support because no iptables binary or docker is already run"
  sed -i '/"iptables":/ s/true/false/' "${DOCKER_ROOT_DIR}/conf/daemon.json"
fi

if ! is_pid_file_running "${DOCKER_ROOT_DIR}/run/containerd.pid";then
  logger "start containerd: \"${DOCKER_ROOT_DIR}/bin/containerd\" --config \"${DOCKER_ROOT_DIR}/conf/config.toml\"  >> \"${DOCKER_ROOT_DIR}/log/containerd.log\" 2>&1"
  PATH="${DOCKER_ROOT_DIR}/bin:${PATH}" "${DOCKER_ROOT_DIR}/bin/containerd" --config "${DOCKER_ROOT_DIR}/conf/config.toml" >> "${DOCKER_ROOT_DIR}/log/containerd.log" 2>&1 &
  echo "$!" > "${DOCKER_ROOT_DIR}/run/containerd.pid"
else
  logger "containerd already run, ignore re-run, pid: $(cat ${DOCKER_ROOT_DIR}/run/containerd.pid)"
fi

if ! is_pid_file_running "${DOCKER_ROOT_DIR}/run/dockerd.pid";then
  logger "start dockerd: \"${DOCKER_ROOT_DIR}/bin/dockerd\" --config-file \"${DOCKER_ROOT_DIR}/conf/daemon.json\" >> \"${DOCKER_ROOT_DIR}/log/dockerd.log\" 2>&1 "
  create_bridge br-sothoth
  PATH="${DOCKER_ROOT_DIR}/bin:${PATH}" "${DOCKER_ROOT_DIR}/bin/dockerd" --config-file "${DOCKER_ROOT_DIR}/conf/daemon.json" >> "${DOCKER_ROOT_DIR}/log/dockerd.log" 2>&1 &
else
  logger "dockerd already run, ignore re-run, pid: $(cat ${DOCKER_ROOT_DIR}/run/dockerd.pid)"
fi

if [ ! -f "${DOCKER_ROOT_DIR}/conf/docker-swarm.conf" ] || [ "x${FORCE_DOWNLOAD}" != "x" ];then
  download "$UPSTREAM/download/package/docker/docker-swarm.conf" "${DOCKER_ROOT_DIR}/confdocker-swarm.conf"
  if [ -f "${DOCKER_ROOT_DIR}/confdocker-swarm.conf" ];then
    . "${DOCKER_ROOT_DIR}/confdocker-swarm.conf" ]
  fi
  if [ "x${DOCKER_SWARM_TOKEN}" != "x" ] && [ "x${DOCKER_SWARM_SERVER}" != "x" ] && is_valid_ip_port "${DOCKER_SWARM_SERVER}";then
    logger "docker swarm info is not none, try to join it:  \"${DOCKER_ROOT_DIR}/bin/docker\" -H \"unix:///${DOCKER_ROOT_DIR}/run/docker.sock\" swarm join --token ${DOCKER_SWARM_TOKEN} ${DOCKER_SWARM_SERVER}"
    max_retries=10
    retry_delay=2
    for ((attempt=1; attempt<=max_retries; attempt++)); do
        if [[ -S "${DOCKER_ROOT_DIR}/run/docker.sock" ]]; then
            "${DOCKER_ROOT_DIR}/bin/docker" -H "unix://${DOCKER_ROOT_DIR}/run/docker.sock" swarm join --token ${DOCKER_SWARM_TOKEN} ${DOCKER_SWARM_SERVER}
            break
        else
            logger "第 $attempt 次检查:${DOCKER_ROOT_DIR}/run/docker.sock 失败，等待 ${retry_delay}秒后重试..."
            sleep $retry_delay
        fi
    done
  else
    logger "docker-swarm.conf exist build not set, ignore swarm mode init"
  fi
else
  logger "docker-swarm.conf not exist, ignore swarm mode init"
fi