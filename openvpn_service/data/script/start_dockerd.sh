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

if [ ! -f "${DOCKER_ROOT_DIR}/bin/dockerd" ];then
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

if [ "x$(command -v iptables)" = "x" ]; then
  logger "disable iptables support because no iptables binary"
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

