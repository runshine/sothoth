#!/bin/sh

ARCH="$(uname -m)"
OS="linux"
WORKSPACE="$1"
UPSTREAM="$2"
TARGET_DIR="$3"

# avaiable environment
# VPN_ONLY_NODE: when set, means only do in openvpn
# FORCE_DOWNLOAD: when set, means we do download everytime
# CURL: when set, must point to a avaiable curl binary
# WGET: when set, must point to a avaiable wget binary
# DOCKER_MOUNT_CGROUP: when set, start docker check and mount cgroup before
# DOCKER_IPTABLES_ENABLE: when set, enable use iptables
# UPDATE_ALL: when set, stop all and update all

unset http_proxy
unset https_proxy
unset HTTP_PROXY
unset HTTPS_PROXY

ulimit -n 65535

if [ "$ARCH" = "armv7l" ] || [ "$ARCH" = "armv7" ] || [ "$ARCH" = "armv8l" ];then
  if [ "x$(cat /proc/self/maps | grep ld-linux-armhf)" != "x" ];then
    echo "$(date): set current ARCH=armv7l"
    ARCH="armv7l"
  elif [ "x$(cat /proc/self/maps | grep ld-linux.so)" != "x" ];then
    echo "$(date): set current ARCH=armv5"
    ARCH="armv5"
  else
    echo "$(date): unable current ARCH, use origin: $ARCH"
  fi
else
  echo "$(date): set current ARCH=$ARCH"
fi

if [ "x${WORKSPACE}" = "x" ] || [ "x${UPSTREAM}" = "x" ];then
  #we are in local run mode
  ROOT_DIR="$(cd "$(dirname $0)";pwd)"
  chmod 755 "${ROOT_DIR}"
  chmod +x "${ROOT_DIR}/sothoth.conf"
  .  "$ROOT_DIR/sothoth.conf"
else
  echo "$(date): start generate config"
  if [ "x${TARGET_DIR}" = "x" ];then
    TARGET_DIR="/sothothv2"
  fi
  ROOT_DIR="$TARGET_DIR"
  if [ ! -d "${TARGET_DIR}" ];then
    mkdir -p "$TARGET_DIR"
  fi

  if [ -f "${TARGET_DIR}/sothoth.conf" ] && [ "x${FORCE_DOWNLOAD}" = "x" ];then
    .  "$ROOT_DIR/sothoth.conf"
    ROOT_DIR="$TARGET_DIR"
  else
    echo "WORKSPACE=${WORKSPACE}"    > "${TARGET_DIR}/sothoth.conf"
    echo "UPSTREAM=${UPSTREAM}"     >> "${TARGET_DIR}/sothoth.conf"
    echo "TARGET_DIR=${TARGET_DIR}" >> "${TARGET_DIR}/sothoth.conf"
    uuid="$(cat /dev/urandom | od -x | head -1 | awk '{print $2$3"-"$4$5"-"$6$7"-"$8$9}')"
    echo "NODE_ID=$uuid" >> "${TARGET_DIR}/sothoth.conf"
    if [ "x${VPN_ONLY_NODE}" != "x" ];then
      echo "VPN_ONLY_NODE=1" >> "${TARGET_DIR}/sothoth.conf"
    fi
    ROOT_DIR="$TARGET_DIR"
    cp "$0" "$TARGET_DIR/bootstrap.sh"
    chmod +x "$TARGET_DIR/bootstrap.sh"
  fi
  chmod 755 "${ROOT_DIR}"
fi

if [ "x${WORKSPACE}" = "x" ] || [ "x${UPSTREAM}" = "x" ] || [ "x${TARGET_DIR}" = "x" ];then
  echo "$(date):Run error, must re-generate sothoth config"
  exit 255
fi

UPSTREAM_SERVER="$(echo $2 | awk -F':' '{print $1}')"
UPSTREAM_PORT="$(echo $2 | awk -F':' '{print $2}')"


download() {
    local url="$1"
    local output_file="$2"

    # 检查URL是否为空
    if [ -z "$url" ]; then
        echo "$(date):错误：URL参数为空" >&2
        return 1
    fi

    # 检查输出路径是否为空
    if [ -z "$output_file" ]; then
        echo "$(date):错误：输出文件路径为空" >&2
        return 1
    fi

    if [ -f "$output_file" ] && [ "x${FORCE_DOWNLOAD}" = "x" ];then
      return 0
    fi

    #ignore base even in force download
    if [ -f "$output_file" ] && [ "x$(basename $output_file)" = "xbash" ];then
      return 0;
    fi

    # 创建输出目录（如果不存在）
    local output_dir=$(dirname "$output_file")
    if [ ! -d "$output_dir" ]; then
        mkdir -p "$output_dir" || {
            echo "$(date):错误：无法创建目录 '$output_dir'" >&2
            return 1
        }
    fi
    if [ "x${CURL}" != "x" ];then
      if ! "${CURL}" -fL -s -o "$output_file" "$url"; then
            echo "$(date):错误：${CURL}下载失败: $url" >&2
            rm -f "$output_file"  # 删除可能的部分下载文件
            return 1
      else
        echo "$(date):下载成功: $url --> $output_file"
      fi
    elif [ "x${WGET}" != "x" ]; then
      if ! "${WGET}" -q -O "$output_file" "$url"; then
        echo "$(date):错误：${WGET}下载失败: $url" >&2
        rm -f "$output_file"  # 删除可能的部分下载文件
        return 1
      else
        echo "$(date):下载成功: $url --> $output_file"
      fi
    else
      # 检查下载工具
      if [ "x$(command -v curl)" != "x" ]; then
          if ! curl -fL -s -o "$output_file" "$url"; then
              echo "$(date):错误：curl下载失败: $url" >&2
              rm -f "$output_file"  # 删除可能的部分下载文件
              return 1
          else
            echo "$(date):下载成功: $url --> $output_file"
          fi
      elif [ "x$(command -v wget)" != "x" ]; then
          if ! wget -q -O "$output_file" "$url"; then
              echo "$(date):错误：wget下载失败: $url" >&2
              rm -f "$output_file"  # 删除可能的部分下载文件
              return 1
          else
            echo "$(date):下载成功: $url --> $output_file"
          fi
      else
          echo "$(date):错误：未找到curl或wget，请安装任一工具" >&2
          return 1
      fi
    fi
    return 0
}

download_script(){
  url=$1
  target=$2
  download "${url}" "${target}"
  if [ -f "${target}" ];then
    chmod +x "${target}"
  fi

  if [ -f "${ROOT_DIR}/utils/bash" ];then
    sed -i "1s:.*:#!${ROOT_DIR}/utils/bash:g" "${target}"
  elif [ -f '/bin/bash' ];then
    sed -i "1s/.*/#!\/bin\/bash/" "$2"
  fi
}

pre_build_dirs="$ROOT_DIR/utils $ROOT_DIR/script  $ROOT_DIR/client_service"
for dir in ${pre_build_dirs};
do
  if [ ! -d "${dir}" ];then
    echo "$(date): start create dir: ${dir}"
    mkdir -p "$dir"
  fi
done

if [ "x${UPDATE_ALL}" != "x" ];then
  echo "$(date): re-start with UPDATE_ALL env set"
  "$ROOT_DIR/stop_all.sh"
  export FORCE_DOWNLOAD="true"
  download_script "$UPSTREAM/download/bootstrap.sh" "$ROOT_DIR/bootstrap.sh"
  unset UPDATE_ALL
  "$ROOT_DIR/bootstrap.sh"
  exit 0
fi

if [ "x${VPN_ONLY_NODE}" = "x" ];then
  echo "$(date): we are in FULL MODE"
  bootstrap_utils_list="busybox bash nginx ttyd strace tcpdump openvpn curl socat ip rpcapd gdb frida_server 7zz docker-compose jattach"
else
  echo "$(date): we are in VPN_ONLY_MODE"
  bootstrap_utils_list="busybox bash nginx ttyd strace tcpdump openvpn curl socat ip rpcapd gdb"
fi
for bin in ${bootstrap_utils_list};
do
  download "$UPSTREAM/utils/$bin/$OS/$ARCH" "${ROOT_DIR}/utils/$bin"
  if [ -f "${ROOT_DIR}/utils/$bin" ];then
    chmod +x "${ROOT_DIR}/utils/$bin"
  fi
done

if [ -f "${ROOT_DIR}/utils/curl" ];then
  export CURL="${ROOT_DIR}/utils/curl"
fi
download_script "$UPSTREAM/download/script/gef.py" "$ROOT_DIR/script/gef.py"
download_script "$UPSTREAM/download/script/common.sh" "$ROOT_DIR/script/common.sh"
download_script "$UPSTREAM/download/stop_all.sh" "$ROOT_DIR/stop_all.sh"
download_script "$UPSTREAM/download/stop_all.sh" "$ROOT_DIR/uninstall.sh"
download_script "$UPSTREAM/download/script/start_ttyd.sh" "$ROOT_DIR/script/start_ttyd.sh"
download_script "$UPSTREAM/download/script/stop_ttyd.sh" "$ROOT_DIR/script/stop_ttyd.sh"
download_script "$UPSTREAM/download/script/start_openvpn.sh" "$ROOT_DIR/script/start_openvpn.sh"
download_script "$UPSTREAM/download/script/stop_openvpn.sh" "$ROOT_DIR/script/stop_openvpn.sh"
download_script "$UPSTREAM/download/script/start_nginx.sh" "$ROOT_DIR/script/start_nginx.sh"
download_script "$UPSTREAM/download/script/stop_nginx.sh" "$ROOT_DIR/script/stop_nginx.sh"
download_script "$UPSTREAM/download/script/reload_nginx.sh" "$ROOT_DIR/script/reload_nginx.sh"
download_script "$UPSTREAM/download/script/download_utils.sh" "$ROOT_DIR/script/download_utils.sh"
download_script "$UPSTREAM/download/script/start_rpcapd.sh" "$ROOT_DIR/script/start_rpcapd.sh"
download_script "$UPSTREAM/download/script/stop_rpcapd.sh" "$ROOT_DIR/script/stop_rpcapd.sh"
if [ "x${VPN_ONLY_NODE}" = "x" ];then
  download_script "$UPSTREAM/download/script/start_frida_server.sh" "$ROOT_DIR/script/start_frida_server.sh"
  download_script "$UPSTREAM/download/script/stop_frida_server.sh" "$ROOT_DIR/script/stop_frida_server.sh"
  download_script "$UPSTREAM/download/script/start_nacos_client.sh" "$ROOT_DIR/script/start_nacos_client.sh"
  download_script "$UPSTREAM/download/script/stop_nacos_client.sh" "$ROOT_DIR/script/stop_nacos_client.sh"
  download_script "$UPSTREAM/download/script/prepare_cpython.sh" "$ROOT_DIR/script/prepare_cpython.sh"
  download_script "$UPSTREAM/download/script/start_openssh.sh" "$ROOT_DIR/script/start_openssh.sh"
  download_script "$UPSTREAM/download/script/stop_openssh.sh" "$ROOT_DIR/script/stop_openssh.sh"
  download_script "$UPSTREAM/download/script/start_dockerd.sh" "$ROOT_DIR/script/start_dockerd.sh"
  download_script "$UPSTREAM/download/script/stop_dockerd.sh" "$ROOT_DIR/script/stop_dockerd.sh"
  download_script "$UPSTREAM/download/client_service/start_client_service.sh" "$ROOT_DIR/client_service/start_client_service.sh"
fi

"$ROOT_DIR/script/start_nginx.sh"
"$ROOT_DIR/script/start_ttyd.sh"
"$ROOT_DIR/script/start_openvpn.sh"
"$ROOT_DIR/script/start_rpcapd.sh"

if [ "x${VPN_ONLY_NODE}" = "x" ];then
  "$ROOT_DIR/script/start_frida_server.sh"
  "$ROOT_DIR/script/prepare_cpython.sh"
  "$ROOT_DIR/script/start_nacos_client.sh"
  "$ROOT_DIR/script/start_openssh.sh"
  "$ROOT_DIR/script/start_dockerd.sh"
fi

if [ -f "$ROOT_DIR/script/gef.py" ];then
  STARTUP_COMMAND="python sys.path.insert(0, \"${ROOT_DIR}/script\"); from gef import *; Gef.main()"
  GDBINIT_PATH="/root/.gdbinit"
  echo "${STARTUP_COMMAND}" > "${GDBINIT_PATH}"
  GDBINIT_PATH="${ROOT_DIR}/script/.gdbinit"
  echo "${STARTUP_COMMAND}" > "${GDBINIT_PATH}"
  GDBINIT_PATH="/tmp/.gdbinit"
  echo "${STARTUP_COMMAND}" > "${GDBINIT_PATH}"
  echo ""
fi

if [ -d "/usr/lib/systemd/system" ];then
  echo "$(date): find systemd, enable it for autoboot"
  download "$UPSTREAM/download/conf/systemd/sothothv2.service" "$ROOT_DIR/share/sothothv2.service" && sed -i "s#/SOTHOTHV2_ROOT#${ROOT_DIR}#g" "$ROOT_DIR/share/sothothv2.service"
  if [ -f "$ROOT_DIR/share/sothothv2.service" ];then
    cp -f "$ROOT_DIR/share/sothothv2.service" "/usr/lib/systemd/system/sothothv2.service"
    systemctl daemon-reload
    systemctl enable sothothv2
    #systemctl status sothothv2
  fi
else
  echo "$(date): not find systemd, unable enable autoboot"
fi

exit 0