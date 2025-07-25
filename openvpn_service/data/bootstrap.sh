#!/bin/sh


ARCH="$(uname -m)"
OS="linux"
WORKSPACE="$1"
UPSTREAM="$2"
TARGET_DIR="$3"


if [ "x${WORKSPACE}" = "x" ] || [ "x${UPSTREAM}" = "x" ];then
  #we are in local run mode
  ROOT_DIR="$(cd "$(dirname $0)";pwd)"
  chmod +x "${ROOT_DIR}/sothoth.conf"
  .  "$ROOT_DIR/sothoth.conf"
else
  echo "$(date): start generate config"
  if [ "x${TARGET_DIR}" = "x" ];then
    TARGET_DIR="/sothoth"
  fi
  if [ ! -d "${TARGET_DIR}" ];then
    mkdir -p "$TARGET_DIR"
  fi

  if [ -f "${TARGET_DIR}/sothoth.conf" ];then
    source "$ROOT_DIR/sothoth.conf" | .  "$ROOT_DIR/sothoth.conf"
    ROOT_DIR="$TARGET_DIR"
  else
    echo "WORKSPACE=${WORKSPACE}"    > "${TARGET_DIR}/sothoth.conf"
    echo "UPSTREAM=${UPSTREAM}"     >> "${TARGET_DIR}/sothoth.conf"
    echo "TARGET_DIR=${TARGET_DIR}" >> "${TARGET_DIR}/sothoth.conf"
    uuid="$(cat /dev/urandom | od -x | head -1 | awk '{print $2$3"-"$4$5"-"$6$7"-"$8$9}')"
    echo "NODE_ID=$uuid" >> "${TARGET_DIR}/sothoth.conf"
    ROOT_DIR="$TARGET_DIR"
    cp "$0" "$TARGET_DIR/bootstrap.sh"
    chmod +x "$TARGET_DIR/bootstrap.sh"
  fi
fi

if [ "x${WORKSPACE}" = "x" ] || [ "x${UPSTREAM}" = "x" ] || [ "x${TARGET_DIR}" = "x" ];then
  echo "Run error, must re-generate sothoth config"
  exit 255
fi

UPSTREAM_SERVER="$(echo $2 | awk -F':' '{print $1}')"
UPSTREAM_PORT="$(echo $2 | awk -F':' '{print $2}')"


download() {
    url=$1
    target=$2
    if [ -f "$target" ];then
      return
    fi
    wget "${url}" -O "$target" || curl "${url}" -o "$target"
    if [ ! -f "$target" ];then
      echo "$(date): file: $target download failed --> $url"
    else
      echo "$(date): file: $target download success"
    fi
}

download_script(){
  url=$1
  target=$2
  download "${url}" "${target}"
#  if [ ! -f '/bin/bash' ];then
#    sed -i 's#/bin/bash#${ROOT_DIR}/utils/bash#g' "${target}"
#  fi
}

pre_build_dirs="$ROOT_DIR/utils $ROOT_DIR/script"
for dir in ${pre_build_dirs};
do
  if [ ! -d "${dir}" ];then
    echo "$(date): start create dir: ${dir}"
    mkdir -p "$dir"
  fi
done

bootstrap_utils_list="bash nginx ttyd strace tcpdump openvpn ip"
for bin in ${bootstrap_utils_list};
do
  download "$UPSTREAM/utils/$bin/$OS/$ARCH" "${ROOT_DIR}/utils/$bin"
done

download_script "$UPSTREAM/download/stop_all.sh" "$ROOT_DIR/stop_all.sh"
chmod +x "$ROOT_DIR/stop_all.sh"

download_script "$UPSTREAM/download/script/start_nginx.sh" "$ROOT_DIR/script/start_nginx.sh"
chmod +x "$ROOT_DIR/script/start_nginx.sh"
"$ROOT_DIR/script/start_nginx.sh" "${WORKSPACE}" "${UPSTREAM}"

download_script "$UPSTREAM/download/script/start_ttyd.sh" "$ROOT_DIR/script/start_ttyd.sh"
chmod +x "$ROOT_DIR/script/start_ttyd.sh"
"$ROOT_DIR/script/start_ttyd.sh" "${WORKSPACE}" "${UPSTREAM}"

download_script "$UPSTREAM/download/script/start_openvpn.sh" "$ROOT_DIR/script/start_openvpn.sh"
chmod +x "$ROOT_DIR/script/start_openvpn.sh"
"$ROOT_DIR/script/start_openvpn.sh" "${WORKSPACE}" "${UPSTREAM}"
