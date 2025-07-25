#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)";pwd)"
ret="true"
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

if [ -f "${ROOT_DIR}/sothoth.conf" ];then
  chmod +x "${ROOT_DIR}/sothoth.conf"
  .  "$ROOT_DIR/sothoth.conf"

  download "$UPSTREAM/download/script/stop_ttyd.sh" "$ROOT_DIR/script/stop_ttyd.sh"
  chmod +x "$ROOT_DIR/script/stop_ttyd.sh"

  download "$UPSTREAM/download/script/stop_openvpn.sh" "$ROOT_DIR/script/stop_openvpn.sh"
  chmod +x "$ROOT_DIR/script/stop_openvpn.sh"

  download "$UPSTREAM/download/script/stop_nginx.sh" "$ROOT_DIR/script/stop_nginx.sh"
  chmod +x "$ROOT_DIR/script/stop_nginx.sh"

  "$ROOT_DIR/script/stop_ttyd.sh"
  "$ROOT_DIR/script/stop_openvpn.sh"
  "$ROOT_DIR/script/stop_nginx.sh"

  if [ "x$(ps -ef|grep -v grep|grep sothoth)" = "x" ];then
    echo "check success"
  else
    echo "check failed"
  fi

else
  ret="false"
fi

if [ "${ret}" = "true" ];then
  echo "$(date): stop_all done"
  exit 0
else
  echo "$(date): stop_all failed"
  exit 255
fi

