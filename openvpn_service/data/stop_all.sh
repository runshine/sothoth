#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)";pwd)"
ret="true"

if [ -f "${ROOT_DIR}/sothoth.conf" ];then
  chmod +x "${ROOT_DIR}/sothoth.conf"
  .  "$ROOT_DIR/sothoth.conf"

  "$ROOT_DIR/script/stop_ttyd.sh"
  "$ROOT_DIR/script/stop_openvpn.sh"
  "$ROOT_DIR/script/stop_nginx.sh"
  "$ROOT_DIR/script/stop_nacos_client.sh"
  "$ROOT_DIR/script/stop_openssh.sh"

  check_result="$(ps -ef|grep -v grep|grep "$ROOT_DIR" | grep -v stop_all)"
  if [ "x${check_result}" = "x" ];then
    echo "check success"
  else
    echo "check failed, result: ${check_result}"
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

