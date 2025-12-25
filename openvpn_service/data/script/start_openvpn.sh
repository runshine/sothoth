#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
OPENVPN_ROOT_DIR="${ROOT_DIR}/openvpn"
cd "$(cd "$(dirname $0)";pwd)"
if [ ! -d "${OPENVPN_ROOT_DIR}" ];then
  mkdir -p "${OPENVPN_ROOT_DIR}"
fi
. "${OPENVPN_ROOT_DIR}/../script/common.sh"


pre_build_dirs="$OPENVPN_ROOT_DIR/log $OPENVPN_ROOT_DIR/conf $OPENVPN_ROOT_DIR/run"
prepare_dir "$pre_build_dirs"

download_if_none_exist "$UPSTREAM/download/cert/ca.crt" "${OPENVPN_ROOT_DIR}/conf/ca.crt"

if [ ! -f "${OPENVPN_ROOT_DIR}/conf/auth.txt" ];then
  .  "$OPENVPN_ROOT_DIR/../sothoth.conf"
  echo "$NODE_ID" > "${OPENVPN_ROOT_DIR}/conf/auth.txt"
  echo "pass" >> "${OPENVPN_ROOT_DIR}/conf/auth.txt"
fi

if [ ! -f "${OPENVPN_ROOT_DIR}/conf/client.ovpn" ];then
cat << EOF > ${OPENVPN_ROOT_DIR}/conf/client.ovpn
client
dev tap-sothoth
proto udp
;remote $UPSTREAM_SERVER 11194
;remote $UPSTREAM_SERVER 11195
;remote $UPSTREAM_SERVER 11196
;remote $UPSTREAM_SERVER 11197
remote 127.0.0.1 11194
remote 127.0.0.1 11195
remote 127.0.0.1 11196
remote 127.0.0.1 11197
tls-client
cipher none
auth none
ca ${OPENVPN_ROOT_DIR}/conf/ca.crt
auth-user-pass  ${OPENVPN_ROOT_DIR}/conf/auth.txt
nobind
persist-key
persist-tun
log ${OPENVPN_ROOT_DIR}/log/log.txt
status ${OPENVPN_ROOT_DIR}/log/openvpn-status.log
verb 3
keepalive 10 60
reneg-sec 0
remote-random

EOF
#if [ "${ARCH}" = "aarch64" ];then
#  echo "data-ciphers none" >> "${OPENVPN_ROOT_DIR}/conf/client.ovpn"
#fi
fi



if [ ! -c "/dev/net/tun" ];then
  if [ ! -d "/dev/net" ];then
    mkdir -p "/dev/net"
    chmod 777 '/dev/net'
  fi
  mknod /dev/net/tun c 10 200
  chmod 0666 /dev/net/tun
fi

if ! is_pid_file_running "${OPENVPN_ROOT_DIR}/run/client.pid";then
  if [ "$ARCH" = "x86_64" ];then
    logger "start openvpn client: \"${OPENVPN_ROOT_DIR}/../utils/openvpn\" --config \"${OPENVPN_ROOT_DIR}/conf/client.ovpn\" --writepid \"$OPENVPN_ROOT_DIR/run/client.pid\" --iproute \"$OPENVPN_ROOT_DIR/../utils/ip\""
    "${OPENVPN_ROOT_DIR}/../utils/openvpn" --config "${OPENVPN_ROOT_DIR}/conf/client.ovpn" --writepid "$OPENVPN_ROOT_DIR/run/client.pid" --iproute  "$OPENVPN_ROOT_DIR/../utils/ip" &
  elif [ "$ARCH" = "aarch64" ];then
    logger "start openvpn client: \"${OPENVPN_ROOT_DIR}/../utils/openvpn\" --config \"${OPENVPN_ROOT_DIR}/conf/client.ovpn\" --writepid \"$OPENVPN_ROOT_DIR/run/client.pid\" --iproute \"$OPENVPN_ROOT_DIR/../utils/ip\""
    "${OPENVPN_ROOT_DIR}/../utils/openvpn" --config "${OPENVPN_ROOT_DIR}/conf/client.ovpn" --writepid "$OPENVPN_ROOT_DIR/run/client.pid"  --iproute  "$OPENVPN_ROOT_DIR/../utils/ip" &
  elif [ "$ARCH" = "armv8l" ] || [ "$ARCH" = "armv7l" ] || [ "$ARCH" = "armv5" ];then
    logger "start openvpn client: \"${OPENVPN_ROOT_DIR}/../utils/openvpn\" --config \"${OPENVPN_ROOT_DIR}/conf/client.ovpn\" --writepid \"$OPENVPN_ROOT_DIR/run/client.pid\" --iproute \"$OPENVPN_ROOT_DIR/../utils/ip\""
    "${OPENVPN_ROOT_DIR}/../utils/openvpn" --config "${OPENVPN_ROOT_DIR}/conf/client.ovpn" --writepid "$OPENVPN_ROOT_DIR/run/client.pid" --iproute  "$OPENVPN_ROOT_DIR/../utils/ip" &
  else
    logger "unable start openvpn client, unknown arch: $ARCH"
  fi
else
  logger "openvpn already run, ignore re-run , pid: $(cat ${OPENVPN_ROOT_DIR}/run/client.pid)"
fi
