#!/bin/sh

OPENVPN_ROOT_DIR="$(cd "$(dirname $0)";pwd)/../openvpn"
ARCH="$(uname -m)"
OS="linux"
WORKSPACE="$1"
UPSTREAM="$2"
UPSTREAM_SERVER="$(echo $2 | awk -F':' '{print $1}')"
UPSTREAM_PORT="$(echo $2 | awk -F':' '{print $2}')"

if [ -f "$OPENVPN_ROOT_DIR/run/client.pid" ];then
  pid="$(cat $OPENVPN_ROOT_DIR/run/client.pid)"
  if [ "x$(ps -ef|grep $pid|grep -v grep|grep openvpn)" != "x" ];then
    echo "$(date): try to stop openvpn: $pid"
    kill -9 "$pid"
  fi
else
  echo "$(date): pid file not exist,ignore stop"
fi