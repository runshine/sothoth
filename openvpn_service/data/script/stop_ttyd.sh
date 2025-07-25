#!/bin/sh

TTYD_ROOT_DIR="$(cd "$(dirname $0)";pwd)/../ttyd"
ARCH="$(uname -m)"
OS="linux"
WORKSPACE="$1"
UPSTREAM="$2"
UPSTREAM_SERVER="$(echo $2 | awk -F':' '{print $1}')"
UPSTREAM_PORT="$(echo $2 | awk -F':' '{print $2}')"

if [ -f "$TTYD_ROOT_DIR/run/ttyd.pid" ];then
  pid="$(cat $TTYD_ROOT_DIR/run/ttyd.pid)"
  if [ "x$(ps -ef|grep $pid|grep -v grep|grep ttyd)" != "x" ];then
    echo "$(date): try to stop ttyd: $pid"
    kill -9 $pid
  fi
else
  echo "$(date): pid file not exist,ignore stop"
fi
