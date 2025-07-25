#!/bin/sh

NGINX_ROOT_DIR="$(cd "$(dirname $0)";pwd)/../nginx"
ARCH="$(uname -m)"
OS="linux"
WORKSPACE="$1"
UPSTREAM="$2"
UPSTREAM_SERVER="$(echo $2 | awk -F':' '{print $1}')"
UPSTREAM_PORT="$(echo $2 | awk -F':' '{print $2}')"


if [ -f "$NGINX_ROOT_DIR/run/nginx.pid" ];then
  "${NGINX_ROOT_DIR}/../utils/nginx" -p "${NGINX_ROOT_DIR}" -c "${NGINX_ROOT_DIR}/conf/nginx.conf" -s quit
  pid=$(cat "$NGINX_ROOT_DIR/run/nginx.pid")
  echo "$(date): try to stop nginx manual: $pid"
  sub_pid="$(ps -ef|grep "$pid" | grep nginx | awk '{print $2}')"
  if [ "x$(ps -ef|grep $pid| grep nginx|grep -v grep)" != "x" ];then
    kill -9 "$pid"
    for i in $sub_pid
    do
      if [ "x$(ps -ef|grep $i| grep nginx|grep -v grep)" != "x" ];then
        echo "try to nginx sub pid: $pid"
        kill -9  "$i"
      fi
    done
  fi
else
  echo "$(date): pid file not exist,ignore stop"
fi