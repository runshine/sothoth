#!/bin/sh

OPENSSH_ROOT_DIR="$(cd "$(dirname $0)";pwd)/../openssh"
ARCH="$(uname -m)"
OS="linux"
WORKSPACE="$1"
UPSTREAM="$2"
UPSTREAM_SERVER="$(echo $2 | awk -F':' '{print $1}')"
UPSTREAM_PORT="$(echo $2 | awk -F':' '{print $2}')"
cd "$(cd "$(dirname $0)";pwd)"
. common.sh

kill_pid_file "${OPENSSH_ROOT_DIR}/run/sshd.pid"