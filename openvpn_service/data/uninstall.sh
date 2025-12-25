#!/bin/bash

ROOT_DIR="$(cd "$(dirname $0)";pwd)"

if [ -f "/usr/lib/systemd/system/sothothv2.service" ]; then
  systemctl disable sothothv2
  rm -rf "/usr/lib/systemd/system/sothothv2.service"
fi

"${ROOT_DIR}/stop_all.sh"
