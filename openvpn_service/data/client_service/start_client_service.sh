#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
CLIENT_SERVICE_ROOT_DIR="${ROOT_DIR}/client_service"
cd "${ROOT_DIR}"
if [ ! -d "${CLIENT_SERVICE_ROOT_DIR}" ];then
  mkdir -p "${CLIENT_SERVICE_ROOT_DIR}"
fi
. "${ROOT_DIR}/script/common.sh"


pre_build_dirs="${CLIENT_SERVICE_ROOT_DIR}/tetragon"
prepare_dir "$pre_build_dirs"

download_script_if_none_exist "$UPSTREAM/download/client_service/stop_client_service.sh"            "${CLIENT_SERVICE_ROOT_DIR}/stop_client_service.sh"
download_script_if_none_exist "$UPSTREAM/download/client_service/tetragon/start_tetragon.sh"            "${CLIENT_SERVICE_ROOT_DIR}/tetragon/start_tetragon.sh"

"${CLIENT_SERVICE_ROOT_DIR}/tetragon/start_tetragon.sh"
