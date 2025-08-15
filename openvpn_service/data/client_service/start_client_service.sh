#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
CLIENT_SERVICE_ROOT_DIR="${ROOT_DIR}/client_service"
cd "${ROOT_DIR}"
if [ ! -d "${CLIENT_SERVICE_ROOT_DIR}" ];then
  mkdir -p "${CLIENT_SERVICE_ROOT_DIR}"
fi
. "${ROOT_DIR}/script/common.sh"


pre_build_dirs="${CLIENT_SERVICE_ROOT_DIR}/tetragon ${CLIENT_SERVICE_ROOT_DIR}/opentelemetry_java ${CLIENT_SERVICE_ROOT_DIR}/opentelemetry_go"
prepare_dir "$pre_build_dirs"

download_script_if_none_exist "$UPSTREAM/download/client_service/stop_client_service.sh"                               "${CLIENT_SERVICE_ROOT_DIR}/stop_client_service.sh"
download_script_if_none_exist "$UPSTREAM/download/client_service/tetragon/start_tetragon.sh"                           "${CLIENT_SERVICE_ROOT_DIR}/tetragon/start_tetragon.sh"
download_script_if_none_exist "$UPSTREAM/download/client_service/tetragon/stop_tetragon.sh"                            "${CLIENT_SERVICE_ROOT_DIR}/tetragon/stop_tetragon.sh"
download_script_if_none_exist "$UPSTREAM/download/client_service/opentelemetry_java/start_opentelemetry.sh"            "${CLIENT_SERVICE_ROOT_DIR}/opentelemetry_java/start_opentelemetry.sh"
download_script_if_none_exist "$UPSTREAM/download/client_service/opentelemetry_java/stop_opentelemetry.sh"             "${CLIENT_SERVICE_ROOT_DIR}/opentelemetry_java/stop_opentelemetry.sh"
download_script_if_none_exist "$UPSTREAM/download/client_service/opentelemetry_go/start_opentelemetry.sh"              "${CLIENT_SERVICE_ROOT_DIR}/opentelemetry_java/opentelemetry_go.sh"
download_script_if_none_exist "$UPSTREAM/download/client_service/opentelemetry_go/stop_opentelemetry.sh"               "${CLIENT_SERVICE_ROOT_DIR}/opentelemetry_java/stop_opentelemetry.sh"

"${CLIENT_SERVICE_ROOT_DIR}/tetragon/start_tetragon.sh"
