#!/bin/sh

set -e

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
cd "$(cd "$(dirname $0)";pwd)"
. "${ROOT_DIR}/script/common.sh"

deploy_package.sh sothothv2_agent
