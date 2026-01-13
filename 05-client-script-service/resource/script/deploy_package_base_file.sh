#!/bin/sh

set -e

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
cd "$(cd "$(dirname $0)";pwd)"
. "${ROOT_DIR}/script/common.sh"

package_list="tcpdump iproute2 gdb"
for package in ${package_list};
do
  deploy_package.sh  ${package}
done