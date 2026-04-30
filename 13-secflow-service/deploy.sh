#!/bin/bash

# 部署脚本
#set -e

if [[ -f "./images.env" ]]; then
  # shellcheck disable=SC1091
  source "./images.env"
fi

for file in ./*;
do
  if [[ "$file" =~ \.yaml$ ]];then
    echo "$(date): start apply: ${file}"
    if grep -q '\${SECFLOW_PLATFORM_RESOURCE_IMAGE}\|\${SECFLOW_PLATFORM_RESOURCE_FILE_GATEWAY_WORKER_IMAGE}\|\${SECFLOW_APP_FIRMWARE_UNPACKER_IMAGE}' "${file}"; then
      if command -v envsubst >/dev/null 2>&1; then
        envsubst < "${file}" | kubectl apply -f -
      else
        echo "[WARN] envsubst not found, apply raw yaml: ${file}"
        kubectl apply -f "${file}"
      fi
    else
      kubectl apply -f "${file}"
    fi
  fi
done

echo "done"
