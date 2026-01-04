#!/bin/bash

# 部署脚本
set -e

for file in ./*;
do
  if [[ "$file" =~ \.yaml$ ]];then
    echo "$(date): start apply: ${file}"
    kubectl apply -f ${file}
  fi
done


./deploy_resource.sh --dir ./resource --pvc sothothv2-client-script-service-nfs-pvc --namespace sothothv2-ns