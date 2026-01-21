#!/bin/bash

# 部署脚本
set -e

bash setup-nginx-traefik-tls.sh

for file in ./*;
do
  if [[ "$file" =~ \.yaml$ ]];then
    echo "$(date): start apply: ${file}"
    kubectl apply -f ${file}
  fi
done
