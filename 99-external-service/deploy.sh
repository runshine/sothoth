#!/bin/bash

# 部署脚本
set -e

# kubectl create -f https://download.elastic.co/downloads/eck/3.2.0/crds.yaml
# kubectl apply -f https://download.elastic.co/downloads/eck/3.2.0/operator.yaml

source ../00-pre-init/setup-k8s-tls-secrets.sh
main

for file in ./*;
do
  if [[ "$file" =~ \.yaml$ ]];then
    echo "$(date): start apply: ${file}"
    kubectl apply -f ${file}
  fi
done
