#!/bin/bash

# 部署脚本
#set -e

if [ "x$(which helm)" = "x" ];then
  curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-4 | bash
fi

#helm repo add harbor https://helm.goharbor.io
#helm fetch harbor/harbor --untar

for file in ./*;
do
  if [[ "$file" =~ \.yaml$ ]];then
    echo "$(date): start apply: ${file}"
    kubectl apply --server-side -f ${file}
  fi
done

./setup-ingress-tls.sh

helm install  -n harbor-ns harbor ./harbor

echo "done"