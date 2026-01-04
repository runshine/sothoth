#!/bin/bash

#https://dev.mysql.com/doc/mysql-operator/en/mysql-operator-installation.html
# 部署脚本
set -e

for file in ./*;
do
  if [[ "$file" =~ \.yaml$ ]];then
    echo "$(date): start apply: ${file}"
    kubectl apply -f ${file}
  fi
done

# kubectl get innodbcluster --watch