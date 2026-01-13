#!/bin/bash

# 部署脚本
#set -e

for file in ./*;
do
  if [[ "$file" =~ \.yaml$ ]];then
    echo "$(date): start apply: ${file}"
    if [ "$file" = "./redis-00-databases.spotahome.com_redisfailovers.yaml" ];then
      kubectl create -f ${file}
    else
      kubectl apply -f ${file}
    fi
  fi
done
