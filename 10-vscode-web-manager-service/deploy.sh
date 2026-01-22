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

echo "done"
