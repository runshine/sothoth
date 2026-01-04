#!/bin/bash

# 清理脚本
set -e

echo "开始清理应用服务..."


files=( ./* )
len=${#files[@]}

for (( i=len-1; i>=0; i-- )); do
  if [[ "${files[i]}" =~ \.yaml$ ]];then
    file="${files[i]}"
    echo "start process: $file"
    kubectl delete -f ${file} --ignore-not-found
  fi
done
echo "清理完成！"