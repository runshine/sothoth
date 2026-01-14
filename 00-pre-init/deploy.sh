#!/bin/bash

#kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.14.1/deploy/static/provider/cloud/deploy.yaml

# 部署脚本
set -e

#modprobe nfsd      # NFS服务器守护进程
#modprobe exportfs  # 导出文件系统
#modprobe auth_rpcgss  # 认证支持
#modprobe lockd     # 文件锁
#modprobe nfs_acl
#sysctl -w vm.max_map_count=262144
#apt-get install -y nfs-common


for file in ./*;
do
  if [[ "$file" =~ \.yaml$ ]];then
    echo "$(date): start apply: ${file}"
    kubectl apply -f ${file}
  fi
done
