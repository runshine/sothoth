#!/bin/bash

# 清理脚本
set -e

echo "开始清理Web应用服务..."

kubectl delete -f service.yaml --ignore-not-found
kubectl delete -f deployment.yaml --ignore-not-found
kubectl delete -f app-config.yaml --ignore-not-found
kubectl delete -f nginx-config.yaml --ignore-not-found
kubectl delete -f nfs-storage.yaml --ignore-not-found
kubectl delete -f namespace.yaml --ignore-not-found

echo "清理完成！"