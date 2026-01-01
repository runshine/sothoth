#!/bin/bash

# 部署脚本
set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}开始部署Web应用服务...${NC}"

# 替换NFS服务器配置
read -p "请输入NFS服务器IP地址: " NFS_SERVER
read -p "请输入NFS共享路径 (例如: /data/nfs_share): " NFS_PATH

# 替换NFS配置中的占位符
echo -e "${YELLOW}配置NFS存储...${NC}"
sed -i "s/<NFS_SERVER_IP>/$NFS_SERVER/g; s|\"/path/to/nfs/share\"|\"$NFS_PATH\"|g" nfs-storage.yaml

# 按顺序部署所有组件
echo -e "${YELLOW}创建命名空间...${NC}"
kubectl apply -f namespace.yaml

echo -e "${YELLOW}配置NFS存储...${NC}"
kubectl apply -f nfs-storage.yaml

echo -e "${YELLOW}创建Nginx配置...${NC}"
kubectl apply -f nginx-config.yaml

echo -e "${YELLOW}创建应用配置...${NC}"
kubectl apply -f app-config.yaml

echo -e "${YELLOW}部署主应用...${NC}"
kubectl apply -f deployment.yaml

echo -e "${YELLOW}创建服务...${NC}"
kubectl apply -f service.yaml

echo -e "${YELLOW}等待Pod启动...${NC}"
sleep 10

# 检查部署状态
echo -e "${YELLOW}检查部署状态...${NC}"
kubectl -n sothothv2-ns get pods
kubectl -n sothothv2-ns get svc
kubectl -n sothothv2-ns get pvc

echo -e "${GREEN}部署完成！${NC}"
echo -e "${YELLOW}使用以下命令检查服务状态：${NC}"
echo "kubectl -n sothothv2-ns get all"
echo "kubectl -n sothothv2-ns describe svc web-app-service"

