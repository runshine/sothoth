#!/bin/bash

set -e

# 配置变量
VERSION="1.0.0"

# 支持的平台
PLATFORMS="linux/amd64,linux/arm64,linux/arm/v7,linux/arm/v6"

# 构建参数
BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
COMMIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

echo "==========================================="
echo "Tetragon Monitor 多架构镜像构建"
echo "==========================================="
echo "版本: ${VERSION}"
echo "平台: ${PLATFORMS}"
echo "构建时间: ${BUILD_DATE}"
echo "提交哈希: ${COMMIT_SHA}"
echo "==========================================="

# 检查Docker Hub登录状态
if ! docker info | grep -q "Username"; then
    echo "请先登录Docker Hub:"
    echo "docker login"
    exit 1
fi

# 创建构建器实例（如果不存在）
if ! docker buildx ls | grep -q "multiarch"; then
    echo "创建多架构构建器..."
    docker buildx create --name multiarch --driver docker-container --use
    docker buildx inspect --bootstrap
fi

# 开始构建
echo "开始构建多架构镜像..."

docker buildx build \
    --platform ${PLATFORMS} \
    --tag runshine0819/secflow-agent-service-tetragon-monitor:latest \
    --tag ghcr.io/runshine/secflow-agent-service-tetragon-monitor:latest \
    --build-arg VERSION=${VERSION} \
    --build-arg BUILD_DATE=${BUILD_DATE} \
    --build-arg COMMIT_SHA=${COMMIT_SHA} \
    --push \
    .

echo "==========================================="
echo "镜像构建并推送完成!"
echo ""
