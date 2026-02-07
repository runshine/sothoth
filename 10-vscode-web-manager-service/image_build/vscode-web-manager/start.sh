#!/bin/bash
# Code Server Manager 启动脚本
#
# 注意: 服务启动参数均在 config.yaml 中配置
# 包括: host, port, debug 等

# 切换工作目录
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "========================================="
echo "  Code Server Manager 启动脚本"
echo "========================================="

# 检查配置文件
if [ ! -f "config.yaml" ]; then
    echo "提示: 配置文件 config.yaml 不存在，将使用默认配置"
    echo "默认配置: host=0.0.0.0, port=8080, debug=false"
else
    echo "使用配置文件: config.yaml"
fi

# 启动服务 (参数使用 config.yaml)
echo "启动服务..."
python app/main.py
