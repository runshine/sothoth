#!/bin/bash

# 入口脚本
set -e

echo "=========================================="
echo "Remote Command Executor Container"
echo "=========================================="
echo "Timeout: ${TIMEOUT} seconds"
echo "Port: ${PORT}"
echo "Workdir: ${WORKDIR}"
echo "Container ID: $(cat /proc/self/cgroup | head -1 | cut -d/ -f3)"
echo "=========================================="

# 检查调试工具
echo "Available Debug Tools:"
echo "----------------------"
which gcc g++ clang gdb lldb strace ltrace make cmake python3
echo "----------------------"

# 挂载信息
echo "Mount Information:"
echo "----------------------"
mount | grep -E "/host|/proc|/sys|/dev"
echo "----------------------"

# 设置权限
if [ -d "/host" ]; then
    echo "Host directory mounted at /host"
    ls -la /host
fi

# 启动服务
echo "Starting API service on port ${PORT}..."
exec gunicorn \
    --bind 0.0.0.0:${PORT} \
    --workers 4 \
    --timeout ${TIMEOUT} \
    --access-logfile - \
    --error-logfile - \
    app:app