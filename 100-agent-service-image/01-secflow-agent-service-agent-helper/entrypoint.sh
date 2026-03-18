#!/bin/bash

# 入口脚本
#set -e

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

nohup ttyd -p 20002 -w / -W  /bin/bash 2>&1 >> /tmp/ttyd.log &

# 启动 code-server
echo "Starting code-server on port ${CODE_SERVER_PORT}..."
# 加载 nvm 环境
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"

# 设置 code-server 密码
if [ -z "$CODE_SERVER_PASSWORD" ]; then
    # 生成随机密码
    CODE_SERVER_PASSWORD=$(openssl rand -base64 12)
    echo "Generated code-server password: ${CODE_SERVER_PASSWORD}"
fi

# 确定 code-server 工作目录
CODE_SERVER_WORKDIR="${WORKDIR}"
if [ -d "/host" ]; then
    CODE_SERVER_WORKDIR="/host"
fi

# 启动 code-server
nohup code-server \
    --bind-addr 0.0.0.0:${CODE_SERVER_PORT} \
    --auth password \
    --disable-telemetry \
    --disable-update-check \
    ${CODE_SERVER_WORKDIR} \
    2>&1 >> /tmp/code-server.log &

nohup claude-a2a 2>&1 >> /tmp/claude-a2a.log &

echo "code-server started with workdir: ${CODE_SERVER_WORKDIR}"
echo "code-server password: ${CODE_SERVER_PASSWORD}"

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