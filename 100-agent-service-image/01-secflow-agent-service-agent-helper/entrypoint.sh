#!/bin/bash

# 入口脚本
#set -e

resolve_node_global_bin() {
    local bin_name="$1"
    local resolved=""

    # 先尝试当前PATH
    resolved="$(command -v "$bin_name" 2>/dev/null || true)"
    if [ -n "$resolved" ]; then
        echo "$resolved"
        return 0
    fi

    # 尝试加载nvm并激活常见版本
    export NVM_DIR="${HOME}/.nvm"
    if [ -s "${NVM_DIR}/nvm.sh" ]; then
        . "${NVM_DIR}/nvm.sh"
        nvm use --silent 24 >/dev/null 2>&1 || nvm use --silent default >/dev/null 2>&1 || true
        resolved="$(command -v "$bin_name" 2>/dev/null || true)"
        if [ -n "$resolved" ]; then
            echo "$resolved"
            return 0
        fi
    fi

    # 兜底：直接在nvm目录下找最新安装的可执行文件
    if [ -d "${NVM_DIR}/versions/node" ]; then
        resolved="$(find "${NVM_DIR}/versions/node" -type f -path '*/bin/'"${bin_name}" 2>/dev/null | sort | tail -n 1)"
        if [ -n "$resolved" ]; then
            echo "$resolved"
            return 0
        fi
    fi

    return 1
}

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

CODE_SERVER_BIN="$(resolve_node_global_bin code-server || true)"
CLAUDE_A2A_BIN="$(resolve_node_global_bin claude-a2a || true)"

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
if [ -n "${CODE_SERVER_BIN}" ]; then
    nohup "${CODE_SERVER_BIN}" \
        --bind-addr 0.0.0.0:${CODE_SERVER_PORT} \
        --auth password \
        --disable-telemetry \
        --disable-update-check \
        "${CODE_SERVER_WORKDIR}" \
        2>&1 >> /tmp/code-server.log &
    echo "code-server started with workdir: ${CODE_SERVER_WORKDIR}"
    echo "code-server password: ${CODE_SERVER_PASSWORD}"
else
    echo "WARNING: code-server binary not found; skip starting code-server" >&2
fi

if [ -n "${CLAUDE_A2A_BIN}" ]; then
    nohup "${CLAUDE_A2A_BIN}" 2>&1 >> /tmp/claude-a2a.log &
else
    echo "WARNING: claude-a2a binary not found; skip starting claude-a2a" >&2
fi

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
