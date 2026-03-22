#!/bin/bash

# 入口脚本
#set -e

cd "${WORKDIR:-/app}" 2>/dev/null || cd /app || cd /root

REST_PORT="${REST_PORT:-20001}"
TTYD_PORT="${TTYD_PORT:-20002}"
CODE_SERVER_PORT="${CODE_SERVER_PORT:-20003}"

TTYD_PID=""
CODE_SERVER_PID=""
CLAUDE_A2A_PID=""

cleanup_children() {
    for pid in "$TTYD_PID" "$CODE_SERVER_PID" "$CLAUDE_A2A_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
}

trap cleanup_children EXIT INT TERM

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
echo "Port: ${REST_PORT}"
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

ttyd -p "${TTYD_PORT}" -w / -W /bin/bash >> /tmp/ttyd.log 2>&1 &
TTYD_PID=$!

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
    export PASSWORD=${CODE_SERVER_PASSWORD}
    "${CODE_SERVER_BIN}" \
        --port ${CODE_SERVER_PORT} \
        --bind-addr 0.0.0.0:${CODE_SERVER_PORT} \
        --auth password \
        --disable-telemetry \
        --disable-update-check \
        "${CODE_SERVER_WORKDIR}" \
        >> /tmp/code-server.log 2>&1 &
    CODE_SERVER_PID=$!
    echo "code-server started with workdir: ${CODE_SERVER_WORKDIR}"
    echo "code-server password: ${CODE_SERVER_PASSWORD}"
else
    echo "WARNING: code-server binary not found; skip starting code-server" >&2
fi

if [ -n "${CLAUDE_A2A_BIN}" ]; then
    "${CLAUDE_A2A_BIN}" >> /tmp/claude-a2a.log 2>&1 &
    CLAUDE_A2A_PID=$!
else
    echo "WARNING: claude-a2a binary not found; skip starting claude-a2a" >&2
fi

# 设置权限
if [ -d "/host" ]; then
    echo "Host directory mounted at /host"
    ls -la /host
fi

# 启动服务
echo "Starting API service on port ${REST_PORT}..."
exec gunicorn \
    --bind 0.0.0.0:${REST_PORT} \
    --workers 4 \
    --timeout ${TIMEOUT} \
    --access-logfile - \
    --error-logfile - \
    app:app
