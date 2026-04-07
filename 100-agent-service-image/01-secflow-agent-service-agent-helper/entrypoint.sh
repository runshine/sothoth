#!/bin/bash

# 入口脚本
#set -e

cd "${WORKDIR:-/app}" 2>/dev/null || cd /app || cd /root

REST_PORT="${REST_PORT:-20001}"
TTYD_PORT="${TTYD_PORT:-20002}"
CODE_SERVER_PORT="${CODE_SERVER_PORT:-20003}"
PROCESS_MONITOR_PORT="${PROCESS_MONITOR_PORT:-20004}"

TTYD_PID=""
CODE_SERVER_PID=""
PROCESS_MONITOR_PID=""
GUNICORN_PID=""

cleanup_children() {
    for pid in "$GUNICORN_PID" "$TTYD_PID" "$CODE_SERVER_PID" "$PROCESS_MONITOR_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done

    sleep 1

    for pid in "$GUNICORN_PID" "$TTYD_PID" "$CODE_SERVER_PID" "$PROCESS_MONITOR_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
        wait "$pid" 2>/dev/null || true
    done
}

trap cleanup_children EXIT INT TERM

ensure_port_available() {
    local port="$1"
    local owner=""

    owner="$(ss -ltnp 2>/dev/null | awk -v needle=":${port}" '$4 ~ needle {print $0}' | head -n 1)"
    if [ -n "$owner" ]; then
        echo "ERROR: port ${port} is already in use: ${owner}" >&2
        return 1
    fi
    return 0
}

resolve_node_global_bin() {
    local bin_name="$1"
    local resolved=""

    resolved="$(command -v "$bin_name" 2>/dev/null || true)"
    if [ -n "$resolved" ]; then
        echo "$resolved"
        return 0
    fi

    if [ -x "${HOME}/.local/bin/${bin_name}" ]; then
        echo "${HOME}/.local/bin/${bin_name}"
        return 0
    fi

    resolved="$(find "${HOME}/.local/lib" -maxdepth 4 -type f -path '*/bin/'"${bin_name}" 2>/dev/null | sort | tail -n 1)"
    if [ -n "$resolved" ]; then
        echo "$resolved"
        return 0
    fi

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
echo "Agent AI Service Container"
echo "=========================================="
echo "Timeout: ${TIMEOUT} seconds"
echo "REST Port: ${REST_PORT}"
echo "Process Monitor Port: ${PROCESS_MONITOR_PORT}"
echo "Workdir: ${WORKDIR}"
echo "Container ID: $(cat /proc/self/cgroup | head -1 | cut -d/ -f3)"
echo "=========================================="

# DNS hijack at container startup:
# when DNS_SERVER is configured, overwrite /etc/resolv.conf with that value only.
if [ -n "${DNS_SERVER:-}" ]; then
    echo "DNS_SERVER detected, overwriting /etc/resolv.conf ..."
    : > /etc/resolv.conf
    printf '%s' "${DNS_SERVER}" | tr ',; \t' '\n' | while IFS= read -r dns_item; do
        dns_item="$(echo "${dns_item}" | xargs)"
        [ -z "${dns_item}" ] && continue
        echo "nameserver ${dns_item}" >> /etc/resolv.conf
    done
else
    echo "DNS_SERVER is empty, skip /etc/resolv.conf overwrite."
fi

echo "Available Debug Tools:"
echo "----------------------"
which gcc g++ clang gdb lldb strace ltrace make cmake python3 || true
echo "----------------------"

echo "Mount Information:"
echo "----------------------"
mount | grep -E "/host|/proc|/sys|/dev" || true
echo "----------------------"

ensure_port_available "${REST_PORT}" || exit 1
ensure_port_available "${TTYD_PORT}" || exit 1
ensure_port_available "${CODE_SERVER_PORT}" || exit 1
ensure_port_available "${PROCESS_MONITOR_PORT}" || exit 1

ttyd -p "${TTYD_PORT}" -w / -W /bin/bash >> /tmp/ttyd.log 2>&1 &
TTYD_PID=$!

echo "Starting code-server on port ${CODE_SERVER_PORT}..."
CODE_SERVER_BIN="$(resolve_node_global_bin code-server || true)"
mkdir -p "${AGENT_HELPER_STATE_DIR:-/app/data}"

if [ -z "$CODE_SERVER_PASSWORD" ]; then
    CODE_SERVER_PASSWORD=$(openssl rand -base64 12)
    echo "Generated code-server password: ${CODE_SERVER_PASSWORD}"
fi

CODE_SERVER_WORKDIR="${WORKDIR}"
if [ -d "/host" ]; then
    CODE_SERVER_WORKDIR="/host"
fi

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

# 智能体后端进程由 REST API 统一管理，不在入口脚本中自动启动

echo "Starting Process monitor service on port ${PROCESS_MONITOR_PORT}..."
echo "Process monitor DNS_SERVER: ${DNS_SERVER:-<empty>}"
if [ -f "/etc/resolv.conf" ]; then
    echo "Process monitor resolv.conf nameservers(before start):"
    grep -E '^\s*nameserver\s+' /etc/resolv.conf || echo "(no nameserver entries)"
fi
python3 -u -m process_monitor_service.app > >(tee -a /tmp/process-monitor.log) 2>&1 &
PROCESS_MONITOR_PID=$!

if [ -d "/host" ]; then
    echo "Host directory mounted at /host"
    ls -la /host
fi

echo "Starting Agent AI service on port ${REST_PORT}..."
export PYTHONPATH="${WORKDIR}:${PYTHONPATH}"
gunicorn \
    --chdir ${WORKDIR} \
    --bind 0.0.0.0:${REST_PORT} \
    --workers 1 \
    --timeout ${TIMEOUT} \
    --access-logfile - \
    --error-logfile - \
    agent_ai_service.app:app &
GUNICORN_PID=$!

wait -n "$GUNICORN_PID" "$TTYD_PID" "$CODE_SERVER_PID" "$PROCESS_MONITOR_PID"
exit_code=$?

echo "A helper process exited unexpectedly, shutting down remaining processes..." >&2
cleanup_children
exit "${exit_code}"
