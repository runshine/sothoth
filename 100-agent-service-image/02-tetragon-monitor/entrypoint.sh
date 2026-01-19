#!/bin/bash

set -e

# 加载环境变量
export TETRAGON_LOG_LEVEL=${TETRAGON_LOG_LEVEL:-info}
export DEDUP_WINDOW_MINUTES=${DEDUP_WINDOW_MINUTES:-5}
export CACHE_MAX_SIZE=${CACHE_MAX_SIZE:-10000}
export EVENTS_INTERVAL_MS=${EVENTS_INTERVAL_MS:-100}

# 创建Tetragon配置文件
cat > /tmp/tetragon-config.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: tetragon
spec:
  containers:
  - name: tetragon
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /sys/fs/bpf
      name: bpf
    - mountPath: /var/run/tetragon
      name: tetragon-run
  volumes:
  - name: bpf
    hostPath:
      path: /sys/fs/bpf
      type: Directory
  - name: tetragon-run
    hostPath:
      path: /var/run/tetragon
      type: DirectoryOrCreate
EOF

# Tetragon事件选择器配置 - 只监控文件访问和进程执行
cat > /tmp/tetragon-observability.yaml << EOF
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-process-monitoring"
spec:
  observers:
  - name: "file-access"
    file:
      path: "/**"
  - name: "process-exec"
    process:
      exec: true
  selectors:
  - matchBinaries:
    - operator: "In"
      values:
      - "*"
    matchActions:
    - action: Post
  output: stdout
EOF

# 函数：检查Tetragon是否就绪
wait_for_tetragon() {
    echo "等待Tetragon启动..."
    for i in {1..30}; do
        if tetra getevents 2>&1 | grep -q "connected"; then
            echo "Tetragon已就绪"
            return 0
        fi
        sleep 2
    done
    echo "Tetragon启动超时"
    return 1
}

# 函数：启动监控管道
start_monitoring_pipeline() {
    echo "启动监控管道..."

    # 启动Tetragon并获取事件
    tetragon --config /tmp/tetragon-config.yaml \
             --tracing-policy /tmp/tetragon-observability.yaml \
             --export-filename /tmp/tetragon-events.json \
             --log-level ${TETRAGON_LOG_LEVEL} &

    TETRAGON_PID=$!

    # 等待Tetragon启动
    sleep 5

    # 使用tetra获取事件流，通过管道传递给去重处理器
    tetra getevents --output json \
        --file-access \
        --process-exec \
        --interval ${EVENTS_INTERVAL_MS} | \
    python3 /app/deduplicator.py \
        --dedup-window ${DEDUP_WINDOW_MINUTES} | \
    python3 /app/es_uploader.py

    wait $TETRAGON_PID
}

# 主执行流程
echo "========================================"
echo "Tetragon监控系统启动"
echo "========================================"
echo "配置信息:"
echo "- Tetragon日志级别: ${TETRAGON_LOG_LEVEL}"
echo "- 去重时间窗口: ${DEDUP_WINDOW_MINUTES}分钟"
echo "- 事件间隔: ${EVENTS_INTERVAL_MS}ms"
echo "- ES启用: ${ES_ENABLED}"
echo "- ES主机: ${ES_HOST}:${ES_PORT}"
echo "- ES索引: ${ES_INDEX}"
echo "========================================"

# 确保必要的目录存在
mkdir -p /var/run/tetragon /var/log/tetragon

# 启动监控管道
start_monitoring_pipeline

echo "监控系统已停止"