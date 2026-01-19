# 基于Tetragon构建监控镜像
FROM quay.io/cilium/tetragon:latest as tetragon

# 构建阶段：安装Python和依赖
FROM python:3.11-slim

# 安装必要的工具
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    wget \
    && rm -rf /var/lib/apt/lists/*

# 复制Tetragon二进制文件
COPY --from=tetragon /usr/bin/tetragon /usr/bin/tetragon
COPY --from=tetragon /usr/bin/tetra /usr/bin/tetra

# 创建应用目录
WORKDIR /app

# 复制Python去重和上传脚本
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt --break-system-packages

COPY deduplicator.py .
COPY es_uploader.py .
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# 创建数据目录
RUN mkdir -p /var/run/tetragon /var/log/tetragon

# 环境变量
ENV TETRAGON_LOG_LEVEL=info \
    ES_ENABLED=false \
    ES_HOST=localhost \
    ES_PORT=9200 \
    ES_USER=elastic \
    ES_PASSWORD=elastic \
    ES_INDEX=tetragon-events \
    DEDUP_ENABLED=true \
    DEDUP_WINDOW_MINUTES=5 \
    CACHE_MAX_SIZE=10000 \
    EVENTS_INTERVAL_MS=100

EXPOSE 54321

CMD ["./entrypoint.sh"]