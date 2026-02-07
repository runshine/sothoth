# Secflow Input Management Service Dockerfile
FROM python:3.11-slim-bookworm

# 设置工作目录
WORKDIR /app

# 设置环境变量
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    unzip \
    zip \
    tar \
    curl \
    vim \
    && rm -rf /var/lib/apt/lists/*

# 创建必要目录
RUN mkdir -p /app/uploads /app/temp /app/task_logs /app/config

# 复制依赖文件
COPY requirements.txt /app/

# 安装Python依赖
RUN pip install -r /app/requirements.txt

# 复制应用代码
COPY app/ /app/app/
COPY start.py /app/start.py

# 复制配置文件
COPY config.yaml /app/config.yaml

# 暴露端口（使用配置文件中指定的端口）
EXPOSE 10002

# 健康检查（端口在运行时从配置读取）
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import yaml; import subprocess; port=yaml.safe_load(open('/app/config.yaml'))['app'].get('port',10002); subprocess.run(['curl','-f',f'http://localhost:{port}/api/resource/health'])" || exit 1

# 启动命令
CMD ["python", "/app/start.py"]