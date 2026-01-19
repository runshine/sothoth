# 使用官方Python运行时作为基础镜像
FROM python:3.9-slim

# 设置环境变量
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Shanghai

# 设置工作目录
WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    vim \
    gcc \
    g++ \
    make \
    libssl-dev \
    libffi-dev \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# 复制requirements.txt文件
COPY requirements.txt .

# 安装Python依赖
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 复制应用程序代码
COPY . .

# 创建必要的目录
RUN mkdir -p \
    ./services \
    ./templates \
    ./logs \
    ./data

# 创建非root用户并设置权限
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

# 切换到非root用户
USER appuser

# 暴露端口
EXPOSE 18080

# 设置健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:18080/api/health || exit 1

# 设置启动命令
CMD ["python", "app.py", "--config", "config.json"]