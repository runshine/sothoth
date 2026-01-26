# Dockerfile
FROM python:3.12-slim

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    git \
    nodejs \
    npm \
    curl vim \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 安装Python依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 安装CodeWiki
RUN pip install git+https://github.com/FSoft-AI4Code/CodeWiki.git

# 创建必要的目录
RUN mkdir -p /config/workspace /app/logs /app/data

# 复制应用代码
COPY app/ ./app/

# 设置环境变量
ENV PYTHONPATH=/app
ENV LOG_LEVEL=INFO
ENV DATABASE_URL=sqlite+aiosqlite:////app/data/codewiki.db
ENV LOGS_DIR=/app/logs

# 暴露端口
EXPOSE 8080


# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# 启动命令
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]