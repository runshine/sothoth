FROM python:3.11-slim

# 设置工作目录
WORKDIR /app

# 设置时区
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 创建虚拟环境
RUN python -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# 复制依赖文件
COPY requirements.txt /app/

# 安装Python依赖
RUN pip install --no-cache-dir -r /app/requirements.txt

# 复制应用代码
COPY app/ /app/app/
COPY config.yaml /app/config.yaml

# 暴露端口
EXPOSE 10005

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:10005/api/k8s/health || exit 1

# 启动命令
CMD ["python", "-m", "app.main"]