# Code Server Manager Dockerfile
FROM python:3.11-slim

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY requirements.txt .

# 安装Python依赖
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY . .

# 暴露端口 (默认8080，可在config.yaml中配置)
EXPOSE 8080

# 启动命令 (所有参数从 config.yaml 读取)
CMD ["python", "app/main.py"]
