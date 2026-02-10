FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件并安装
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir pymysql cryptography

# 复制配置文件
COPY config.yaml /app/

# 复制启动脚本
COPY app/start.py /app/app/

# 复制应用代码
COPY app/ /app/app/

EXPOSE 8080

# 使用启动脚本（从配置文件读取host和port）
CMD ["python", "/app/app/start.py"]