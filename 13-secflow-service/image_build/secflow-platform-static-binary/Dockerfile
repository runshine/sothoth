FROM python:3.11-alpine

WORKDIR /app

#sudo apt install default-libmysqlclient-dev
# 安装编译依赖
RUN apk add --no-cache --virtual .build-deps \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    python3-dev \
    && apk add --no-cache mariadb-dev  # 如果使用pymysql可能需要

RUN apk --no-cache add ca-certificates   && update-ca-certificates

COPY requirements.txt requirements.txt

RUN pip3 install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

COPY . .

# 默认使用默认配置文件，可以通过环境变量覆盖
ENV CONFIG_PATH=/app/config.yaml

# 启动命令支持通过环境变量指定配置文件路径
CMD ["sh", "-c", "python3 app.py --config ${CONFIG_PATH}"]