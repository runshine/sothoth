FROM python:3.11-alpine

WORKDIR /python-docker

# 安装编译依赖
RUN apk add --no-cache --virtual .build-deps \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    python3-dev \
    && apk add --no-cache mariadb-dev  # 如果使用pymysql可能需要

COPY requirements.txt requirements.txt

RUN pip3 install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

COPY . .

CMD [ "python3", "app.py"]