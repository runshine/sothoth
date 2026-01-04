FROM python:3.11-alpine

WORKDIR /python-docker

#sudo apt install default-libmysqlclient-dev
# 安装编译依赖
RUN apk add --no-cache --virtual .build-deps \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    python3-dev \
    && apk add --no-cache mariadb-dev  # 如果使用pymysql可能需要

RUN RUN apk --no-cache add ca-certificates   && update-ca-certificates

COPY requirements.txt requirements.txt

RUN pip3 install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

COPY . .

CMD [ "python3", "app.py"]