FROM ubuntu:24.04

LABEL maintainer="icsl"
LABEL description="Firmware unpacking microservice powered by pi coding agent"

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai
ENV NODE_VERSION=v25.8.1
ENV CONFIG_PATH=/app/config.yaml
ENV FIRMWARE_UNPACKER_CONFIG=/app/config.yaml
ENV UNPACKER_AGENT_DIR=/app/app/agent
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    ca-certificates \
    git \
    build-essential \
    file \
    software-properties-common \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    xz-utils \
    binwalk \
    squashfs-tools \
    mtd-utils \
    unyaffs \
    fusecram \
    cpio \
    p7zip-full \
    cabextract \
    lzop \
    lzma \
    gzip \
    bzip2 \
    zstd \
    unrar \
    xxd \
    && rm -rf /var/lib/apt/lists/*

RUN ln -sf /usr/bin/python3 /usr/bin/python

RUN python3 -m venv "${VIRTUAL_ENV}"

COPY requirements.txt /app/
RUN pip3 install --no-cache-dir --default-timeout=300 \
    -i https://pypi.tuna.tsinghua.edu.cn/simple \
    -r /app/requirements.txt

RUN pip3 install --no-cache-dir --default-timeout=300 \
    -i https://pypi.tuna.tsinghua.edu.cn/simple \
    jefferson \
    ubi_reader

RUN ARCH=$(dpkg --print-architecture) \
    && if [ "$ARCH" = "amd64" ]; then NODE_ARCH="x64"; \
       elif [ "$ARCH" = "arm64" ]; then NODE_ARCH="arm64"; \
       else NODE_ARCH="x64"; fi \
    && curl -fsSL "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz" \
       -o /tmp/node.tar.xz \
    && mkdir -p /usr/local/lib/nodejs \
    && tar -xJf /tmp/node.tar.xz -C /usr/local/lib/nodejs \
    && ln -sf "/usr/local/lib/nodejs/node-${NODE_VERSION}-linux-${NODE_ARCH}/bin/node" /usr/local/bin/node \
    && ln -sf "/usr/local/lib/nodejs/node-${NODE_VERSION}-linux-${NODE_ARCH}/bin/npm" /usr/local/bin/npm \
    && ln -sf "/usr/local/lib/nodejs/node-${NODE_VERSION}-linux-${NODE_ARCH}/bin/npx" /usr/local/bin/npx \
    && rm /tmp/node.tar.xz

RUN npm install -g @mariozechner/pi-coding-agent \
    && ARCH=$(dpkg --print-architecture) \
    && if [ "$ARCH" = "amd64" ]; then NODE_ARCH="x64"; \
       elif [ "$ARCH" = "arm64" ]; then NODE_ARCH="arm64"; \
       else NODE_ARCH="x64"; fi \
    && ln -sf "/usr/local/lib/nodejs/node-${NODE_VERSION}-linux-${NODE_ARCH}/bin/pi" /usr/local/bin/pi

RUN mkdir -p /root/.pi/agent && cat > /root/.pi/agent/settings.json <<'PICONF'
{
  "defaultProvider": "my_llm",
  "defaultModel": "zai-org/GLM-5"
}
PICONF

RUN cat > /root/.pi/agent/models.json <<'PICONF'
{
  "providers": {
    "my_llm": {
      "baseUrl": "http://172.31.29.10:8000/v1/",
      "api": "openai-completions",
      "apiKey": "sk-12345678",
      "models": [
        { "id": "zai-org/GLM-5" }
      ]
    }
  }
}
PICONF

COPY app/ /app/app/
COPY config.yaml /app/config.yaml
COPY start.sh /app/start.sh

RUN mkdir -p /app/data \
    && chmod +x /app/start.sh

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python3 -c "from urllib.request import urlopen; urlopen('http://localhost:8080/api/app/firmware-unpacker/health', timeout=5)" || exit 1

CMD ["/app/start.sh"]
