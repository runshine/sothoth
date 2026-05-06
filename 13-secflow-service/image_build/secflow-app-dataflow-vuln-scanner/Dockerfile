FROM python:3.11-slim

ARG INSTALL_PI_CLI=1
ARG PI_NPM_PACKAGE=@mariozechner/pi-coding-agent

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        git \
        nodejs \
        npm \
        ripgrep \
        tar \
        tini \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

RUN if [ "$INSTALL_PI_CLI" = "1" ]; then \
      npm install -g "$PI_NPM_PACKAGE"; \
    fi

COPY app/ ./app/
COPY plugins/ ./plugins/
COPY examples/ ./examples/
COPY prompts/ ./prompts/
COPY docs/ ./docs/
COPY run_vuln_scan.py ./run_vuln_scan.py
COPY README.md ./README.md
COPY config.json ./config.json
COPY config.pi_vuln.example.json ./config.pi_vuln.example.json
COPY config.vuln_scan_default.json ./config.vuln_scan_default.json
COPY config.full_pipeline.json ./config.full_pipeline.json
COPY config.yaml ./config.yaml
COPY .docker-runtime-home/ /opt/runtime-home/
COPY docker/entrypoint.sh /usr/local/bin/secflow-entrypoint

RUN chmod +x /usr/local/bin/secflow-entrypoint \
    && mkdir -p /app/runs /data /root \
    && if [ -d /opt/runtime-home/root/.pi ]; then cp -a /opt/runtime-home/root/.pi /root/.pi; fi \
    && if [ -d /opt/runtime-home/root/.copilot ]; then cp -a /opt/runtime-home/root/.copilot /root/.copilot; fi \
    && rm -rf /opt/runtime-home

EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/secflow-entrypoint"]
CMD ["serve"]
