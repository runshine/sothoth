ARG SECFLOW_PI_AGENT_RUNTIME_IMAGE=ghcr.io/runshine/secflow-base-pi-agent-runtime:20260602
FROM ${SECFLOW_PI_AGENT_RUNTIME_IMAGE}

ENV PYTHONUNBUFFERED=1
ENV PI_CODING_AGENT_DIR=/root/.pi/agent

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN arch="$(dpkg --print-architecture)" \
    && case "$arch" in \
        amd64) kubectl_arch="amd64" ;; \
        arm64) kubectl_arch="arm64" ;; \
        *) echo "unsupported arch: $arch" && exit 1 ;; \
    esac \
    && curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/v1.30.3/bin/linux/${kubectl_arch}/kubectl" \
    && chmod +x /usr/local/bin/kubectl

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY main.py service.yaml.example ./

RUN mkdir -p /root/.pi/agent

RUN mkdir -p /data/files/platform/secflow-platform-diagnostic-assistant

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -fsS http://localhost:8080/api/diagnostic-assistant/healthz || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
