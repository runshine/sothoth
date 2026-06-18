ARG SECFLOW_PI_AGENT_RUNTIME_IMAGE=ghcr.io/runshine/secflow-base-pi-agent-runtime:20260602
FROM ${SECFLOW_PI_AGENT_RUNTIME_IMAGE}

ARG SECFLOW_BUILD_VERSION=""
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app:/opt/vuln-verify/src:/opt/vuln-verify/packages/vuln-dispatch/src \
    PI_CODING_AGENT_DIR=/root/.pi/agent \
    PI_MODELS_JSON=/root/.pi/agent/models.json

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl ca-certificates procps psmisc findutils coreutils jq git rclone python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
    && pip install --no-cache-dir httpx PyYAML \
    && (/usr/bin/python3 -m pip install --no-cache-dir --break-system-packages httpx PyYAML \
        || /usr/bin/python3 -m pip install --no-cache-dir httpx PyYAML)

COPY vendor/vuln-verify /opt/vuln-verify

COPY app/ /app/app/
COPY config.yaml /app/config.yaml
RUN printf '{"build_version":"%s"}\n' "$SECFLOW_BUILD_VERSION" > /app/build_meta.json

RUN mkdir -p /root/.pi/agent/bin /root/.pi/agent/skills /root/.config/secocto /data/config /data/files \
    && for _cmd in rg grep find head tail cat sed awk cut tr sort uniq wc xargs ls stat file basename dirname readlink realpath jq python3 rclone; do \
        _target="$(command -v "$_cmd" 2>/dev/null)" && [ -x "$_target" ] && ln -sf "$_target" "/root/.pi/agent/bin/$_cmd" 2>/dev/null || true; \
    done \
    && if [ -x /opt/venv/bin/python3 ]; then ln -sf /opt/venv/bin/python3 /root/.pi/agent/bin/python3; fi

COPY skills/ /root/.pi/agent/skills/
RUN find /root/.pi/agent/skills -type f -name "*.sh" -exec chmod +x {} \; \
    && find /root/.pi/agent/skills -type f -name "*.py" -exec chmod +x {} \; || true

COPY scripts/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8080/api/app/vuln-verify/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python3", "-m", "app.main"]
