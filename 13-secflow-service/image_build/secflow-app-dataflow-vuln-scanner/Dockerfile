ARG SECFLOW_PI_AGENT_RUNTIME_IMAGE=ghcr.io/runshine/secflow-base-pi-agent-runtime:20260602
FROM ${SECFLOW_PI_AGENT_RUNTIME_IMAGE}

ARG SECFLOW_BUILD_VERSION=""

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY plugins/ ./plugins/
COPY prompts/ ./prompts/
COPY run_vuln_scan.py ./run_vuln_scan.py
COPY config.json ./config.json
COPY config.pi_vuln.example.json ./config.pi_vuln.example.json
COPY config.vuln_scan_default.json ./config.vuln_scan_default.json
COPY config.full_pipeline.json ./config.full_pipeline.json
COPY config.yaml ./config.yaml
COPY docker/entrypoint.sh /usr/local/bin/secflow-entrypoint
RUN printf '{"build_version":"%s"}\n' "$SECFLOW_BUILD_VERSION" > /app/build_meta.json

RUN chmod +x /usr/local/bin/secflow-entrypoint \
    && mkdir -p /app/runs /data /root

EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/secflow-entrypoint"]
CMD ["serve"]
