# secflow-app-poc-gen-verify Dockerfile
# Wraps the `poc` CLI (cli/poc_cli.py, which drives `claude -p` + gdb-via-tmux-mcp)
# behind a FastAPI service. Cloned from secflow-app-kernel-scan + tmux/gdb/tmux-mcp.
ARG NODE_BASE_IMAGE=docker.io/library/node:22-bookworm-slim
ARG PYTHON_BASE_IMAGE=docker.io/library/python:3.11-slim

FROM ${NODE_BASE_IMAGE} AS node_runtime

FROM ${PYTHON_BASE_IMAGE}
ARG NPM_REGISTRY_URL=https://registry.npmjs.org/

COPY --from=node_runtime /usr/local/ /usr/local/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Asia/Shanghai \
    SERVICE_YAML=/app/service.yaml \
    POC_GEN_VERIFY_STATE_ROOT=/var/lib/secflow-poc-gen-verify \
    POC_GEN_VERIFY_POC_BIN=poc \
    POC_GEN_VERIFY_CLAUDE_MODEL=glm-5.2 \
    POC_SCHEDULER_HOST=secflow-app-poc-gen-verify-redis \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash ca-certificates curl git iproute2 jq procps ripgrep tini unzip \
      build-essential gcc g++ make binutils libc-dev \
      tmux gdb \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

RUN npm config set registry "${NPM_REGISTRY_URL}" \
    && npm install -g @anthropic-ai/claude-code tmux-mcp \
    && claude --version \
    && npm cache clean --force

COPY cli/poc_cli.py /usr/local/bin/poc_cli.py
COPY cli/poc /usr/local/bin/poc
RUN chmod +x /usr/local/bin/poc /usr/local/bin/poc_cli.py

COPY app /app/app
COPY service.yaml /app/service.yaml
COPY .claude.json /app/.claude.json.template
COPY settings.json /app/settings.json.template
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

RUN useradd -m -s /bin/bash -u 1000 scanner \
    && mkdir -p /var/lib/secflow-poc-gen-verify /workspace /home/scanner/.claude \
    && chown -R scanner:scanner /app /var/lib/secflow-poc-gen-verify /workspace /home/scanner
USER scanner
RUN mkdir -p /home/scanner/.claude/projects

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python3 -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8080/api/app/poc-gen-verify/health', timeout=5)" || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/app/entrypoint.sh"]
CMD ["python3", "-m", "app.main"]
