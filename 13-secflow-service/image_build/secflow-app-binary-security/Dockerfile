FROM public.ecr.aws/docker/library/python:3.11-slim

WORKDIR /app

ARG SECFLOW_BUILD_VERSION=""
ENV TZ=Asia/Shanghai \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone \
    && python -m venv "${VIRTUAL_ENV}"

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app/ /app/app/
COPY scripts/ /app/scripts/
COPY config.yaml /app/config.yaml
RUN printf '{"build_version":"%s"}\n' "$SECFLOW_BUILD_VERSION" > /app/build_meta.json
RUN find /app/scripts -name '*.sh' -exec sed -i 's/\r$//' {} + \
    && chmod +x /app/scripts/*.sh

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from urllib.request import urlopen; urlopen('http://localhost:18080/healthz', timeout=5)" || exit 1

CMD ["./scripts/start-with-probe.sh", "python", "-m", "app.main"]
