FROM mcr.microsoft.com/devcontainers/python:1-3.11-bookworm

WORKDIR /app

ARG SECFLOW_BUILD_VERSION=""
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN python -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app/ /app/app/
COPY config.yaml /app/config.yaml
RUN printf '{\"build_version\":\"%s\"}\n' "$SECFLOW_BUILD_VERSION" > /app/build_meta.json

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from urllib.request import urlopen; urlopen('http://localhost:8080/api/app/binary-security/health', timeout=5)" || exit 1

CMD ["python", "-m", "app.main"]
