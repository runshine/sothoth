FROM public.ecr.aws/docker/library/python:3.11-slim

ARG SECFLOW_BUILD_VERSION=""

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TZ=Asia/Shanghai \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}"

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        git \
        ripgrep \
        tini \
        tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && ln -snf /usr/share/zoneinfo/${TZ} /etc/localtime \
    && echo "${TZ}" > /etc/timezone \
    && python -m venv "${VIRTUAL_ENV}"

RUN printf '{"build_version":"%s"}\n' "$SECFLOW_BUILD_VERSION" > /image-build-base.json

ENTRYPOINT ["/usr/bin/tini", "--"]
