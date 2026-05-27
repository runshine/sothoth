FROM node:22-bookworm-slim AS node_runtime

FROM python:3.11-slim-bookworm
ARG SECFLOW_BUILD_VERSION=""

ARG DEBIAN_MIRROR=https://repo.huaweicloud.com/repository/debian
ARG DEBIAN_SECURITY_MIRROR=https://repo.huaweicloud.com/repository/debian-security
ARG PIP_INDEX_URL=https://repo.huaweicloud.com/repository/pypi/simple
ARG PIP_TRUSTED_HOST=repo.huaweicloud.com
ARG NPM_REGISTRY_URL=https://repo.huaweicloud.com/repository/npm/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY --from=node_runtime /usr/local/ /usr/local/

COPY requirements.txt /app/requirements.txt
RUN set -eux; \
 if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
   printf '%s\n' \
     'Types: deb' \
     "URIs: ${DEBIAN_MIRROR}" \
     'Suites: bookworm bookworm-updates' \
     'Components: main' \
     'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
     '' \
     'Types: deb' \
     "URIs: ${DEBIAN_SECURITY_MIRROR}" \
     'Suites: bookworm-security' \
     'Components: main' \
     'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
     > /etc/apt/sources.list.d/debian.sources; \
 else \
   printf '%s\n' \
     "deb ${DEBIAN_MIRROR} bookworm main" \
     "deb ${DEBIAN_MIRROR} bookworm-updates main" \
     "deb ${DEBIAN_SECURITY_MIRROR} bookworm-security main" \
     > /etc/apt/sources.list; \
 fi
# Debian/Ubuntu package qemu-system-arm provides the qemu-system-aarch64 binary.
# There is no qemu-system-arm64 package in the Bookworm/Ubuntu apt metadata used here.
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates curl git ripgrep tini libatomic1 libstdc++6 libgcc-s1 libusb-1.0-0 procps util-linux iproute2 bridge-utils dnsmasq qemu-system-arm qemu-system-x86 qemu-utils socat \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --index-url "${PIP_INDEX_URL}" --trusted-host "${PIP_TRUSTED_HOST}" -r /app/requirements.txt

RUN npm config set registry "${NPM_REGISTRY_URL}" \
 && npm install -g @openai/codex opencode-ai \
 && codex --version \
 && opencode --version \
 && npm cache clean --force

COPY app /app/app
COPY config.example.yaml /app/config.example.yaml
COPY scripts/ipc-audit-qemu.sh /usr/local/bin/ipc-audit-qemu
RUN chmod +x /usr/local/bin/ipc-audit-qemu
RUN printf '{"build_version":"%s"}\n' "$SECFLOW_BUILD_VERSION" > /app/build_meta.json

RUN mkdir -p \
    /var/lib/secflow-ipc-audit \
    /var/lib/secflow-app-ipc-audit \
    /workspace/openharmony_6_1 \
    /workspace/files \
    /root/.codex \
    /root/.config/opencode \
    /root/.local/share/opencode

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8080/api/app/ipc-audit/health', timeout=5)" || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python3", "-m", "app.main"]
