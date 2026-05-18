ARG NODE_BASE_IMAGE=swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/library/node:22-bookworm-slim
ARG PYTHON_BASE_IMAGE=swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/library/python:3.11-slim

FROM ${NODE_BASE_IMAGE} AS node_runtime

FROM ${PYTHON_BASE_IMAGE}

ARG DEBIAN_MIRROR=https://repo.huaweicloud.com/repository/debian
ARG DEBIAN_SECURITY_MIRROR=https://repo.huaweicloud.com/repository/debian-security
ARG PIP_INDEX_URL=https://repo.huaweicloud.com/repository/pypi/simple
ARG PIP_TRUSTED_HOST=repo.huaweicloud.com
ARG NPM_REGISTRY_URL=https://repo.huaweicloud.com/repository/npm/
ARG ANDROID_PLATFORM_TOOLS_URL=https://dl.google.com/android/repository/platform-tools-latest-linux.zip
ARG ANDROID_NDK_URL=https://dl.google.com/android/repository/android-ndk-r29-linux.zip
ARG ANDROID_NDK_SHA1=87e2bb7e9be5d6a1c6cdf5ec40dd4e0c6d07c30b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CI=true \
    PATH="/opt/android-tools:/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:${PATH}" \
    KERNEL_SCAN_DATABASE_URL=sqlite:////var/lib/secflow-kernel-scan/kernel-scan.db \
    KERNEL_SCAN_STATE_ROOT=/var/lib/secflow-kernel-scan \
    KERNEL_SCAN_KERNEL_DIR=/workspace/kernel \
    KERNEL_SCAN_EXECUTION_MODE=claude_cli \
    KERNEL_SCAN_CLAUDE_BIN=/usr/local/bin/claude \
    KERNEL_SCAN_CLAUDE_MODEL=zai-org/GLM-5 \
    KERNEL_SCAN_MAX_PARALLEL_TASKS=1 \
    KERNEL_SCAN_ENTRY_THREADS=4 \
    KERNEL_SCAN_AUDIT_THREADS=4 \
    KERNEL_SCAN_POC_THREADS=2

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

RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates curl git iproute2 jq procps ripgrep tini clangd unzip \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
 mkdir -p /opt/android-tools /opt/android-ndk; \
 curl -fL --retry 3 --retry-delay 5 -o /tmp/platform-tools.zip "${ANDROID_PLATFORM_TOOLS_URL}"; \
 unzip -qo /tmp/platform-tools.zip -d /tmp/platform-tools; \
 cp /tmp/platform-tools/platform-tools/adb /opt/android-tools/adb; \
 cp /tmp/platform-tools/platform-tools/fastboot /opt/android-tools/fastboot; \
 chmod +x /opt/android-tools/adb /opt/android-tools/fastboot; \
 rm -rf /tmp/platform-tools /tmp/platform-tools.zip; \
 curl -fL --retry 3 --retry-delay 5 -o /tmp/android-ndk.zip "${ANDROID_NDK_URL}"; \
 if [ -n "${ANDROID_NDK_SHA1}" ]; then echo "${ANDROID_NDK_SHA1}  /tmp/android-ndk.zip" | sha1sum -c -; fi; \
 unzip -qo /tmp/android-ndk.zip -d /tmp/android-ndk; \
 mv /tmp/android-ndk/android-ndk-*/* /opt/android-ndk/; \
 rm -rf /tmp/android-ndk /tmp/android-ndk.zip; \
 /opt/android-tools/adb version; \
 /opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang --version

RUN pip install --no-cache-dir --index-url "${PIP_INDEX_URL}" --trusted-host "${PIP_TRUSTED_HOST}" -r /app/requirements.txt

RUN npm config set registry "${NPM_REGISTRY_URL}" \
 && npm install -g @anthropic-ai/claude-code \
 && claude --version \
 && npm cache clean --force

COPY app /app/app
COPY ask_claude_entry.py /app/ask_claude_entry.py
COPY ask_claude_kernaudit_v2.py /app/ask_claude_kernaudit_v2.py
COPY ask_claude_poc.py /app/ask_claude_poc.py
COPY config.example.yaml /app/config.example.yaml
COPY entrypoint.sh /app/entrypoint.sh
COPY .claude.json /app/claude.json.template
COPY settings.json /app/settings.json.template

RUN useradd -m -s /bin/bash -u 1000 scanner \
 && chmod +x /app/entrypoint.sh \
 && mkdir -p /var/lib/secflow-kernel-scan /workspace/kernel /home/scanner/.claude /opt/android-tools /opt/android-ndk \
 && chown -R scanner:scanner /var/lib/secflow-kernel-scan /workspace /home/scanner /app /opt/android-tools /opt/android-ndk

COPY --chown=scanner:scanner skills /home/scanner/.claude/skills
COPY --chown=scanner:scanner agents /home/scanner/.claude/agents

USER scanner

# Install clangd-lsp plugin from claude-plugins-official marketplace
# Templates in /app are copied to $HOME by entrypoint.sh on first start
RUN mkdir -p /home/scanner/.claude/projects \
 && claude plugin marketplace add anthropics/claude-plugins-official \
 && claude plugin install clangd-lsp@claude-plugins-official

EXPOSE 8080

VOLUME ["/var/lib/secflow-kernel-scan", "/workspace/kernel"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8080/api/app/kernel-scan/health', timeout=5)" || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/app/entrypoint.sh"]
CMD ["python3", "-m", "app.main"]
