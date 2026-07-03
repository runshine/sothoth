ARG SECFLOW_PYTHON_RUNTIME_IMAGE=ghcr.io/runshine/secflow-base-python311-runtime:20260602
FROM ${SECFLOW_PYTHON_RUNTIME_IMAGE}

ARG PI_NPM_PACKAGE=@earendil-works/pi-coding-agent
ARG SECFLOW_BUILD_VERSION=""

ENV PI_CODING_AGENT_DIR=/root/.pi/agent

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gnupg \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g "${PI_NPM_PACKAGE}" \
    && mkdir -p "${PI_CODING_AGENT_DIR}/bin" "${PI_CODING_AGENT_DIR}/skills" \
    && ln -sf "$(command -v rg)" "${PI_CODING_AGENT_DIR}/bin/rg"

RUN printf '{"build_version":"%s"}\n' "$SECFLOW_BUILD_VERSION" > /image-build-base.json
