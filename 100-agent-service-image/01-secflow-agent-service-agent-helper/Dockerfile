# 使用Ubuntu最新LTS版本作为基础镜像
FROM debian:trixie

# 避免交互式安装提示
ENV DEBIAN_FRONTEND=noninteractive

# 设置环境变量
ENV TIMEOUT=180
ENV REST_PORT=20001
ENV TTYD_PORT=20002
ENV WORKDIR=/app
ENV CODE_SERVER_PORT=20003
ENV PROCESS_MONITOR_PORT=20004
ENV PROCESS_MONITOR_INTERVAL_SEC=15
ENV HOST_ROOT=/host
ENV PROCESS_MONITOR_PROC_ROOT=/host/proc
ENV CODE_SERVER_PASSWORD=
ENV NVM_DIR=/root/.nvm
ENV PATH=/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# 创建工作目录
WORKDIR ${WORKDIR}

# 安装基础工具和编译环境
RUN apt-get update && apt-get install -y \
    # 基础工具
    curl wget vim nano git make cmake \
    # 编译工具链
    gcc g++ clang llvm \
    # 调试工具
    gdb lldb strace \
    # 系统工具
    procps psmisc htop net-tools iproute2 \
    # Python环境
    python3 python3-pip python3-dev \
    # Node/npm 运行时
    nodejs npm \
    # 其他实用工具
    jq tree tmux less file unzip openssl \
    # 清理缓存
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 根据架构下载ttyd（适配GitHub Actions多架构构建）
ARG TARGETARCH
ARG TARGETVARIANT

RUN if [ "$TARGETARCH" = "amd64" ]; then \
        curl -L "https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64" -o /tmp/ttyd; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
        curl -L "https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.aarch64" -o /tmp/ttyd; \
    elif [ "$TARGETARCH" = "arm" ]; then \
        if [ "$TARGETVARIANT" = "v7" ]; then \
            curl -L "https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.armhf" -o /tmp/ttyd; \
        elif [ "$TARGETVARIANT" = "v5" ]; then \
            curl -L "https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.armel" -o /tmp/ttyd; \
        else \
            curl -L "https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.armhf" -o /tmp/ttyd; \
        fi; \
    else \
        echo "Unsupported architecture: $TARGETARCH" && exit 1; \
    fi && \
    chmod +x /tmp/ttyd && \
    mv /tmp/ttyd /usr/bin/ttyd && \
    echo "Downloaded ttyd for architecture: $TARGETARCH $TARGETVARIANT"

# 安装Python依赖
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

RUN set -eux; \
    if [ "$TARGETARCH" = "arm" ] && [ "$TARGETVARIANT" = "v5" ]; then \
        npm install --unsafe-perm -g code-server; \
    else \
        curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash; \
        bash -lc ". \"$NVM_DIR/nvm.sh\" && nvm install 20 && nvm alias default 20 && nvm use --silent default"; \
        curl -fsSL https://code-server.dev/install.sh | sh -s -- --method=standalone; \
        echo ". \"$NVM_DIR/nvm.sh\"" >> /root/.bashrc; \
    fi; \
    npm install --unsafe-perm -g @anthropic-ai/claude-code; \
    npm install --unsafe-perm -g claude-a2a; \
    npm install --unsafe-perm -g @openai/codex; \
    npm install --unsafe-perm -g opencode-ai; \
    NODE_GLOBAL_ROOT="$(npm root -g)"; \
    write_wrapper() { \
        bin_name="$1"; \
        target="$2"; \
        rm -f "/usr/local/bin/${bin_name}"; \
        printf '%s\n' '#!/bin/sh' "exec node \"$target\" \"\$@\"" > "/usr/local/bin/${bin_name}"; \
        chmod +x "/usr/local/bin/${bin_name}"; \
    }; \
    if [ -f "$NODE_GLOBAL_ROOT/@anthropic-ai/claude-code/cli.js" ]; then write_wrapper claude "$NODE_GLOBAL_ROOT/@anthropic-ai/claude-code/cli.js"; fi; \
    if [ -f "$NODE_GLOBAL_ROOT/@openai/codex/bin/codex.js" ]; then write_wrapper codex "$NODE_GLOBAL_ROOT/@openai/codex/bin/codex.js"; fi; \
    if [ -f "$NODE_GLOBAL_ROOT/claude-a2a/dist/server.js" ]; then write_wrapper claude-a2a "$NODE_GLOBAL_ROOT/claude-a2a/dist/server.js"; fi; \
    if [ -f "$NODE_GLOBAL_ROOT/opencode-ai/dist/index.js" ]; then write_wrapper opencode "$NODE_GLOBAL_ROOT/opencode-ai/dist/index.js"; fi; \
    if [ -x /root/.local/bin/code-server ]; then ln -sf /root/.local/bin/code-server /usr/local/bin/code-server; fi; \
    if command -v node >/dev/null 2>&1; then ln -sf "$(command -v node)" /usr/local/bin/node; fi; \
    if command -v npm >/dev/null 2>&1; then ln -sf "$(command -v npm)" /usr/local/bin/npm; fi; \
    if command -v npx >/dev/null 2>&1; then ln -sf "$(command -v npx)" /usr/local/bin/npx; fi; \
    test -x /usr/local/bin/node; \
    test -x /usr/local/bin/npm; \
    test -x /usr/local/bin/claude; \
    test -x /usr/local/bin/claude-a2a; \
    test -x /usr/local/bin/codex; \
    test -x /usr/local/bin/opencode; \
    echo 'export PATH=/root/.local/bin:$PATH' >> /root/.bashrc; 

# 创建 code-server 配置目录
RUN mkdir -p /root/.config/code-server && \
    chmod -R 755 /root/.config/code-server


# 复制应用代码
COPY agent_ai_service ./agent_ai_service
COPY process_monitor_service ./process_monitor_service
COPY entrypoint.sh .

# 设置执行权限
RUN chmod +x entrypoint.sh

# 创建非root用户（安全考虑）
RUN useradd -m -s /bin/bash debuguser && \
    chown -R debuguser:debuguser ${WORKDIR}

# 切换到非root用户
USER root

# 暴露端口
EXPOSE ${REST_PORT}
EXPOSE ${CODE_SERVER_PORT}
EXPOSE ${PROCESS_MONITOR_PORT}

# 启动脚本
ENTRYPOINT ["./entrypoint.sh"]
