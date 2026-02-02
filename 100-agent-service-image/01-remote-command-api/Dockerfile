# 使用Ubuntu最新LTS版本作为基础镜像
FROM debian:trixie

# 避免交互式安装提示
ENV DEBIAN_FRONTEND=noninteractive

# 设置环境变量
ENV TIMEOUT=180
ENV PORT=20001
ENV WORKDIR=/app

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
    # 其他实用工具
    jq tree tmux less file\
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

RUN if [ "$TARGETARCH" = "arm" ] && [ "$TARGETVARIANT" = "v5" ]; then \
        apt-get update && apt-get install -y nodejs npm && apt-get clean && rm -rf /var/lib/apt/lists/* ;\
        npm install -g @anthropic-ai/claude-code ; \
        npm install -g opencode-ai@latest ; \
    else \
        curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash ; \
        bash -c ". $HOME/.nvm/nvm.sh && nvm install 24" ; \
        bash -c ". $HOME/.nvm/nvm.sh && node -v" ; \
        bash -c ". $HOME/.nvm/nvm.sh && npm -v" ; \
        bash -c ". $HOME/.nvm/nvm.sh && npm install -g @anthropic-ai/claude-code" ; \
        bash -c ". $HOME/.nvm/nvm.sh && npm install -g @opencode-ai@latest" ; \
        echo ". $HOME/.nvm/nvm.sh" >> /root/.bashrc ;\
    fi


# 复制应用代码
COPY app.py .
COPY entrypoint.sh .

# 设置执行权限
RUN chmod +x entrypoint.sh

# 创建非root用户（安全考虑）
RUN useradd -m -s /bin/bash debuguser && \
    chown -R debuguser:debuguser ${WORKDIR}

# 切换到非root用户
USER root

# 暴露端口
EXPOSE ${PORT}

# 启动脚本
ENTRYPOINT ["./entrypoint.sh"]