# 使用Ubuntu最新LTS版本作为基础镜像
FROM debian:trixie

# 避免交互式安装提示
ENV DEBIAN_FRONTEND=noninteractive

# 设置环境变量
ENV TIMEOUT=180
ENV PORT=8080
ENV WORKDIR=/app

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
    jq tree tmux less file \
    # 清理缓存
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 安装Python依赖
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# 创建工作目录
WORKDIR ${WORKDIR}

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