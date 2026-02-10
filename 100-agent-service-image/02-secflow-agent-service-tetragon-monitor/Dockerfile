# 构建阶段
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS builder

ARG TARGETARCH
ARG TARGETVARIANT
ARG TARGETPLATFORM

WORKDIR /app

# 设置环境变量用于构建
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux

# 根据目标架构设置GOARCH和GOARM
RUN case ${TARGETARCH} in \
        arm) \
            case ${TARGETVARIANT} in \
                5) export GOARCH=arm GOARM=5 ;; \
                6) export GOARCH=arm GOARM=6 ;; \
                7) export GOARCH=arm GOARM=7 ;; \
                *) export GOARCH=arm GOARM=6 ;; \
            esac ;; \
        arm64) export GOARCH=arm64 ;; \
        amd64) export GOARCH=amd64 ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}" && exit 1 ;; \
    esac

RUN apk add --no-cache git

# 复制go模块文件
COPY go.mod go.sum ./

# 复制源代码
COPY main.go .

RUN go mod tidy

RUN go mod download

# 构建应用
RUN go build -a -installsuffix cgo -ldflags="-w -s" -o tetragon-monitor .

# 运行阶段 - 使用多架构基础镜像
FROM --platform=$TARGETPLATFORM alpine:3.17

# 添加必要的工具
RUN apk add --no-cache \
    tzdata \
    ca-certificates \
    iproute2 \
    wget \
    curl \
    && update-ca-certificates

# 创建工作目录
WORKDIR /app

# 复制可执行文件
COPY --from=builder /app/tetragon-monitor .

# 设置时区为上海
ENV TZ=Asia/Shanghai

# 创建必要的目录
RUN mkdir -p /sothothv2/config

# 设置默认环境变量
ENV TETRAGON_SOCK=/var/run/tetragon/tetragon.sock \
    ES_ENDPOINT=http://elasticsearch:9200 \
    ES_INDEX_PREFIX=tetragon-events \
    GIN_MODE=release

# 暴露API端口
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# 启动命令
CMD ["./tetragon-monitor"]