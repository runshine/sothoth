# 远程调试工具容器

一个功能强大的远程调试和服务容器，集成了 Web API、Web 终端和 VS Code Web IDE。

## 功能特性

### 核心服务

1. **Web API 服务** (端口 20001)
   - 提供远程命令执行 REST API
   - 支持超时控制和进程管理
   - 安全命令过滤机制

2. **ttyd Web 终端** (端口 20002)
   - 基于浏览器的终端访问
   - 完整的 bash shell 环境
   - 实时交互体验

3. **code-server VS Code Web IDE** (端口 20003)
   - 完整的 VS Code 编辑器体验
   - 支持插件扩展
   - 直接在浏览器中编辑代码

### 调试环境

- **编译工具链**: gcc, g++, clang, llvm, make, cmake
- **调试工具**: gdb, lldb, strace
- **系统工具**: procps, htop, net-tools, iproute2
- **开发环境**: Python3, Node.js 24, Git
- **其他工具**: vim, nano, jq, tree, tmux

### 安全与权限

- **特权容器**: 具有系统级访问权限
- **主机目录访问**: 主机根目录只读挂载到 `/host`
- **命名空间共享**: 与主机共享 PID、网络、IPC 命名空间
- **超时控制**: 默认 180 秒超时（可配置）
- **安全控制**: 危险命令黑名单过滤

## 快速开始

### 使用 GitHub Actions 自动构建的镜像

```bash
# 拉取最新镜像
docker pull ghcr.io/runshine/secflow-agent-service-agent-helper:latest

# 或使用日期标签（更稳定）
docker pull ghcr.io/runshine/secflow-agent-service-agent-helper:20260317

# 启动服务
docker-compose up -d
```

### 本地构建

```bash
# 构建镜像
docker-compose build

# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f
```

## 环境变量配置

### 基础配置

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `TIMEOUT` | 180 | 命令执行超时时间（秒） |
| `REST_PORT` | 20001 | API 服务端口 |
| `WORKDIR` | /app | 容器工作目录 |

### code-server 配置

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `CODE_SERVER_PORT` | 20003 | code-server 服务端口 |
| `CODE_SERVER_PASSWORD` | 自动生成 | code-server 访问密码（建议设置） |

### Claude API 配置

| 变量名 | 说明 |
|--------|------|
| `ANTHROPIC_BASE_URL` | Anthropic API 基础 URL |
| `ANTHROPIC_AUTH_TOKEN` | Anthropic API 认证令牌 |
| `API_TIMEOUT_MS` | API 超时时间（毫秒） |

## 端口映射

| 端口 | 服务 | 用途 |
|------|------|------|
| 20001 | Flask API | 远程命令执行 API |
| 20002 | ttyd | Web 终端 |
| 20003 | code-server | VS Code Web IDE |

## 卷挂载

| 主机路径 | 容器路径 | 模式 | 说明 |
|---------|---------|------|------|
| `/` | `/host` | ro | 主机根目录只读访问 |
| `/proc` | `/proc` | rw | 进程信息 |
| `/sys` | `/sys` | rw | 系统信息 |
| `/dev` | `/dev` | rw | 设备文件 |
| `/tmp` | `/tmp` | rw | 临时目录 |

## 使用方法

### 1. 访问 Web API

```bash
# 健康检查
curl http://localhost:20001/health

# 执行命令
curl -X POST http://localhost:20001/api/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "ls -la /host"}'

# 获取系统信息
curl http://localhost:20001/api/system/info

# 查看可用调试工具
curl http://localhost:20001/api/debug/tools
```

### 2. 访问 ttyd Web 终端

打开浏览器访问：
```
http://localhost:20002
```

### 3. 访问 code-server

打开浏览器访问：
```
http://localhost:20003
```

**首次访问密码获取：**

方式一：查看容器日志
```bash
docker logs remote-command-api | grep "code-server password"
```

方式二：设置固定密码（推荐）

在 `docker-compose.yml` 中设置：
```yaml
environment:
  - CODE_SERVER_PASSWORD=your-secure-password
```

## GitHub Actions 自动构建

本项目使用 GitHub Actions 自动构建和推送镜像。

### 构建触发条件

- 推送到 `v2.*` 分支
- 修改 `100-agent-service-image/01-secflow-agent-service-agent-helper/` 目录下的文件
- 修改 `.github/workflows/build-secflow-agent-service-agent-helper-image.yaml`

### 镜像标签策略

每次构建生成两个标签：
- `latest`: 最新版本
- `YYYYMMDD`: 日期标签（如 20260317）

### 支持的架构

- `linux/amd64` (x86_64)
- `linux/arm64` (aarch64)

### 镜像仓库

- GitHub Container Registry: `ghcr.io/runshine/secflow-agent-service-agent-helper`
- Docker Hub: `runshine0819/secflow-agent-service-agent-helper`

## 安全注意事项

⚠️ **警告**: 此容器具有特权模式，拥有系统级访问权限。

### 最佳实践

1. **网络隔离**: 不要将服务直接暴露在公网
2. **密码保护**: 为 code-server 设置强密码
3. **命令过滤**: 在生产环境中配置 `ALLOWED_COMMANDS` 白名单
4. **资源限制**: 使用 docker-compose 中的资源限制
5. **日志审计**: 定期检查容器日志

### 危险命令黑名单

以下命令会被自动拦截：
- `rm -rf /`

可在 `app.py` 中添加更多危险命令。

## 故障排查

### 容器无法启动

```bash
# 查看日志
docker-compose logs

# 检查端口占用
netstat -tunlp | grep -E '20001|20002|20003'
```

### code-server 无法访问

```bash
# 检查服务状态
docker exec -it remote-command-api ps aux | grep code-server

# 查看详细日志
docker exec -it remote-command-api cat /tmp/code-server.log
```

### 命令执行超时

调整 `TIMEOUT` 环境变量：
```yaml
environment:
  - TIMEOUT=300  # 增加到 300 秒
```

## 开发与定制

### 修改 Dockerfile

```bash
# 修改 Dockerfile 后重新构建
docker-compose build --no-cache

# 重启服务
docker-compose down && docker-compose up -d
```

### 添加新工具

编辑 `Dockerfile`，在 `apt-get install` 部分添加工具：
```dockerfile
RUN apt-get update && apt-get install -y \
    your-new-tool \
    ...
```

### 扩展 API

编辑 `app.py` 添加新的 API 端点。

## 许可证

本项目采用 MIT 许可证。

## 贡献

欢迎提交 Issue 和 Pull Request！
