# SecFlow IPC Audit Service

独立的 OpenHarmony IPC 审计微服务骨架，目录位于 `image_build/secflow-app-ipc-audit`。

## Container Base

当前 `Dockerfile` 使用的基础镜像是：

- 运行时基础：`python:3.11-slim-bookworm`
- Node 运行时来源：`node:22-bookworm-slim` 多阶段拷贝

这不是 Ubuntu 24.04，而是 Debian 12 Bookworm 的 slim 变体。

如果你后面明确要求统一到 Ubuntu 24.04，可以再单独改基础镜像；当前这个版本优先追求镜像体积和 Python 运行时稳定性。

当前构建默认会把以下依赖源切到华为云镜像：

- `apt` -> `repo.huaweicloud.com/repository/debian`
- `pip` -> `repo.huaweicloud.com/repository/pypi/simple`
- `npm` -> `repo.huaweicloud.com/repository/npm/`

如果后面需要切回内网源或其他镜像，可以在 `docker build` 时通过 `--build-arg` 覆盖。

## Built-in CLIs

当前容器镜像会内置：

- `codex`
- `opencode`
- `git`
- `ripgrep`
- `bash`

当前镜像还额外显式安装了运行 OpenHarmony 工作区内 `hdc` 所需的基础动态库：

- `libatomic1`
- `libstdc++6`
- `libgcc-s1`

`Dockerfile` 当前不再固定版本，构建时会直接从 npm 安装当时最新的：

- `@openai/codex`
- `opencode-ai`

## Current `hdc` Compatibility

第一轮不把 `hdc` 放进 `secflow-app-ipc-audit` 仓库和镜像，避免二进制文件增大仓库体积。容器运行时固定从挂载的 OpenHarmony 工作区里使用 `hdc`：

- `/workspace/openharmony_6_1/vendor/edu/docker/src/hdc`

对应宿主路径由 `OH_WORKSPACE_HOST_PATH` 挂载到 `/workspace/openharmony_6_1`，例如：

- `/home/icsl/openharmony_6_1/vendor/edu/docker/src/hdc`

这个 `hdc` 的常见动态依赖是：

- `libatomic.so.1`
- `libstdc++.so.6`
- `libgcc_s.so.1`
- `libc.so.6`
- `libm.so.6`
- 同目录下的 `libusb_shared.so`

其中 `hdc` 自身带了：

- `RPATH=$ORIGIN/.`

这意味着只要 OpenHarmony 工作区内 `vendor/edu/docker/src/` 同时包含 `hdc` 和 `libusb_shared.so`，容器里通过该挂载路径调用 `hdc` 时就能找到同目录的 `.so`。

所以结论是：

- 当前这个 `hdc` 不适合直接“只复制单个可执行文件”
- 第一轮不复制 `hdc` 和 `libusb_shared.so` 到镜像
- 容器里只显式装上 `libatomic1`、`libstdc++6`、`libgcc-s1`
- `HDC_BIN` 固定为 `/workspace/openharmony_6_1/vendor/edu/docker/src/hdc`
- `LD_LIBRARY_PATH` 固定为 `/workspace/openharmony_6_1/vendor/edu/docker/src`

如果后续 OpenHarmony 挂载路径或工具链布局变化，再把 `HDC_BIN` / `LD_LIBRARY_PATH` 改成平台配置项，不在第一轮引入仓库内二进制副本。

## Deployment Modes

当前目录下有两套不同用途的模板：

- `docker-compose.yml`
  - 仅用于本地开发 / 手工联调
  - 继续使用宿主机 bind mount：
    - `/root/.codex`
    - `/root/.config/opencode`
    - `/root/.local/share/opencode`
- `docker-compose.platform.yml`
  - 用于平台模板部署
  - 不再依赖宿主机 bind mount 上述三个目录
  - 通过 ConfigCenter 维护 provider，再由 platform-agent 在部署时把 `env_bindings` / `file_bindings` 注入到容器

第一轮只做 deployment-time 注入：

- 不新增 `opencode_cli` 执行器
- 不把 `ipc-audit` 改造成 AI helper 服务
- 不扩展 `file_bindings` 去支持目录树
- `opencode` 仍然只是容器内置调试工具，当前真实执行链路还是 `codex_cli`

当前版本已经具备：

- `sqlite` 初始化和 schema migration
- `health` / `ready` / `capabilities`
- workspace 浏览与输入校验
- preset catalog 后台刷新与缓存
- task / attempt / event / artifact 基础 API
- 单进程内嵌 scheduler
- `max_parallel_tasks` / `IPC_AUDIT_MAX_PARALLEL_TASKS` 控制 attempt 并发度，默认 1，部署时可调
- 两阶段 `audit` / `poc` 执行流水线
- `mock` / `codex_cli` 双执行模式
- `runtime manifest` 与 `session_file(prompt)` 归档

当前执行器状态：

- `mock` 模式会产出可供前端联调的日志、报告、JSON 产物
- `codex_cli` 模式已经具备真正的命令编排能力，会按阶段生成 prompt、拉起 `codex exec`、收集日志并回填产物
- `codex_cli` 模式会使用 `codex exec --add-dir <attempt_root>`，让模型直接把阶段输出写到 attempt 私有目录，而不是污染源码树
- `codex_cli` 模式会额外归档 `prompt.txt`、`events.jsonl`、`last-message.md` 这类 session 文件，方便前端查看 agent 输出
- 服务会把 `events.jsonl` 和 `last-message.md` 摘要回填到 `/tasks/{task_id}/events`，前端无需先下载原始 session 文件也能看到 agent 输出概览
- 真实 prompt 目前已经贴近 `ipc_audit_pipeline_runner.py`，但仍可继续按你本地工作流细化
- 如果某个 workspace 配置了 `allow_custom_project_path=false`，服务端会拒绝 `custom_project` 类型任务

## Run Local

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml
python3 -m app.main
```

或者直接用环境变量：

```bash
IPC_AUDIT_DATABASE_URL=sqlite:////tmp/ipc-audit.db \
IPC_AUDIT_STATE_ROOT=/tmp/secflow-ipc-audit-state \
IPC_AUDIT_EXECUTION_MODE=mock \
IPC_AUDIT_MAX_PARALLEL_TASKS=1 \
IPC_AUDIT_WORKSPACES_JSON='[{"workspace_id":"oh61-main","display_name":"OpenHarmony 6.1 Main Tree","repo_root":"/workspace/openharmony_6_1","entries_file":".audit/ipc_entries.txt","bundle_scan_roots":["base","foundation"],"allow_custom_project_path":true,"supports_poc":true,"default_pipeline_mode":"audit_then_poc","is_default":true}]' \
python3 -m app.main
```

如果要接真实 `codex`：

```bash
IPC_AUDIT_EXECUTION_MODE=codex_cli \
IPC_AUDIT_CODEX_BIN=codex \
IPC_AUDIT_AUDIT_SANDBOX_MODE=workspace-write \
IPC_AUDIT_POC_SANDBOX_MODE=workspace-write \
python3 -m app.main
```

## Build Image

在 `image_build/secflow-app-ipc-audit` 目录下：

```bash
docker build -t secflow-app-ipc-audit:local .
```

如需覆盖默认镜像源，可以额外传：

```bash
docker build \
  --build-arg DEBIAN_MIRROR=https://your.mirror/debian \
  --build-arg DEBIAN_SECURITY_MIRROR=https://your.mirror/debian-security \
  --build-arg PIP_INDEX_URL=https://your.mirror/pypi/simple \
  --build-arg PIP_TRUSTED_HOST=your.mirror \
  --build-arg NPM_REGISTRY_URL=https://your.mirror/npm/ \
  -t secflow-app-ipc-audit:local .
```

如果要检查镜像里是否真的装好了：

```bash
docker run --rm secflow-app-ipc-audit:local codex --version
docker run --rm secflow-app-ipc-audit:local opencode --version
```

如果要顺便检查容器里 `hdc` 的基础运行条件：

```bash
docker run --rm \
  -v /absolute/path/to/openharmony_6_1:/workspace/openharmony_6_1:ro \
  secflow-app-ipc-audit:local \
  sh -lc 'ldd /workspace/openharmony_6_1/vendor/edu/docker/src/hdc && /workspace/openharmony_6_1/vendor/edu/docker/src/hdc -v'
```

## Run With `docker run`

默认建议先跑 `mock` 模式，先把 API、任务流和产物归档链路联调通：

```bash
docker run --rm -d \
  --name secflow-app-ipc-audit \
  -p 8080:8080 \
  -e IPC_AUDIT_EXECUTION_MODE=mock \
  -e IPC_AUDIT_MAX_PARALLEL_TASKS=1 \
  -e IPC_AUDIT_CODEX_BIN=/usr/local/bin/codex \
  -e HDC_BIN=/workspace/openharmony_6_1/vendor/edu/docker/src/hdc \
  -e LD_LIBRARY_PATH=/workspace/openharmony_6_1/vendor/edu/docker/src \
  -e IPC_AUDIT_POC_ENABLED=true \
  -e IPC_AUDIT_POC_RUNTIME_AVAILABLE=true \
  -e IPC_AUDIT_DEFAULT_WORKSPACE_ID=oh61-main \
  -e IPC_AUDIT_WORKSPACES_JSON='[{"workspace_id":"oh61-main","display_name":"OpenHarmony 6.1 Main Tree","repo_root":"/workspace/openharmony_6_1","entries_file":".audit/ipc_entries.txt","bundle_scan_roots":["base","foundation"],"allow_custom_project_path":true,"supports_poc":true,"default_pipeline_mode":"audit_then_poc","is_default":true}]' \
  -v "$(pwd)/state:/var/lib/secflow-ipc-audit" \
  -v /absolute/path/to/your/.codex:/root/.codex \
  -v /absolute/path/to/your/opencode.json:/root/.config/opencode/opencode.json \
  -v /absolute/path/to/your/opencode-data:/root/.local/share/opencode \
  -v /absolute/path/to/openharmony_6_1:/workspace/openharmony_6_1:ro \
  secflow-app-ipc-audit:local
```

如果你只是联调后端 API，不需要真实 `codex` / `opencode` 认证，也可以不挂上面三项。

启动后可以检查：

```bash
curl http://127.0.0.1:8080/api/app/ipc-audit/health
curl http://127.0.0.1:8080/api/app/ipc-audit/ready
```

## Run With Docker Compose

这个文件指的是本地开发用的 [docker-compose.yml](./docker-compose.yml)。

它现在不再把整个 `.codex` / `.config/opencode` / `.local/share/opencode` 目录直接 bind mount 进容器，而是直接在本地模拟最终的 `env_bindings` / `file_bindings` 效果：

- 通过 `environment` 注入运行时 env
- 通过单文件 bind mount 注入：
  - `/root/.codex/auth.json`
  - `/root/.codex/config.toml`
  - `/root/.config/opencode/opencode.json`

目录里已经补了：

- `docker-compose.yml`
- `.env.example`
- `provider-files/codex-auth.json.example`
- `provider-files/config.toml.example`
- `provider-files/opencode.json.example`

使用方式：

```bash
cp .env.example .env
```

然后至少修改：

- `OH_WORKSPACE_HOST_PATH=/absolute/path/to/openharmony_6_1`
- `OPENAI_API_KEY=...`

如果你要换成本地真实文件，而不是仓库内示例文件，再改：

- `CODEX_AUTH_FILE=/absolute/path/to/your/auth.json`
- `CODEX_CONFIG_TOML_FILE=/absolute/path/to/your/config.toml`
- `OPENCODE_CONFIG_FILE=/absolute/path/to/your/opencode.json`

如果你不想让 `/ready` 检查这些注入文件，可以把：

- `IPC_AUDIT_READY_CHECK_FILE_PATHS=`

再启动：

```bash
docker compose up --build -d
```

查看状态：

```bash
docker compose ps
docker compose logs -f secflow-app-ipc-audit
curl http://127.0.0.1:8080/api/app/ipc-audit/ready
```

停止：

```bash
docker compose down
```

## Platform Template Deployment

平台模板请使用 [docker-compose.platform.yml](./docker-compose.platform.yml)，不要再把下面这些宿主机路径作为部署参数传进去：

- `CODEX_CONFIG_HOST_PATH`
- `OPENCODE_CONFIG_HOST_PATH`
- `OPENCODE_DATA_HOST_PATH`

如果你要在平台外先本地校验这一版模板，可以配合：

- [docker-compose.platform.yml](./docker-compose.platform.yml)
- [.env.platform.example](./.env.platform.example)

平台部署时，改为通过 `/api/agent/task/deploy` 的 `extra_params.llm_provider_binding` 传 provider key：

```json
{
  "project_id": "your-project",
  "agent_key": "your-agent",
  "service_name": "secflow-app-ipc-audit",
  "template_name": "secflow-app-ipc-audit",
  "extra_params": {
    "llm_provider_binding": {
      "provider_keys": ["ipc-audit-codex-prod", "ipc-audit-opencode-prod"],
      "target_services": ["secflow-app-ipc-audit"]
    }
  }
}
```

当前平台侧已经具备：

- `ConfigCenter -> env_bindings / file_bindings -> platform-agent -> 模板部署注入`
- `POST /api/agent/templates/llm-providers/preview`
- 多个 `provider_keys` 按顺序合并，后面的 env key 和 file path 会覆盖前面的

这一轮 `ipc-audit` 不自己实现 provider resolve；平台已有的 `resolved_llm_provider_binding` 会在部署时完成解析并改写模板。

Provider 里真正会自动注入到容器的，只有：

- `env_bindings`
- `file_bindings`

`provider_type`、`api_base`、`model`、`api_key` 这些仍然是 ConfigCenter schema 字段，但不会自动变成容器运行时文件或环境变量，除非你显式写进 `env_bindings` / `file_bindings`。

一个最小示例：

```json
{
  "provider_key": "ipc-audit-codex-prod",
  "display_name": "IPC Audit Codex Prod",
  "provider_type": "codex",
  "api_base": "https://api.openai.com/v1",
  "model": "gpt-5-codex",
  "api_key": "schema-required-placeholder",
  "env_bindings": {
    "OPENAI_API_KEY": "sk-xxx",
    "OPENAI_BASE_URL": "https://api.openai.com/v1"
  },
  "file_bindings": [
    {
      "name": "codex-auth.json",
      "path": "/root/.codex/auth.json",
      "content": "{...}",
      "format": "json",
      "enabled": true
    },
    {
      "name": "codex-config.toml",
      "path": "/root/.codex/config.toml",
      "content": "model = \"gpt-5-codex\"",
      "format": "text",
      "enabled": true
    },
    {
      "name": "opencode.json",
      "path": "/root/.config/opencode/opencode.json",
      "content": "{...}",
      "format": "json",
      "enabled": true
    }
  ]
}
```

注意几点：

- 不要把 `IPC_AUDIT_EXECUTION_MODE`、`IPC_AUDIT_STATE_ROOT`、`IPC_AUDIT_WORKSPACES_JSON` 这类服务自身配置塞进 provider
- 对你当前这套本地环境，`codex` 至少要补进：
  - `/root/.codex/auth.json`
  - `/root/.codex/config.toml`
- 其他额外文件是否需要，再按真实环境继续收敛
- 第一轮不迁 `OPENCODE_DATA_HOST_PATH -> /root/.local/share/opencode`
- `docker-compose.platform.yml` 仍然只保留基础卷；当前是 `state` 和 `workspace`

验收时可以重点看：

- `POST /api/agent/templates/llm-providers/preview` 返回的 `mapped_env_keys` / `mapped_file_paths`
- 部署任务日志里的：
  - `注入LLM Provider`
  - `注入环境变量键`
  - `注入配置文件路径`
- 容器内的：
  - `/root/.codex/*`
  - `/root/.config/opencode/opencode.json`

如果你希望 `GET /api/app/ipc-audit/ready` 也顺便校验这些注入文件，可以在服务模板里额外设置：

```text
IPC_AUDIT_READY_CHECK_FILE_PATHS=/root/.codex/auth.json,/root/.codex/config.toml,/root/.config/opencode/opencode.json
```

这个检查是可选的；只有显式配置后才会纳入 readiness。

## Compose / Container Defaults

当前容器和 compose 默认约定：

- 服务监听 `8080`
- sqlite 数据库文件在 `/var/lib/secflow-ipc-audit/ipc-audit.db`
- state/artifact 根目录在 `/var/lib/secflow-ipc-audit`
- OpenHarmony 工作区挂载到 `/workspace/openharmony_6_1`
- `codex` 路径固定为 `/usr/local/bin/codex`
- `opencode` 路径固定为 `/usr/local/bin/opencode`
- `hdc` 路径固定为 `/workspace/openharmony_6_1/vendor/edu/docker/src/hdc`
- `hdc` 依赖的 `libusb_shared.so` 来自同一个挂载目录
- `docker-compose.yml` 默认把源码工作区按只读方式挂进去，避免污染源码树
- `docker-compose.yml` 默认直接模拟 `env_bindings` / `file_bindings` 的最终效果
- `docker-compose.yml` 默认按单文件方式挂载 `codex` / `opencode` 配置
- `docker-compose.platform.yml` 不再挂载 `codex` / `opencode` 宿主目录，而是等平台在部署时注入 env/file bindings
- `docker-compose.yml` 默认还注入了 `host.docker.internal:host-gateway`

如果你确认某个真实执行链路必须改源码树，再把 compose 里的：

- `read_only: true`

改成：

- `read_only: false`

## About `codex_cli` In Container

当前镜像已经支持：

- `mock`
- `codex_cli`

但要注意，当前服务代码真正接入执行流水线的是 `codex_cli`。`opencode` 现在只是装进了容器，方便你后续在容器内手工调试或扩展后端执行器，并没有替代现有 `codex_cli` 路径。

`hdc` 也是类似状态：

- 镜像不内置 `hdc` 和 `libusb_shared.so`
- 容器通过挂载的 OpenHarmony 工作区固定路径调用 `hdc`
- 但后端 Python 服务当前还没有直接调用 `hdc`
- 目前仍然是给 `codex` / skill 在容器内自行调用 `hdc` 做准备

原因是 `codex_cli` 模式除了 Python 服务本身，还依赖容器内存在：

- `codex` 可执行文件
- 挂载的 OpenHarmony 工作区内 `hdc` 运行时文件（如果 PoC 链路需要）
- 对应技能、配置与运行时环境
- 如果要跑真实 PoC，还可能需要额外设备 / OHEMU / `hdc` / 相关工具链

也就是说，当前容器化已经满足：

- 本地单容器测试 API、scheduler、sqlite、artifact 归档
- 前端联调和任务流联调
- 容器内直接使用 `codex` / `opencode`
- 容器内通过挂载的 OpenHarmony 工作区调用 `hdc`

但还没有把“真实 PoC 运行环境”一起完全烘焙进镜像。

## K8s

[k8s-deployment.yaml](./k8s-deployment.yaml) 当前保持“配置中立”：

- 不手工写死 Codex / OpenCode secret
- 可以直接作为原生 K8s manifest 的基础版本

第一轮如果你要走平台模板部署，优先使用 [docker-compose.platform.yml](./docker-compose.platform.yml) 这一条链路，让 platform-agent 复用现有的 LLM Provider 注入能力；不要再单独实现一套自定义 K8s 注入器。

还要额外注意一个网络点：

- 如果容器里执行 `hdc tconn 127.0.0.1:5555`，这里的 `127.0.0.1` 指向的是容器自己，不是宿主
- 在 bridge 网络下，更适合改成 `hdc tconn host.docker.internal:5555`
- 如果你坚持复用 `127.0.0.1:5555` 这种写法，就要把容器改成 `--network host`

如果你下一步要把真实执行也封进容器，建议继续拆两层：

1. 保留当前 `Dockerfile` 作为基础 API 镜像
2. 再做一个面向真实执行的派生镜像，把 `codex` 和所需运行时工具一起装进去

## Key Endpoints

- `GET /api/app/ipc-audit/health`
- `GET /api/app/ipc-audit/ready`
- `GET /api/app/ipc-audit/capabilities`
- `GET /api/app/ipc-audit/workspaces`
- `POST /api/app/ipc-audit/inputs/validate`
- `POST /api/app/ipc-audit/workspaces/{workspace_id}/preset-projects:refresh`
- `POST /api/app/ipc-audit/tasks`
- `GET /api/app/ipc-audit/tasks`
- `GET /api/app/ipc-audit/tasks/{task_id}`

## Tests

```bash
python3 -m unittest discover -s tests
```

## Next Step

下一步更值得做的是继续把你本地 `ipc_audit_pipeline_runner.py` 的提示词和阶段后处理策略迁进来，包括：

- 更细的 audit / poc prompt 模板
- 真实 agent session 文件采集
- 取消任务时对子进程的进一步回收和清理
- 更完整的 API 集成测试与真实执行镜像封装
