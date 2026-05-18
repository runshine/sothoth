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
- `qemu-system-aarch64` / `qemu-system-x86_64`
- `qemu-img`
- `ipc-audit-qemu` 容器内 QEMU helper

当前镜像还额外显式安装了运行 OpenHarmony 工作区内 `hdc` 所需的基础动态库：

- `libatomic1`
- `libstdc++6`
- `libgcc-s1`
- `libusb-1.0-0`
- `iproute2`
- `bridge-utils`
- `dnsmasq`
- `procps`
- `socat`

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

## Current OHEMU / QEMU PoC Runtime

PoC 阶段现在按“当前 `secflow-app-ipc-audit` 容器内直接启动 QEMU”的方式约束，不再让 agent 使用旧的 `ohemu-container.sh` 额外创建 OHEMU Docker 容器。

镜像内置 helper：

- `/usr/local/bin/ipc-audit-qemu`

这个 helper 会复用挂载的 OpenHarmony 工作区脚本：

- `/workspace/openharmony_6_1/vendor/edu/docker/src/init.sh`
- `/workspace/openharmony_6_1/vendor/edu/docker/src/network.sh`
- `/workspace/openharmony_6_1/vendor/edu/docker/src/qemu_common.sh`

默认固定路径和参数：

- `OHEMU_WORKSPACE_ROOT=/workspace/openharmony_6_1`
- `OHEMU_QCOW2_PREPARED_ROOT=/workspace/openharmony_6_1/vendor/edu/docker/volumes/qcow2_cache`
- `OHEMU_RUNTIME_ROOT=/var/lib/secflow-ipc-audit/ohemu`
- `OHEMU_ARCH=arm64`
- `OHEMU_NETWORK_MODE=bridge`
- `OHEMU_HDC_BIND=127.0.0.1`
- `OHEMU_HDC_BASE_PORT=55555`
- `OHEMU_WAIT_FOR_HDC_READY=1`
- `OHEMU_HDC_READY_TIMEOUT=180`

磁盘安全约束：

- QEMU 只能运行在每个实例自己的 overlay qcow2 上
- prepared base qcow2 只作为 backing file，不允许直接写
- OpenHarmony `out/*/packages/phone/images/*.img` 只作为 boot/raw 来源，不允许直接作为可写运行盘
- 实例 overlay 默认写到 `/var/lib/secflow-ipc-audit/ohemu/runtime/instances/<instance>/*.qcow2`
- 如果 overlay 创建失败，PoC runtime 应标记为 `BLOCKED_ENV`，不能退化成直接跑共享 qcow2/raw image

常用命令：

```bash
ipc-audit-qemu list
ipc-audit-qemu ensure ipc-audit-poc
/workspace/openharmony_6_1/vendor/edu/docker/src/hdc tconn 127.0.0.1:<HDC_PORT_FROM_LIST>
/workspace/openharmony_6_1/vendor/edu/docker/src/hdc list targets
```

注意：

- `ipc-audit-qemu` 不调用 `ohemu-container.sh`
- `ipc-audit-qemu` 不调用 `docker run` / `docker exec` / `docker compose`
- 默认使用 QEMU bridge/tap 网络，guest 通常获得 `192.168.111.x` 地址，helper 会用 `socat` 把 `127.0.0.1:<HDC_PORT>` 转发到 `<GUEST_IP>:55555`
- `55555` 是 helper 默认分配的容器内 HDC 转发起始端口，不要把 guest 侧 `5555` 当作连接端口
- `ipc-audit-qemu ensure/start` 默认会继续轮询 `hdc tconn` 和 `hdc list targets -v`，直到 helper 分配的 HDC endpoint 真正 `Connected`，避免把 QEMU `hostfwd` 已监听误判为 hdcd 已就绪
- `usermode` 下 guest 通常会拿到 `20.20.20.21`，QEMU 会立即监听 `127.0.0.1:<HDC_PORT>`，但 hdcd 可能要在 boot 后约一分钟才可握手；自动化脚本必须等 HDC ready
- 非 privileged 容器中 `hdc` server 可能因 `libusb_init failed ctxUSB is nullptr` 退出；即使使用 QEMU usermode 网络，也不要把 PoC runtime 降级成普通非 privileged 容器
- QEMU runtime、state、log 写入 `/var/lib/secflow-ipc-audit/ohemu`
- 默认要求 OpenHarmony 工作区里已经有 prepared qcow2 cache 和 boot 文件
- `ipc-audit-qemu ensure/start` 会检查 prepared base qcow2 是否存在，并调用 OpenHarmony `qemu_common.sh` 创建 per-instance overlay

如果缺少 qcow2 cache，可以先在 OpenHarmony 工作区侧准备：

```bash
cd /home/icsl/openharmony_6_1/vendor/edu/docker
QEMU_ARCH=arm64 ./ohemu-container.sh prepare
```

这一条准备命令仍然是宿主机/工作区维护动作，不是 PoC agent 在 `secflow-app-ipc-audit` 容器内要执行的动作。PoC agent 如果发现 helper、QEMU、挂载工作区、qcow2 cache、boot image 或 `hdc` 不可用，应在报告里把 runtime 验证标为 `BLOCKED_ENV` 并记录具体失败命令。

## Deployment Modes

当前目录下有两套不同用途的模板：

- `docker-compose.yml`
  - 仅用于本地开发 / 手工联调
  - 继续使用宿主机 bind mount：
    - `/root/.codex`
    - `/root/.config/opencode`
    - `/root/.local/share/opencode`
    - `/home/icsl/agentflow-alpha`
- `docker-compose.platform.yml`
  - 用于平台模板部署
  - 不再依赖宿主机 bind mount 上述三个目录
  - 通过 ConfigCenter 维护 provider，再由 platform-agent 在部署时把 `env_bindings` / `file_bindings` 注入到容器

当前默认真实执行链路已经切到 `agentflow_cli`：

- 服务端仍然自己生成阶段 prompt 和输出路径约束
- 真实执行时不再直接 `subprocess` 拉 `codex exec`
- 改为生成按阶段编排的临时 AgentFlow pipeline，然后通过挂载的 `/home/icsl/agentflow-alpha` 驱动节点执行
- `audit_then_poc` 会在一次 AgentFlow run 里执行 `audit -> poc` 两个 stage node，后续扩阶段只需要继续加 node / dependency
- 默认 stage node agent 已切到 `opencode`，后续如果要做多 agent 实验，也是在这个 stage pipeline 框架上扩展

当前版本已经具备：

- `sqlite` 初始化和 schema migration
- `mysql` 初始化和 schema migration
- `health` / `ready` / `capabilities`
- workspace 浏览与输入校验
- preset catalog 后台刷新与缓存
- task / attempt / event / artifact 基础 API
- 单进程内嵌 scheduler
- `max_parallel_tasks` / `IPC_AUDIT_MAX_PARALLEL_TASKS` 控制 attempt 并发度，默认 1，部署时可调
- 两阶段 `audit` / `poc` 执行流水线
- `mock` / `agentflow_cli` / `codex_cli` / `opencode_cli` 执行模式
- `runtime manifest` 与 `session_file(prompt)` 归档

当前执行器状态：

- `mock` 模式会产出可供前端联调的日志、报告、JSON 产物
- `agentflow_cli` 模式会生成 stage pipeline，并通过 `agentflow.cli run` 驱动实际 agent
- `audit_only` / `poc_only` 对应单节点 pipeline，`audit_then_poc` 对应 `audit -> poc` 双节点 pipeline
- 默认 `agentflow_cli` stage node agent 为 `opencode`，并按节点透传 provider runtime；当节点显式指定 `agent: codex` 时仍会继续透传 `--add-dir <attempt_root>` 与 sandbox 配置
- `agentflow_cli` 模式会把 AgentFlow 的 trace / result 回填成同样的 `prompt.txt`、`events.jsonl`、`last-message.md` session 文件，前端链路不需要改
- `audit_then_poc` 的 `poc` 阶段不会再次重复拉起 AgentFlow，而是直接复用同一条 stage pipeline 里 `poc` node 的结果
- `codex_cli` / `opencode_cli` 仍保留，便于对照调试或回退
- 服务会把 `events.jsonl` 和 `last-message.md` 摘要回填到 `/tasks/{task_id}/events`，前端无需先下载原始 session 文件也能看到 agent 输出概览
- 真实 prompt 目前已经贴近 `ipc_audit_pipeline_runner.py`，但仍可继续按你本地工作流细化
- 如果某个 workspace 配置了 `allow_custom_project_path=false`，服务端会拒绝 `custom_project` 类型任务

## Custom Graph Task

现在 `agentflow_cli` 额外支持 `pipeline_mode=custom_graph`，用于把任务执行流完全交给请求体里的 AgentFlow graph：

- 输入侧继续沿用现有 `workspace_id + input_ref`
- 执行图通过 `graph_source` 提供
- 报告输出通过 `report_outputs[]` 显式声明
- attempt 详情接口会回填 `report_outputs[]`，前端可以直接按列表渲染，不需要再写死 `audit_report` / `poc_report`

当前支持两种 graph source：

- `inline_json`
  - 直接传 AgentFlow JSON 模板
  - JSON 字符串值支持 Jinja 占位符，例如 `{{ report_outputs.stage1_report.absolute_path }}`
- `python_builder`
  - 传 `entry` 或 `code`
  - 服务端会先写 `runtime/graph/graph-context.json`
  - 然后调用：
    - `python <builder> --context <graph-context.json> --output <pipeline.json>`

`report_outputs[]` 的 `path` 必须是 attempt root 下的相对路径，例如：

```json
[
  {
    "output_id": "stage1_report",
    "node_id": "stage1",
    "title": "阶段1报告",
    "path": "exports/stage1-report.md",
    "format": "markdown",
    "required": true,
    "order": 10
  },
  {
    "output_id": "stage2_report",
    "node_id": "stage2",
    "title": "阶段2报告",
    "path": "exports/stage2-report.md",
    "format": "markdown",
    "required": true,
    "order": 20
  }
]
```

一个最小 `custom_graph` 请求示例：

```json
{
  "title": "dynamic-graph-demo",
  "workspace_id": "oh61-main",
  "pipeline_mode": "custom_graph",
  "input_ref": {
    "kind": "custom_project",
    "project_path": "foundation/demo/service"
  },
  "executor_mode": "agentflow_cli",
  "graph_source": {
    "type": "inline_json",
    "content": {
      "name": "dynamic-inline-graph",
      "nodes": [
        {
          "id": "stage1",
          "prompt": "Write report to {{ report_outputs.stage1_report.absolute_path }}",
          "success_criteria": [
            {
              "kind": "file_nonempty",
              "path": "{{ report_outputs.stage1_report.absolute_path }}"
            }
          ]
        },
        {
          "id": "stage2",
          "depends_on": ["stage1"],
          "prompt": "Write report to {{ report_outputs.stage2_report.absolute_path }}",
          "success_criteria": [
            {
              "kind": "file_nonempty",
              "path": "{{ report_outputs.stage2_report.absolute_path }}"
            }
          ]
        }
      ]
    }
  },
  "report_outputs": [
    {
      "output_id": "stage1_report",
      "node_id": "stage1",
      "title": "阶段1报告",
      "path": "exports/stage1-report.md",
      "format": "markdown",
      "required": true,
      "order": 10
    },
    {
      "output_id": "stage2_report",
      "node_id": "stage2",
      "title": "阶段2报告",
      "path": "exports/stage2-report.md",
      "format": "markdown",
      "required": true,
      "order": 20
    }
  ]
}
```

任务执行完成后：

- 每个 node 的 prompt / events / last-message 仍然落到 `runtime/<node_id>/`
- 每个 node 的 log 落到 `logs/<node_id>.codex.log`
- 声明过的报告会以 `report_output` artifact 归档
- `/tasks/{task_id}/attempts/{attempt_id}` 返回的 `report_outputs[]` 会包含 `exists`、`preview_url`、`download_url`

## Template API

现在服务端额外支持把任务图模板持久化到数据库，适合保存一组固定的：

- `pipeline_mode`
- `executor_mode`
- `model`
- `provider_keys`
- `graph_source`
- `report_outputs`

当前接口：

- `GET /api/app/ipc-audit/templates?workspace_id=oh61-main`
- `GET /api/app/ipc-audit/templates/{template_id}`
- `POST /api/app/ipc-audit/templates`
- `PUT /api/app/ipc-audit/templates/{template_id}`
- `DELETE /api/app/ipc-audit/templates/{template_id}`

一个最小创建模板示例：

```json
{
  "workspace_id": "oh61-main",
  "name": "four-stage-ipc-audit",
  "description": "四阶段审计图模板",
  "config": {
    "pipeline_mode": "custom_graph",
    "executor_mode": "agentflow_cli",
    "model": "gpt-5-codex",
    "provider_keys": ["anthropic-prod"],
    "graph_source": {
      "type": "inline_json",
      "content": {
        "nodes": [
          {"id": "audit", "prompt": "write {{ report_outputs.audit_report.absolute_path }}"},
          {"id": "triage", "depends_on": ["audit"], "prompt": "write {{ report_outputs.triage_report.absolute_path }}"}
        ]
      }
    },
    "report_outputs": [
      {
        "output_id": "audit_report",
        "node_id": "audit",
        "title": "Audit Report",
        "path": "exports/audit-report.md",
        "format": "markdown",
        "required": true,
        "order": 10
      },
      {
        "output_id": "triage_report",
        "node_id": "triage",
        "title": "Triage Report",
        "path": "exports/triage-report.md",
        "format": "markdown",
        "required": true,
        "order": 20
      }
    ]
  }
}
```

前端现在会优先读取这组服务端模板，而不是只保存在浏览器本地。

## Run Local

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml
python3 -m app.main
```

默认示例配置仍然使用本地 `sqlite`，方便单机开发。

如果要切到 MySQL，可以在 `config.yaml` 里改成：

```yaml
database:
  type: mysql
  host: mysql.sothothv2-ns.svc.cluster.local
  port: 3306
  username: secflow
  password: Huawei12#$
  name: secflow
```

或者继续直接用环境变量 URL：

```bash
IPC_AUDIT_DATABASE_URL='mysql+pymysql://secflow:Huawei12%23%24@mysql.sothothv2-ns.svc.cluster.local:3306/secflow'
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

如果要接真实 AgentFlow 引擎：

```bash
IPC_AUDIT_EXECUTION_MODE=agentflow_cli \
IPC_AUDIT_AGENTFLOW_ROOT=/home/icsl/agentflow-alpha \
IPC_AUDIT_AGENTFLOW_PYTHON_BIN=python3 \
IPC_AUDIT_AGENTFLOW_AGENT=codex \
IPC_AUDIT_CODEX_BIN=codex \
IPC_AUDIT_AUDIT_SANDBOX_MODE=workspace-write \
IPC_AUDIT_POC_SANDBOX_MODE=workspace-write \
python3 -m app.main
```

## K8s Database

K8s 默认不再把任务元数据写到挂载的 NFS `sqlite` 文件里，而是改为：

- 元数据表：MySQL
- 任务产物、日志、runtime 文件：`state_root` 对应的 PVC / NFS

这样可以避免 `sqlite + NFS` 下的锁竞争和 `database is locked` / `worker lease expired` 连带问题。

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
  -p 18080:8080 \
  -e IPC_AUDIT_EXECUTION_MODE=mock \
  -e IPC_AUDIT_MAX_PARALLEL_TASKS=1 \
  -e IPC_AUDIT_CODEX_BIN=/usr/local/bin/codex \
  -e HDC_BIN=/workspace/openharmony_6_1/vendor/edu/docker/src/hdc \
  -e LD_LIBRARY_PATH=/workspace/openharmony_6_1/vendor/edu/docker/src \
  -e OHEMU_HELPER_BIN=/usr/local/bin/ipc-audit-qemu \
  -e OHEMU_WORKSPACE_ROOT=/workspace/openharmony_6_1 \
  -e OHEMU_QCOW2_PREPARED_ROOT=/workspace/openharmony_6_1/vendor/edu/docker/volumes/qcow2_cache \
  -e OHEMU_RUNTIME_ROOT=/var/lib/secflow-ipc-audit/ohemu \
  -e OHEMU_ARCH=arm64 \
  -e OHEMU_NETWORK_MODE=bridge \
  -e OHEMU_HDC_BIND=127.0.0.1 \
  -e OHEMU_HDC_BASE_PORT=55555 \
  -e IPC_AUDIT_POC_ENABLED=true \
  -e IPC_AUDIT_POC_RUNTIME_AVAILABLE=true \
  -e IPC_AUDIT_DEFAULT_WORKSPACE_ID=oh61-main \
  -e IPC_AUDIT_WORKSPACES_JSON='[{"workspace_id":"oh61-main","display_name":"OpenHarmony 6.1 Main Tree","repo_root":"/workspace/openharmony_6_1","entries_file":".audit/ipc_entries.txt","bundle_scan_roots":["base","foundation"],"allow_custom_project_path":true,"supports_poc":true,"default_pipeline_mode":"audit_then_poc","is_default":true}]' \
  --privileged \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
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
curl http://127.0.0.1:18080/api/app/ipc-audit/health
curl http://127.0.0.1:18080/api/app/ipc-audit/ready
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
curl http://127.0.0.1:18080/api/app/ipc-audit/ready
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
- QEMU helper 路径固定为 `/usr/local/bin/ipc-audit-qemu`
- PoC runtime 默认在当前容器内直接启动 QEMU，不再通过 `ohemu-container.sh` 额外启动 Docker 容器
- QEMU prepared qcow2 默认读取 `/workspace/openharmony_6_1/vendor/edu/docker/volumes/qcow2_cache`
- QEMU runtime/state/log 默认写入 `/var/lib/secflow-ipc-audit/ohemu`
- QEMU 实例盘默认写入 `/var/lib/secflow-ipc-audit/ohemu/runtime/instances/<instance>/*.qcow2` overlay，不直接写 prepared base qcow2 或原始 image
- QEMU 默认使用 `arm64` + `bridge` 网络，guest 通常在 `192.168.111.x`，容器内 HDC 转发端口默认从 `127.0.0.1:55555` 开始分配
- `docker-compose.yml` 默认把源码工作区按只读方式挂进去，避免污染源码树
- `docker-compose.yml` 默认直接模拟 `env_bindings` / `file_bindings` 的最终效果
- `docker-compose.yml` 默认按单文件方式挂载 `codex` / `opencode` 配置
- `docker-compose.platform.yml` 不再挂载 `codex` / `opencode` 宿主目录，而是等平台在部署时注入 env/file bindings
- `docker-compose.yml` 默认还注入了 `host.docker.internal:host-gateway`

本地开发建议创建 gitignore 掉的 `.env`，显式指向真实配置文件：

```bash
OH_WORKSPACE_HOST_PATH=/home/icsl/openharmony_6_1
CODEX_AUTH_FILE=/home/icsl/.codex/auth.json
CODEX_CONFIG_TOML_FILE=/home/icsl/.codex/config.toml
OPENCODE_CONFIG_FILE=/home/icsl/.config/opencode/opencode.json
IPC_AUDIT_PROVIDER_FALLBACK_HOST_FILE=/home/icsl/sothoth/13-secflow-service/image_build/secflow-app-ipc-audit/provider-files/providers.fallback.json.example
```

如果没有这些变量，compose 会退回到 `provider-files/*.example`，这些文件只用于 ready 链路占位，不能作为真实执行配置。`agentflow_cli` 额外还要求宿主机存在并挂载 `/home/icsl/agentflow-alpha`。

本地 Docker 联调时，后端还会额外挂载一份 `provider-files/providers.fallback.json.example` 到容器内，并设置 `IPC_AUDIT_PROVIDER_FALLBACK_FILE=/app/provider-files/providers.fallback.json`。如果容器里请求 ConfigCenter / provider API 失败，服务会自动改读这份 fallback 文件，让前端本地也能拿到 Provider 列表并继续测试。文件里的 `${OPENAI_API_KEY}`、`${OPENAI_BASE_URL}`、`${IPC_AUDIT_PROVIDER_FALLBACK_MODEL}` 会在容器内按环境变量展开；如果你要换成本地自己的 Provider 清单，只需要覆盖 `IPC_AUDIT_PROVIDER_FALLBACK_HOST_FILE` 指向另一份 JSON。

OpenCode 运行时注意：

- 服务会为每个 task attempt stage 注入独立的 `XDG_DATA_HOME` / `XDG_CACHE_HOME` / `XDG_STATE_HOME`
- OpenCode 配置仍从 `/root/.config/opencode/opencode.json` 读取，保留平台 `file_bindings` 注入语义
- OpenCode 数据库和日志会写到当前 stage 的 `runtime/<stage>/opencode-env/` 下，避免多个并发任务共享 `/root/.local/share/opencode/opencode.db` 导致 SQLite WAL 冲突

如果你确认某个真实执行链路必须改源码树，再把 compose 里的：

- `read_only: true`

改成：

- `read_only: false`

## About `agentflow_cli` In Container

当前镜像已经支持：

- `mock`
- `agentflow_cli`
- `codex_cli`

但要注意，服务进程自身不直接执行 IPC PoC 逻辑，而是通过 `agentflow_cli` / `codex_cli` / `opencode_cli` 拉起 agent，并由 PoC prompt 约束 agent 使用容器内的 QEMU/HDC helper。

`hdc` 也是类似状态：

- 镜像不内置 `hdc` 和 `libusb_shared.so`
- 容器通过挂载的 OpenHarmony 工作区固定路径调用 `hdc`
- 后端 Python 服务不直接调用 `hdc`
- PoC prompt 会要求 agent 在当前容器内通过 `ipc-audit-qemu` 启动/复用 QEMU，再用固定路径 `hdc` 连接

`agentflow_cli` 模式除了 Python 服务本身，还依赖容器内存在：

- 可导入的 AgentFlow 源码目录 `/home/icsl/agentflow-alpha`
- `python3`、`jinja2`、`typer` 等 AgentFlow 运行时依赖
- `codex` 可执行文件
- 挂载的 OpenHarmony 工作区内 `hdc` 运行时文件（如果 PoC 链路需要）
- `ipc-audit-qemu` helper 和镜像内置 QEMU 运行时
- 挂载的 OpenHarmony 工作区内 `vendor/edu/docker/src/*.sh`
- prepared qcow2 cache / boot image

也就是说，当前容器化已经满足：

- 本地单容器测试 API、scheduler、sqlite、artifact 归档
- 前端联调和任务流联调
- 容器内直接使用 `codex` / `opencode`
- 容器内通过挂载的 OpenHarmony 工作区调用 `hdc`
- 容器内直接启动或复用 QEMU/OHEMU，并通过容器内 HDC 端口连接

仍然没有烘焙进镜像的是 OpenHarmony 工作区、`hdc`、`libusb_shared.so`、qcow2 cache 和 boot image；这些继续来自挂载的 OpenHarmony 工作区。

## K8s

[k8s-deployment.yaml](./k8s-deployment.yaml) 当前保持“配置中立”：

- 不手工写死 Codex / OpenCode secret
- 可以直接作为原生 K8s manifest 的基础版本

第一轮如果你要走平台模板部署，优先使用 [docker-compose.platform.yml](./docker-compose.platform.yml) 这一条链路，让 platform-agent 复用现有的 LLM Provider 注入能力；不要再单独实现一套自定义 K8s 注入器。

还要额外注意一个网络点：

- 当前推荐路径是在 `secflow-app-ipc-audit` 容器内直接启动 QEMU，并使用 `OHEMU_NETWORK_MODE=bridge`
- 这种路径下 guest 通常会拿到 `192.168.111.x` 地址，helper 会启动 `socat` 把容器内 `127.0.0.1:<HDC_PORT>` 转发到 `<GUEST_IP>:55555`
- 因此 `hdc tconn 127.0.0.1:<HDC_PORT>` 仍然是正确入口，但 `<HDC_PORT>` 必须来自 `ipc-audit-qemu list` 或 state 文件，不要写死 guest 端口
- 如果以后改成连接宿主机或另一个容器里已经存在的 QEMU，才需要重新评估 `host.docker.internal`、Service DNS 或 `--network host`
- 不要把 guest 侧 HDC 端口和当前容器内 helper 分配出来的 HDC 转发端口混用

如果你下一步要把真实执行也封进容器，建议继续拆两层：

1. 保留当前 `Dockerfile` 作为基础 API 镜像
2. 再做一个面向真实执行的派生镜像，把 `agentflow-alpha`、`codex` 和所需运行时工具一起装进去

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
