# secflow-app-binary-to-source

SecFlow B2S 后端适配服务，用于保持前端现有 `/api/app/binary-to-source` API 不变，并在后端调用 `pi-re-agent` REST API 执行二进制到源码恢复任务。

## 主要能力

- 兼容前端 B2S API：任务列表、创建、详情、终止、重试。
- 启动时使用服务机机 Token 校验 Auth 服务，完成微服务间认证自检。
- 运行时通过 Auth 服务校验用户 Bearer Token。
- 通过 Project 服务校验用户是否可访问当前 `project_id`。
- 通过 ConfigCenter 拉取 LLM Provider，并物化为 pi-re-agent 可读取的模型配置。
- 启动后向 `secflow-platform-menu` 注册服务和菜单，并定时发送心跳。
- 按项目根目录校验 `elf_path` 与 `output_dir`，避免跨项目路径访问。
- 维护 B2S Task / Item 与 pi-re-agent Job 的映射。
- 将 pi-re-agent 的 `queued/running/completed/failed/cancelled` 映射为前端使用的任务状态。

## API

```text
GET  /api/app/binary-to-source/health
GET  /api/app/binary-to-source/ready
GET  /api/app/binary-to-source/projects/{project_id}/tasks
POST /api/app/binary-to-source/projects/{project_id}/tasks
GET  /api/app/binary-to-source/projects/{project_id}/tasks/{task_id}
POST /api/app/binary-to-source/projects/{project_id}/tasks/{task_id}/terminate
POST /api/app/binary-to-source/projects/{project_id}/tasks/{task_id}/retry
```

## 注册中心与微服务认证

配置结构对齐 `secflow-platform-fileserver/config.yaml`：

```yaml
auth_service:
  host: "secflow-platform-auth"
  port: 80
  validate_token_path: "/api/auth/validate-token"
  service_machine_token: "..."

project_service:
  host: "secflow-platform-project"
  port: 80
  get_project_path: "/api/project"

configcenter_service:
  enabled: true
  base_url: "http://secflow-platform-configcenter/api/configcenter"
  timeout: 30

pi_re_agent:
  llm_provider_key: "share_codex"
  agent_config_dir: "/data/pi-re-agent-config"

registry:
  enabled: true
  menu_service_url: "http://secflow-platform-menu"
  service_id: "secflow-app-binary-to-source-manager"
  service_name: "ELF源码还原服务"
  host: "secflow-app-binary-to-source-manager"
  port: 80
  api_prefix: "/api/app/binary-to-source"
```

启动流程：

1. 初始化数据库表。
2. 使用 `auth_service.service_machine_token` 或环境变量 `SECFLOW_SERVICE_MACHINE_TOKEN` 调用 Auth `/api/auth/validate-token`，确认 token 类型为 `machine`。
3. 使用同一个机机 Token 调用 ConfigCenter `/api/configcenter/service/llm/providers/{llm_provider_key}` 拉取 LLM Provider。
4. 将 Provider 转换为 pi-re-agent 可读取的 `/data/pi-re-agent-config/models.json`、`settings.json`、`auth.json`。
5. 向 Menu 注册中心调用 `/api/menu/register` 注册服务和菜单。
6. 后台每 30 秒调用 `/api/menu/heartbeat/{service_id}` 发送心跳。
7. 停止时调用 `/api/menu/unregister/{service_id}` 注销服务。

项目管理：

- 所有项目级接口均要求 `Authorization: Bearer <user-token>`。
- 每次请求都会调用 Project 服务 `GET /api/project/{project_id}` 校验当前用户是否有项目访问权限。
- `project_id` 经过白名单格式校验，并用于限制 `/data/files/{project_id}` 下的输入/输出路径。

## 路径隔离

默认配置：

```yaml
storage:
  project_root_template: "/data/files/{project_id}"
  app_root_name: "app/secflow-app-binary-to-source"
  output_root_name: "binary-to-source-outputs"
```

服务会要求：

```text
请求中的 elf_path 必须在 /data/files/{project_id} 下
B2S 会把输入 ELF 复制到 /data/files/{project_id}/app/secflow-app-binary-to-source/{task_id}/{sequence_no}/input
output_dir 自动创建在 /data/files/{project_id}/app/secflow-app-binary-to-source/{task_id}/{sequence_no}/output
```

因此 pi-re-agent 建议挂载同一份 `/data` 存储，并设置：

```text
PI_RE_ALLOWED_DIRS=/data/files
```

## pi-re-agent 请求

每个 ELF item 会创建一个 pi-re-agent job：

```json
{
  "target": "/data/files/<project_id>/app/secflow-app-binary-to-source/<task_id>/1/input/demo.elf",
  "output_dir": "/data/files/<project_id>/app/secflow-app-binary-to-source/<task_id>/1/output",
  "batch_size": 8192,
  "max_retries": 3,
  "model": "share_codex/gpt-5.4",
  "functions": null,
  "clean": false,
  "engine": "hybrid",
  "concurrency": 4
}
```

## 缓存机制

当前 B2S 只保留一套固定行为的共享结果缓存，不再支持可配置的 `scope`、`ttl_days`、`max_size_gb`。

缓存行为如下：

- 仅缓存 `success` 的分析结果。
- 缓存键固定为 `sha256(ELF 文件内容) + mode(fast/deep)`。
- `reuse_cache=true` 时，任务创建阶段会优先查缓存；命中后直接物化已有输出，不再派发到 `pi-re-agent`。
- 缓存目录默认位于 `/data/files/.secflow-cache/binary-to-source`。
- 当前可配置项只保留：
  - `cache.enabled`
  - `cache.root_dir`
  - `cache.materialize_mode`
  - `cache.cache_success_only`

当前限制：

- 缓存是共享结果缓存，不是项目级隔离缓存。
- 目前没有内建 TTL 淘汰和容量上限治理。
- 目前缓存签名只包含文件内容哈希和 `mode`，不包含模型、provider、engine、concurrency 等更细执行参数。

## 运行

```bash
pip install -r requirements.txt
python -m app.main
```

或者：

```bash
docker build -t secflow-app-binary-to-source .
docker run --rm -p 8080:8080 -v /data:/data secflow-app-binary-to-source
```

## Kubernetes

仓库根部署目录已提供/复用以下清单：

```text
13-secflow-service/00-secflow-102-00-app-binary-to-source-configmap.yaml
13-secflow-service/00-secflow-102-03-app-binary-to-source-manager-deployment.yaml
13-secflow-service/00-secflow-102-05-app-binary-to-source-manager-service.yaml
13-secflow-service/00-secflow-102-06-app-binary-to-source-pi-re-agent-service.yaml
13-secflow-service/00-secflow-102-07-app-binary-to-source-pi-re-agent-deployment.yaml
```

Ingress 路径：

```text
/api/app/binary-to-source -> secflow-app-binary-to-source-manager:80
```

注意：`secflow-pi-re-agent` 镜像默认写为 `ghcr.io/skiyer/pi-re-agent:main`，部署前请确认该镜像包含当前所需的 `pi-re-server` REST API；如使用自建镜像，请按实际镜像仓库修改清单。

`secflow-pi-re-agent` 会将同一份 fileserver PVC 的 `pi-re-agent-config` 子目录挂载到 `/root/.pi/agent`，并设置：

```text
PI_MODELS_JSON=/root/.pi/agent/models.json
PI_CODING_AGENT_DIR=/root/.pi/agent
```

B2S adapter 启动时从 ConfigCenter 物化 LLM Provider 到该目录，因此 pi-re-agent 和 pi CLI 能读取统一的模型与 API Key 配置。
