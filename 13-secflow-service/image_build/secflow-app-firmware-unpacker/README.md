# SecFlow Firmware Unpacker Service

固件解包微服务，基于 `pi coding agent` 执行固件提取任务，并按 SecFlow 现有应用型微服务的方式接入认证、项目服务和菜单注册中心。

## 主要接口

- `GET /api/app/firmware-unpacker/health`
- `GET /api/app/firmware-unpacker/ready`
- `POST /api/app/firmware-unpacker/projects/{project_id}/tasks`
- `GET /api/app/firmware-unpacker/projects/{project_id}/tasks`
- `GET /api/app/firmware-unpacker/projects/{project_id}/tasks/{task_id}`
- `GET /api/app/firmware-unpacker/projects/{project_id}/tasks/{task_id}/agentflow`
- `DELETE /api/app/firmware-unpacker/projects/{project_id}/tasks/{task_id}`

兼容保留的旧接口：

- `POST /api/app/firmware-unpacker/unpack`
- `GET /api/app/firmware-unpacker/tasks`
- `GET /api/app/firmware-unpacker/tasks/{task_id}`
- `GET /api/app/firmware-unpacker/tasks/{task_id}/agentflow`
- `DELETE /api/app/firmware-unpacker/tasks/{task_id}`

## 配置

配置文件为 `config.yaml`，主要分为以下几段：

- `app`: 服务监听地址和端口
- `database`: MySQL/SQLite 任务状态存储
- `auth_service`: Token 校验与机机 Token
- `project_service`: 项目权限校验
- `service`: 线程池并发等运行参数
- `agentflow`: 解包引擎模式、运行目录、并发和 fallback 配置
- `registry`: 菜单注册中心配置
- `logging`: 日志级别与格式

支持通过 `CONFIG_PATH` 或 `FIRMWARE_UNPACKER_CONFIG` 指定配置文件路径。

AgentFlow 默认关闭，legacy 路径保持不变。灰度启用时可使用：

```yaml
agentflow:
  enabled: true
  engine_mode: "agentflow"
  fallback_to_legacy: true
  runs_dir: "/data/files/.agentflow/runs"
  max_concurrent_runs: 2
  node_timeout_seconds: 1800
  use_worktree: false
```

也可通过环境变量覆盖：

- `UNPACKER_ENGINE_MODE=legacy|agentflow`
- `AGENTFLOW_RUNS_DIR=/data/files/.agentflow/runs`
- `AGENTFLOW_MAX_CONCURRENT_RUNS=2`
- `AGENTFLOW_FALLBACK_TO_LEGACY=true`

AgentFlow 运行日志写入任务 `run/agentflow/runs/<run_id>/`，任务响应会返回 `engine_mode`、`agentflow_run_id` 和 `run_path`。

## 构建与运行

```bash
docker build -t secflow-app-firmware-unpacker .
docker run -p 8080:8080 secflow-app-firmware-unpacker
```

## Kubernetes

服务目录下提供：

- `k8s-configmap.yaml`
- `k8s-deployment.yaml`
- `k8s-serviceaccount.yaml`
- `k8s-service.yaml`

平台总装部署文件位于：

- `13-secflow-service/00-secflow-103-00-app-firmware-unpacker-configmap.yaml`
- `13-secflow-service/00-secflow-103-01-app-firmware-unpacker-serviceaccount.yaml`
- `13-secflow-service/00-secflow-103-02-app-firmware-unpacker-deployment.yaml`
- `13-secflow-service/00-secflow-103-03-app-firmware-unpacker-service.yaml`
