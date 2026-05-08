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

AgentFlow Web API 在本服务 REST 前缀下同步暴露，保留原始 `/api/runs` 后缀：

- `GET /api/app/firmware-unpacker/api/examples/default`
- `POST /api/app/firmware-unpacker/api/runs/validate`
- `POST /api/app/firmware-unpacker/api/runs`
- `GET /api/app/firmware-unpacker/api/runs`
- `GET /api/app/firmware-unpacker/api/runs/{run_id}`
- `POST /api/app/firmware-unpacker/api/runs/{run_id}/cancel`
- `POST /api/app/firmware-unpacker/api/runs/{run_id}/rerun`
- `GET /api/app/firmware-unpacker/api/runs/{run_id}/events`
- `GET /api/app/firmware-unpacker/api/runs/{run_id}/artifacts/{node_id}/{name}`
- `GET /api/app/firmware-unpacker/api/runs/{run_id}/scratchboard`
- `GET /api/app/firmware-unpacker/api/runs/{run_id}/stream`
- `GET /api/app/firmware-unpacker/api/health`

同时提供等价别名 `/api/app/firmware-unpacker/agentflow/...`。

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
- `agentflow`: 解包引擎运行目录、并发和节点超时配置
- `registry`: 菜单注册中心配置
- `logging`: 日志级别与格式

支持通过 `CONFIG_PATH` 或 `FIRMWARE_UNPACKER_CONFIG` 指定配置文件路径。

服务仅保留 AgentFlow 解包模式，配置示例：

```yaml
agentflow:
  enabled: true
  profile: "production"
  runs_dir: "/data/files/.agentflow/runs"
  max_concurrent_runs: 2
  node_timeout_seconds: 1800
  use_worktree: false
  graph_optimization_enabled: false
  graph_optimizer: "codex"
  graph_optimization_rounds: 1
```

也可通过环境变量覆盖：

- `AGENTFLOW_RUNS_DIR=/data/files/.agentflow/runs`
- `AGENTFLOW_MAX_CONCURRENT_RUNS=2`
- `AGENTFLOW_PROFILE=staging`
- `AGENTFLOW_GRAPH_OPTIMIZATION_ENABLED=false`
- `AGENTFLOW_GRAPH_OPTIMIZATION_ROUNDS=1`

AgentFlow 运行日志统一写入 `agentflow.runs_dir/<run_id>/`，任务目录 `run/` 仅保留 `agentflow_run_id.txt`、`agentflow_run_dir.txt`、阶段日志和最终结果。任务响应会返回 `agentflow_run_id`、`agentflow_run_dir` 和任务日志目录 `run_path`。图级优化只会在 `profile` 为 `test` 或 `staging` 且显式开启优化轮次时运行；优化产物由 AgentFlow 写入统一 run 目录。

离线回归评测入口：

```bash
scripts/agentflow_regression_eval.py --manifest plan/agentflow-regression-samples.json
```

该命令会读取固定样本 manifest、校验每个样本的期望结果，并按 manifest 中的阈值执行门禁；不通过时返回非零退出码。

从已归档 run 手工沉淀候选 skill：

```bash
scripts/agentflow_evolve_skill_from_run.py --run-dir /path/to/run --node-id generic_executor --skill-document /path/to/skill.md --skills-dir /data/files/tools
```

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
