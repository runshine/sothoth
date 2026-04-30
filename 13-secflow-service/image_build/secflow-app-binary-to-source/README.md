# secflow-app-binary-to-source

SecFlow B2S 后端适配服务，用于保持前端现有 `/api/app/binary-to-source` API 不变，并在后端调用 `pi-re-agent` REST API 执行二进制到源码恢复任务。

## 主要能力

- 兼容前端 B2S API：任务列表、创建、详情、终止、重试。
- 通过 Auth 服务校验 Bearer Token。
- 通过 Project 服务校验用户是否可访问当前 `project_id`。
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

## 路径隔离

默认配置：

```yaml
storage:
  project_root_template: "/data/files/{project_id}"
  output_root_name: "binary-to-source-outputs"
```

服务会要求：

```text
elf_path 必须在 /data/files/{project_id} 下
output_dir 自动创建在 /data/files/{project_id}/binary-to-source-outputs/{task_id}/{sequence_no}
```

因此 pi-re-agent 建议挂载同一份 `/data` 存储，并设置：

```text
PI_RE_ALLOWED_DIRS=/data/files
```

## pi-re-agent 请求

每个 ELF item 会创建一个 pi-re-agent job：

```json
{
  "target": "/data/files/<project_id>/.../demo.elf",
  "output_dir": "/data/files/<project_id>/binary-to-source-outputs/<task_id>/1",
  "batch_size": 8192,
  "max_retries": 3,
  "model": null,
  "functions": null,
  "clean": false,
  "engine": "hybrid",
  "concurrency": 4
}
```

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
