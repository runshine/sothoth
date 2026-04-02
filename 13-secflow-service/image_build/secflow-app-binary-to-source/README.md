# secflow-app-binary-to-source

ELF 到源码还原微服务，采用单镜像双角色部署：
- `ROLE=manager`：提供 REST API、任务调度、故障恢复、重试控制
- `ROLE=worker`：消费 Celery 任务并调用第三方还原组件

## 架构

- 后端：FastAPI + SQLAlchemy + Celery + Redis
- 任务模型：父任务（用户提交）+ 子任务（单 ELF 执行单元）
- 高可用：Manager 多副本 + Redis 选主，只有 leader 执行调度
- 存储：Manager/Worker 共享同一 PVC（`/data/binary-to-source`）
- 项目约束：所有 API 必须绑定 `project_id`，并通过 `secflow-platform-project` 鉴权

## 任务状态

父任务状态：
- `pending`
- `running`
- `completed`
- `failed`
- `cancelling`
- `cancelled`
- `partial_success`

子任务状态：
- `pending`
- `queued`
- `running`
- `success`
- `partial_success`
- `failed`
- `cancelled`

失败分类：
- `worker_business_error`：第三方返回失败，默认不自动重试
- `transient_system_error`：系统类失败，可自动重试
- `cancelled_by_user`：用户终止

## 第三方库接口（目标签名）

当前代码内使用 mock 适配器，目标第三方接口签名如下：

```python
def decompile_elf(input_elf_path: str, output_dir: str) -> DecompileResult:
    ...
```

```python
@dataclass
class DecompileResult:
    status: str  # success | partial_success | failed
    generated_files: list[str]
    message: str
    error_reason: str | None
    raw_payload: dict
```

## 运行

### Manager

```bash
ROLE=manager python -m app.main
```

### Worker

```bash
ROLE=worker python -m app.worker_entry
```

Worker 并发参数（用于单 Pod 多 worker 槽位）：
- `WORKER_CONCURRENCY`：每个 Worker Pod 的并发进程数，默认 `1`
- `WORKER_POOL`：Celery pool 类型，默认 `prefork`

## 配置

配置文件：`config.yaml`（容器内默认 `/app/config.yaml`）

关键配置段：
- `database`
- `redis`
- `celery`
- `scheduler`
- `task_policy`
- `storage`
- `project_service`
- `auth_service`
- `registry`
- `app`
- `logging`

## 部署文件

K8S 清单位于 `13-secflow-service/`：
- `00-secflow-102-00-app-binary-to-source-configmap.yaml`
- `00-secflow-102-01-app-binary-to-source-pvc.yaml`
- `00-secflow-102-02-app-binary-to-source-serviceaccount.yaml`
- `00-secflow-102-03-app-binary-to-source-manager-deployment.yaml`
- `00-secflow-102-04-app-binary-to-source-worker-deployment.yaml`
- `00-secflow-102-05-app-binary-to-source-manager-service.yaml`

GitHub Actions：
- `.github/workflows/build-secflow-app-binary-to-source-image.yaml`

API 文档见：`doc/API.md`
