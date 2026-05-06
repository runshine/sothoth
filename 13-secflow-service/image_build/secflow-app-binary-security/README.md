# secflow-app-binary-security

统一的二进制软件包安全编排微服务，负责按固定阶段顺序调用：

`firmware-unpacker -> system-analyse -> binary-to-source -> entry-analyse -> dataflow-analyse -> dataflow-vuln-scanner`

## 主要能力

- 项目级任务统一入口
- 认证与项目权限校验
- 菜单注册与心跳
- 数据库持久化总任务、阶段运行、阶段子任务、事件流
- 阶段顺序固定，阶段内按并发上限并行
- 默认局部失败不中止整条流水线
- 聚合统一产物目录与时间线

## API

```text
GET  /api/app/binary-security/health
GET  /api/app/binary-security/ready
GET  /api/app/binary-security/projects/{project_id}/tasks
POST /api/app/binary-security/projects/{project_id}/tasks/prepare
POST /api/app/binary-security/projects/{project_id}/tasks
GET  /api/app/binary-security/projects/{project_id}/tasks/{task_id}
GET  /api/app/binary-security/projects/{project_id}/tasks/{task_id}/timeline
GET  /api/app/binary-security/projects/{project_id}/tasks/{task_id}/artifacts
POST /api/app/binary-security/projects/{project_id}/tasks/{task_id}/cancel
POST /api/app/binary-security/projects/{project_id}/tasks/{task_id}/retry
POST /api/app/binary-security/projects/{project_id}/tasks/{task_id}/resume
GET  /api/app/binary-security/projects/{project_id}/config
PUT  /api/app/binary-security/projects/{project_id}/config
```

## 工作目录

默认工作目录：

```text
/data/files/{project_id}/app/secflow-app-binary-security/{task_id}/
```

目录结构：

```text
input/
runtime/
artifacts/unpack/
artifacts/system-analysis/
artifacts/b2s/
artifacts/entry/
artifacts/dataflow/
artifacts/vuln/
summary/
logs/
```

## 运行

```bash
pip install -r requirements.txt
python -m app.main
```

或：

```bash
docker build -t secflow-app-binary-security .
docker run --rm -p 8080:8080 -v /data:/data secflow-app-binary-security
```
