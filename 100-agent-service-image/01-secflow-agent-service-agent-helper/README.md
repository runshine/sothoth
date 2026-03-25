# Agent Helper Image

运行在 Agent 节点上的辅助服务镜像，当前按“每个独立进程一个目录”组织。

当前进程目录：
- `agent_ai_service/`: 智能体服务进程，对外提供 REST/A2A/后端管理 API
- `process_monitor_service/`: 进程监控服务，对外提供系统进程查询、信号控制、完整 `/proc/<pid>` 详情 API

最外层目录只保留镜像级文件：
- `Dockerfile`
- `docker-compose.yml`
- `entrypoint.sh`
- `requirements.txt`
- `README.md`

## 目录结构

```text
.
├── Dockerfile
├── README.md
├── docker-compose.yml
├── entrypoint.sh
├── requirements.txt
├── agent_ai_service/
│   ├── __init__.py
│   ├── app.py
│   ├── api/
│   ├── services/
│   ├── adapters/
│   ├── a2a/
│   ├── persistence/
│   ├── models/
│   └── tests/
└── process_monitor_service/
    ├── __init__.py
    ├── app.py
    ├── config.py
    └── monitor.py
```

## 端口

- `20001` Agent AI REST API
- `20002` ttyd
- `20003` code-server
- `20004` Process Monitor REST API

## 关键环境变量

- `PROCESS_MONITOR_PORT`: Process Monitor 服务端口
- `PROCESS_MONITOR_INTERVAL_SEC`: 进程摘要巡检周期
- `HOST_ROOT`: 宿主机根目录挂载点，默认 `/host`
- `PROCESS_MONITOR_PROC_ROOT`: 进程详情读取时使用的 procfs 根目录，默认 `/host/proc`
- `AGENT_HELPER_STATE_DIR`: 本地状态与快照持久化目录

## process_monitor_service API

### 实时查询系统进程
- `GET /api/processes`
- 支持查询参数：
  - `name`
  - `keyword`

### 进程摘要与巡检
- `GET /health`
- `GET /ready`
- `GET /api/processes/summary`
- `POST /api/processes/check`

### 查询指定进程详细信息
- `GET /api/processes/<pid>`

返回内容包括：
- 基础进程信息
- open files
- connections
- threads
- environ
- memory/cpu/io 信息
- 以及 `/proc/<pid>` 下可读取的完整目录树信息
  - `fd`
  - `fdinfo`
  - `maps`
  - `smaps`
  - `mounts`
  - `net`
  - `status`
  - `environ`
  - 其它可读项

### 进程信号控制
- `POST /api/processes/<pid>/signal`
- `POST /api/processes/signal`

批量接口支持：
- `pid`
- `pids`
- `name`
- `keyword`

请求示例：

```json
{
  "pids": [123, 456],
  "signal": "TERM",
  "force": false
}
```

```json
{
  "keyword": "python",
  "force": true
}
```

说明：
- `force=true` 时使用 `SIGKILL`
- 否则默认 `SIGTERM`
- 也可显式指定：`TERM` / `KILL` / `USR1` / `SIGTERM` / 数字信号

## 设计说明

- 容器最外层只保留镜像构建相关文件。
- 每个独立运行进程使用一个独立目录承载源码。
- `entrypoint.sh` 启动顺序为：`ttyd` -> `code-server` -> `process_monitor_service` -> `agent_ai_service`。
- 智能体后端进程仍由 `agent_ai_service` 的 REST API 统一管理，不在入口脚本中自动启动。
- 当前容器与宿主机共享 PID namespace，且宿主机根目录挂载在 `/host`；`process_monitor_service` 对涉及系统文件的读取优先走 `/host/proc/<pid>`，避免把容器自身文件视角混进结果。
