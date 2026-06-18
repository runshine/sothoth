---
name: task-trace
namespace: bootstrap
description: |
  将当前任务轨迹缓存到本地，并在启用配置时上传到 MinIO。
  OpenCode/KiloCode 场景会尽量合并 dispatcher + 所有 subagent transcript。
  作为默认 post-task 生命周期的一环，必须先于 skill-recall-propose 执行，
  为 proposal 提供 provenance。
tags: [post-task, trace]
---

# Task Trace

将本次任务的 transcript 缓存到本地 `~/.cache/task-trace/`，并在启用配置时上传到 MinIO，供 task-collect、vuln-report 和 skill-recall-propose 引用。

OpenCode/KiloCode 场景下，脚本会先解析真实 dispatcher/root session，再沿 DB `parent_id` 递归发现 subagent session，将 dispatcher + subagent 的消息按时间全局排序后合并到同一个 JSONL 文件。每条 record 会附带：

- `_trace_session_id`：该消息所属 session ID
- `_trace_agent`：该消息所属 agent 名称

如果 DB 不可用或没有 subagent，则回退为只导出当前/root session，保持旧行为。

## 触发条件

这是默认 post-task 生命周期的一环，排在 `task-score` 之后、`skill-recall-propose` 之前。
也可手动 `/task-trace`。

## Session ID 发现机制

脚本通过多层 fallback 自动发现真实 session ID：

| 优先级 | 机制 | 说明 |
|---|---|---|
| 1 | `--session-id` CLI 参数 | 显式传入，最高优先级 |
| 2 | Env var + DB parent_id 递归 | 如果 env var 是 subagent session，沿 DB `parent_id` 找到 root dispatcher |
| 3 | DB 查询当前 cwd root session | 当没有 env var 时，查询 `directory=cwd AND parent_id IS NULL` 的最新 session；优先匹配 `TASK_TRACE_DISPATCHER_AGENT` |
| 4 | Env var 直接使用 | DB 不可用但 env var 存在时使用 |
| 5 | 全失败 | `sys.exit(2)` 并输出错误原因 |

`TASK_TRACE_DISPATCHER_AGENT` 可配置逗号分隔的 dispatcher agent 名称，默认包含 `nazhua-audit`；若没有匹配，脚本会回退到当前 cwd 下最新 root session。

## 配置约束

MinIO / trace 对象存储地址必须来自 `TASK_TRACE_UPLOAD_ENABLED`、`TASK_TRACE_HTTP_ENDPOINT`、`TASK_TRACE_PUBLIC_BASE_URL`、`TASK_TRACE_BUCKET`、`TASK_TRACE_PREFIX` 等环境变量。执行命令时应先加载 `~/.config/secocto/.env`，不要在命令或脚本参数中写死 MinIO 地址。

```bash
python3 <skills-dir>/task-trace/scripts/trace.py

# 如需显式指定 session 或 agent：
python3 <skills-dir>/task-trace/scripts/trace.py --agent opencode --session-id ses_xxxxxxxx
```

脚本自动检测 agent 类型（Claude Code / OpenCode / KiloCode），定位 transcript 文件，写入 `~/.cache/task-trace/<agent>/trace-<session_id>.jsonl`。

如果 `TASK_TRACE_UPLOAD_ENABLED=1`，脚本会用 HTTP PUT 上传到：

```text
${TASK_TRACE_PUBLIC_BASE_URL}/${TASK_TRACE_BUCKET}/${TASK_TRACE_PREFIX}/<agent>/trace-<session_id>.jsonl
```

MinIO bucket 由 `docker-compose.lifecycle.yml` 初始化为内网匿名读写，因此上传不需要额外 SDK 或 CLI 依赖。

## 输出

```json
{
  "agent": "opencode",
  "session_id": "ses_xxx",
  "local_path": "~/.cache/task-trace/opencode/trace-ses_xxx.jsonl",
  "subagent_count": 3,
  "trace_url": "${TASK_TRACE_PUBLIC_BASE_URL}/${TASK_TRACE_BUCKET}/${TASK_TRACE_PREFIX}/opencode/trace-ses_xxx.jsonl"
}
```

同一份结果会写入 `~/.cache/task-trace/<agent>/trace-<session_id>.json`，供后续 skill 自动读取。

报告输出结果即可（agent 类型、session ID、本地路径、subagent_count、trace_url 或 upload_error）。
