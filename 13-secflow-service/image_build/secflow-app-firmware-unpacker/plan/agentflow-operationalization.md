# AgentFlow Operationalization Evidence

更新日期：2026-05-09

## 告警口径

| 告警 | 指标来源 | 建议阈值 | 严重级别 | 说明 |
| --- | --- | --- | --- | --- |
| 任务失败率升高 | `/metrics` 的 `firmware_unpacker_tasks_total{status="failed"}` 与成功/失败任务总数 | 15 分钟失败率 >= 20% | warning | 用于发现 pipeline、工具或外部 agent 异常。 |
| 任务失败率严重升高 | 同上 | 15 分钟失败率 >= 50% | critical | 需要暂停策略发布或回滚最近变更。 |
| AgentFlow 接近并发上限 | 集群 API `agentflow_active_runs` / `agentflow_max_concurrent` 或 `/metrics` 同名指标 | >= 80% 持续 10 分钟 | warning | 表明队列可能堆积。 |
| runs 目录占用过高 | 集群 API `agentflow_runs_dir_usage_mb` 或 `/metrics` 同名指标 | >= 80% PVC 预算 | warning | 触发 `cleanup_runs_retention_days` 检查。 |
| token 激增 | `/metrics` 的 `firmware_unpacker_agentflow_tokens_total` 增量，或任务详情 `total_tokens` | 单任务超过固定样本 P95 的 3 倍 | warning | 用于发现 prompt 漂移或 agent 循环。 |
| 节点超时/失败 | `/agentflow` 的 `failed_nodes`、节点 `duration_seconds`、结构化日志 `node_failed` | reviewer 超过 `node_timeout_seconds / 2` 或 executor 超过运行 SLA | warning | 定位到 `node_id`，避免依赖登录 Pod 看文件。 |

## Dashboard 和实时进度

当前采用服务内置 AgentFlow API 暴露运行详情，不单独反向代理 AgentFlow Web Dashboard：

- run 列表与详情：`/api/app/firmware-unpacker/agentflow/runs` 和 `/api/app/firmware-unpacker/agentflow/runs/{run_id}`。
- run 事件：`/api/app/firmware-unpacker/agentflow/runs/{run_id}/events`。
- SSE 进度流：`/api/app/firmware-unpacker/agentflow/runs/{run_id}/stream`，从 `events.jsonl` 增量推送。
- artifact 读取：`/api/app/firmware-unpacker/agentflow/runs/{run_id}/artifacts/{node_id}/{name}`。

所有 AgentFlow API 路由复用 `get_current_subject` 认证依赖；项目任务视图继续通过项目级接口校验项目访问权限。

## 回归门禁

固定样本集入口：`plan/agentflow-regression-samples.json`。

门禁命令：

```bash
python scripts/agentflow_regression_eval.py --manifest plan/agentflow-regression-samples.json
```

当前固定样本覆盖：

- `zip-preprocess`: preprocess success
- `skill-hit`: skill hit success
- `skill-fallback-author`: skill hit failed then fallback success
- `generic-success`: no skill then generic success
- `generic-max-retries`: generic failed / max retries

真实 `pi` smoke 证据保存在 `plan/agentflow-regression-fixtures/real-pi-generic-smoke/` 和 `plan/agentflow-regression-fixtures/real-pi-skill-hit-smoke/`，包含脱敏后的 `final_result.json`、`tokens_summary.json`、`run.json` 和关键 stage 输出。这些样本 token 成本较高，不纳入默认离线门禁阈值。
