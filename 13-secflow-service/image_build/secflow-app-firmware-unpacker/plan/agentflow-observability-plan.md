# AgentFlow 可观测性剩余计划

更新日期：2026-05-08

## 范围说明

基础可观测性已经存在：结构化日志、DB 任务字段、AgentFlow run 状态 API、运行产物、健康检查和 Pod 资源监控。本文只保留尚未完成的增强项。

## 完成事项

### Phase 1：补齐关键可观测性 `[DONE]`

目标：让每次解包都能量化成本、定位失败节点，并从应用日志中看到 AgentFlow 关键事件。

#### G1. Token 消耗聚合 `[DONE]`

任务：

- 在 `app/cli.py` 中从 AgentFlow trace / events / node outputs 聚合 token 使用量。
- 写入 `tokens_summary.json`，包含总量和节点级明细。
- 在结果或 DB 可见字段中暴露总 token 数，便于任务列表和回归评测使用。

涉及文件：

- `app/cli.py`
- `app/model.py`
- `app/schemas.py`
- `tests/`

验收标准：

- `tokens_summary.json` 不再只是空壳结构。
- 至少包含 `total_prompt_tokens`、`total_completion_tokens`、`total_tokens`、`nodes`。
- fake trace 和真实 `pi` trace 都有测试或 fixture 覆盖。

#### G2. 节点级耗时 API `[DONE]`

任务：

- 增强任务 AgentFlow 状态接口，返回每个节点的 `started_at`、`completed_at`、`duration_seconds`、`status`、`error`。
- 兼容旧 run.json 中字段缺失的情况。

涉及文件：

- `app/api/firmware.py`
- `app/schemas.py`
- `tests/test_agentflow_runs_api.py`

验收标准：

- `GET .../tasks/{task_id}/agentflow` 可直接看到节点耗时和失败摘要。
- 字段缺失时接口稳定返回 `null`，不抛 500。

#### G3. Trace 事件桥接到应用日志 `[DONE]`

任务：

- 在 runner 等待循环中增量读取 `events.jsonl`。
- 将 `run_started`、`node_started`、`node_completed`、`node_failed`、`run_completed`、`run_cancelled` 写入结构化日志。
- 日志字段包含 `task_id`、`project_id`、`agentflow_run_id`、`node_id`、`status`、`duration_seconds`、`error`。

涉及文件：

- `app/cli.py`
- `tests/`

验收标准：

- 不登录 Pod 文件系统也能通过日志平台定位失败节点。
- 重启、取消、失败场景不会重复刷同一批事件。

#### G4. 基础告警口径 `[DONE]`

任务：

- 定义任务失败率、节点超时、run 目录磁盘占用、token 激增的告警口径。
- 先以文档和指标字段形式落地，后续再接 Prometheus / AlertManager。

涉及文件：

- `plan/`
- `app/services/worker.py`
- `app/cli.py`

验收标准：

- 每条告警有明确指标来源、阈值和严重级别。
- 告警字段可从 API、日志或 metrics 中获取。

### Phase 2：降低排查与运维成本 `[DONE]`

#### G5. AgentFlow API 增强 `[DONE]`

任务：

- `/agentflow` 响应增加 `failed_nodes`、`token_summary`、`trace_files`、`stage_files`。
- 对不存在的 run 目录、缺失 fixture、损坏 JSON 做稳定降级。

涉及文件：

- `app/api/firmware.py`
- `app/schemas.py`
- `tests/test_agentflow_runs_api.py`

验收标准：

- 任务详情页无需登录机器即可看到失败节点、token 摘要和可追踪文件列表。

#### G6. 集群级 AgentFlow 指标 `[DONE]`

任务：

- 在集群快照中增加 `agentflow_active_runs`、`agentflow_max_concurrent`、`agentflow_runs_dir_usage_mb`。
- 明确这些指标来自配置、DB 状态还是 runs 目录扫描。

涉及文件：

- `app/services/worker.py`
- `app/api/firmware.py`
- `tests/`

验收标准：

- 集群接口能判断 AgentFlow 是否接近并发或磁盘上限。

#### G7. Run 清理策略 `[DONE]`

任务：

- 实现 `cleanup_runs_retention_days`。
- 清理已完成且超过保留期的 AgentFlow run 目录。
- 跳过运行中、缺少完成时间或结构异常的目录，并记录 warning。

涉及文件：

- `app/services/worker.py`
- `app/cli.py`
- `tests/`

验收标准：

- 过期 run 会被清理。
- 运行中的 run 不会被误删。
- 清理行为有结构化日志。

#### G8. 取消事件可观测性 `[DONE]`

任务：

- 取消任务时记录当前 AgentFlow run 所处节点。
- 写入结构化日志和最终结果中的取消摘要。

涉及文件：

- `app/cli.py`
- `app/services/task_manager.py`
- `tests/test_agentflow_migration.py`

验收标准：

- cancelled 任务能看出取消发生在哪个节点、当时节点状态是什么。

### Phase 3：外部监控集成 `[DONE]`

#### G9. Prometheus / OpenTelemetry 指标 `[DONE]`

任务：

- 增加任务总数、任务耗时、节点耗时、token 总量、活跃 run 数指标。
- 如平台需要，增加 OpenTelemetry span。

涉及文件：

- `app/metrics.py`
- `app/main.py`
- `app/cli.py`
- `requirements.txt`

验收标准：

- `/metrics` 可被 Prometheus 抓取。
- 指标标签不会引入高基数路径或错误文本。

#### G10. AgentFlow Dashboard 集成 `[DONE]`

任务：

- 明确是否以内嵌链接、反向代理或独立服务方式暴露 AgentFlow Web Dashboard。
- 加入认证和访问范围限制。

验收标准：

- 运维能从任务跳转到对应 AgentFlow run。
- 未授权用户无法访问 run 详情。

#### G11. 实时进度推送 `[DONE]`

任务：

- 评估 SSE 或 WebSocket 推送 AgentFlow events。
- 从 `events.jsonl` 增量推送节点状态。

验收标准：

- 前端不依赖高频轮询即可看到节点进度。
- 连接断开重连后可从最后事件继续。


## 完成证据

- 固定回归门禁：`python scripts/agentflow_regression_eval.py --manifest plan/agentflow-regression-samples.json`。
- 自进化 smoke：`scripts/agentflow_self_evolution_smoke.sh`。
- 全量测试：`pytest -q`。
- 运行与运维证据：`plan/agentflow-operationalization.md`。
