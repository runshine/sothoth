# Dataflow Node-level Resume

为 dataflow-vuln-scanner 的“重试 Run”设计并落地节点级断点恢复机制：把“最近轮次阶段图”中的节点精确定义为一次与 piagent 的提示词交互，在网络异常、Pod 回滚、后端进程被杀等场景下，从最近未完成/失败节点继续，而不是从头重跑整个 Run。

## Context

- 前端任务详情实际由 `13-secflow-service/image_build/secflow-frontend/pages/execution/DataflowFileserverRunDashboardPage.tsx` 渲染：
  - `renderExecutionTraceOverview()` 在“会话记录”页展示“最近轮次阶段图”。
  - 图中节点来自 `current_step` / `step_history` checkpoint，并通过 `sessions/<session>/calls/*` 的 prompt 文件做预览补充。
  - 现有“重试 Run”按钮在 `retryCurrentRun()` 中只询问 `extra_cycles`，调用 `retryDataflowFileserverRun()` -> `POST /api/dataflow-vuln-scanner/runs/{run_id}/retry`，没有向用户展示将从哪个节点恢复。
- 后端已有良好基础：
  - API 入口：`app/api/tasks.py` 的 `/runs/{run_id}/retry`。
  - 服务层：`app/services/execution_service.py::retry_run()` 校验 `process_state.can_retry`，执行 `_preflight_run_resume()`，然后创建新的执行尝试，命令为 `run_vuln_scan.py --resume-run-dir ... --extra-cycles ...`。
  - CLI：`run_vuln_scan.py` 已支持 `--resume-run-dir`、`--dry-run-resume`，会生成 `_meta/resume_preview.json`。
  - 核心恢复：`app/pi_vuln_core/resume.py::build_resume_plan()` 读取 `_meta/checkpoints/current_step.json` 和 `steps/` 生成 `resume_cursor`，`resume_run()` 调用 `AtomicWorkflowEngine.resume_from_existing()`。
  - checkpoint：`app/pi_vuln_core/engine/checkpoint.py` 已有 `record_step_checkpoint()` / `load_step_checkpoint()`，文件落盘在 run workspace 的 `_meta/checkpoints/`，适合 Pod 回滚后恢复。
  - Worker/summary/reflection/global review/result review 已在多处记录 step-level checkpoint，并且 `sessions/<session>/calls/<turn>_*` 已持久化 `request.json`、`response.json`、`user_prompt.md`、`system_prompt.md`。
- 主要缺口：
  1. 当前 checkpoint 的“step”更接近业务步骤；严格的“节点 = 一次 piagent prompt 交互”还未覆盖所有交互，尤其是 global/result review 的 schema repair follow-up prompt。
  2. checkpoint 未稳定保存 `call_dir`、prompt 路径、响应路径、turn 等直接关联信息，前端只能用启发式匹配 prompt。
  3. resume plan 虽已能从当前 checkpoint 恢复，但需要正式化为 prompt-node 级 cursor，并在并行 result review、schema repair、partial artifact 等场景下保持确定性和幂等。
  4. 前端“重试 Run”缺少 resume 预览、目标节点展示、风险提示与确认，用户无法判断是否真正从断点继续。

## Plan:

1. **固化节点定义与 checkpoint schema** — 在 `app/pi_vuln_core/engine/checkpoint.py` 中扩展现有 checkpoint（保持兼容）：新增/规范字段 `node_id`、`parent_node_id`、`node_kind`、`cycle`、`phase`、`step_key`、`status`、`resume_policy`、`agent_id`、`session_id`、`turn_count`、`call_dir`、`prompt_user_path`、`prompt_system_path`、`response_path`、`artifact_digest_before/after`、`started/finished/duration`、`extra`。定义稳定 `node_id = cycle::<cycle>::<phase>::<safe step_key>`，把“节点”明确为一次外层 piagent prompt 交互；同一次 prompt 的 runtime timeout retry 作为该节点 attempts，不单独成为节点。

2. **补齐所有 piagent prompt 交互的节点落盘** — 在 `app/pi_vuln_core/engine/worker.py`、`app/pi_vuln_core/review/global_review.py`、`app/pi_vuln_core/review/result_review.py` 中统一按“发送 prompt 前 started、收到结果并完成业务校验后 completed/failed/soft_failed/partial_salvaged”的模式记录节点。Worker 主分析、分段 rework、自审 reflection、summary、global advisor、result advisor 都必须写入稳定 step_key，并在响应后把 `AgentResponse.metadata.call_dir`、`turn_count`、prompt/response 文件相对路径写回 checkpoint。

3. **把 schema repair follow-up 也纳入节点体系** — 修改 `GlobalReviewExecutor._parse_with_schema_repair()` 与 `ResultReviewExecutor._parse_with_schema_repair()`：为每个 repair prompt 记录独立节点，例如 `global::<advisor>::repair_01`、`result::<result_file>::<advisor>::repair_01`。同时让 repair prompt 包含上一次无效输出的必要内容（可截断），使 Pod 回滚后即使原 piagent 内存上下文丢失，也可以安全重跑该 repair 节点；如果无法做到自包含，则该 repair 节点的 `resume_policy` 必须声明为 `rerun_parent_node`。

4. **实现确定性 NodeResumePlan** — 在 `app/pi_vuln_core/resume.py` 中把现有 `_build_resume_cursor()` 升级为节点级 planner：
   - 读取 current checkpoint、step history、已完成轮次、review_state、当前 result 文件与配置中的 advisor/reflection/rework 顺序。
   - 若 current node 是 `started` / `retrying` / `failed` / `error` 且所在 cycle 未完整完成，则目标为当前节点。
   - 若 current node 是 `completed` / `soft_failed` / `partial_salvaged`，目标为确定性顺序中的下一个节点。
   - 若 cycle 已有完整 `review_summaries/cycle_XXX.json`，则从下一轮 worker 节点开始。
   - 输出 `resume_cursor` 包含 `target_node_id`、`cycle`、`phase`、`step_key`、`node_kind`、`source_node`、`resume_policy`、`resume_start_cycle`、`completed_node_count`、`skipped_node_count`。

5. **让执行器严格按 node cursor 跳过/执行** — 在 `AtomicWorkflowEngine._run_review_cycles()`、`WorkerExecutor`、`GlobalReviewExecutor`、`ResultReviewExecutor` 中使用统一 helper 判定节点是否可跳过：只有 terminal checkpoint 且业务产物有效才跳过。global review 与 result review 要按稳定顺序过滤/调度节点；result review 并行时，先确定 pending node 列表，跳过 cursor 之前已 terminal 的节点，从 cursor 节点及之后继续，并保持不同 result/advisor 的 session 隔离。

6. **处理非幂等/部分产物场景** — 对 worker/summary 这类会写文件的节点，记录执行前后的 artifact digest（至少覆盖 `summary.md`、`results/*.md`、`supporting_docs/*.md`、`previous_limitations.md`）。恢复非 terminal 的 worker/summary 节点时不默认删除已有部分产物，而是标记前一次 attempt 为 aborted 并在 prompt 中要求 reconcile；对 review 节点，继续沿用“存在有效 JSON 则跳过；`agent_error`/`ERROR`/read-only violation 视为未完成并重跑”的策略。

7. **加强 Run 级互斥与 stale runtime 判定** — 在 `app/services/execution_service.py` 的 `retry_run()` 流程中继续使用 `process_state.can_retry`，并补充 run-level resume lock/control 状态：当 DB 中已有 pending/queued/running resume 执行时拒绝重复重试；当 Pod 回滚导致进程不存在但 Run 状态仍 active 时，基于本地进程、worker job、run control 文件与 heartbeat 判断 stale，并允许 resume。

8. **新增后端 resume 预览 API 与响应字段** — 在 `app/schemas.py` 增加 `RunResumePlanResponse`，在 `app/api/tasks.py` 增加 `POST /runs/{run_id}/resume-preview`（或等价命名）调用 `_preflight_run_resume()` 但不排队；扩展 `RunMutationResponse` 增加可选 `resume_preflight`。`POST /runs/{run_id}/retry` 成功时返回同一份 preflight，便于前端在提交后展示“已从某节点恢复”。

9. **让 Run index/inspector 原生暴露节点信息** — 在 `app/services/run_inspector.py` 和 `app/services/run_index_service.py` 中确保 `current_step`、`step_history`、`cycle_timing` 包含新增 node 字段与 call/prompt 相对路径；旧 Run 无新增字段时仍按现有逻辑展示。必要时把 `resume_preview.json` 作为 Meta 文件列出，方便前端打开。

10. **更新前端 client 类型与 API 封装** — 在 `secflow-frontend/clients/dataflowVulnScanner.ts` 增加 `DataflowRunResumePlan`、扩展 `DataflowRunRetryPayload` / `DataflowRunMutationResponse`，新增 `previewRunResume()`；在 `clients/dataflowVulnRunsFileserver.ts` 增加 `previewRetryDataflowFileserverRun()`。

11. **改造“重试 Run”交互为 resume 预览确认** — 在 `DataflowFileserverRunDashboardPage.tsx` 中把 `retryCurrentRun()` 从简单 `prompt(extra_cycles)` 改成两步：先输入/选择追加轮次并调用 resume-preview；在 modal/confirm 中展示目标节点（轮次、阶段、stepLabel、status、resume_policy）、当前 checkpoint、预计总轮次、重试命令、风险提示；用户确认后再调用 retry。提交后清理缓存并刷新 Run。

12. **增强“最近轮次阶段图”对节点级 resume 的表达** — 继续以 checkpoint 为主渲染节点，但利用新增 `node_id/call_dir/prompt_*` 精准展示 prompt 预览，不再只靠启发式匹配；当存在 `resume_preview` 或 `current_step.status=started` 且 Run stale 时，对目标节点加“恢复点/将从此重跑”徽标。旧 Run 没有 checkpoint 时仍 fallback 到 callSessions。

13. **补充自动化测试** — 后端新增/扩展测试：
    - `tests/test_resume_convergence_consistency.py`：构造 started/failed/completed checkpoint，验证 `build_resume_plan()` 返回正确 target node。
    - 新增 schema repair 中断测试：mock advisor 第一次返回非 canonical JSON，第二次 repair 前/中断，resume 后只重跑 repair 或按 policy 重跑 parent，并最终产出有效 review。
    - `tests/test_scheduler_recovery_api.py` 或新 API 测试：stale active run 可 preview/retry，已有 queued resume 时拒绝重复。
    - 前端类型/契约测试或 `npm run lint`：确保新增 client 类型与页面调用通过。

14. **兼容与文档** — 保留旧 step_key alias（如 `worker`、`global::<advisor>`、`result::<file>::<advisor>`），旧 Run 无 node 字段时仍可按现有阶段级方式恢复；在 `docs/` 或 README 中补充“节点级 resume 使用说明”和故障处理建议（Pod 回滚、网络中断、timeout、partial_salvage）。

## Risks / Open Questions

- PiAgent 长上下文在 Pod 回滚后未必能完全恢复；因此每个可作为 resume 目标的 prompt 必须尽量自包含，特别是 schema repair prompt 不能只依赖“你刚才”的内存上下文。
- Worker/summary 节点会修改文件，非 terminal 状态下重跑可能叠加部分产物；方案选择保留并 reconcile，而不是自动回滚，需通过 prompt 与 artifact digest 降低重复/污染风险。
- Result review 并行会让节点完成顺序与计划顺序不同；resume planner 必须使用稳定排序和有效产物判断，而不是仅靠 mtime。
- 已有代码已经实现了一部分 step-level resume；实施时应优先扩展现有 checkpoint/resume 机制，避免另起一套不兼容的状态文件。
