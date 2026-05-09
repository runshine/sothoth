# AgentFlow 自进化剩余计划

更新日期：2026-05-08

## 范围说明

当前项目已经具备自进化骨架：AgentFlow pipeline、runner result adapter、skill success/fallback、候选 skill 保存和 skill 生命周期都已接入。本文只保留尚未完成的闭环建设。

## 当前缺口

- token / 成本聚合仍需补齐。
- 节点级耗时、失败摘要和演化来源字段仍不完整。
- 固定离线评测集还需要扩展到真实固件样本。
- 图级优化和 tuned agent 演化还没有纳入服务运行面。
- 失败样本还没有形成可复用的离线演化输入。

## 完成阶段

### 阶段 A：补齐观测与判定 `[DONE]`

目标：让系统能判断策略变化是真的变好，还是只是输出更像成功。

任务：

- 补齐 `tokens_summary.json`。
- 增强节点级耗时与失败原因。
- 给 `final_result.json` 增加更明确的演化来源字段：
  - `matched_skill`
  - `generated_skill_path`
  - `fallback_to_llm`
  - `run_id`
  - `node_attempts`
  - `failure_category`

涉及文件：

- `app/agentflow_runner.py`
- `app/api/firmware.py`
- `app/model.py`
- `app/schemas.py`

验收标准：

- 任意一次解包都能回溯到 run、节点、轮次、技能来源。
- 能区分 skill success、skill fallback success、generic success、generic failed。

### 阶段 B：稳住在线自修正闭环 `[DONE]`

目标：让失败重试变成稳定、可解释、可配置的闭环。

任务：

- 给 `skill_reviewer` 和 `generic_reviewer` 的失败分类标准化。
- 给 `generic_executor` 和 `generic_reviewer` 增加更明确的回边条件。
- 让 `skill_author` 只在成功结果上生成候选 skill。
- 增加失败样本结构化记录，供后续离线演化使用。

失败分类建议：

- `structure_error`
- `missing_content`
- `protocol_error`
- `tool_error`
- `timeout`
- `retryable_unknown`
- `non_retryable`

涉及文件：

- `app/agentflow_pipeline.py`
- `app/agentflow_runner.py`
- `app/skill_store.py`
- `app/agent/prompt/review-firmware-unpack.md`

验收标准：

- 同类失败可以稳定触发预期重试或降级。
- 失败原因能从日志、`final_result.json` 和 `/agentflow` API 中直接看懂。

### 阶段 C：接入离线 skill 演化 `[DONE]`

目标：把成功解包经验沉淀成可复用 skill，而不是只停留在单次运行。

任务：

- 定义候选 skill 的评估门槛。
- 将成功 run 的 trace、stage 输出和 final result 归档为训练样本。
- 增加离线演化入口：
  - 输入：run id / node id
  - 输出：candidate skill 或 tuned agent 版本
- 在 skill 生命周期里加入来源 run、来源样本和评估批次信息。

涉及文件：

- `app/skill_store.py`
- `app/agentflow_runner.py`
- `app/api/firmware.py`
- `scripts/`
- `tests/`

验收标准：

- 成功样本能自动变成可追踪的候选 skill。
- 候选 skill 可以被后续任务直接复用。
- 候选 skill 的来源 run 和评估结果可查。

### 阶段 D：试点图级优化 `[DONE]`

目标：让 pipeline 自身也能进化，但只在安全环境试点。

任务：

- 新增优化轮次开关。
- 只允许在 test / staging profile 下执行 `optimizer + n_run`。
- 限制优化器只能改安全区：
  - 节点 prompt
  - 节点顺序
  - reviewer 数量
  - retry 策略
- 保存优化前后图与校验结果。
- 建立优化结果是否更好的验收表。

禁止优化器直接改动：

- DB 结构
- 任务状态语义
- 输出目录协议
- 对外 API 兼容字段

涉及文件：

- `app/agentflow_pipeline.py`
- `app/config.py`
- `config.yaml`
- `tests/`

验收标准：

- 能生成 `pipeline.original.py` 和 `pipeline.edited.py` 或等价可审计产物。
- 优化轮次不会破坏任务状态和输出协议。
- 优化后的 pipeline 必须通过固定样本集回归。

### 阶段 E：建立回归评测门禁 `[DONE]`

目标：让自进化有稳定判卷标准。

任务：

- 扩展稳定固件样本集。
- 为每个样本记录正确结果基线。
- 用批量跑法比较：
  - 原始图
  - 加优化轮次
  - 加 tuned skill
  - 加 tuned agent
- 将评测结果作为新策略上线前的门禁。

推荐指标：

- `success_rate`
- `avg_rounds`
- `avg_duration_seconds`
- `avg_token_count`
- `fallback_to_llm_rate`
- `candidate_skill_promotion_rate`

涉及文件：

- `plan/agentflow-regression-samples.json`
- `plan/agentflow-regression-fixtures/`
- `scripts/agentflow_regression_eval.py`
- `tests/test_agentflow_regression_eval.py`

验收标准：

- 新策略必须在固定样本集上通过回归门槛才允许启用。
- 评测报告能解释失败样本、退化样本和收益样本。

## 推荐落地顺序

1. 阶段 A：补齐观测与判定。
2. 阶段 B：稳住在线自修正闭环。
3. 阶段 E：扩展回归评测门禁。
4. 阶段 C：接入离线 skill 演化。
5. 阶段 D：试点图级优化。

## 失败保护

- 图优化只在测试环境启用。
- tuned agent 先只允许本地 target。
- 候选 skill 默认不自动升 active，仍然要看成功计数和离线评测结果。
- 所有自动演化都必须保留原始 run 产物，便于回滚和追责。


## 完成证据

- 固定回归门禁：`python scripts/agentflow_regression_eval.py --manifest plan/agentflow-regression-samples.json`。
- 自进化 smoke：`scripts/agentflow_self_evolution_smoke.sh`。
- 全量测试：`pytest -q`。
- 运行与运维证据：`plan/agentflow-operationalization.md`。
