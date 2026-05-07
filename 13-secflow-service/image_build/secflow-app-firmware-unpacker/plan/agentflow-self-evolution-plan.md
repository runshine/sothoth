# SecFlow Firmware Unpacker AgentFlow 自进化落地计划

编写日期：2026-05-07
更新日期：2026-05-07

## 0. 执行摘要

当前项目已经不是“从零搭自进化”，而是已经具备一条可以继续长出来的骨架：

- `app/agentflow_pipeline.py` 已经把解包流程编成 AgentFlow 图。
- `app/agentflow_runner.py` 已经把运行结果、技能沉淀、回退逻辑接到业务侧。
- `app/skill_store.py` 已经有 `candidate` / `active` / `archived` 的技能生命周期。

所以本计划不再讨论“要不要做自进化”，而是把它拆成 4 条可落地的闭环：

1. 在线自修正：失败后自动重试、评审回流、分歧仲裁。
2. 离线演化：把成功轨迹沉淀成可复用 skill 或 tuned agent。
3. 图级优化：让 AgentFlow 在正式执行前改写 pipeline。
4. 批量评测：用固定样本集持续验证新策略是否真的更好。

## 1. 现状与边界

### 1.1 已有能力

- `app/agentflow_pipeline.py`
  - `preprocess -> feature_match -> skill_executor -> skill_reviewer -> generic_executor -> generic_reviewer -> skill_author -> cleanup -> finalize`
  - 已有 `on_failure` 回边，天然支持局部迭代。
- `app/agentflow_runner.py`
  - 已能读取 run store、写 `final_result.json`、`stage*.json`、`tokens_summary.json`。
  - 已能基于运行结果更新技能成功次数，并保存候选 skill。
- `app/skill_store.py`
  - 已有候选 skill 保存、版本递增、成功计数、激活阈值。

### 1.2 当前缺口

- token / 成本聚合还是占位。
- 节点级耗时和失败摘要还不够完整。
- 没有固定的离线评测集来比较新旧策略。
- 图级优化和 tuned agent 演化还没有纳入服务运行面。

## 2. 自进化机制到项目能力的映射

### 2.1 在线自修正

对应机制：

- `review.on_failure >> executor`
- 多 reviewer 互审
- `success_criteria` 作为硬门槛

落地到本项目：

- 继续保留 `generic_executor` / `generic_reviewer` 的失败回流。
- 给 `skill_reviewer`、`generic_reviewer` 加更明确的失败分类：
  - 结构性失败
  - 内容缺失
  - 输出不符合协议
  - 需要重新尝试
- 让 `finalize` 根据失败分类决定是重试、降级还是直接失败。

### 2.2 离线演化

对应机制：

- `evolve(...)`
- trace 驱动的 tuned agent
- 成功样本反哺 profile / prompt / skill

落地到本项目：

- 把成功的 `trace.jsonl`、`final_result.json`、`stage*.json` 作为训练样本。
- 离线生成两类产物：
  - `skill`：用于固件家族级别复用。
  - `tuned agent`：用于固定角色的提示词和工具策略升级。
- 将演化过程放到后台维护任务或手工运维命令中，不直接阻塞在线任务。

### 2.3 图级优化

对应机制：

- `optimizer="codex"`
- `n_run > 1`
- 让模型在执行前改写 pipeline

落地到本项目：

- 先只在测试环境启用图优化轮次。
- 让优化器只改“安全区”：
  - 节点 prompt
  - 节点顺序
  - reviewer 数量
  - retry 策略
- 严禁优化器直接改动：
  - DB 结构
  - 任务状态语义
  - 输出目录协议

### 2.4 批量评测

对应机制：

- fanout / merge
- 多模型 debate
- 多样本回归评测

落地到本项目：

- 建立固定固件样本集。
- 为每个样本跑同一 pipeline 的多个变体：
  - 原始版本
  - 加强 reviewer 版本
  - tuned skill 版本
  - tuned agent 版本
- 用统一指标比较：
  - 成功率
  - 平均轮次
  - 平均耗时
  - token 消耗
  - 候选 skill 命中率

## 3. 分阶段实施计划

### 阶段 A：补齐观测与判定

目标：让系统能判断“这次改动是变好了，还是只是更会说话了”。

任务：

- 补齐 `tokens_summary.json`。
- 增强节点级耗时与失败原因。
- 给 `final_result.json` 增加更明确的演化来源字段：
  - `matched_skill`
  - `generated_skill_path`
  - `fallback_to_llm`
  - `run_id`
  - `node_attempts`

涉及文件：

- `app/agentflow_runner.py`
- `app/api/firmware.py`
- `app/model.py`

验收标准：

- 任意一次解包都能回溯到 run、节点、轮次、技能来源。
- 能区分“成功但退化”和“成功且更优”。

### 阶段 B：稳住在线自修正闭环

目标：把失败重试变成稳定、可解释、可配置的闭环。

任务：

- 给 reviewer 失败分类标准化。
- 给 `generic_executor` 和 `generic_reviewer` 增加更明确的回边条件。
- 让 `skill_author` 只在成功结果上生成候选 skill。
- 增加失败样本的结构化记录，供后续离线演化使用。

涉及文件：

- `app/agentflow_pipeline.py`
- `app/agentflow_runner.py`
- `app/skill_store.py`

验收标准：

- 同类失败可以稳定触发重试。
- 失败原因能从日志和结果文件里直接看懂。

### 阶段 C：接入离线 skill 演化

目标：把成功解包经验沉淀成可复用 skill，而不是只停留在单次运行。

任务：

- 定义候选 skill 的评估门槛。
- 将成功 run 的 trace 和产物归档为训练样本。
- 增加一个离线演化入口：
  - 输入：run id / node id
  - 输出：candidate skill 或 tuned agent 版本
- 在 skill 生命周期里加入“来源 run”与“评估批次”信息。

涉及文件：

- `app/skill_store.py`
- `app/agentflow_runner.py`
- `app/api/firmware.py`

验收标准：

- 成功样本能自动变成可追踪的候选 skill。
- 候选 skill 可以被后续任务直接复用。

### 阶段 D：试点图级优化

目标：让 pipeline 自己也能进化，但先只在安全环境试点。

任务：

- 新增优化轮次开关。
- 只允许在 staging / test profile 下执行 `optimizer + n_run`。
- 保存优化前后图与校验结果。
- 建立“优化后是否真的更好”的验收表。

涉及文件：

- `app/agentflow_pipeline.py`
- `app/config.py`
- `config.yaml`
- `plan/agentflow-migration-plan.md`（补充阶段说明）

验收标准：

- 能生成 `pipeline.original.py` 和 `pipeline.edited.py`。
- 优化轮次不会破坏任务状态和输出协议。

### 阶段 E：建立回归评测集

目标：让自进化有判卷标准。

任务：

- 收集一批稳定固件样本。
- 为每个样本记录“正确结果”的基线。
- 用批量跑法比较：
  - 原始图
  - 加优化轮次
  - 加 tuned skill
  - 加 tuned agent

推荐指标：

- `success_rate`
- `avg_rounds`
- `avg_duration_seconds`
- `avg_token_count`
- `candidate_skill_promotion_rate`

涉及文件：

- `plan/`
- `scripts/`
- `tests/`

验收标准：

- 新策略必须在固定样本集上通过回归门槛才允许上线。

## 4. 推荐落地顺序

1. 先补观测。
2. 再稳在线重试。
3. 然后做离线 skill 演化。
4. 再试图做图级优化。
5. 最后把批量评测变成上线门禁。

这个顺序的好处是：每一步都能独立带来收益，而且不会把“自进化”做成一个黑箱。

## 5. 失败保护

- 图优化只在测试环境启用。
- tuned agent 先只允许本地 target。
- 候选 skill 默认不自动升 active，仍然要看成功计数和离线评测结果。
- 所有自动演化都必须保留原始 run 产物，便于回滚和追责。

## 6. 里程碑

### M1

- 运行结果可完整回溯。
- token / 耗时 / 失败原因可见。

### M2

- 在线重试闭环稳定。
- 候选 skill 生成可追踪。

### M3

- 离线 skill 演化可跑通。
- 能从 run 生成可复用版本。

### M4

- 图级优化在测试环境可验证。

### M5

- 固定样本集回归门禁上线。

