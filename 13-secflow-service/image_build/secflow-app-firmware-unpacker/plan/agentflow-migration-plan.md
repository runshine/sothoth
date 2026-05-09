# SecFlow Firmware Unpacker AgentFlow 迁移剩余计划

更新日期：2026-05-08

## 范围说明

AgentFlow 迁移主干已完成：服务入口、pipeline builder、runner、skill 命中/fallback、skill author、DB/API 字段、Docker runtime smoke 和基础单测均已落地。

生产灰度与生产切换不再纳入本计划。本文只保留已完成的迁移验收工作。

## 完成事项

### 1. 扩展真实固件回归样本集 `[DONE]`

目标：覆盖当前 smoke 没有充分验证的真实 LLM/pi 执行路径。

任务：

- 增加非 `preprocess` 成功路径的真实固件样本。
- 增加真实 `generic_executor` / `generic_reviewer` 解包样本。
- 增加真实 skill success 样本。
- 增加真实 skill fallback 到 generic 的样本。
- 为每个样本保存稳定的期望结果、耗时、轮次、fallback 行为和候选 skill 行为。

涉及文件：

- `plan/agentflow-regression-samples.json`
- `plan/agentflow-regression-fixtures/`
- `scripts/agentflow_regression_eval.py`
- `tests/test_agentflow_regression_eval.py`

验收标准：

- 固定样本集至少覆盖：
  - `preprocess` success
  - skill hit success
  - skill hit failed then fallback success
  - no skill then generic success
  - generic failed / max retries
- `python scripts/agentflow_regression_eval.py plan/agentflow-regression-samples.json` 能稳定通过。
- 回归结果能展示每个样本的 `status`、`rounds`、`fallback_to_llm`、`generated_skill_path`、token 汇总和耗时。

### 2. 补齐真实 AgentFlow 运行证据 `[DONE]`

目标：证明迁移链路不只在 fake `pi` 和小 zip smoke 下可用。

任务：

- 用真实 `pi` 跑通固定样本集中的 generic 解包样本。
- 用真实 `pi` 跑通固定样本集中的 skill success/fallback 样本。
- 保存每类样本的 `final_result.json`、`tokens_summary.json`、`run.json` 和关键 stage 输出。
- 记录失败样本的节点、原因和是否触发预期 fallback。

涉及文件：

- `plan/agentflow-regression-fixtures/`
- `app/agentflow_runner.py`
- `app/agentflow_pipeline.py`

验收标准：

- 每类关键路径至少有一份可复查的真实运行 fixture。
- fixture 不依赖临时绝对路径或本机私有状态。
- regression eval 可以读取这些 fixture 并给出稳定判定。

### 3. 收敛 prompt 复用差异 `[DONE]`

目标：降低 AgentFlow 迁移后与旧解包语义的漂移风险。

任务：

- 核对 `app/agentflow_pipeline.py` 中各节点 prompt 与 `app/agent/prompt/*.md` 的差异。
- 将仍依赖临时 marker 协议的 prompt 逐步收敛到现有模板。
- 保留 AgentFlow 必需的 success marker，但避免重复维护两套业务语义。

涉及文件：

- `app/agentflow_pipeline.py`
- `app/agent/prompt/unpack-firmware.md`
- `app/agent/prompt/retry-firmware-unpack.md`
- `app/agent/prompt/review-firmware-unpack.md`
- `app/agent/prompt/author-firmware-skill.md`
- `app/agent/prompt/cleanup-firmware.md`

验收标准：

- pipeline 中的核心 agent prompt 均能追溯到现有 prompt 模板。
- prompt 改动后固定样本集回归通过。


## 完成证据

- 固定回归门禁：`python scripts/agentflow_regression_eval.py --manifest plan/agentflow-regression-samples.json`。
- 自进化 smoke：`scripts/agentflow_self_evolution_smoke.sh`。
- 全量测试：`pytest -q`。
- 运行与运维证据：`plan/agentflow-operationalization.md`。
