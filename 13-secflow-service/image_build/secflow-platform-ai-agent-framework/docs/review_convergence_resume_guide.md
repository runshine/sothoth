# 漏洞扫描收敛控制与 resume 操作说明

本文说明本次新增的 3 组机制在**真实 run**里的表现、应该查看哪些文件、以及何时适合继续 `resume`、何时应该拆任务/止损。

---

## 一、这次新增了什么

### 1. Global review 改为 packet/path-based
全局评审不再把 `task.md`、`summary.md`、上一轮 limitations 等大文件全文直接塞进 prompt。

现在每轮会先生成一个评审入口文件：

- `_meta/review_packets/cycle_XXX/global_review_packet.json`

并同时生成：

- `_meta/review_packets/cycle_XXX/results_manifest.json`
- `_meta/review_packets/cycle_XXX/previous_limitations.md`
- `_meta/review_packets/cycle_XXX/open_blockers.json`

advisor prompt 只拿这些**路径**，再通过 `read/bash` 按需读取真实文件。

**效果：**
- reviewer 输入体积被限制住，不再随着 summary 无上限膨胀
- 更不容易触发 provider 长上下文失败（如 499 / timeout / body 过大）

---

### 2. 引入 blocker backlog
每轮 global review 不再只是返回一段自由文本，而是尽量返回结构化：

- `blocking_issues`
- `resolved_issues`

框架会把它们维护成一个**稳定 backlog**：

- 未显式 `resolved` 的 blocker，不会因为下一轮没提到就消失
- 同一 blocker 应复用同一 `id`
- backlog 数量有上限，避免无限膨胀

每轮会写：

- `reviews/global/cycle_XXX/<advisor>.json`（原始评审记录）
- `_meta/blockers/cycle_XXX.json`（归一化后的 open blockers 快照）

**效果：**
- global review 的目标不再每轮漂移
- worker 返工 prompt 拿到的是 backlog，而不是一大段不可执行 prose
- “还有哪些没关掉”变成可审计状态

---

### 3. 引入 plateau detection + closure mode
框架现在会监控每轮的收敛指标：

- open blocker 是否下降
- passed result 是否增长
- global review scores 是否有提升
- summary/results 是否至少表现出收缩趋势

如果连续多轮满足“没进展”，则：

1. 先切换到 `closure` 模式
2. 如果在 `closure` 模式里仍继续停滞，则**提前终止**，而不是一直跑到 `max_review_cycles`

每轮会写：

- `_meta/cycle_metrics/cycle_XXX.json`
- `_meta/review_summaries/cycle_XXX.json`

其中：
- `review_summaries` 是高层摘要
- `cycle_metrics` 更偏向收敛诊断

**效果：**
- 不再出现“明知没收敛还继续无脑返工很多轮”的情况
- 后期 worker 会进入“收敛模式”，优先关 backlog、修弱报告、修 summary 一致性，而不是继续无限扩张

---

## 二、三个单调性如何在真实 run 中体现

### 单调性 1：已通过结果集合单调增长
现在即使 **global review 不通过**，框架也会继续执行 **result review**。

这意味着：
- 某个 `result_NNN.md` 一旦通过结果评审，就会被尽早冻结
- 下一轮 worker prompt 会明确列出：
  - `已通过评审的结果（请勿修改）`
- 若模型误覆盖该文件，框架会尝试恢复并把新内容迁移到更高编号

你可以查看：
- `reviews/results/result_XXX/cycle_YYY/*.json`
- `_meta/review_summaries/cycle_YYY.json`

重点看：
- `passed_files`
- `failed_files`

如果某文件一直没变、且已通过，那么 resume 后通常不会再进入 pending result review。

---

### 单调性 2：open blocker 集合有界且不会被静默清空
你可以查看：

- `_meta/blockers/cycle_XXX.json`
- `_meta/review_packets/cycle_XXX/open_blockers.json`
- `reviews/global/cycle_XXX/global_quality.json`

重点关注：
- `blockers[].id`
- `blockers[].required_action`
- `open_count`

正常现象：
- 同一个 blocker id 跨多轮持续存在，直到真正解决
- reviewer 即使下一轮没再提，框架也会继续保留旧 blocker

异常信号：
- backlog 里的 blocker 长期不变
- `required_action` 基本没变化
- worker 一直在扩张 summary/result，但 blocker 没减少

这通常意味着：**进入 plateau / 需要 closure / 或应拆任务**。

---

### 单调性 3：review 输入体积有上限
你可以检查：

- `_meta/review_packets/cycle_XXX/global_review_packet.json`
- 对应 advisor 调用目录下的 `user_prompt.md`（若底层 runtime 会落盘）

正常现象：
- prompt 里应该主要是文件路径，而不是大段 summary 正文
- `summary.md` 越大，packet 文件里引用路径仍然稳定，不会等比例膨胀进 prompt

---

## 三、真实 run 中建议怎么排查

假设 run 目录为：

- `runs/<run_name>/`

其 atomic 工作目录通常在：

- `runs/<run_name>/workspace/pipeline_<execution_id>/stage_01_vuln_scan/vuln_scan_initial_001/`

下面简称为 `<atomic_work_dir>`。

### 第一步：先看每轮摘要
看：

- `<atomic_work_dir>/_meta/review_summaries/cycle_XXX.json`

重点字段：
- `workflow_mode`
- `outcome`
- `global_review.passed`
- `global_review.open_blockers`
- `result_review.passed_files`
- `result_review.failed_files`
- `plateau_status`

如果发现：
- `workflow_mode` 从 `discovery` 变成 `closure`
- `open_blockers` 长期不变
- `passed_files` 长期不增长

说明系统已经识别到“继续扩张没有意义”，开始尝试收敛。

---

### 第二步：看 blocker backlog 到底卡在哪
看：

- `<atomic_work_dir>/_meta/blockers/cycle_XXX.json`

重点看：
- `id`
- `category`
- `target`
- `required_action`
- `first_seen_cycle`
- `last_seen_cycle`
- `seen_count`

判断方法：
- 如果 blocker id 一直相同，`seen_count` 持续增加，说明 worker 没真正关掉它
- 如果 blocker 已经很少（例如只剩 1~3 个），但仍一直关不掉，通常说明应该切分任务，或者需要人工介入检查要求是否过严

---

### 第三步：看 plateau 诊断
看：

- `<atomic_work_dir>/_meta/cycle_metrics/cycle_XXX.json`

重点看：
- `scores`
- `open_blocker_count`
- `passed_result_count`
- `summary_size`
- `plateau_status.stagnant`
- `plateau_status.streak`
- `plateau_status.switched_to_closure`
- `plateau_status.abort`
- `plateau_status.reason`

如果看到：
- `switched_to_closure = true`

说明从这一轮开始，下一轮 worker prompt 会变成“优先收敛，不再无限扩张”。

如果看到：
- `abort = true`

说明框架判断：
- backlog 没减少
- passed results 没增加
- scores 没提升
- 产物没有收缩趋势

继续跑只是在烧 token。

---

## 四、resume 之后会发生什么

使用：

```bash
python run_vuln_scan.py \
  --resume-run-dir runs/<run_name> \
  --extra-cycles 3
```

resume 时框架会自动恢复：

### 1. worker session
会尝试从：
- `<atomic_work_dir>/sessions/`

中找到历史 `pi-worker` session，继续在原上下文上执行。

### 2. review state
会从历史文件重建：
- global review history
- open blockers backlog
- passed / failed result 状态
- closure mode

来源主要是：
- `reviews/global/cycle_*/...json`
- `reviews/results/result_*/cycle_*/...json`

### 3. worker prompt 模式
如果你在失败前已经进入 `closure`，resume 后下一轮 worker prompt 会直接继续：
- closure 模式
- 带着旧 blocker backlog
- 带着已通过结果保护列表

这意味着 resume **不会丢失收敛上下文**。

---

## 五、什么时候适合 resume，什么时候不适合

### 适合 resume
满足以下任一：
- 已有 run 被机器中断/断电/进程退出，但 backlog 还很清晰
- 已通过结果已经稳定，且只剩少量 blocker 未关
- 已进入 `closure`，但你愿意再给 1~3 轮机会

建议：
- `--extra-cycles 1~3`
- 不建议一口气加太多轮

---

### 不适合 resume
满足以下情况时，更适合拆任务或改策略：
- open blockers 长期不下降
- worker 不断扩 summary/result，但 scores 基本不动
- 一个原子任务攻击面过大（例如大量 EXPORT/USED）
- 已经多次进入 closure 后仍停滞

此时更推荐：
- 拆分数据流子任务
- 将 backlog 最关键 blocker 转成 follow-up task
- 或降低“单原子任务必须接近穷尽”的范围

---

## 六、建议的实际操作顺序

### 场景 A：run 失败，想判断值不值得 resume
1. 看 `_meta/review_summaries/` 最后 2~3 轮
2. 看 `_meta/blockers/` 最后一轮还有几个 blocker
3. 看 `_meta/cycle_metrics/` 是否已经 `abort=true` 或 `workflow_mode=closure`

如果：
- blocker 很少
- passed results 已经稳定
- 没有明显继续膨胀

则可以尝试：

```bash
python run_vuln_scan.py --resume-run-dir runs/<run_name> --extra-cycles 1
```

---

### 场景 B：resume 后仍失败
优先看：
- 新一轮的 `_meta/blockers/cycle_XXX.json`
- 新一轮的 `_meta/cycle_metrics/cycle_XXX.json`

如果 blocker id 基本没变、`seen_count` 增加，但 `required_action` 仍然相同，说明问题不是“轮次不够”，而是：
- 任务应拆分
- reviewer 标准与任务规模不匹配
- 或 worker 无法在当前上下文下再实质推进

---

## 七、关键文件速查

在 `<atomic_work_dir>` 下：

### 收敛控制相关
- `_meta/review_summaries/cycle_XXX.json`
- `_meta/cycle_metrics/cycle_XXX.json`
- `_meta/blockers/cycle_XXX.json`

### global review 输入相关
- `_meta/review_packets/cycle_XXX/global_review_packet.json`
- `_meta/review_packets/cycle_XXX/results_manifest.json`
- `_meta/review_packets/cycle_XXX/previous_limitations.md`
- `_meta/review_packets/cycle_XXX/open_blockers.json`

### 评审原始记录
- `reviews/global/cycle_XXX/*.json`
- `reviews/results/result_XXX/cycle_YYY/*.json`

### 结果与备份
- `results/result_NNN.md`
- `removed_results/cycle_XXX/result_NNN.md`
- `removed_results/cycle_XXX/result_NNN.json`
- `final_output/results/...`
- `final_output/removed_results/...`

---

## 八、一句话判断规则

- **看到 backlog 在减少、passed results 在增加**：可以继续跑
- **看到进入 closure 后仍无进展**：不要盲目继续加轮次
- **看到 backlog 长期不变且 summary 继续变大**：应拆任务，而不是继续堆 prompt
