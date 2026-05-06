# 漏洞扫描收敛控制与 resume 操作说明

当前版本使用**轻量 issue / feedback 链**，不再维护独立的阻塞项状态机。

## 关键产物

- `_meta/review_summaries/cycle_XXX.json`：每轮全局评审、结果评审和收敛状态摘要。
- `_meta/cycle_metrics/cycle_XXX.json`：分数、结果数量、文件指纹、停滞检测信息。
- `_meta/review_feedback/cycle_XXX.json`：最近一轮结构化 issues 与自然语言反馈快照。
- `_meta/checkpoints/current_step.json`：最近执行步骤，用于从中断点 resume。
- `reviews/global/cycle_XXX/*.json`：每个全局评审参谋的原始结构化结论。
- `reviews/results/<result>/cycle_XXX/*.json`：每个结果文件的评审结论。

## issue / feedback 语义

全局评审可输出 `issues` 数组。框架不会把它们维护成长期队列，而是：

1. 记录到对应评审 JSON。
2. 写入最近反馈快照。
3. 注入下一轮 Worker 的返工上下文。
4. 用最近反馈和评分趋势判断是否进入 closure 模式。

因此，Worker 看到的是最近评审反馈，而不是需要手动关闭的持久对象列表。

## resume 行为

`python run_vuln_scan.py --resume-run-dir runs/<name> --dry-run-resume` 会输出：

- 当前 workflow 状态。
- 已完成 cycle。
- 最近 issue 数量和预览。
- plateau / closure 状态。
- step checkpoint 恢复点。
- 若最近一次 agent 调用超时，会显示超时调用目录。

实际 resume 会从 checkpoint 对应阶段继续；已经落盘的全局评审参谋和结果评审项不会重复执行。

## 何时继续 resume

适合继续：

- 最近评分仍在提升。
- 通过的结果文件数量在增加。
- issue 数量下降或内容发生实质变化。
- 上一次失败是超时、网络、进程退出或人工中断。

不建议继续：

- 多轮评分无提升。
- summary 越来越大但问题没有收敛。
- closure 模式下仍无法产生新的证据或修复结果。

此时应拆分任务或人工检查评审要求是否过严。
