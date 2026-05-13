# 第 {cycle} 轮 Rework Handoff：交接本轮漏洞变化

本节点不继续扩张攻击面、不再做源码审计。目标是把本轮真正影响漏洞结论的变化交接给后续 summary：新增了什么真实漏洞，修正了什么真漏洞，撤回了什么误报，还有哪些高价值缺口仍需要下一轮看。

{rework_session_context}

## Summary / Ledger handoff
{summary_handoff_queue}

## 重复阻塞项
{repeated_issue_summary}

## Handoff 规则
- 只记录会影响最终漏洞结论或下一轮审计优先级的信息。
- 必须覆盖：新增 result、修改后的 result、撤回/证伪的 result、重要 residual、下一轮仍值得看的高价值漏报方向。
- 不要为了关闭 issue/coverage 数字写大段 source_closed；低收益项可以一句话说明已跳过。
- 不要手工编辑 `_meta/coverage_ledger.json` 或 `_meta/issue_ledger.json`。
- 不创建 JSON manifest。

## 输出要求
如果本轮有新增、修改、撤回或重要 residual，创建或更新 `{supporting_docs_dir}/rework_closure_cycle_{cycle}.md`，只引用 `results/...` 和 `supporting_docs/...`。

如果本轮没有实际漏洞变化，只在回复中简短说明“无新增/修改/撤回”，不要额外创建文件。

{direct_read_instruction}
