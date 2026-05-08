# 第 {cycle} 轮评审返工 Rework：数据流 issue 定向闭环

你现在进入返工阶段。本阶段目标不是重复首轮完整扫描，而是在上一轮产物基础上围绕 **failed results / active issues / coverage obligations** 做有边界的补全、修复和加深。

核心职责：
- 补全上一轮全局评审、结果评审和 active issue backlog 中指出的问题。
- 修复、撤回或补证未通过评审的 `results/result_NNN.md`。
- 围绕数据流文件中的 INPUT / EXPORT / USED / CLEANED / ★ 及其直接上下游源码做定向闭环。
- 新增探索必须能回应评审问题、coverage obligation、failed result 或明确源码证据缺口；禁止脱离数据流主轴做无边界全量重扫。
- 本阶段只产出或修复 `results/` 与 `supporting_docs/`；正式 `summary.md`、`previous_limitations.md`、coverage/issue ledger 映射交给后续显式 summary 阶段统一整理和同步。

{rework_recovery_context}

{review_delta_text}

{global_review_feedback}

{repeated_issue_summary}

{active_issue_backlog}

{coverage_context}

{failed_result_reasons}

{rework_scope_policy}

## 本轮工作目标

- 逐项关闭 worker 可执行 issue：补齐源码证据、调用链、数据流条件、利用前提和风险结论。
- 对未通过结果优先做最小必要修复；确认不成立时应显式撤回或移动为辅助文档，而不是让失败结果继续留在 `results/`。
- 对 coverage obligation 中仍 open 的入口、EXPORT/USED 终点和关键 sink 做定向追踪，必要时新增更高编号的 `result_NNN.md`。
- 若发现已有结论背后还有更深的攻击面，请把新证据写入 `supporting_docs/`，把能独立成立的漏洞拆成新的最小粒度结果。
- 结束时产物必须让下一步 summary 能直接整理：每个新增或修复结果都应能对应到评审 issue、coverage obligation 或源码证据。

## Issue / Obligation Closure 记录（本轮强制）

{issue_closure_template}

## 本阶段输出位置

{output_contract_text}

## result_NNN.md 强制模板

{result_report_template}

{numbering_rules}

{convergence_requirements}

{direct_read_instruction}
