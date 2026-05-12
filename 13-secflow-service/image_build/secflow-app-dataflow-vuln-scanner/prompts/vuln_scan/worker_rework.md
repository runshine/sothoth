# 第 {cycle} 轮评审返工 Rework：数据流 issue 定向闭环

你现在进入返工阶段。注意：**Worker 的所有 cycle 共用同一个 session**，你已经保留了前序 work / reflection / summary 的上下文。本轮不要重复首轮完整扫描，也不要重读所有历史产物；只围绕下面的增量目标队列做有边界的补全、修复和加深。

核心职责：
- P0：修复、撤回或补证未通过评审的 `results/result_NNN.md`。
- P1：关闭 worker 可执行 active issues。
- P2：只处理本轮目标队列列出的高优先级 coverage obligations。
- 新增探索必须能回应 P0/P1/P2 或明确源码证据缺口；禁止脱离数据流主轴做无边界全量重扫。
- 本阶段只产出或修复 `results/` 与 `supporting_docs/`；正式 `summary.md`、`previous_limitations.md`、coverage/issue ledger 映射交给后续显式 summary 阶段统一整理和同步。
- 如果历史 session 中的旧目标与本 prompt 冲突，以本 prompt 的 P0/P1/P2 队列为准。

{rework_session_context}

{required_read_files}

{review_delta_text}

{global_review_feedback}

{repeated_issue_summary}

{rework_priority_queue}

{summary_handoff_queue}

{failed_result_reasons}

{rework_scope_policy}

## 本轮工作目标

- 先完成 P0 failed results 的最小必要修复；确认不成立时应显式撤回或移动为辅助文档，而不是让失败结果继续留在 `results/`。
- 再处理 P1/P2 队列列出的目标：补齐源码证据、调用链、数据流条件、利用前提和风险结论。
- 不要求本轮关闭全部 open obligations；未列入 P2 的大量 open 项不要在本轮主动扩张。
- 若发现已有结论背后还有更深的攻击面，请把新证据写入 `supporting_docs/`；只有能独立成立的漏洞才拆成新的更高编号 `result_NNN.md`。
- 结束时产物必须让下一步 summary 能直接整理：每个新增或修复结果都应能对应到 P0/P1/P2 目标或源码证据。

## Issue / Obligation Closure 记录（本轮强制）

{issue_closure_template}

## 本阶段输出位置

{output_contract_text}

## result_NNN.md 强制模板

{result_report_template}

{numbering_rules}

{convergence_requirements}

{direct_read_instruction}
