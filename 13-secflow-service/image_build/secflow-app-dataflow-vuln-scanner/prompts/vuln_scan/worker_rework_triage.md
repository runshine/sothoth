# 第 {cycle} 轮 Rework Triage：只处理失败评审的阻塞项

Worker 的所有 cycle 共用同一个 session。你已拥有前序上下文；本节点只做判断和取舍，不写文件、不改 `results/`、不改 `summary.md`、不改 `_meta/`。

目标：只从 **FAIL advisor issues** 和 **failed result** 中找出本轮最值得投入的漏洞审计方向。判断标准只有两个：能否降低漏报率，能否降低误报率。PASS 评审只作为 guardrail，不得当成继续挖洞、继续修结果或放松审计的理由。

{rework_session_context}
{required_read_files}

## 全面性评审 FAIL issues / PASS guardrail
{completeness_rework_summary}

## 深入性评审 FAIL issues / PASS guardrail
{depth_rework_summary}

## 结果评审 failed result 摘要
{result_repair_summary}

## Triage 方式
- 先识别必须处理的误报风险：failed result、严重度被评审质疑、证据与源码冲突、无法验证 JSON 但结论可能影响结果可信度。详细修复留给下一节点，不在 triage 重复展开。
- 再识别最可能漏报的审计缺口：只接受 failed advisor issue 中明确指出的入口/分支/sink、已有 result 的兄弟路径、保护条件疑似不充分的路径、或缺少源码证据的高风险路径。
- PASS advisor 的反馈不进入行动清单；若某维度 PASS，只输出 `no_action / guardrail`，不要复述表扬性长反馈。
- 每个保留方向都要能落到实际源码审计动作：读哪个函数/文件、跟哪条数据流、检查哪个校验或危险操作。
- 低收益项直接放弃或延后：只影响 coverage 数字、只要求整理文档、不能指向具体代码路径、不能提升漏洞发现或误报压制的反馈，不要占用后续节点。

## 输出要求
只在当前回复里给后续节点一个短计划：
- `Must_fix_false_positives`: 只列 failed result 文件名和优先级，不复述详细原因。
- `Missed_vuln_focus`: 只列 failed advisor issue 驱动的 2-4 个源码审计方向。
- `Passed_review_guardrails`: 列出 PASS advisor 的 no-action/保护边界，不写表扬性原文。
- `Skip_or_defer`: 不处理的低收益反馈及一句话原因。

不要复制长评审文本，不要粘贴长源码，不要创建计划文件，但是你要对计划负责。

{direct_read_instruction}
