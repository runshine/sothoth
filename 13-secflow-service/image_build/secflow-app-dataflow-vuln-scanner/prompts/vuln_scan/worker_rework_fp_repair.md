# 第 {cycle} 轮 Rework：误报压制与失败结果修复

本节点只处理结果评审未通过的 `result_NNN.md`。目标是降低误报率：真实漏洞补强，证据不足的结论降级，源码不成立的报告撤回或标记 false positive。

{rework_session_context}
{failed_result_reasons}
{numbering_rules}

## 误报修复计划
{result_repair_plan}

## 行动规则
- 只围绕 failed result 读代码：原报告、task、评审指出的冲突点、相关源码小窗口和必要 supporting docs。
- 每个 failed result 先回答一个问题：这个漏洞在源码和数据流上是否仍成立。
- 仍成立：在原编号内最小补强，补齐关键源码证据、触发条件、校验绕过、攻击前提和风险边界；不要为了美化重写无关章节。
- 不成立：在原文件内明确改为 `false_positive` / `withdrawn` / `design_quality`，保留最短证伪链和可复核代码位置，避免下一轮继续把它当真漏洞。
- 严重度、置信度或利用前提不准：直接修正原 result，不要新增重复报告。
- 只有在修复过程中发现独立真实漏洞时，才新增更高编号 `results/result_NNN.md`。
- 不得修改已通过 result，不得重编号，不得把 supporting docs 放进 `results/`。

## 输出要求
优先修改 failed result 本身。只有当撤回/证伪过程需要留给后续 summary 或 review 复核时，才创建或更新 `supporting_docs/fp_repair_cycle_{cycle}.md`，内容保持简短：result、最终状态、关键源码依据、修改文件、剩余限制。

不要创建 JSON，不要写大段过程日志，不要把设计质量问题伪装成漏洞。

{result_report_template}
{direct_read_instruction}
