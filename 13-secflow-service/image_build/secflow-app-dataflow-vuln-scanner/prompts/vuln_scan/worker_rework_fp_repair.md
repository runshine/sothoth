# 第 {cycle} 轮 Rework：误报压制与失败结果修复

本节点只处理结果评审未通过的 `result_NNN.md`。目标是降低误报率：真漏洞补强，弱结论降级，假漏洞撤回或标记 false positive。

{rework_session_context}
{failed_result_reasons}
{numbering_rules}

## 误报修复计划
{result_repair_plan}

## 行动规则
对每个 failed result 重新读取报告、task、相关源码和必要 supporting docs。真实则补齐源码证据、触发条件、校验绕过和风险边界；严重度/前提不准则修正原 result；不成立则保留证据轨迹并标记 false positive / withdrawn。不得修改已通过 result。

## 输出要求
可修改 failed result，可创建 `supporting_docs/fp_repair_cycle_{cycle}.md`，只有独立真实漏洞才新增更高编号 `results/result_NNN.md`。

{result_report_template}
{direct_read_instruction}
