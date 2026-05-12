# 第 {cycle} 轮 Rework：评审驱动的漏报补扫与深挖

本节点的目标是降低漏报率。只围绕全面性评审和深入性评审指出的高收益路径继续挖真漏洞，不做全量重扫。

{rework_session_context}

## 全面性评审驱动的漏报补扫
{completeness_rework_plan}

## 深入性评审驱动的深挖问题
{depth_rework_plan}

## Coverage / Issue 作为漏洞假设来源
{coverage_hypothesis_queue}

## 行动规则
对每个高优先级假设，先形成攻击者可控性、传播路径、sink、校验绕过问题。确认真实漏洞则新增最小粒度 `results/result_NNN.md`；证伪高价值路径则写入 `supporting_docs/missed_hunt_cycle_{cycle}.md`。不要为了关闭 coverage 数字处理低收益 obligation。

{numbering_rules}
{result_report_template}
{direct_read_instruction}
