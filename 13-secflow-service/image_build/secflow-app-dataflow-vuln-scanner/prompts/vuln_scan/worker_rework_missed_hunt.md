# 第 {cycle} 轮 Rework：依据评审缺口挖掘遗漏漏洞

本节点唯一目标是降低漏报率：**根据全面性评审和深入性评审指出的缺失，继续审计真实源码，挖掘之前轮次漏掉、跳过或只浅尝辄止的漏洞。** 不要把本节点做成 coverage closure、候选管理、JSON 记录或文档补全。

{rework_session_context}

## 全面性评审指出的缺失范围
{completeness_rework_plan}

## 深入性评审指出的深挖方向
{depth_rework_plan}

## 已有有效结果的变体参考
{missed_hunt_variant_seeds}

## Coverage / Issue 辅助线索
{coverage_hypothesis_queue}

## 本节点的源码审计方式
- 先从全面性评审中选出最可能造成漏报的缺失范围：未覆盖入口、未跟入 EXPORT/USED、未检查兄弟分支、未分析的高风险 sink、未闭环的 INPUT 到 sink 路径。
- 再从深入性评审中提取需要继续深挖的问题：保护条件是否真的充分、边界值是否绕过、类型转换/整数截断是否改变长度、错误路径/释放路径/并发时序是否和主路径不同、已有结论是否遗漏变体。
- 对每条高价值缺口，必须读取实际代码并沿数据流跟踪：攻击者可控输入或状态 -> 关键变量传播 -> 校验点 -> sink/危险操作 -> 影响。不要只复述 summary、ledger 或评审意见。
- 优先查“可能产出真实漏洞”的路径，而不是机械处理 open obligation 数字。Coverage / Issue 只作为定位源码和风险路径的线索，不是本节点的完成目标。
- 已有有效 result 只作为变体种子：入/出方向、成功/失败路径、配置/状态差异、相邻函数或相似调用链是否存在同类但尚未报告的漏洞。
- 如果源码证明某条路径没有漏洞，可以简短记录原因后切换到下一条高价值缺口，不要把本轮时间消耗在大批量 source_closed。

## 产出规则
- 发现真实新漏洞：新增最小粒度 `results/result_NNN.md`，必须说明它相对已有 result 的新增点，不要重复包装旧结论。
- 发现已有 result 背后遗漏的独立变体：新增更高编号 result，并在开头标注它和原 result 的关系。
- 未发现新漏洞：可创建或更新 `supporting_docs/missed_hunt_cycle_{cycle}.md`，只记录本轮实际审计过的高价值缺口、读取的关键源码位置、为什么没有形成漏洞；控制在 80 行以内。
- 不创建 JSON manifest，不编辑 `summary.md`，不手工编辑 `_meta/coverage_ledger.json` 或 `_meta/issue_ledger.json`。

不要复制 coverage ledger 大表，不要粘贴长源码，不要把 design-quality 建议伪装成安全漏洞。

{numbering_rules}
{result_report_template}
{direct_read_instruction}
