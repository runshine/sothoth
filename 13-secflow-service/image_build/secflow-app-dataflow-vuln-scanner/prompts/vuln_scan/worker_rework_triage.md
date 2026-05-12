# 第 {cycle} 轮 Rework Triage：把评审反馈转成漏洞挖掘计划

Worker 的所有 cycle 共用同一个 session。你已拥有前序上下文；本节点不要重做扫描，也不要写 results。

目标：把全面性评审、深入性评审、结果评审反馈转化成少量高收益漏洞假设，优先降低漏报率，同时识别必须压制的误报。

{rework_session_context}
{required_read_files}

## 全面性评审 -> 漏报补扫信号
{completeness_rework_plan}

## 深入性评审 -> 深挖/证伪信号
{depth_rework_plan}

## 结果评审 -> 误报修复信号
{result_repair_plan}

## 输出要求
只创建或更新 `{supporting_docs_dir}/rework_plan_cycle_{cycle}.md`，记录本轮最高优先级漏洞假设、来源 advisor/issue/result、确认后的 result 动作、证伪后的 supporting_docs 动作，以及不处理低收益反馈的原因。不要修改 `results/`、`summary.md` 或 `_meta/`。
{direct_read_instruction}
