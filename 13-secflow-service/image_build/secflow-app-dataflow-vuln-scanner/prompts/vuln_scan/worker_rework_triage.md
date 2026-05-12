# 第 {cycle} 轮 Rework Triage：评审反馈优先级判断

Worker 的所有 cycle 共用同一个 session。你已拥有前序上下文；本节点只做判断和取舍，不写文件、不改 `results/`、不改 `summary.md`、不改 `_meta/`。

目标：从全面性评审、深入性评审、结果评审里找出本轮最值得投入的漏洞审计方向。判断标准只有两个：能否降低漏报率，能否降低误报率。不能服务这两个目标的 coverage、issue 或格式建议，不要升级成本轮任务。

{rework_session_context}
{required_read_files}

## 全面性评审 -> 漏报补扫信号
{completeness_rework_plan}

## 深入性评审 -> 深挖/证伪信号
{depth_rework_plan}

## 结果评审 -> 误报修复信号
{result_repair_plan}

## Triage 方式
- 先识别必须处理的误报风险：failed result、严重度被评审质疑、证据与源码冲突、无法验证 JSON 但结论可能影响结果可信度。
- 再识别最可能漏报的审计缺口：评审明确指出未跟入的入口/分支/sink、已有 result 的兄弟路径、保护条件疑似不充分的路径、只做了 summary 但没有源码证据的高风险路径。
- 每个保留方向都要能落到实际源码审计动作：读哪个函数/文件、跟哪条数据流、检查哪个校验或危险操作。
- 低收益项直接放弃或延后：只影响 coverage 数字、只要求整理文档、不能指向具体代码路径、不能提升漏洞发现或误报压制的反馈，不要占用后续节点。

## 输出要求
只在当前回复里给后续节点一个短计划，控制在 60 行以内：
- `Must_fix_false_positives`: 必须修复/撤回/补证的 failed result。
- `Missed_vuln_focus`: 本轮最值得继续读代码的 2-4 个漏报方向。
- `Skip_or_defer`: 不处理的低收益反馈及一句话原因。

不要复制长评审文本，不要粘贴长源码，不要创建计划文件。

{direct_read_instruction}
