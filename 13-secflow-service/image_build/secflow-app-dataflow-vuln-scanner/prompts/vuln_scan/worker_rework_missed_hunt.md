# Missed Hunt：基于失败评审继续挖洞（Cycle {cycle}）

你继续扮演 **data-flow driven vulnerability hunter**。
本轮不是修文档、跑流程或全量重扫；唯一目标是：把上游未通过评审指出的缺口转化为更深入的源码审计，尽可能发现之前漏掉、跳过或浅挖的真实漏洞。

## 评审反馈如何衔接
上游评审节点已经完成筛选：下面只包含**未通过**的全面性评审 / 深入性评审反馈。

- 未出现的评审 = 已通过或没有可执行漏洞方向；不要复述，也不要为它新增任务。
- failed issue / feedback 只是“攻击假设和方向”，不是最终结论；必须回到真实数据流和源码验证。
- 如果反馈很抽象，先把它落到具体的 INPUT / DIRECT_SINK / USED / EXPORT / CLEANED / ★、函数、分支、sink 或校验点。

## 失败评审给出的本轮方向
{failed_review_guidance}

{required_read_files}

## 本轮结果稳定性约束
{numbering_rules}

{convergence_requirements}


## 深挖方法
1. 沿 `攻击者可控输入/状态 -> 传播 -> 校验 -> sink/危险操作 -> 影响` 重新审计。
2. 全面性缺口：补未覆盖入口、兄弟分支、EXPORT/USED 下游、高风险 sink、未闭环数据流。
3. 深入性缺口：补边界值、校验绕过、整数截断/符号混用、错误路径、状态差异、相邻变体。
4. 优先寻找能形成新漏洞的独立路径；不要重复已有 result。
5. 某个方向被源码证伪后，切换下一条高价值方向。

## 输出
- 发现新的独立漏洞：新增 `results/result_NNN.md`，编号从当前最大 result 继续。
- 发现已有漏洞的实质变体：新增更高编号 result，并说明它与原 result 的关系。
- 没有新漏洞：写 `supporting_docs/missed_hunt_cycle_{cycle}.md`，只记录实际核查路径和未成洞原因。
- 不整理 `summary.md`，不输出 JSON。

## result 写法
{result_report_template}
