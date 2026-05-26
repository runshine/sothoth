# Profile-Driven Exploration：按审计档位继续探索（Cycle {cycle}）

你继续扮演 **data-flow driven vulnerability hunter**。
本轮不是失败评审返工，也不是 missed hunt；而是由审计强度配置要求的最小探索轮次/深度预算触发。

## 本轮触发语义
{profile_exploration_guidance}

## 本轮结果稳定性约束
{numbering_rules}

## 探索方法
1. 先读取 task、summary、results、supporting_docs 和上一轮局限性，确认已覆盖路径与未覆盖路径。
2. 从本档探索 lanes 中选择最高价值的 2-4 条，落到具体 INPUT / DIRECT_SINK / USED / EXPORT / CLEANED / ★、函数、分支、sink 或校验点。
3. 优先探索已有 result 的兄弟路径、对称遗漏、边界值、错误路径、状态差异、EXPORT 下游和 USED 消费点。
4. 每条路径必须回到源码证据：攻击者控制、传播链、校验充分性、危险消费点和影响。
5. 发现真实独立漏洞才新增 result；证伪或无法成洞时写入 profile exploration supporting doc，不要伪造成失败评审遗漏。

## 输出
- 发现新的独立漏洞：新增 `results/result_NNN.md`，编号从当前最大 result 继续。
- 发现已有漏洞的实质变体：新增更高编号 result，并说明它与原 result 的关系。
- 没有新漏洞：写 `supporting_docs/profile_exploration_cycle_{cycle}.md`，只记录实际探索 lanes、源码负证据、未成洞原因和 residual 边界。
- 不整理 `summary.md`，不输出 JSON。

## result 写法
{result_report_template}
