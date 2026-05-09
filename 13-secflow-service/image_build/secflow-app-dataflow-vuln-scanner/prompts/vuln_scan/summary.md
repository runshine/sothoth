请整理所有漏洞分析结果，尤其是数据流驱动漏洞分析结果，生成稳定、可评审、可下游消费的最终总结。

## 当前轮次
Cycle {cycle}

## 当前执行上下文
{summary_runtime_context}

## 输出位置
{output_contract_text}

## 本轮额外规则
{summary_rework_rules}

## 评审反馈上下文
{summary_feedback_context}

## 执行要求
1. 直接整理工作目录中的正式产物，不要依赖中间对话内容。
2. 本阶段接管 `summary.md` 与 `previous_limitations.md` 的统一整理；前序 Worker/Reflection 主要负责 `results/` 与 `supporting_docs/`。
3. 严格写出 `summary.md`、`supporting_docs/`、`previous_limitations.md`，并确保 `results/` 中仅保留真实漏洞报告。
4. 除非当前评审反馈明确要求修复某个 result，或本轮处于结果修复，不要在 summary 阶段新增、删除、重编号或重写 `results/result_NNN.md`。
5. 不要把辅助文档写进 `results/`，不要把结果写进 `sessions/` 或 `calls/`。

## summary.md 固定章节模板（必须严格使用 7 个章节标题）

请将 `{summary_file}` 写成以下结构，章节标题必须保留编号和名称：

```markdown
# 数据流驱动漏洞挖掘总结

## 1. 攻击面分析
- 目标函数/模块：
- 数据流分析文件：
- 源码目录：
- 攻击者可控输入概述：
- 关键 sink / EXPORT / USED 概述：

## 2. 分析覆盖度

### 2.1 Coverage Closure Matrix
| obligation_id | 类型 | 对象 | 数据流来源 | status | evidence | residual/限制 |
|---|---|---|---|---|---|---|
| INPUT:xxx | INPUT | ... | data_flow.md:Lx | source_closed/promoted_to_result/accepted_residual/unused/not_applicable/external_blocked | results/... 或 supporting_docs/... | ... |

### 2.2 Open / Residual Obligations
- <若无，明确写“无仍需 Worker 处理的 open obligations”。>

## 3. EXPORT 跟入汇总
| EXPORT/函数 | 数据流来源 | 跟入结论 | status | evidence | residual/限制 |
|---|---|---|---|---|---|

## 4. 关键发现验证
| ★/发现 | 源码验证结论 | status | evidence | residual/限制 |
|---|---|---|---|---|

## 5. 漏洞汇总表
| result_file | title | CWE/category | severity | confidence | 数据流绑定 | 状态 | 备注 |
|---|---|---|---|---|---|---|---|

## 6. 风险评估与修复建议
- 总体风险：
- 优先修复项：
- 代码级修复建议：
- 测试/验证建议：

## 7. 局限性与未覆盖区域
| 项目 | 类型 | 原因 | residual status | 人工验收条件 |
|---|---|---|---|---|
```

## Coverage Closure Matrix 硬性要求
- 必须覆盖 `_meta/coverage_ledger.json` 中的 INPUT / EXPORT / USED / CLEANED / ★ obligations，至少覆盖所有 open/high/STAR 项；若本轮范围要求完整闭环，则尽量逐项覆盖全部 obligations。
- `status` 只能使用：`source_closed`、`promoted_to_result`、`accepted_residual`、`unused`、`not_applicable`、`external_blocked`。
- `evidence` 必须指向 `results/*.md` 或 `supporting_docs/*.md` 或 summary 中的具体章节；不要只写“已分析”。
- 对 active issue backlog 中的每个 issue，summary.md 或 supporting_docs 必须明确写出关闭状态和证据；不能只泛化描述。
- `previous_limitations.md` 必须与第 7 节同步，且不得静默删除上一轮 residual；若已闭环，写明闭环依据。

## results/ 一致性要求
- 漏洞汇总表必须与 `results/` 中的**独立漏洞报告**一一对应；若某个 `result_NNN.md` 只是对已存在漏洞的补充/修正，不要在“有效漏洞数量”里重复计数。
- 若存在补充/修正报告，请在该文件开头明确写出 `- **原始报告**: result_NNN.md` 与 `- **本报告性质**: 补充分析/修正`，并在 summary 中说明它关联哪份原报告。
- `results/` 目录只允许保留 `result_NNN.md`；辅助材料必须在 `supporting_docs/`。

## 本阶段核心目标
- 生成完整、准确、结构化的总结文档。
- 确保 summary.md 与 results/、supporting_docs/、previous_limitations.md 内容一致。
- 确保所有 coverage obligations 和 active issues 都有明确状态。
- 不用 summary 阶段替代源码验证；summary 只整理已有 evidence 与结果关系，不凭空确认漏洞真实性。

## 输出前自检
- [ ] `summary.md` 严格包含 7 个固定章节标题
- [ ] `Coverage Closure Matrix` 字段完整：obligation_id / 类型 / 对象 / 数据流来源 / status / evidence / residual
- [ ] status 只使用允许枚举
- [ ] `results/` 中只包含 `result_NNN.md`
- [ ] `supporting_docs/` 中只包含辅助审计文档
- [ ] `previous_limitations.md` 已与 summary 第 7 节同步
- [ ] active issue backlog 每项都有 source_closed / promoted_to_result / accepted_residual / unused / not_applicable / external_blocked 状态
