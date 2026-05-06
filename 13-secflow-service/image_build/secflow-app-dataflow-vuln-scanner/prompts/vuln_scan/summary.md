请整理所有漏洞分析结果，确保输出完整。

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
3. 严格写出 `summary.md`、`results/`、`supporting_docs/`、`previous_limitations.md`。
4. 不要把辅助文档写进 `results/`，不要把结果写进 `sessions/` 或 `calls/`。

## summary.md 最低要求
- 必须包含完整的 7 个章节：攻击面分析、分析覆盖度、EXPORT 跟入汇总、关键发现验证、漏洞汇总表、风险评估与修复建议、局限性与未覆盖区域。
- 漏洞汇总表必须与 `results/` 中的**独立漏洞报告**一一对应；若某个 `result_NNN.md` 只是对已存在漏洞的补充/修正，不要在"有效漏洞数量"里重复计数。
- 若存在补充/修正报告，请在该文件开头明确写出 `- **原始报告**: result_NNN.md` 与 `- **本报告性质**: 补充分析/修正`，并在 summary 中说明它关联哪份原报告。
- "局限性与未覆盖区域"必须诚实保留未闭环项；若某项已闭环，需明确说明如何解决。
- "分析覆盖度"必须包含 coverage closure matrix，对 `_meta/coverage_ledger.json` 中的 INPUT / EXPORT / USED / CLEANED / ★ obligations 逐项或分组列出：`obligation_id`、`对象`、`status`、`evidence`、`residual/限制`。
- `status` 只能使用：`source_closed`、`promoted_to_result`、`accepted_residual`、`unused`、`not_applicable`、`external_blocked`。不要使用“基本覆盖/应该安全/继续分析”这种不可验收状态。
- 对 active issue backlog 中的每个 issue，summary.md 或 supporting_docs 必须明确写出关闭状态和证据；不能只在正文里泛化描述。

## 本阶段核心目标
- **生成完整、准确、结构化的总结文档**，不是判断覆盖率——覆盖率由全局评审负责。
- 确保 summary.md 与 results/ 和 supporting_docs/ 的内容一致。
- 确保所有文件在正确的输出位置。

## 输出前自检
- [ ] `summary.md` 含 7 个章节
- [ ] `results/` 中只包含 `result_NNN.md`
- [ ] `supporting_docs/` 中只包含辅助审计文档
- [ ] `previous_limitations.md` 已与 summary 第 7 节同步
- [ ] coverage closure matrix 覆盖了 `_meta/coverage_ledger.json` 的 open obligations
- [ ] active issue backlog 每项都有 source_closed / promoted_to_result / accepted_residual / unused / not_applicable / external_blocked 状态
