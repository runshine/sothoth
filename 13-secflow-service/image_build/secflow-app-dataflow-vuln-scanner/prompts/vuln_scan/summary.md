请整理所有漏洞分析结果，尤其是数据流驱动漏洞分析结果，生成稳定、可评审、可下游消费的最终总结。

## 当前轮次

Cycle {cycle}

## 当前执行上下文

{summary_runtime_context}

## 输出位置
{output_contract_text}


## 执行要求
以工作目录中已落盘的正式产物为准；不要仅凭中间对话记忆补写未落盘的信息。

## summary.md 固定章节模板

请将 {summary_file} 写成以下结构，章节标题必须保留编号和名称：

```
{summary_section_template}
```

## results/ 一致性要求

`漏洞汇总表`必须与 results/ 中的独立漏洞报告一一对应；若某个 result_NNN.md 只是对已存在漏洞的补充/修正，不要在“有效漏洞数量”里重复计数。
若存在补充/修正报告，请在该文件开头明确写出 - 原始报告: result_NNN.md 与 - 本报告性质: 补充分析/修正，并在 summary 中说明它关联哪份原报告。
results/ 目录只允许保留 result_NNN.md；辅助材料必须在 supporting_docs/。{summary_limitations_requirement}
## 本阶段核心目标

生成完整、准确、结构化的总结文档。
确保 summary.md 与 results/、supporting_docs/ 内容一致。


## 输出前自检
[ ] summary.md 严格包含 {summary_section_count} 个固定章节标题
[ ] results/ 中只包含 result_NNN.md
[ ] supporting_docs/ 中只包含辅助审计文档
