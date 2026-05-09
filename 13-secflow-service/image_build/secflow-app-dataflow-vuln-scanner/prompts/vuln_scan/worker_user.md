对目标函数进行全面、深入的 **data-flow driven vulnerability hunting**。

{worker_runtime_context}

## 你的执行要求
1. 先 `read` 上下文中列出的必读文件；不要要求框架重复粘贴大文件全文。
2. 本任务不是无边界全源码审计；所有正式结果必须能回链到数据流文件中的 INPUT / EXPORT / USED / CLEANED / ★，或其直接上下游源码证据。
3. 以攻击者视角完成本轮漏洞挖掘：梳理 INPUT / EXPORT / USED / CLEANED / ★ 关键发现，并做源码级验证。
4. 对本轮范围要求内的 EXPORT 终点继续跟入；对 USED 终点逐项扫描漏洞模式。
5. **本阶段只负责沉淀漏洞发现与证据**，正式产物只写到下列位置：
{output_contract_text}
6. `summary.md` 和 `previous_limitations.md` 由后续显式 summary 阶段统一整理/同步；除非后续 prompt 明确要求进入 summary 阶段，否则当前不要反复整理总结。
7. 不要把 `result_*.md`、辅助文档或其他正式产物写到 `sessions/`、`calls/` 或 prompt 文件目录。

## result_NNN.md 强制模板

{result_report_template}

## 输出要求（静态约束）
- `results/` 目录只允许放 `result_NNN.md`。
- **每个 `result_NNN.md` 只能描述一个独立漏洞问题**；不要把多个 `VULN-*` 打包进同一个结果文件。
- 每个 `result_NNN.md` 必须按上方强制模板填写疑点元信息、数据流绑定、源码证据、触发条件、校验/绕过分析、影响和修复建议。
- `supporting_docs/` 只放辅助审计文档。
- 当前阶段核心目标是：把正式漏洞证据写进 `results/`，把覆盖矩阵/删除审计/补扫记录写进 `supporting_docs/`。
- `summary.md` / `previous_limitations.md` 将由后续 summary 阶段统一整理；本阶段不要为了“排版总结”而反复改写它们。
- 没有源码级证据、没有明确 sink、无法回链到数据流主轴的内容，不得写入 `results/`；应写入 `supporting_docs/` 或不保留。
