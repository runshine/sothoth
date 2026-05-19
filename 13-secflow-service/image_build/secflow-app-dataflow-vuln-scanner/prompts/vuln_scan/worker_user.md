对目标函数进行全面、深入的 **data-flow driven vulnerability hunting**。

{worker_runtime_context}

## 你的执行要求
1. 先 `read` 上下文中列出的必读文件；不要要求框架重复粘贴大文件全文。
2. 本任务不是无边界全源码审计；所有正式结果必须能回链到数据流文件中的 INPUT / DIRECT_SINK / USED / EXPORT / CLEANED / ★，或其直接上下游源码证据。
3. 以攻击者视角完成本轮漏洞挖掘：梳理 INPUT / DIRECT_SINK / USED / EXPORT / CLEANED / ★ 关键发现，并做源码级验证。


## result_NNN.md 强制模板
{result_report_template}


## 输出规范
1. 独立漏洞报告按数字序号递增：`results/result_001.md`, `results/result_002.md`, ...（三位数编号）。你只需要通过创建这些报告表达漏洞发现。
2. 辅助审计文档：`supporting_docs/`，不要把辅助审计文档混入 `results/`。
3. 每个 result 文件只允许对应一个独立漏洞疑点；不要在一份 `result_NNN.md` 中打包多个漏洞。
4. 若外部源码或上下文缺失导致关键路径无法判断，应在 `supporting_docs/` 记录已查证范围、缺失依赖、风险边界和人工验收条件；低收益、低风险、无法指向漏洞判断的项可以不保留。
