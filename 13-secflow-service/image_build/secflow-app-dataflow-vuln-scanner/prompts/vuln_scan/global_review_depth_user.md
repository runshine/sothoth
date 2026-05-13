请对本轮漏洞挖掘成果进行**漏洞产出导向的深入性审计**。

## 当前评审角色
- advisor_instance_id: {advisor_instance_id}
- role_name: {advisor_role_name}
- 本轮顺序: {current_global_review_index}/{total_global_review_advisors}
- 当前轮次: Cycle {cycle}
- 当前工作模式: {workflow_mode}

## 上游全局评审结果
{prior_global_findings}

## Worker 漏洞挖掘清单基线
若需核对 Worker 的稳定角色/输出契约，请 `read` 此文件：`{worker_system_prompt_file}`。
实际漏洞模式广度由本轮范围动态裁剪，已在下方评审上下文的范围要求与 Coverage / issue radar 中体现；不要机械要求超出本轮范围的全量清单。

## 当前评审上下文
{review_context}

## 收敛评审策略
{closure_review_policy}

### 重要说明
- 上面的结果状态摘要和 评审反馈 都是**本轮评审开始前**的快照；
- 直接 `read` 上下文中列出的文件；不要要求框架把大文件全文再次塞进 prompt。
- 不要写任何文件。

## 审计任务
1. 核对 Worker 是否对最可能产出真实漏洞的关键路径做了相关漏洞模式扫描。
2. 若当前是 closure 模式，只检查仍影响漏洞真实性、漏报风险或误报风险的 active issues / coverage signals。
3. 判断关键校验是否做了绕过分析（边界值、符号混用、竞争条件）。
4. 判断 EXPORT 跟入后是否继续下钻到危险使用点、可信边界或重要 residual。
5. 判断代码证据是否充分（源码片段、完整路径、字段级触发条件）。
6. 若不通过，返回**结构化问题列表**；最多 6 个 issue，且每个 issue 必须能提升真漏洞发现或误报压制。

## 本角色专属评分参考
{score_thresholds}

## 输出要求（严格遵守，否则框架会拒绝并要求重新输出）

直接输出一个 JSON 对象，禁止任何前言、后记、Markdown 代码块或解释文字。

通过时的输出示例：
```
{"passed":true,"verdict":"PASS","feedback":"关键路径已做充分多模式扫描，证据深度达标。","scores":{"vuln_pattern_breadth":0.92,"code_evidence_depth":0.91},"confidence":0.90,"issues":[]}
```

不通过时的输出示例：
```
{"passed":false,"verdict":"FAIL","feedback":"AH 选项循环未做边界值绕过分析。","scores":{"vuln_pattern_breadth":0.65,"code_evidence_depth":0.70},"confidence":0.85,"issues":[{"id":"DPT-ah-option-bypass","category":"scan_depth","target":"IPSEC_AH_HandleInputPktV4","severity":"high","required_action":"对 AH 选项循环做 option_len=0/1/0xFF 边界值绕过分析","actionable_by":"worker","blocking_type":"evidence_gap","acceptance_criteria":"给出 option_len=0/1/0xFF 的源码级验证结论"}]}
```

关键约束：
- `scores` 只填本角色负责的字段：{required_score_fields}
- 不要填写本角色不负责的字段
- `feedback` 必须是非空字符串（不能是数组）
- `scores` 和 `confidence` 必须是 0.0-1.0 数值，不能写 HIGH/MEDIUM/LOW
- `passed=true` 时 `issues` 应为空数组
- `passed=false` 时 `verdict` 必须是 `FAIL`，并尽量返回结构化 `issues`
- 每个 issue 必须标注 `actionable_by`：需要继续分析/补证据填 `worker`；只需整理 summary/limitations/supporting_docs 填 `summary`；框架生成文件、schema、只读契约或 advisor 运行问题填 `framework`
- 每个 issue 必须标注 `blocking_type` 与 `acceptance_criteria`；若受外部源码/上下文限制不可闭环，使用 `blocking_type=needs_external_source`
- 不要因普通 open obligation、coverage 数字、supporting_docs 数量、报告格式或低收益文档缺失判失败
- 不要写任何文件
