请对本轮漏洞挖掘成果进行**最高强度的全面性审计**。

## 当前评审角色
- advisor_instance_id: {advisor_instance_id}
- role_name: {advisor_role_name}
- 本轮顺序: {current_global_review_index}/{total_global_review_advisors}
- 当前轮次: Cycle {cycle}
- 当前工作模式: {workflow_mode}
- 近期未解决问题数: {current_issue_count}

## 上游全局评审结果
{prior_global_findings}

## 当前评审上下文
{review_context}

## 收敛评审策略
{closure_review_policy}

### 重要说明
- 上面的结果状态摘要和 评审反馈 都是**本轮评审开始前**的快照；
- 直接 `read` 上下文中列出的文件；不要要求框架把大文件全文再次塞进 prompt。
- 不要写任何文件。

## 审计任务
1. 核对 INPUT / EXPORT / USED / CLEANED / ★ 的覆盖情况。
2. 优先依据 coverage ledger 的 obligations 与 issue ledger 的 active backlog 判断是否闭环。
3. 判断 Worker 是否真正缩小了 近期评审问题，而不是只把 summary 写得更长。
4. 对照 previous limitations，严查静默删除、弱化或遗漏。
5. 若不通过，返回**结构化问题列表**；最多 8 个 issue。

## 本角色评分参考
{score_thresholds}

## 输出要求（严格遵守，否则框架会拒绝并要求重新输出）

直接输出一个 JSON 对象，禁止任何前言、后记、Markdown 代码块或解释文字。

通过时的输出示例：
```
{"passed":true,"verdict":"PASS","feedback":"本轮覆盖度与诚实性均已达标，未见剩余问题。","scores":{"input_coverage":0.96,"export_followthrough":0.93,"used_coverage":0.91,"limitations_honesty":0.95,"report_completeness":0.92},"confidence":0.88,"issues":[]}
```

不通过时的输出示例：
```
{"passed":false,"verdict":"FAIL","feedback":"ESP 出方向长度回绕家族未闭环。","scores":{"input_coverage":0.90,"export_followthrough":0.66,"used_coverage":0.74,"limitations_honesty":0.82,"report_completeness":0.64},"confidence":0.87,"issues":[{"id":"CMP-esp-out-wrap","category":"coverage_gap","target":"IPSEC_ESP_HandleOutputPkt","severity":"high","required_action":"跟入 ESP 出方向短 payload 回绕路径并给出源码结论","actionable_by":"worker","blocking_type":"analysis_gap","acceptance_criteria":"给出该 EXPORT 的源码跟入结论，或记录 accepted_residual 与缺失依赖"}]}
```

关键约束：
- `scores` 只填本角色负责的字段：{required_score_fields}
- 不要填写本角色不负责的字段
- `feedback` 必须是非空字符串（不能是数组）
- `scores` 和 `confidence` 必须是 0.0-1.0 数值，不能写 HIGH/MEDIUM/LOW
- `passed=true` 时 `issues` 应为空数组
- `passed=false` 时 `verdict` 必须是 `FAIL`，并尽量返回结构化 `issues`
- 每个 issue 必须标注 `actionable_by`：需要继续分析/补证据填 `worker`；只需整理 summary/limitations/supporting_docs 填 `summary`；框架生成文件、schema、只读契约或 advisor 运行问题填 `framework`
- 每个 issue 必须标注 `blocking_type` 与 `acceptance_criteria`；不要只写“继续分析”
- 不要写任何文件
