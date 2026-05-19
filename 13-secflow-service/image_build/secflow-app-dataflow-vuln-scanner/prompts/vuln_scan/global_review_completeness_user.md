请评审当前漏洞挖掘工作覆盖是否足够全面。

## 当前评审角色
- advisor_instance_id: {advisor_instance_id}
- role_name: {advisor_role_name}
- 当前轮次: Cycle {cycle}
- 当前工作模式: {workflow_mode}
- 近期未解决问题数: {current_issue_count}

## 当前评审上下文
{review_context}

## 收敛策略
{closure_review_policy}

## 评审任务

1. 读取 task、summary、results manifest、必要的 result 和 supporting_docs。
2. 判断关键代码路径和数据流路径是否已经覆盖充分。
3. 重点核对 INPUT / DIRECT_SINK / USED / EXPORT / CLEANED / ★ 是否有源码级结论。
4. 如果覆盖已足够全面，直接 PASS。
5. 如果覆盖不足，只输出能指导下一轮 missed_hunt 的具体遗漏方向，最多 5 个 issue。

## 评分
{score_thresholds}

## 输出要求

直接输出一个 JSON 对象，禁止前言、后记和 Markdown 代码块。

通过示例：
```
{"passed":true,"verdict":"PASS","feedback":"关键代码路径和高风险数据流均已覆盖，剩余遗漏不影响主要漏洞结论。","scores":{"coverage":0.94},"confidence":0.88,"issues":[]}
```

不通过示例：
```
{"passed":false,"verdict":"FAIL","feedback":"仍有高风险 EXPORT 下游未跟到源码结论。","scores":{"coverage":0.68},"confidence":0.86,"issues":[{"id":"CMP-export-missing-sink","category":"coverage_gap","target":"EXPORT_L42 -> dangerous_sink","severity":"high","required_action":"跟入 EXPORT_L42 的下游调用，确认是否到达长度、拷贝、分配、索引或循环边界 sink","actionable_by":"worker","blocking_type":"analysis_gap","acceptance_criteria":"下一轮在 result 或 supporting_docs 中给出源码级结论；若源码缺失，记录 external_blocked/accepted_residual 和缺失边界"}]}
```

关键约束：
- `scores` 只填：{required_score_fields}
- `scores.coverage` 和 `confidence` 必须是 0.0-1.0 数值。
- `passed=true` 时 `issues` 必须为空数组。
- `passed=false` 时 `verdict` 必须是 `FAIL`。
- issue 必须具体到函数、文件、数据流标记、sink 或源码路径。
- 不要写任何文件。
