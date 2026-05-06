请对本轮漏洞挖掘成果进行**最高强度的全面性与深入性审计**。

## 当前轮次
Cycle {cycle}

## 当前工作模式
{workflow_mode}

## 当前评审上下文
{review_context}

## 收敛评审策略
{closure_review_policy}

### 重要说明
- 上面的结果状态摘要和 评审反馈 都是**本轮评审开始前**的快照；若某问题已真正关闭，请放进 `resolved_issues`，不要仅因快照尚未同步就新增“状态不一致” issue。
- 直接 `read` 上下文中列出的文件；不要要求框架把大文件全文再次塞进 prompt。
- 不要写任何文件。

## 审计任务
1. 核对 INPUT / EXPORT / USED / CLEANED / ★ 的覆盖情况。
2. 优先依据 coverage ledger 的 obligations 与 issue ledger 的 active backlog 判断是否闭环。
3. 判断 Worker 是否真正缩小了 近期评审问题，而不是只把 summary 写得更长。
4. 检查是否做了源码级跟入、漏洞模式覆盖、校验绕过分析与代码证据支撑。
5. 对照 previous limitations，严查静默删除、弱化或遗漏。
6. 若不通过，返回**结构化问题列表**；最多 8 个 issue。

## 本轮分数通过阈值（由框架注入，随轮次渐进提升）
{score_thresholds}

## 输出要求
- 只输出一个 JSON 对象，不要输出前言/后记/Markdown 代码块
- 顶层至少包含：`passed`、`feedback`、`scores`、`confidence`
- 若输出 `verdict`，只能是 `PASS` 或 `FAIL`
- `scores` 不能为空，但只填写本角色负责的字段：{required_score_fields}
- 不要填写本角色不负责的 score 字段；框架会按参谋角色合并分数
- `scores` 和 `confidence` 必须直接写成 `0.0-1.0` 数值，不要写 `HIGH/MEDIUM/LOW`
- 若 `passed=true`，`issues` 必须为空数组
- 若 `passed=false`，尽量返回结构化 `issues`
- 若 `passed=false`，每个 issue 必须标注 `actionable_by`、`blocking_type`、`acceptance_criteria`
- `blocking_type` 建议取值：`analysis_gap`、`evidence_gap`、`summary_sync`、`framework_contract`、`needs_external_source`、`accepted_residual`
- 不要写任何文件
