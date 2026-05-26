# 简化数据流漏洞挖掘任务概览页

重整“数据流漏洞挖掘”任务详情页的“概览”标签：保留分数趋势与评审轮次概况，删除低价值的“当前评审问题”概览卡片，引入“漏洞发现总数趋势图”，并把“框架产物一致性”改造成更贴近业务结果的简洁摘要。

## Context
- 前端任务详情入口在 `13-secflow-service/image_build/secflow-frontend/pages/execution/DataflowVulnScannerPage.tsx`，真正的 Run 详情 UI 由 `DataflowFileserverRunDashboardPage` 渲染。
- 目标页面核心实现集中在 `13-secflow-service/image_build/secflow-frontend/pages/execution/DataflowFileserverRunDashboardPage.tsx`；该页面不是普通 React JSX 逐段渲染，而是：
  - 通过 `DASHBOARD_HTML` 写死 Shadow DOM 结构；
  - 通过 `createDashboardApp()` 里的一组 imperative render 方法更新 DOM；
  - 通过 `DATAFLOW_DASHBOARD_STYLES` 注入样式。
- 当前概览区 HTML 结构是：
  - `scoreChart`：分数趋势
  - `issuesCard`：当前评审问题
  - `manifestCard`：框架产物一致性
  - `cycleTimeline`：评审轮次概览
- 当前 overview 渲染链路：
  - `renderOverview(data)` 依次调用 `renderScoreChart`、`renderIssuesCard`、`renderManifestCard`、`renderCycleTimeline`。
  - `showLoadingState()` / `showLoadError()` 也写死了 `issuesCard` 等占位逻辑。
- 后端已经提供本次改造所需数据，无需新增 API：
  - `cycles[*].scores`：用于现有分数趋势图；
  - `cycles[*].new_result_count`、`cycles[*].new_results`：可用于“漏洞发现总数趋势图”；
  - `manifests.total_result_files`、`active_result_count`、`inactive_result_count`、`taskable_result_count`；
  - `manifests.vulnerability_status_counts`：来自 `vulnerability_list.json`，包含 `total`、`pending_review`、`confirmed`、`false_positive`、`inactive`。
- 关键后端来源：
  - `13-secflow-service/image_build/secflow-app-dataflow-vuln-scanner/app/services/run_index_service.py` 的 `_cycle_payloads()` 暴露了 `new_result_count`；
  - `13-secflow-service/image_build/secflow-app-dataflow-vuln-scanner/app/services/run_inspector.py` 的 `_load_manifest_summary()` 暴露了 `vulnerability_status_counts`。
- 现有“框架产物一致性”里确实有明显低价值/失真项：
  - 前端展示了 `coverage_ledger` 链接，但后端 manifest summary 并未返回该字段；
  - `missing_referenced_results` / `unreferenced_active_results` 在后端当前实现里是硬编码空数组，因此 overview 中的 `missing refs` 基本没有信息量；
  - `global_review_advisors` + `score_fields` 更偏框架配置，不符合“少关注工程化”的目标。
- `latest_issues` 虽然会从最新 `review_feedback` 文件加载，但全局/结果评审 issue 仍能在“评审轮次”页及每轮展开内容里看到，因此删除 overview 的问题卡片不会让问题信息彻底消失。
- `DataflowFileserverRunDashboardCss.ts` 是一整段导出的长字符串 CSS，编辑成本高；如果必须新增少量样式，优先放在 `DataflowFileserverRunDashboardPage.tsx` 内部的 `DATAFLOW_DASHBOARD_SECFLOW_REFRESH_CSS`，否则尽量复用现有 `grid-2`、`score-chart`、`manifest-grid`、`score-pill` 等类。

## Plan:
1. 调整 overview 容器与加载/报错占位，明确替换“当前评审问题”卡片。
   - 修改 `DataflowFileserverRunDashboardPage.tsx` 中 `DASHBOARD_HTML` 的 `tabOverview`：把 `issuesCard` 替换为新的漏洞趋势卡片容器（推荐显式改成 `vulnTrendCard`，避免语义错位）。
   - 同步更新 `showLoadingState()` 与 `showLoadError()` 中对该卡片的占位/报错文案与 DOM 查询，确保 overview 四块卡片仍能稳定刷新。
   - 保持 `scoreChart`、`manifestCard`、`cycleTimeline` 的位置关系不变，避免额外影响其他 tab 或页面逻辑。

2. 新增“漏洞发现总数趋势图”，复用当前分数趋势图的视觉风格。
   - 在 `createDashboardApp()` 中新增专门的渲染方法（如 `renderVulnerabilityTrendCard(cycles)`），并在 `renderOverview(data)` 里替换掉 `renderIssuesCard(...)` 调用。
   - 数据来源直接使用 `data.cycles[*].new_result_count`，按轮次累加形成“累计发现总数”折线；必要时可同时在卡片底部用轻量说明显示每轮新增量。
   - 图表风格尽量沿用 `renderScoreChart()` 的 inline SVG 方案：相同的容器、坐标轴风格、点位/折线风格，避免引入 Recharts 或新的工程化抽象。
   - 兼容三类场景：
     - 无轮次数据：显示空状态；
     - 单轮数据：显示单点；
     - 旧 Run / 回填 Run：优先读 `new_result_count`，若某轮缺失则按 `0` 回退，依赖后端现有兼容逻辑。

3. 从 overview 中移除“当前评审问题”视图，但不删除底层 issue 数据能力。
   - 删除/停用 `renderIssuesCard()` 在 overview 中的入口，不再把 `latest_issues` 作为概览主卡片展示。
   - 不改动 cycles tab 和 cycle detail 中已有的 issue 展示逻辑，让需要深挖的人仍能在轮次细节里查看问题与评审反馈。
   - 若 `renderIssuesCard()` 仅剩 overview 使用，则可一并删除；若保留更稳妥，则确保其不再被 overview 调用即可。

4. 重整“框架产物一致性”为更贴近业务结果的四项摘要，并清理无效字段。
   - 保留 `manifestCard` 这个位置，但把内容从“框架一致性检查”改成更业务化的“漏洞结果概况”或同类命名。
   - 默认四项摘要建议改为：
     1. `累计发现` → `manifests.total_result_files`（或缺失时回退 `vulnerability_status_counts.total`）
     2. `当前有效` → `manifests.active_result_count`
     3. `已确认` → `manifests.vulnerability_status_counts.confirmed`
     4. `待评审` → `manifests.vulnerability_status_counts.pending_review`
   - 将 `false_positive`、`inactive` 这类次级状态下沉为卡片底部的小字/标签摘要，而不是继续占用主四格。
   - 链接区改成真正有价值且后端已提供的三个入口：
     - `result_relations_manifest` → 结果关系
     - `results_manifest` → 结果生命周期
     - `vulnerability_list` → 漏洞状态列表
   - 移除当前无效或低价值内容：
     - `coverage_ledger` 链接
     - `missing refs`
     - `global_review_advisors` / `score_fields` 列表
     - 纯框架导向的英文标签（如 `taskable` / `supplement`）

5. 明确保留“评审轮次概况”，避免对核心信息做减法。
   - 保持 `renderCycleTimeline(cycles)` 仍在 overview 中展示，不删该卡片。
   - 当前 step 先不做大改，只保证其仍紧跟在新的业务摘要卡片后面；如实现时发现文案很容易顺手优化，可仅做轻微中文文案修正，不改变结构与交互。

6. 用轻量验证收尾，优先确保改动稳定而不是补工程化基础设施。
   - 在 `13-secflow-service/image_build/secflow-frontend` 下运行 `npm run lint`，确认 TS 编译通过。
   - 结合已有后端契约，至少手动检查三类数据情况：
     - 没有 cycles 的空 Run；
     - 多轮且 `new_result_count` 持续增长的 Run；
     - 存在 removed/inactive result 的 Run。
   - 不为这次需求额外引入测试框架或大规模重构；改动应尽量局限在 `DataflowFileserverRunDashboardPage.tsx`，只有在确实需要新类名时才补少量样式。

## Risks / Open Questions
- 四个摘要字段里第 4 个主字段，默认建议用“待评审”；如果产品更想强调收敛结果，也可以改成“已撤回/失效”或“误报”。这是唯一需要产品快速拍板的点。
- “漏洞发现总数趋势图”按当前需求更适合展示“累计发现数”（由 `new_result_count` 累加得到），而不是“当前有效数”；若后续想强调收敛而不是发现过程，需要再明确是否改成 active/confirmed 曲线。
- `DataflowFileserverRunDashboardCss.ts` 的大字符串 CSS 不适合做大规模编辑；实现时应优先复用现有类，避免把这次小改动扩散成样式重构。
- 某些老 Run 可能没有完整的 `vulnerability_status_counts`；实现时要做好数值兜底，避免出现 `undefined` 或空白卡片。