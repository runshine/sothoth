# Handoff Prompt: 简化数据流漏洞挖掘任务概览页

你将实现“数据流漏洞挖掘”任务详情页（Run 详情页）的概览重整。你**没有这次对话上下文**，所以这里提供完整背景、文件路径、现状、目标、数据来源与执行步骤。

## 目标
把“数据流漏洞挖掘”任务详情页的“概览”页改得更简洁、更聚焦业务目标：

1. **必须保留**：分数趋势图。
2. **删除** overview 里的“当前评审问题”卡片。
3. 用它的位置替换为：**漏洞发现总数趋势图**，体现“随着轮次上升，发现的漏洞数量如何增加”。
4. **必须保留**：评审轮次概况。
5. 把“框架产物一致性”那张卡重整为更贴近业务结果的摘要，不再强调工程/框架内部细节。
6. 这次需求强调“**化繁为简，少关注工程化问题**”，所以：
   - 不要引入新图表库；
   - 不要做大规模抽象重构；
   - 尽量局部改动、就地复用现有实现。

---

## 关键代码位置

### 1) 路由入口 / 详情页挂载点
- `13-secflow-service/image_build/secflow-frontend/pages/execution/DataflowVulnScannerPage.tsx`
  - `DataflowVulnTaskDetailPage` 会在 fileserver mode 下渲染：
  - `DataflowFileserverRunDashboardPage`

### 2) 这次主要要改的文件
- `13-secflow-service/image_build/secflow-frontend/pages/execution/DataflowFileserverRunDashboardPage.tsx`

这是一个**Shadow DOM + imperative renderer** 页面，不是普通 React JSX 组件树。主要结构如下：
- 顶部 `DASHBOARD_HTML`：写死整个 DOM 骨架
- `createDashboardApp()`：一大组方法直接 `innerHTML` 更新 DOM
- `DATAFLOW_DASHBOARD_STYLES`：给 Shadow DOM 注入样式

### 3) 样式文件（尽量不改）
- `13-secflow-service/image_build/secflow-frontend/pages/execution/DataflowFileserverRunDashboardCss.ts`

**重要 gotcha：** 这个文件是一个超长的字符串常量，编辑很痛苦。**优先复用现有类名**（如 `grid-2`、`score-chart`、`manifest-grid`、`score-pill` 等）。如果确实要补少量样式，优先加到 `DataflowFileserverRunDashboardPage.tsx` 里的 `DATAFLOW_DASHBOARD_SECFLOW_REFRESH_CSS`，不要去大改 `DataflowFileserverRunDashboardCss.ts`。

---

## 当前 overview 结构（你需要改这里）

`DataflowFileserverRunDashboardPage.tsx` 中 `DASHBOARD_HTML` 目前 overview 区域是：

```html
<div id="tabOverview" class="tab-content active">
  <div class="grid-2">
    <div class="card" id="scoreChart"></div>
    <div class="card" id="issuesCard"></div>
  </div>
  <div class="card" id="manifestCard"></div>
  <div class="card" id="cycleTimeline"></div>
</div>
```

当前对应的渲染方法：

- `renderOverview(data)`
  - `renderScoreChart(data.cycles || [])`
  - `renderIssuesCard(data.latest_issues || [])`
  - `renderManifestCard(data.manifests || {}, data.config || {})`
  - `renderCycleTimeline(data.cycles || [])`

当前 loading / error 占位也写死依赖这些 DOM id：
- `showLoadingState()`
- `showLoadError()`

所以如果你替换 `issuesCard`，**必须同步更新**上述两个方法中的 DOM 查询和占位逻辑。

---

## 已有数据能力：这次不需要改后端 API

### A. score trend 已有数据
- 来自 `data.cycles[*].scores`
- 当前 `renderScoreChart(cycles)` 已在使用

### B. 漏洞发现总数趋势图需要的数据已经有
后端已经提供：
- `data.cycles[*].new_result_count`
- `data.cycles[*].new_results`

相关来源：
- `13-secflow-service/image_build/secflow-app-dataflow-vuln-scanner/app/services/run_index_service.py`
  - `_cycle_payloads()` 会返回：
    - `new_result_count`
    - `new_results`
- `13-secflow-service/image_build/secflow-app-dataflow-vuln-scanner/app/services/run_inspector.py`
  - `collect_new_results_by_cycle()` / `inspect_run_detail()` 也会把这些信息放进 cycles 里

测试也证明了这个契约存在：
- `13-secflow-service/image_build/secflow-app-dataflow-vuln-scanner/tests/test_run_api.py`
  - `test_run_detail_groups_new_results_by_first_review_cycle`
  - `test_run_api_exposes_new_results_and_derives_legacy_cycle_cache`

这意味着：
- 你**不需要**新增 API；
- 你可以直接在前端把每轮 `new_result_count` 累加，生成“累计发现总数”趋势。

### C. manifest/结果摘要所需数据也已经有
`data.manifests` 里已有：
- `total_result_files`
- `active_result_count`
- `inactive_result_count`
- `taskable_result_count`
- `supplemental_result_count`
- `vulnerability_status_counts`
- `result_relations_manifest`
- `results_manifest`
- `vulnerability_list`

`vulnerability_status_counts` 的计数语义来自：
- `13-secflow-service/image_build/secflow-app-dataflow-vuln-scanner/app/pi_vuln_core/utils/vulnerability_list.py`
- 其中 `status_counts()` 会返回：
  - `total`
  - `pending_review`
  - `confirmed`
  - `false_positive`
  - `inactive`

---

## 当前 manifest card 为什么低价值（这正是本次要改的原因）

当前 `renderManifestCard(manifests, config)` 做了这些事情：
- 四个字段：
  - `taskable_result_count`
  - `supplemental_result_count`
  - `inactive_result_count`
  - `missing_referenced_results.length`
- 三个链接：
  - `result_relations_manifest`
  - `results_manifest`
  - `coverage_ledger`
- 还会展示 `config.global_review_advisors[*].score_fields`

问题：
1. `coverage_ledger` 前端在显示，但后端 manifest summary 并没有提供这个字段，等于 overview 里这个链接天然不可靠/经常缺失。
2. `missing_referenced_results` 在当前后端实现里是硬编码空数组，overview 里的 `missing refs` 基本没有信息量。
3. `global_review_advisors + score_fields` 更偏框架/工程配置，不符合“少关注工程化”的目标。
4. `taskable/supplement/inactive` 这些词也不够业务化。

后端证据：
- `13-secflow-service/image_build/secflow-app-dataflow-vuln-scanner/app/services/run_inspector.py`
  - `_load_manifest_summary()` 当前返回：
    - `missing_referenced_results: []`
    - `unreferenced_active_results: []`
  - 并没有 `coverage_ledger`

---

## 当前“当前评审问题”卡片为什么可以删

overview 当前问题卡来自：
- `data.latest_issues`

这个字段来自最新一轮 `review_feedback`，但问题信息**并不只存在 overview**。在 cycles 页和每轮详情里，global review / result review 仍然会展示 issue 细节。所以：
- **删掉 overview 的 issues 卡片不会让信息丢失**；
- 只是把 overview 从“问题驱动”改成“核心结果驱动”。

因此，这次只需要：
- 删掉 overview 的 issue 卡片入口；
- 不要去动 cycles detail 里的 issue 展示逻辑。

---

## 实现建议（推荐，不要过度工程化）

### 1) 新增一个漏洞趋势渲染方法
在 `createDashboardApp()` 内，新增类似：
- `renderVulnerabilityTrendCard(cycles)`

推荐逻辑：
1. 取 `cycles`，按 `cycle` 升序。
2. 每轮读取：
   - `newCount = Number(c.new_result_count || 0)`
3. 计算累计值：
   - `cumulative += Math.max(newCount, 0)`
4. 用当前 `renderScoreChart()` 相同风格的 inline SVG 画**单条折线**：
   - x 轴：`C1`, `C2`, `C3` ...
   - y 轴：0 到 max(cumulative)
   - 一条线，一个颜色，一组点
5. 卡片标题建议：
   - `漏洞发现总数趋势`
   - 或 `漏洞发现趋势`
6. 卡片底部可以加一行轻量说明：
   - `累计 3 · 本轮新增 1`
   - 或者各轮 `+N`

**注意：** 这里更适合画“累计发现数”，因为用户要的是“随着轮次上升，发现的漏洞数量的增加趋势”。

### 2) 分数趋势图继续保留，最好原样不动
- 现有 `renderScoreChart()` 可继续用
- 不要为这次需求重写成 Recharts
- 只要保证 overview 左上还是它即可

### 3) 简化 manifest card，变成“业务摘要”
建议把 `renderManifestCard(manifests, config)` 改成更偏业务语义的四格摘要。

**默认推荐四项：**
1. `累计发现`
   - `manifests.total_result_files`
   - 若缺失则回退 `manifests.vulnerability_status_counts.total`
2. `当前有效`
   - `manifests.active_result_count`
3. `已确认`
   - `manifests.vulnerability_status_counts.confirmed`
4. `待评审`
   - `manifests.vulnerability_status_counts.pending_review`

**次级信息（不要占主四格，可以下沉）**：
- `误报` → `false_positive`
- `失效/撤回` → `inactive`
- `supplemental_result_count` 只有在 > 0 时再显示，否则直接不强调

**链接区改成三个真正有价值的入口：**
- `result_relations_manifest` → 结果关系
- `results_manifest` → 结果生命周期
- `vulnerability_list` → 漏洞状态列表

**明确移除：**
- `coverage_ledger` 链接
- `missing refs`
- `advisors / score_fields` 列表
- 过于工程化的 `taskable` / `supplement` 等英文标签

**标题建议：**
- `漏洞结果概况`
- 或 `漏洞产物概况`

### 4) 保留评审轮次概况
- `renderCycleTimeline(cycles)` 保留
- 不要删
- 位置仍在 overview 下半部分
- 除非顺手需要做小文案调整，否则不要大动结构

### 5) loading / error 必须同步
你如果把 `issuesCard` 改成 `vulnTrendCard`，要一起改：
- `showLoadingState()`
- `showLoadError()`

否则 overview 一进页面会有空白或报错占位失配。

---

## 执行步骤
完成每一步后，请在你的工作输出里显式打上 `[DONE:n]`。

1. **改 overview DOM 骨架与占位逻辑**  `[DONE:1]`
   - 文件：`DataflowFileserverRunDashboardPage.tsx`
   - 改 `DASHBOARD_HTML` 的 `tabOverview`
   - 把 `issuesCard` 换成新的漏洞趋势卡容器（推荐 `vulnTrendCard`）
   - 同步改 `showLoadingState()` / `showLoadError()` 中对应 DOM 查询与占位文案

2. **实现漏洞发现总数趋势图**  `[DONE:2]`
   - 文件：`DataflowFileserverRunDashboardPage.tsx`
   - 新增 `renderVulnerabilityTrendCard(cycles)`
   - 数据来自 `cycles[*].new_result_count`
   - 计算累计发现数并画单折线图
   - 视觉风格向 `renderScoreChart()` 靠齐
   - 在 `renderOverview(data)` 中调用它，替换原 `renderIssuesCard(...)`

3. **移除 overview 的问题卡片逻辑**  `[DONE:3]`
   - 文件：`DataflowFileserverRunDashboardPage.tsx`
   - 不再在 overview 调 `renderIssuesCard(...)`
   - 不改 cycles/detail 中的问题展示逻辑
   - 如果 `renderIssuesCard()` 已无用途，可删除；否则允许保留但不再入口调用

4. **重写 manifest card 为业务摘要**  `[DONE:4]`
   - 文件：`DataflowFileserverRunDashboardPage.tsx`
   - 重写 `renderManifestCard(manifests, config)` 的内容输出
   - 改成 4 个业务摘要字段：
     - 累计发现
     - 当前有效
     - 已确认
     - 待评审
   - 下沉显示：误报 / 失效
   - 链接区只保留：
     - 结果关系
     - 结果生命周期
     - 漏洞状态列表
   - 去掉 `coverage_ledger`、`missing refs`、advisor 列表

5. **确认评审轮次概况仍保留**  `[DONE:5]`
   - 文件：`DataflowFileserverRunDashboardPage.tsx`
   - 保证 `renderCycleTimeline(cycles)` 仍在 `renderOverview(data)` 中调用
   - 不做无关重构

6. **轻量验证**  `[DONE:6]`
   - 前端目录：`13-secflow-service/image_build/secflow-frontend`
   - 运行：`npm run lint`
   - 如果能本地打开页面，至少肉眼检查：
     - 无 cycles 的空状态
     - 多轮 + `new_result_count` 有值
     - 有 inactive / removed 结果时 manifest 摘要是否合理

---

## 约束 / gotchas

1. **不要改后端 API**
   - 这次前端需要的数据已经有了。

2. **不要引入新图表库**
   - 这次是 overview 局部整理，不是可视化系统重构。

3. **不要大改 CSS 体系**
   - 先复用：`grid-2`、`card`、`score-chart`、`manifest-grid`、`score-pill`、`text-muted` 等现有类。
   - 如果非要补样式，优先在 `DataflowFileserverRunDashboardPage.tsx` 的 `DATAFLOW_DASHBOARD_SECFLOW_REFRESH_CSS` 加极少量规则。

4. **优先做局部修改**
   - 主要文件应只落在：
     - `DataflowFileserverRunDashboardPage.tsx`
   - 只有确实需要新类名时，才碰样式定义。

5. **语义比工程一致性更重要**
   - 这次需求明确要“化繁为简，专注核心目标”。
   - 所以业务摘要 > 框架一致性字段。

---

## 如果你需要快速理解字段含义，可参考这些文件

### 前端
- `13-secflow-service/image_build/secflow-frontend/pages/execution/DataflowVulnScannerPage.tsx`
- `13-secflow-service/image_build/secflow-frontend/pages/execution/DataflowFileserverRunDashboardPage.tsx`
- `13-secflow-service/image_build/secflow-frontend/clients/dataflowVulnRunsFileserver.ts`
- `13-secflow-service/image_build/secflow-frontend/clients/dataflowVulnScanner.ts`

### 后端数据来源
- `13-secflow-service/image_build/secflow-app-dataflow-vuln-scanner/app/services/run_index_service.py`
- `13-secflow-service/image_build/secflow-app-dataflow-vuln-scanner/app/services/run_inspector.py`
- `13-secflow-service/image_build/secflow-app-dataflow-vuln-scanner/app/pi_vuln_core/utils/vulnerability_list.py`

### 后端契约示例 / 测试
- `13-secflow-service/image_build/secflow-app-dataflow-vuln-scanner/tests/test_run_api.py`

---

## 最终交付预期
完成后，overview 页应该是：

- 左上：**分数趋势图**（保留）
- 右上：**漏洞发现总数趋势图**（新增）
- 中间：**漏洞结果概况 / 业务摘要**（重整，不再强调框架一致性）
- 下方：**评审轮次概况**（保留）

而“当前评审问题”不再占 overview 的核心版面。

请按步骤执行，并在每一步完成后输出对应的 `[DONE:n]` 标记。