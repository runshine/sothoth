请对本轮漏洞挖掘成果进行**最高强度的全面性与深入性审计**。

**重要：不要要求框架把大文件全文再次塞进 prompt。**
本轮你会拿到一个“评审入口文件（review packet）”，请先读取它，再按需读取其中引用的 task / summary / results manifest / previous limitations / open blockers 文件。

---

## 当前轮次

Cycle {cycle}

## 当前工作模式

{workflow_mode}

## 评审入口文件（必须先读取）

- review packet: `{review_packet_path}`
- task file: `{task_file}`
- summary file: `{summary_file}`
- results dir: `{results_dir}`
- results manifest: `{results_manifest_file}`
- supporting docs dir: `{supporting_docs_dir}`
- supporting docs manifest: `{supporting_docs_manifest_file}`
- previous limitations file: `{previous_limitations_file}`
- current open blockers file: `{open_blockers_file}`

当前 backlog 中已打开的 blocker 数量：{current_open_blocker_count}

### 重要时序说明（必须遵守）

- `open_blockers_file` 是**本轮评审开始前**生成的 backlog 快照，不是本轮评审结束后的状态文件。
- 如果当前 `summary.md` 声称某个旧 blocker 已经在本轮被解决，但 `open_blockers_file` 里它仍是 `open`，这通常是**正常时序**：框架会在你返回 JSON 后，根据 `resolved_issues` / `blocking_issues` 同步状态。
- `results_manifest_file` 也是**本轮 result review 开始前**的结果状态快照；其中 `passed=false, failed=false` 表示该结果当前仍是 `pending_review`，不应仅因其尚未被结果评审标记为 passed 就新增元数据类 blocker。
- 因此，**不要仅因为 summary 与这个 pre-review 快照尚未同步，就新增“状态不一致” blocker**。
- 正确做法是：核实该 blocker 是否真的被关闭；若已关闭，把它的 id 放进 `resolved_issues`；若技术上仍未闭环，再继续保留在 `blocking_issues` 中。

---

## 你的审计任务

### A. 先读取 review packet，并据此有选择地核查
1. 先 `read` review packet，理解：
   - 本轮 cycle
   - 当前 workflow mode（discovery / closure）
   - summary / results / previous limitations / open blockers 的实际文件路径
   - 当前结果数量、已通过/未通过结果数量、当前 backlog 规模
   - supporting docs 的位置与数量
2. 再按需读取：
   - `summary.md`
   - `previous_limitations_file`
   - `results_manifest_file`
   - `supporting_docs_manifest_file`
   - 必要时抽查具体 `results/result_NNN.md`
   - 必要时回到 task 中指定的数据流文件和源码目录做只读验证

### B. 接近零遗漏的覆盖性核查
3. 核对 INPUT / EXPORT / USED / CLEANED / ★ 的覆盖情况。
4. 判断 Worker 是否真正缩小了 backlog，而不是只是把 summary 写得更长。
5. 如果仍存在明显未覆盖路径、未跟入 EXPORT、未验证关键发现，直接判定不通过。

### C. 深入性核查
6. 判断是否真正做了源码级跟入，而不是停留在摘要层。
7. 检查漏洞模式覆盖是否足够广：内存安全、整数安全、输入验证、逻辑缺陷、资源耗尽。
8. 检查重要安全结论是否都有代码证据。
9. 检查是否做了校验绕过分析，而不是看到 if 就判安全。

### D. “局限性与未覆盖区域”硬门槛
10. 必须对照 `previous_limitations_file`：
   - 上一轮未解决项，本轮是否仍保留或明确说明已解决？
   - 是否存在静默删除、弱化或遗漏？
11. 若该章节不诚实、不穷尽、与真实残留盲区不匹配，直接不通过。

### E. Blocker backlog 纪律（非常重要）
12. 若不通过，请输出**结构化 blocking_issues**，而不是无边界自由文本。
13. `blocking_issues` 中每一项都必须：
   - 有稳定 `id`（同一问题跨轮应复用同一 id）
   - 指明 `category`
   - 指明 `target`
   - 指明 `severity`
   - 指明 `required_action`
   - 尽量指明 `actionable_by`：`worker` 或 `framework`
14. **不要静默删除旧 blocker**：
   - 如果旧 blocker 仍未解决，继续出现在 `blocking_issues` 中，保持同一 `id`
   - 如果旧 blocker 已真正关闭，把它的 `id` 放进 `resolved_issues`
   - **不要**因为 `summary.md` 的闭环声明与 `open_blockers_file` 这个 pre-review 快照暂时不一致，就新建“状态不一致” blocker
15. 请只返回**最关键、最阻塞收敛**的 blocker，最多 **8 个**。不要把几十个细碎问题都塞进 backlog。

---

## 输出要求

请输出 JSON：

```json
{
  "passed": true或false,
  "feedback": "简明判定摘要",
  "scores": {
    "input_coverage": 0.0-1.0,
    "export_followthrough": 0.0-1.0,
    "used_coverage": 0.0-1.0,
    "vuln_pattern_breadth": 0.0-1.0,
    "code_evidence_depth": 0.0-1.0,
    "limitations_honesty": 0.0-1.0,
    "report_completeness": 0.0-1.0
  },
  "confidence": 0.0-1.0,
  "blocking_issues": [
    {
      "id": "stable-blocker-id",
      "category": "input_coverage|export_followthrough|used_coverage|limitations_honesty|report_completeness|code_evidence_depth|vuln_pattern_breadth|other",
      "target": "具体函数 / 路径 / 表格 / 章节 / 结果文件",
      "severity": "critical|high|medium",
      "required_action": "下一轮必须补做的动作",
      "detail": "可选，更具体的说明",
      "actionable_by": "worker或framework",
      "status": "open"
    }
  ],
  "resolved_issues": [
    "上一轮已经真正关闭的 blocker id"
  ]
}
```

规则：
- 若 `passed=true`，`blocking_issues` 应为空数组。
- 若 `passed=false`，尽量返回结构化 blocker；不要只返回一大段自由文本。
- `feedback` 仍应给出简明摘要；详细执行动作放进 `blocking_issues[].required_action`。
- 不要写入任何文件；全部结果通过 JSON 返回。

**注意：禁止 write/edit。仅允许 read/bash(grep 等只读命令)。**
