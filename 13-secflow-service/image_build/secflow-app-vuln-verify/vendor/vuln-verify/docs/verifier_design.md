# 多维语义验证引擎（Verifier）

## 1. 定位

验证引擎是系统中执行深度研判的核心单元。每个分组（指向同一段代码的一组报告）启动一个独立的 LLM Agent，在完全隔离的上下文中完成从源码语义理解到二进制逆向分析的全链路推理。

**Phase 1 能力范围**：源码语义理解 + 二进制逆向分析。可利用性验证（PoC 构造与沙箱执行）纳入 Phase 2。

## 2. 输入

| 输入 | 说明 |
|:---|:---|
| 报告原文 | 该分组内的全部报告（Markdown） |
| 源码 | 目标函数的 C 语言反编译产物 |
| 二进制 | 目标函数的编译产物（.so） |
| 威胁模型 | 定义安全边界、攻击者假设、已知防护措施 |
| 分组元信息 | 文件路径、函数名、报告 ID 列表 |

## 3. 四维校验矩阵

每个报告经历四个独立维度的校验——不走「真/假」的二元判定，而是对每个维度独立给出结论：

| 维度 | 校验问题 | true 含义 |
|:---|:---|:---|
| 源码一致性 | 报告的代码描述与实际 ground truth 是否一致？ | 源码和二进制中的代码与报告描述吻合 |
| 攻击可达性 | 在威胁模型定义的安全边界下，攻击路径是否可达？ | source 在安全边界内，sink 可被外部输入触发 |
| 防御完备性 | 代码路径上的校验逻辑是否可被绕过？ | 所有通向 sink 的路径上不存在有效防护 |
| 安全影响性 | 如果通过以上三维，触发后是否对系统保密性、完整性或可用性造成实质损害？ | 存在明确的、非 trivial 的安全后果 |

### 3.1 判定规则

```
四个维度全部 true   → 确认为真实漏洞
任一维度为 false    → 归档（精确记录该维度为排除原因）
任一维度为 null     → 标记待验证（静态分析无法确定，需 Phase 2 动态验证）
```

**归档不等于误判**。排除了 code_accurate 维度，意味着报告对代码的描述不准确——扫描规则本身需要校准。排除了 path_reachable，意味着该代码路径不在安全边界内——威胁模型正确发挥了过滤作用。每一次归档都是有价值的反馈信号。

## 4. 输出

每个报告产出独立的研判结论：

```json
{
  "report_id": "报告标识",
  "verdict": "confirmed | ruled_out | unresolved",
  "dimensions": {
    "code_accurate":    { "status": true|false|null, "detail": "判定理由" },
    "path_reachable":   { "status": true|false|null, "detail": "判定理由" },
    "unmitigated":      { "status": true|false|null, "detail": "判定理由" },
    "security_impact":  { "status": true|false|null, "detail": "判定理由" }
  },
  "ruled_out_by": "当 verdict=ruled_out 时，指向触发归档的维度",
  "root_cause_summary": "漏洞根因简述（用于下游聚合）",
  "exploitability": {
    "preconditions": "攻击前置条件",
    "trigger_complexity": "low | medium | high",
    "worst_case_impact": "最坏安全后果"
  },
  "evidence": [
    { "type": "source | binary | defense | attack_surface | impact", "claim": "...", "finding": "..." }
  ]
}
```

## 5. 研判原则

- **默认怀疑**：Agent 的初始立场是「此报告不构成真实漏洞」，需要代码证据推翻
- **代码即 ground truth**：源码和二进制是最终权威，报告的描述只是假设
- **证据链完整**：每个维度的判定都附带具体证据——代码位置、汇编片段、校验逻辑描述
- **不确定不硬判**：静态分析无法覆盖的维度标记为 null，不强迫二元选择
