# 智能研判引擎（Triager） — 实现

> 此文档面向开发者，描述研判引擎的内部实现。定位与设计理念见 [triager_design.md](triager_design.md)。

## 1. 核心设计决策

| 决策 | 理由 |
|:---|:---|
| 确定性预处理 + LLM 语义分析，不是纯 LLM | 精确字符串匹配、统计、schema 验证这些不需要 LLM。LLM 只做需要语义理解的部分 |
| 一个 pi 进程，不是 G 个并行 | Triager 的价值在于全局视角。拆成并行就失去了跨 Verifier 对比的能力 |
| 预处理产出摘要表，不是全文 | 18 份 JSON 全部喂给 LLM 可能超 context。预处理提取关键字段，LLM 需要细节时用 `read` 工具自行获取 |
| 直接在 `vuln-verify` 内部，不是独立 CLI | Triager 是流水线的一部分，启动时机由 launcher 控制。独立 CLI 有价值但 P0 不加 |
| 复用现有的 log/launcher/prompt 模式 | 与 Verifier 启动方式一致，减少认知负担 |

## 2. 模块结构

```
src/vuln_verify/
├── __init__.py
├── cli.py                    ← 新增 --triager 标志
├── launcher.py               ← 新增 _run_triager()，在 Verifier 全部结束后调用
├── prompt.py                 ← 新增 load_triager_prompt()
├── triager/
│   ├── __init__.py
│   ├── ingest.py             ← 确定性：加载、校验、分类、精确去重、构建摘要
│   ├── model.py              ← 数据类型
│   └── runner.py             ← 启动 pi，解析 LLM 输出，写入文件

templates/
├── verifier_prompt.md        (existing)
├── triager_prompt.md         ← new
└── threat_model.md           (existing)
```

### 2.1 `triager/model.py` — 数据类型

```python
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Verdict = Literal["confirmed", "ruled_out", "unresolved"]
DimensionStatus = bool | None

@dataclass
class Dimensions:
    code_accurate: DimensionStatus
    path_reachable: DimensionStatus
    unmitigated: DimensionStatus
    security_impact: DimensionStatus

@dataclass
class Exploitability:
    preconditions: str
    trigger_complexity: Literal["low", "medium", "high"]
    worst_case_impact: str

@dataclass
class Finding:
    """单个 Verifier 产出的验证结论，从 result_*.json 解析而来。"""
    report_id: str
    verdict: Verdict
    ruled_out_by: str | None
    root_cause_summary: str
    dimensions: Dimensions
    exploitability: Exploitability
    file: str          # from manifest / filename convention
    function: str      # from manifest

@dataclass
class RootCause:
    """去重后的根因。"""
    root_cause_id: str
    title: str
    verdict: Verdict
    severity: str
    severity_reasoning: str
    root_cause: str
    merged_reports: list[str]
    representative: str
    dimensions: Dimensions
    exploitability: Exploitability
    fix_priority: str
    fix_dependencies: list[str] = field(default_factory=list)
    fix_also_resolves: list[str] = field(default_factory=list)
    poc_score: float = 0.0
    poc_recommended: bool = False

@dataclass
class SystemicWeakness:
    pattern: str
    affected_root_cause_ids: list[str]
    affected_functions: list[str]
    recommendation: str

@dataclass
class Contradiction:
    type: str          # "verdict_conflict" | "dimension_conflict" | "threat_model_conflict"
    report_ids: list[str]
    issue: str
    recommended_action: str

@dataclass
class TriageOutput:
    meta: dict
    ranked_findings: list[RootCause]
    systemic_weaknesses: list[SystemicWeakness]
    contradictions: list[Contradiction]
    poc_priority: list[dict]
    fp_analysis: dict
    statistics: dict
```

### 2.2 `triager/ingest.py` — 确定性预处理

```python
"""
确定性预处理管线：
1. 扫描 verifier_output/result_*.json
2. 解析每个文件，校验 schema
3. 按 verdict 分类
4. root_cause_summary 精确匹配去重
5. 组装结构化摘要表 → 传给 LLM prompt
6. 计算基础统计
"""

from pathlib import Path
from triager.model import Finding, TriageOutput

def ingest(verifier_output_dir: Path) -> dict:
    """
    返回:
      - findings: list[Finding]          去重前的全部 finding
      - by_verdict: dict[Verdict, list[Finding]]
      - exact_dup_groups: list[list[Finding]]   root_cause_summary 完全相同的组
      - deduplicated: list[Finding]             exact-match 去重后的列表
      - summary_text: str                       给 LLM 的摘要表（Markdown table）
      - stats: dict                             基础统计
    """


def validate_finding(data: dict) -> Finding | None:
    """校验 JSON schema，返回 Finding 或 None（标记为 corrupt）。"""


def build_summary_table(findings: list[Finding]) -> str:
    """将去重后的 finding 列表转为紧凑的 Markdown table。"""


def exact_dedup(findings: list[Finding]) -> tuple[list[list[Finding]], list[Finding]]:
    """root_cause_summary 完全相同 → 合并。返回 (groups, deduplicated)。"""
```

**摘要表的格式**（写入 triager prompt 的 `{{FINDINGS_TABLE}}` 占位符）：

```markdown
| ID | Verdict | Function | Dimensions (CA/PR/UM/SI) | Ruled By | Impact | Complexity | Root Cause Summary |
|:---|:---|:---|:---:|:---|:---|:---|:---|
| result_001 | confirmed | IPSEC_AH_HandleInputPktV4 | T/T/T/T | - | Remote DoS | low | AH IPv4 入站 option len=0 死循环... |
| result_004 | ruled_out | IPSEC_PKT_ParseAndVerifyHdrV4 | T/T/T/F | security_impact | - | low | payload_len 整数下溢... |
| result_006 | unresolved | IPSEC_AH_HandleInputPktV4 | T/T/null/null | - | Info leak? | low | VOS_MemCmp 非常量时间... |
```

列含义：CA=code_accurate, PR=path_reachable, UM=unmitigated, SI=security_impact。T=true, F=false, ?=null.

### 2.3 `templates/triager_prompt.md` — LLM 提示词

```markdown
# 角色

你是漏洞裁决者（Triager）。你看到 G 个独立 Verifier 产出的全部验证结论，任务是：
去重、校准严重度、识别系统模式、检测矛盾、输出排序结果。

# 输入

## 威胁模型

{{THREAT_MODEL}}

## 验证结论摘要

{{FINDINGS_TABLE}}

你需要时可以用 `read` 工具查看 `verifier_output/result_*.json` 的完整内容。

# 任务

按顺序执行以下步骤。每步完成后再进入下一步。

## 步骤 1：语义去重

标准：「修复一个漏洞的代码变更能否同时解除另一个漏洞」。

规则（按强度递减）：
1. 同一函数、同一行代码、同一操作 → 合并为一个根因
2. 同一函数、不同行，但都因「同一个缺失的输入校验」→ 合并
3. 不同函数、但完全相同的缺失模式 → 标记但不强制合并
4. 函数、位置、根因、影响都不同 → 独立保留

输出第一步结论（纯文本）：
- 合并了哪些 report_id → 哪个根因
- 每个根因选择一个「最佳代表报告」（evidence 最完整）

## 步骤 2：严重度校准

对每个去重后的根因，依次回答（不只看 Verifier 的 exploitability 字段）：
1. 攻击者前提条件？（位置、认证、配置）
2. 威胁模型中有明确补偿控制吗？
3. 最坏实际影响？
4. 严重度：critical / high / medium / low

## 步骤 3：系统模式检测

跨根因找共同点。触发条件：
- ≥3 个 confirmed 共享同一 root_cause 模式
- 同一 sink 函数被 ≥2 个根因指向
- IPv4/IPv6 对同一逻辑有一方检查另一方没有

输出：systemic_weaknesses[] 列表

## 步骤 4：矛盾检测

交叉检查 Verifier 输出：
1. 同一代码段的不同 verdict
2. 维度冲突（一方 T 一方 F）
3. 威胁模型解读冲突

输出：contradictions[] 列表

## 步骤 5：排序

A. **修复优先级**（给开发）：severity × dependency_factor
   - dependency_factor: 1.5 若修复自动解除其他; 0.5 若依赖先修别的

B. **PoC 优先级**（给安全研究）：
   poc_score = severity × value_of_resolution / cost
   - value_of_resolution: security_impact=null → 10; 其他 null → 5; confirmed → 3
   - cost: 无前置条件 → 1; 需 SA → 2; 需同网段 → 3

## 步骤 6：误报分析

从 ruled_out 中总结模式（不逐条分析，找规律）。

# 输出格式

## 文件 1：triage.json

严格按照以下 JSON schema 输出到 `verifier_output/../triage/triage.json`。

```json
{
  "meta": {
    "generated_at": "ISO8601",
    "input_count": 18,
    "post_exact_dedup_count": 15,
    "output_root_cause_count": 6
  },
  "ranked_findings": [
    {
      "rank": 1,
      "root_cause_id": "RC-001",
      "title": "一句话标题",
      "verdict": "confirmed",
      "severity": "critical",
      "severity_reasoning": "为什么是这个严重度",
      "root_cause": "完整根因描述",
      "merged_reports": ["result_001", "result_022"],
      "representative": "result_001",
      "dimensions": {"code_accurate": true, "path_reachable": true, "unmitigated": true, "security_impact": true},
      "exploitability": {"preconditions": "...", "trigger_complexity": "low", "worst_case_impact": "..."},
      "fix_priority": "critical",
      "fix_dependencies": [],
      "fix_also_resolves": [],
      "poc_score": 30.0,
      "poc_recommended": true
    }
  ],
  "systemic_weaknesses": [
    {
      "pattern": "...",
      "affected_root_cause_ids": ["RC-001"],
      "affected_functions": ["..."],
      "recommendation": "..."
    }
  ],
  "contradictions": [
    {
      "type": "verdict_conflict",
      "report_ids": ["result_004", "result_019"],
      "issue": "...",
      "recommended_action": "..."
    }
  ],
  "poc_priority": [
    {"root_cause_id": "RC-006", "reason": "...", "poc_score": 40.0}
  ],
  "fp_analysis": {
    "top_ruled_out_reasons": {
      "path_reachable": {"count": 5, "pattern": "LLM 批量扫描不区分入站/出站路径"}
    }
  },
  "statistics": {
    "verdict_distribution": {"confirmed": 5, "ruled_out": 12, "unresolved": 1},
    "total_input_reports": 18,
    "post_exact_dedup_count": 15,
    "unique_root_causes": 6,
    "average_reports_per_root_cause": 2.2
  }
}
```

## 文件 2：triage_report.md

完整的 Markdown 技术报告。包含：
1. 执行摘要（关键数字 + Top 3 风险）
2. 按严重度排序的详细报告
3. 系统性弱点
4. 矛盾标记
5. PoC 建议
6. 误报分析
7. 统计附录

## 文件 3：executive_summary.md

一页非技术摘要。包含：
- 关键数字（total / confirmed / ruled_out / unresolved）
- Top N 风险一句话描述
- 建议的下一步行动
- 不包含技术细节

# 规则

1. 先每步完成后再进入下一步。不要跳步。
2. 步骤 1-4 的中间结论以纯文本输出（便于审计）。
3. 最终 JSON 必须可解析。结束前用 Python 验证 triage.json 是合法 JSON。
4. 不要编造 report_id 或函数名——只使用摘要表中出现的。
5. 如果 Verifier 对同一代码段判相反结论，标记为矛盾，不做简单投票。
```

### 2.4 `triager/runner.py` — 启动 pi 并解析输出

```python
"""启动 Triager pi 进程，解析输出。"""

import json
import subprocess
import tempfile
from pathlib import Path
from vuln_dispatch.log import get_logger
from vuln_verify.prompt import load_triager_prompt
from triager.ingest import ingest, build_summary_table, exact_dedup
from triager.model import TriageOutput


def run_triage(verifier_output_dir: Path, threat_path: Path, output_dir: Path) -> int:
    """
    1. ingest → 加载所有 Verifier JSON
    2. 构建摘要表
    3. 替换 triager prompt 占位符
    4. 启动 pi
    5. 解析 triage.json 输出
    6. 验证 schema
    7. 写入 triage/ 目录
    """
    log = get_logger("triager")

    # Step 1-2: ingest
    ingested = ingest(verifier_output_dir)
    if ingested["finding_count"] == 0:
        log.error("no_findings", verifier_output_dir=str(verifier_output_dir))
        return 1

    # Step 3: build prompt with table
    base_prompt = load_triager_prompt(threat_path)
    prompt = base_prompt.replace("{{FINDINGS_TABLE}}", ingested["summary_text"])

    # Step 4: launch pi
    triage_dir = output_dir.resolve() / "triage"
    triage_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix="_triager_prompt.md", delete=False
    ) as handle:
        handle.write(prompt)
        tmp_prompt = Path(handle.name)

    try:
        log.info("triager_start", finding_count=ingested["finding_count"])
        result = subprocess.run(
            ["pi", "--append-system-prompt", str(tmp_prompt), "-p",
             f"执行 triage。将 triage.json、triage_report.md、executive_summary.md 输出到 {triage_dir}。"],
            cwd=str(output_dir),
            capture_output=True,
            text=True,
        )
        log.info("triager_done", returncode=result.returncode)

        # Step 5: validate output
        triage_json_path = triage_dir / "triage.json"
        if not triage_json_path.exists():
            log.error("missing_triage_json")
            return 1

        triage_data = json.loads(triage_json_path.read_text(encoding="utf-8"))
        log.info("triager_summary",
                 output_root_cause_count=len(triage_data.get("ranked_findings", [])),
                 contradiction_count=len(triage_data.get("contradictions", [])),
                 systemic_count=len(triage_data.get("systemic_weaknesses", [])))

        return 0
    finally:
        try:
            tmp_prompt.unlink()
        except FileNotFoundError:
            pass
```

### 2.5 `cli.py` 修改

```python
# 新增参数
parser.add_argument("--triager", action="store_true",
                    help="run Triager after all Verifiers complete")

# _run_pipeline 中
def _run_pipeline(args, output_dir, logfile):
    ...
    launch(...)
    if args.triager:
        from vuln_verify.triager.runner import run_triage
        run_triage(
            verifier_output_dir=output_dir / "verifier_output",
            threat_path=Path(args.threat).expanduser(),
            output_dir=output_dir,
        )
    return 0
```

### 2.6 `launcher.py` 修改

不修改 `launcher.py`。Triager 在 launcher 返回后由 `_run_pipeline` 有条件地调用。这样 launcher 职责保持单一。

## 3. 数据流

```
verifier_output/result_*.json
        │
        ▼
┌─────────────────┐
│  ingest.py       │  确定性预处理
│                  │
│ 1. 扫描 JSON     │
│ 2. 校验 schema   │
│ 3. 按 verdict 分  │
│ 4. 精确字符串去重 │
│ 5. 构建摘要表    │
└────────┬────────┘
         │ summary_text (Markdown table)
         ▼
┌─────────────────┐
│  triager_prompt  │  {{FINDINGS_TABLE}} + {{THREAT_MODEL}}
│  substitution    │
└────────┬────────┘
         │ full prompt text
         ▼
┌─────────────────┐
│  pi process      │  LLM 执行 6 个步骤
│  (1 instance)    │  需要时可 read 完整 JSON
└────────┬────────┘
         │ triage.json + triage_report.md + executive_summary.md
         ▼
┌─────────────────┐
│  runner.py       │  后处理
│                  │
│ 1. 解析 JSON     │
│ 2. 校验 schema   │
│ 3. 日志摘要      │
└────────┬────────┘
         │
         ▼
    triage/
    ├── triage.json
    ├── triage_report.md
    └── executive_summary.md
```

## 4. 输出目录结构（完整）

```
output/
├── verify.jsonl                  ← Router + Verifier + Triager 全流程 JSONL 日志
├── verify.log                    ← 路由决策摘要 JSON
├── threat_model.md
├── groups/                       ← Router 分组产物
│   └── group_001/
│       ├── manifest.json
│       └── reports/
├── verifier_output/              ← Verifier 产物
│   ├── result_001.json
│   ├── group_001_analysis.md
│   ├── group_001.stdout
│   └── group_001.stderr
└── triage/                       ← Triager 产物（新增）
    ├── triage.json
    ├── triage_report.md
    └── executive_summary.md
```

## 5. 测试策略

| 层级 | 测试内容 | 测试方式 |
|:---|:---|:---|
| **ingest.py** | 合法 JSON 解析正确；损坏 JSON 返回 None；schema 不完整时降级；精确去重正确 | 单元测试，用 fixture 提供各种 result_*.json |
| **ingest.py** | 摘要表格式正确；列对齐；特殊字符转义 | snapshot 测试 |
| **runner.py** | 无 JSON 文件时返回错误；JSON 文件不存在时返回错误 | 单元测试，mock subprocess |
| **集成** | 完整 verifier_output 目录 → Triager 产出 triage.json | 集成测试，用已知的 18 份报告结果 |
| **prompt** | LLM 输出的 JSON 可解析；schema 符合预期 | 手工验证 + 自动 schema 校验 |

## 6. 与 P0 需求的对齐

| 需求 | 实现位置 |
|:---|:---|
| R1 跨组语义去重 | ingest.py 做精确去重 + triager_prompt.md 步骤 1 |
| R2 严重度统一校准 | triager_prompt.md 步骤 2 |
| R3 排序产出 | triager_prompt.md 步骤 5 → ranked_findings |
| R12 技术报告 | triage_report.md（LLM 生成） |
| R14 机器输出 | triage.json（LLM 生成，runner 校验） |

P1-P3 需求在 prompt 中有规则框架，但具体实现是 LLM 自主推理，不需要额外代码——这是 Triager 作为 LLM Agent 的优势：加需求 = 加 prompt 规则，不写代码。

## 7. 实施顺序

```
1. model.py          ← 数据类型（零依赖，先定义 schema）
2. ingest.py         ← 确定性预处理（可单独测试）
3. triager_prompt.md ← 提示词
4. runner.py         ← pi 集成
5. cli.py 修改       ← --triager 标志
6. 测试              ← 单元 + 快照 + 集成
```
