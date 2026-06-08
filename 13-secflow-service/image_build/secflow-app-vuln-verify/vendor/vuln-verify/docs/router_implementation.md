# 确定性路由引擎（Router） — 实现

> 此文档面向开发者，描述路由引擎的内部实现。定位与设计理念见 [router_design.md](router_design.md)。

## 1. 定位

确定性路由引擎是 vuln-verify 内部子包（`packages/vuln-dispatch/`），通过 uv workspace 机制引用。vuln-verify CLI 在内部调用它完成报告分组。

单次执行，无状态，无网络，无 LLM，无并发。输入扫描报告 → 输出分组。不做任何安全价值判断。

---

## 2. 输入输出规格

### 2.1 命令行接口

```
vuln-dispatch \
  --reports     ./reports/           # .md 文件所在目录
  --source-root ./src/               # .c 文件根目录
  --binary-root ./bin/               # .so 文件根目录
  --threat      ./threat_model.md    # 威胁模型（必填）
  --output      ./output/            # Verifier 上下文包输出目录
  --logfile     ./routing_log.json   # 路由决策记录
```

六个参数全部必填。

### 2.2 输出目录结构

```
output/
├── routing_log.json
├── threat_model.md                # 威胁模型副本（所有组共用）
├── groups/
│   ├── group_001/
│   │   ├── manifest.json
│   │   └── reports/
│   │       ├── result_001.md
│   │       └── result_004.md
│   └── group_002/
│       └── ...
└── unrouteable/                   # 无法解析的报告
```

### 2.3 manifest.json 格式

```yaml
group_id: "group_001"
file: "libipsec.c"
file_path: "/data/src/libipsec.c"
binary_root: "/data/bin"
function: "IPSEC_AH_HandleOutputPktV4"
report_ids: ["result_001", "result_004"]
```

Verifier 读取 `manifest.json` 获取分组元信息。`binary_root` 告诉 Verifier 从哪里搜索 .so 文件——具体对应哪个 .so 由 Verifier 自行推断（通常同基名替换扩展名，或搜索符号表）。

---

## 3. 实现架构

### 3.1 模块划分

```
                    ┌──────────────────┐
                    │      CLI         │  参数解析 + 流程编排
                    └────────┬─────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
              ▼                             ▼
     ┌──────────────┐              ┌──────────────┐
     │ ReportParser │              │  Assembler   │
     │              │              │              │
     │ .md → 结构体  │              │ 分组 → 目录   │
     │ 3 字段提取    │              │ manifest 生成 │
     │ 容错处理     │              │ 上下文包装配  │
     └──────┬───────┘              └──────────────┘
            │
            ▼
   ┌───────────────┐
   │   Pipeline    │  顺序管道
   │               │
   │ Parse →       │
   │ Dedup →       │
   │ Group         │
   └───────┬───────┘
           │
  ┌────────┼────────┐
  │        │        │
  ▼        ▼        ▼
┌──────┐ ┌──────┐ ┌──────┐
│Dedup │ │Group │ │(仅此 │
│Eng   │ │er    │ │两个) │
└──────┘ └──────┘ └──────┘
```

两个核心模块：`ReportParser` 负责解析，`Assembler` 负责输出。管道中的 `DedupEngine` 和 `Grouper` 是无状态的纯函数，不单独作为模块。

### 3.2 核心数据结构

```
ParsedReport {
    report_id:    string          // 从 §1 提取
    fingerprint:  string | null   // 从 §1 提取
    file:         string | null   // 从 §2 subject.locator 提取
    function:     string | null   // 从 §2 subject.name 提取
    source_path:  string          // 原始 .md 文件绝对路径
}

VerifierGroup {
    group_id:  string
    file:      string
    function:  string
    reports:   ParsedReport[]
}

DedupRecord {
    fingerprint:          string
    kept_report_id:       string
    removed_report_ids:   string[]
}

UnrouteableRecord {
    report_id:     string
    reason:        string
    source_path:   string
}

RouterOutput {
    groups:        VerifierGroup[]
    deduplicated:  DedupRecord[]
    unrouteable:   UnrouteableRecord[]
}
```

### 3.3 处理管道

三个步骤，顺序执行，不可变转换：

```
Reports[] ──[Parse]──→ ParsedReport[]
   │
   ▼
ParsedReport[] ──[Dedup]──→ {reports: ParsedReport[], deduplications[]}
   │
   ▼
ParsedReport[] ──[Group]──→ VerifierGroup[]
   │
   ▼
VerifierGroup[] ──[Assemble]──→ 磁盘目录 + routing_log.json
```

---

## 4. 各模块设计要点

### 4.1 ReportParser

**任务**：从 .md 文本中提取 `fingerprint`、`file`、`function`。

**方法**：逐行正则匹配。

```
fingerprint 行: /fingerprint:\s*(.+)/
subject.name 行: /subject\.name:\s*(.+)/
subject.locator 行: /subject\.locator:\s*(.+?):(.+)/  → 冒号前为 file
```

**容错**：

- 字段缺失 → 对应字段为 `null`，不阻塞
- 文件不可读 → unrouteable
- 编码异常 → 尝试 UTF-8，失败则 Latin-1，都失败则 unrouteable

### 4.2 DedupEngine

**任务**：找出 fingerprint 完全相同的报告，只保留一份。

**方法**：以 `fingerprint` 为键建 HashMap。每 bucket 取第一份保留，其余标记为合并。`fingerprint` 为 `null` 的报告不参与去重。

### 4.3 Grouper

**任务**：按 `file + function` 两键分组。

**方法**：以元组 `(file, function)` 为键建 HashMap。

**空值处理**：`file` 或 `function` 任一为 `None` 的报告各自成组——无法解析的报告之间没有共享代码上下文，合在一起没有收益。只有两键都非 `None` 且相同的报告才共享同一个组。

- `file` 为 `None` → 键中 file 部分为 `"file_unknown"`，但该报告不与其他 null-file 报告共享组
- `function` 为 `None` → 键中 function 部分为 `"function_unknown"`，同样不共享

### 4.4 Assembler

**任务**：将分组结果物化为磁盘上的 Verifier 上下文包。

**操作**：

1. 为每组创建 `output/groups/group_NNN/` 目录
2. 写入 `manifest.json`（包含 `file`、`file_path = source_root + "/" + file`、`binary_root`、`function`、`report_ids`）
3. 复制威胁模型 .md 到 `output/threat_model.md`（所有组共用，不重复复制）
4. 复制组内 .md 报告到 `reports/` 子目录
5. 写 `routing_log.json`

---

## 5. 技术选型

| 决策 | 选择 | 理由 |
|------|------|------|
| 实现语言 | Python 3.11+ | 标准库全覆盖。**零外部依赖** |
| 报告解析 | `re` 正则，逐行匹配 | 不解析 Markdown 结构，容错性强 |
| 管道模式 | 函数式不可变管道 | 每步输出可序列化，便于测试 |
| 测试框架 | pytest | 用一组示例 .md + 期望输出做快照测试 |
| 并发 | 不做并发 | 百份报告毫秒级完成 |
| 外部依赖 | **零** | 全部使用 Python 标准库：`re`、`argparse`、`pathlib`、`json`、`shutil` |

---

## 6. 测试策略

| 模块 | 测试内容 |
|------|---------|
| ReportParser | 正常 .md → 正确字段；字段缺失 → null；损坏/空文件 → unrouteable |
| DedupEngine | 相同 fingerprint 合并；不同 fingerprint 保留；null fingerprint 不参与 |
| Grouper | 两键相同 → 同一组；任一键不同 → 不同组 |
| Assembler | 目录结构正确；manifest 内容正确；威胁模型复制完成 |
| 集成测试 | 完整输入 → 输出与快照对比 |

---

## 7. 与 Verifier 的协议

vuln-dispatch 和 Verifier 通过**文件系统**通信。Verifier 以组目录为工作上下文启动，读取 `manifest.json` 获取元信息，从 `reports/` 读取报告原文。威胁模型位于 `output/threat_model.md`，所有组共用同一份。

**vuln-dispatch 明确不提供的**：具体 .so 文件名——Verifier 拿到 `binary_root` 后自行定位
