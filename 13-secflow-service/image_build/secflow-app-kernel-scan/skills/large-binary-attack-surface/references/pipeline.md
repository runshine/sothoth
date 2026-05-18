# Pipeline 总览

核心思路：**不要让模型吞下整个二进制**。用确定性工具先产出权威全集，模型只看筛过的候选 + 每批回执强制校验覆盖率。

```
binary (100M+)
   ↓ build_manifest.sh
manifest.jsonl  (全量符号，几万到几十万)
   ↓ prefilter.py
candidates.jsonl (几百到几千，三档 tier)
   ↓ make_batches.py
batches/batch_000.jsonl ... batch_N.jsonl
   ↓ ida_export_candidates.py (可选但推荐)
ida_out/<sym>.c, <sym>.xrefs
   ↓ 模型按批分析，每批写 receipts.jsonl
receipts.jsonl
   ↓ verify_coverage.py
coverage.json → missing == 0 才能出最终报告
```

## 每个产物的作用

| 文件 | 作用 | 产生者 |
|---|---|---|
| `manifest.jsonl` | 全量符号权威清单，校验基准 | build_manifest.sh |
| `strings.txt` | 所有字符串，用来识别设备节点/服务名 | build_manifest.sh |
| `candidates.jsonl` | 三档候选，模型只分析这部分 | prefilter.py |
| `batches/batch_*.jsonl` | 分片，控制模型上下文 | make_batches.py |
| `ida_out/<sym>.c` | IDA 伪 C，喂给模型 | ida_export_candidates.py |
| `receipts.jsonl` | 模型产出的回执，记录处理结果 | 模型每批处理后追加 |
| `coverage.json` | 覆盖率校验 | verify_coverage.py |

## 为什么一定要走这个流水线

1. **IDA/Ghidra 全量反编译几万个函数要几十分钟到几小时**，浪费。先筛再反编译。
2. **模型上下文有限**：一次喂 40–50 个符号的伪 C 大致在 30–80K tokens，刚好。
3. **防止漏扫**：manifest 是权威全集，每个符号必须落到 `processed/skipped/error` 三桶之一，`verify_coverage.py` 拒绝打报告的接口是唯一硬约束。

## Tier 语义

- **tier1**：导出符号 + 名字命中攻击面 pattern。**必须分析**。
- **tier2**：导出符号 + 有一定规模但名字没明显特征。**必须分析**，常见于匿名 dispatch。
- **tier3**：名字像入口但非导出，或 size 很小。**抽样**或**只分析名字非常典型的那些**，但仍然必须在 receipts 里给出 skipped 原因。

tier1/tier2 不得 skip，必须有真实分析结论。tier3 可以根据时间成本有选择地处理，但总体覆盖率 `missing == 0` 这条不能破。
