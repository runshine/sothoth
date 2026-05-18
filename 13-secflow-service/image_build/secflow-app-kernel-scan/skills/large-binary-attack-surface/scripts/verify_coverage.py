#!/usr/bin/env python3
"""verify_coverage.py — 比对 batches 和 receipts，强制校验 missing == 0。

回执协议：
  每个 batch 处理完后，模型追加写一行到 <run-dir>/receipts.jsonl：
      {"batch": "batch_000.jsonl",
       "processed": ["sym1","sym2",...],
       "skipped":   [{"name": "sym3", "reason": "..."}],
       "error":     [{"name": "sym4", "reason": "..."}]}

本脚本:
  - 汇总 receipts，对比 batches/*.jsonl 的全集
  - 输出 missing 列表（应该处理但没回执的符号）
  - 退出码 0 表示全覆盖，非 0 表示有漏
"""
import json, sys, pathlib

def main():
    run = pathlib.Path(sys.argv[1])
    batches_dir = run / "batches"
    expected = {}           # sym -> batch name
    for bf in sorted(batches_dir.glob("batch_*.jsonl")):
        for line in bf.open():
            s = json.loads(line)
            expected[s["name"]] = bf.name

    seen = {"processed": set(), "skipped": set(), "error": set()}
    receipts_file = run / "receipts.jsonl"
    if receipts_file.exists():
        for line in receipts_file.open():
            if not line.strip(): continue
            r = json.loads(line)
            for n in r.get("processed", []):
                seen["processed"].add(n)
            for x in r.get("skipped", []):
                seen["skipped"].add(x["name"] if isinstance(x, dict) else x)
            for x in r.get("error", []):
                seen["error"].add(x["name"] if isinstance(x, dict) else x)

    covered = seen["processed"] | seen["skipped"] | seen["error"]
    missing = sorted(set(expected) - covered)
    report = {
        "total_candidates":  len(expected),
        "processed":         len(seen["processed"]),
        "skipped":           len(seen["skipped"]),
        "error":             len(seen["error"]),
        "missing":           len(missing),
        "missing_samples":   missing[:20],
        "run_dir":           str(run),
    }
    (run / "coverage.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(json.dumps(report, indent=2, ensure_ascii=False))
    sys.exit(0 if report["missing"] == 0 else 2)

if __name__ == "__main__":
    main()
