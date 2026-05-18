#!/usr/bin/env python3
"""make_batches.py — 把 candidates.jsonl 切成固定大小的分片。

用法:
    make_batches.py <run-dir> [batch-size]
默认 batch-size=40。tier1 先排，tier2 其次，tier3 最后。
输出:
    <run-dir>/batches/batch_000.jsonl
    <run-dir>/batches/batch_001.jsonl
    ...
    <run-dir>/batches/INDEX.json
"""
import json, sys, pathlib

def main():
    run = pathlib.Path(sys.argv[1])
    batch_size = int(sys.argv[2]) if len(sys.argv) > 2 else 40
    cands = [json.loads(l) for l in (run / "candidates.jsonl").open()]
    cands.sort(key=lambda x: (x["tier"], -x.get("size", 0), x["name"]))
    out = run / "batches"
    out.mkdir(exist_ok=True)
    # 清理旧 batch
    for p in out.glob("batch_*.jsonl"):
        p.unlink()
    index = []
    for i in range(0, len(cands), batch_size):
        chunk = cands[i:i+batch_size]
        name = f"batch_{i//batch_size:03d}.jsonl"
        fp = out / name
        with fp.open("w") as f:
            for c in chunk:
                f.write(json.dumps(c, ensure_ascii=False) + "\n")
        index.append({
            "batch": name,
            "count": len(chunk),
            "tier_min": min(c["tier"] for c in chunk),
            "tier_max": max(c["tier"] for c in chunk),
            "first": chunk[0]["name"],
            "last": chunk[-1]["name"],
        })
    (out / "INDEX.json").write_text(json.dumps({
        "total_candidates": len(cands),
        "batch_size": batch_size,
        "batches": index,
    }, indent=2, ensure_ascii=False))
    print(f"[+] {len(cands)} candidates -> {len(index)} batches in {out}")

if __name__ == "__main__":
    main()
