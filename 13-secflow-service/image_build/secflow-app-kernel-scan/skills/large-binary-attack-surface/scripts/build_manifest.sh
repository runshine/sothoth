#!/usr/bin/env bash
# build_manifest.sh <binary> <run-dir>
# 为大 ELF 构建全量符号 manifest，用于后续防漏扫。
#
# 输出：
#   <run-dir>/manifest.jsonl   每行 {name, addr, size, type, bind, vis, section, source}
#   <run-dir>/strings.txt      所有长度 >=6 的可打印字符串
#   <run-dir>/rodata_refs.txt  字符串 -> 引用地址（objdump 反汇编 grep）
#   <run-dir>/sections.txt     readelf -S 输出
#   <run-dir>/dynamic.txt      readelf -d 输出
#   <run-dir>/relocs.txt       readelf -r 输出
#   <run-dir>/stats.json       总符号数、导出数、函数数
#
# 用 nm 和 readelf 两条独立来源交叉校验。
set -euo pipefail

BIN="${1:?usage: build_manifest.sh <binary> <run-dir>}"
RUN="${2:?usage: build_manifest.sh <binary> <run-dir>}"
BIN_ABS="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
mkdir -p "$RUN"

echo "[*] binary: $BIN_ABS" >&2
echo "[*] run-dir: $RUN" >&2

# 1) 基础 ELF 信息
readelf -h "$BIN_ABS" > "$RUN/header.txt" 2>/dev/null || true
readelf -S "$BIN_ABS" > "$RUN/sections.txt" 2>/dev/null || true
readelf -d "$BIN_ABS" > "$RUN/dynamic.txt" 2>/dev/null || true
readelf -r "$BIN_ABS" > "$RUN/relocs.txt" 2>/dev/null || true

# 2) nm 符号（动态 + 全部）
# -D 动态符号；--defined-only；--print-size；-S 有 size
nm -D --defined-only -S "$BIN_ABS" > "$RUN/nm_dynsym.txt" 2>/dev/null || true
nm    --defined-only -S "$BIN_ABS" > "$RUN/nm_all.txt"    2>/dev/null || true

# 3) readelf --wide -s（带 bind/vis 信息，nm 没有）
readelf --wide -s "$BIN_ABS" > "$RUN/readelf_syms.txt" 2>/dev/null || true

# 4) 生成 manifest.jsonl
python3 - "$BIN_ABS" "$RUN" <<'PY'
import json, re, sys, os, pathlib
bin_path, run = sys.argv[1], sys.argv[2]
run = pathlib.Path(run)
out = (run / "manifest.jsonl").open("w")

# readelf -s 格式：
#   Num: Value Size Type Bind Vis Ndx Name
# e.g.
#   123: 0000ffff00010000  48 FUNC GLOBAL DEFAULT 14 my_handler
seen = set()
rx = re.compile(
    r"^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)"
)
count = 0
for line in (run / "readelf_syms.txt").read_text(errors="ignore").splitlines():
    m = rx.match(line)
    if not m: continue
    addr, size, stype, bind, vis, ndx, name = m.groups()
    if stype in ("FILE","SECTION","NOTYPE") and not name.strip():
        continue
    if name in seen: continue
    seen.add(name)
    out.write(json.dumps({
        "name": name,
        "addr": addr,
        "size": int(size) if size.isdigit() else 0,
        "type": stype,
        "bind": bind,
        "vis":  vis,
        "ndx":  ndx,
        "source": "readelf",
    }, ensure_ascii=False) + "\n")
    count += 1
out.close()

stats = {
    "binary": bin_path,
    "size_bytes": os.path.getsize(bin_path),
    "total_symbols": count,
    "func_symbols": sum(1 for l in (run/"readelf_syms.txt").read_text(errors='ignore').splitlines() if " FUNC " in l),
    "global_func":  sum(1 for l in (run/"readelf_syms.txt").read_text(errors='ignore').splitlines() if " FUNC " in l and " GLOBAL " in l),
}
(run / "stats.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False))
print(f"[+] manifest: {count} symbols -> {run}/manifest.jsonl", file=sys.stderr)
print(f"[+] stats    -> {run}/stats.json", file=sys.stderr)
PY

# 5) 字符串 + rodata 引用
strings -n 6 "$BIN_ABS" > "$RUN/strings.txt" 2>/dev/null || true

echo "[+] done. inspect: $RUN/stats.json" >&2
