"""ida_export_candidates.py — IDA Pro headless 脚本。

用途：对 candidates.jsonl 里的每个符号导出伪 C 代码 + 交叉引用来源，
交给模型做攻击入口判断。每个符号一个 .c 文件，文件名用 safe-name。

用法（IDA Pro 9.x+ / idat）:
    idat -A -Lida.log \
         -S"ida_export_candidates.py <run-dir>" \
         <binary>

前置: <run-dir>/candidates.jsonl 已由 prefilter.py 生成。

输出:
    <run-dir>/ida_out/<safe_name>.c      decompiled pseudo-C
    <run-dir>/ida_out/<safe_name>.xrefs  caller list
    <run-dir>/ida_export_manifest.json   sym -> file 映射
"""
import json, os, re, sys, pathlib

# IDA 环境
import idaapi, idc, idautils, ida_hexrays, ida_funcs, ida_name, ida_xref

def safe(name):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:180]

def export_one(ea, name, outdir):
    out_c = outdir / (safe(name) + ".c")
    out_x = outdir / (safe(name) + ".xrefs")
    # pseudocode
    try:
        cfunc = ida_hexrays.decompile(ea)
        pc = str(cfunc) if cfunc else None
    except Exception as e:
        pc = f"// decompile failed: {e}"
    if pc is None:
        # 回退到反汇编
        lines = []
        f = ida_funcs.get_func(ea)
        if f:
            for insn_ea in idautils.Heads(f.start_ea, f.end_ea):
                lines.append(f"{insn_ea:#x}: {idc.GetDisasm(insn_ea)}")
        pc = "// decompile N/A; disasm:\n" + "\n".join(lines)
    out_c.write_text(pc)
    # xrefs
    xr = []
    for xref in idautils.XrefsTo(ea):
        frm = xref.frm
        fn  = ida_funcs.get_func(frm)
        fn_name = ida_name.get_ea_name(fn.start_ea) if fn else "<no-func>"
        xr.append(f"{frm:#x} <- {fn_name} ({xref.type:#x})")
    out_x.write_text("\n".join(xr))
    return out_c.name, out_x.name

def main():
    idaapi.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        print("[!] hex-rays unavailable, using disasm fallback")
    args = idc.ARGV
    if len(args) < 2:
        print("usage: -S\"ida_export_candidates.py <run-dir>\"")
        idc.qexit(2)
    run = pathlib.Path(args[1])
    outdir = run / "ida_out"
    outdir.mkdir(exist_ok=True)
    manifest = {}
    cands = [json.loads(l) for l in (run / "candidates.jsonl").open()]
    for i, c in enumerate(cands, 1):
        ea = idc.get_name_ea_simple(c["name"])
        if ea == idc.BADADDR:
            ea = int(c["addr"], 16)
        if ea == idc.BADADDR or not ida_funcs.get_func(ea):
            manifest[c["name"]] = {"status": "not-found"}
            continue
        cfile, xfile = export_one(ea, c["name"], outdir)
        manifest[c["name"]] = {"c": cfile, "xrefs": xfile, "ea": f"{ea:#x}"}
        if i % 50 == 0:
            print(f"[*] exported {i}/{len(cands)}")
    (run / "ida_export_manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    print(f"[+] exported {sum(1 for v in manifest.values() if 'c' in v)}/{len(cands)}")
    idc.qexit(0)

main()
