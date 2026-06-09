"""poc-dynamic-verify — thin CLI that invokes pi agent with phase Skills.

Architecture:
  phase1 → pi --skill poc-phase1-binary-dependency → binary_dependency_map.json
  phase2 → pi --skill poc-phase2-qiling-emulation   → poc_result.{json,md} + patch/branch logs

The heavy lifting (source analysis, binary exploration, Qiling scripting) is
done by the pi agent guided by the Skill. This CLI only parses args and invokes pi.
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path

log = logging.getLogger(__name__)

SKILL_DIR = Path(__file__).resolve().parent.parent / "skills"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="poc-dynamic-verify",
        description="POC 动态仿真验证 — Phase 1 二进制依赖分析 + Phase 2 Qiling 仿真",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", required=True)

    # ── phase1 ────────────────────────────────────────────────────
    p1 = sub.add_parser("phase1", help="仅执行 Phase 1: 二进制依赖分析",
        epilog="""\
示例:
  poc-dynamic-verify phase1 \\
      --vuln-report vuln.md \\
      --entry-func main \\
      --source-dir source/ \\
      --binary-dir binaries/""")
    p1.add_argument("--vuln-report", required=True, help="漏洞报告 (Markdown 或 JSON)")
    p1.add_argument("--entry-func", required=True, help="入口函数名 (如 main)")
    p1.add_argument("--source-dir", required=True, help="源码根目录")
    p1.add_argument("--binary-dir", required=True, help="固件解包后 binary 根目录")
    p1.add_argument("-o", "--output-dir", default="./poc_output", help="输出目录")
    p1.add_argument("--model", help="指定 pi 模型")
    p1.add_argument("-v", "--verbose", action="count", default=0)

    # ── phase2 ────────────────────────────────────────────────────
    p2 = sub.add_parser("phase2", help="仅执行 Phase 2: Qiling 动态仿真",
        epilog="""\
示例:
  poc-dynamic-verify phase2 \\
      --dep-map poc_output/binary_dependency_map.json \\
      --binary-dir binaries/ \\
      --output-dir poc_output/""")
    p2.add_argument("--dep-map", required=True, help="Phase 1 产出的 binary_dependency_map.json")
    p2.add_argument("--binary-dir", required=True, help="固件 binary 根目录")
    p2.add_argument("-o", "--output-dir", default="./poc_output", help="输出目录")
    p2.add_argument("--rootfs", help="Qiling rootfs (默认同 --binary-dir)")
    p2.add_argument("--model", help="指定 pi 模型")
    p2.add_argument("-v", "--verbose", action="count", default=0)

    # ── run (both) ────────────────────────────────────────────────
    pr = sub.add_parser("run", help="执行完整流程: Phase 1 + Phase 2",
        epilog="""\
示例:
  poc-dynamic-verify run \\
      --vuln-report vuln.md \\
      --entry-func main \\
      --source-dir source/ \\
      --binary-dir binaries/""")
    pr.add_argument("--vuln-report", required=True, help="漏洞报告 (Markdown 或 JSON)")
    pr.add_argument("--entry-func", required=True, help="入口函数名")
    pr.add_argument("--source-dir", required=True, help="源码根目录")
    pr.add_argument("--binary-dir", required=True, help="固件解包后 binary 根目录")
    pr.add_argument("-o", "--output-dir", default="./poc_output", help="输出目录")
    pr.add_argument("--rootfs", help="Qiling rootfs")
    pr.add_argument("--model", help="指定 pi 模型")
    pr.add_argument("-v", "--verbose", action="count", default=0)

    args = p.parse_args(argv)
    _setup_logging(args.verbose)

    try:
        if args.command == "phase1":
            return _run_phase1(args)
        elif args.command == "phase2":
            return _run_phase2(args)
        else:
            output_dir = Path(args.output_dir).resolve()
            args.dep_map = str(output_dir / "binary_dependency_map.json")
            rc = _run_phase1(args)
            if rc != 0:
                return rc
            return _run_phase2(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        if args.verbose >= 1:
            import traceback; traceback.print_exc()
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1


# ── helpers ───────────────────────────────────────────────────────────

def _setup_logging(verbose: int) -> None:
    level = logging.DEBUG if verbose >= 2 else (logging.INFO if verbose >= 1 else logging.WARNING)
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")


def _check_paths(**paths: str) -> int:
    ok = True
    for label, p in paths.items():
        if not Path(p).exists():
            print(f"error: {label} not found: {p}", file=sys.stderr)
            ok = False
    return 0 if ok else 1


def _invoke_pi(skill_name: str, prompt: str, cwd: Path, model: str | None = None) -> int:
    skill_md = SKILL_DIR / skill_name / "SKILL.md"
    if not skill_md.is_file():
        print(f"error: skill not found: {skill_md}", file=sys.stderr)
        return 1

    cwd.mkdir(parents=True, exist_ok=True)
    stdout = cwd / f"{skill_name}.stdout"
    stderr = cwd / f"{skill_name}.stderr"

    cmd = ["pi", "--append-system-prompt", str(skill_md), "-p", prompt]
    if model:
        cmd.extend(["--model", model])

    log.info("pi: %s", " ".join(cmd))
    with open(stdout, "w") as fo, open(stderr, "w") as fe:
        rc = subprocess.Popen(cmd, cwd=str(cwd), stdout=fo, stderr=fe).wait()

    if rc != 0:
        log.warning("pi exit %d — %s", rc, stderr)
    return rc


# ── Phase 1 ───────────────────────────────────────────────────────────

def _run_phase1(args) -> int:
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    vuln   = Path(args.vuln_report).resolve()
    src    = Path(args.source_dir).resolve()
    bindir = Path(args.binary_dir).resolve()

    meta = {
        "vuln_report": str(vuln),
        "entry_function": args.entry_func,
        "source_dir": str(src),
        "binary_dir": str(bindir),
        "output_dir": str(output),
    }
    meta_f = output / "phase1_input.json"
    meta_f.write_text(json.dumps(meta, indent=2, ensure_ascii=False))

    if _check_paths(vuln_report=str(vuln), source_dir=str(src), binary_dir=str(bindir)) != 0:
        return 1

    prompt = (
        f"执行 Phase 1 二进制依赖分析。\n\n"
        f"输入信息见 {meta_f}。\n\n"
        f"任务：\n"
        f"1. 读取漏洞报告获取漏洞函数名和漏洞文件\n"
        f"2. 在源码目录中，从入口函数 {args.entry_func} 出发，追踪到漏洞函数的调用链\n"
        f"   — 在源文件中查找函数调用关系 (call graph / callsite analysis)\n"
        f"   — 记录完整的函数调用路径\n"
        f"3. 探索 binary 目录下所有 ELF 文件，用 file/readelf/nm 获取架构、符号、依赖\n"
        f"4. 将调用链中的每个函数匹配到对应的 binary 和地址\n"
        f"5. 收集所有需要的 .so 依赖\n"
        f"6. 输出 {output}/binary_dependency_map.json\n"
    )
    rc = _invoke_pi("poc-phase1-binary-dependency", prompt, output, model=getattr(args, 'model', None))

    dep_map = output / "binary_dependency_map.json"
    if rc == 0 and dep_map.exists():
        print(f"\n  Phase 1 完成 → {dep_map}\n")
    else:
        print(f"\n  Phase 1 未成功完成 (exit={rc})\n", file=sys.stderr)
    return rc


# ── Phase 2 ───────────────────────────────────────────────────────────

def _run_phase2(args) -> int:
    output  = Path(args.output_dir).resolve()
    dep_map = Path(args.dep_map).resolve()
    bindir  = Path(args.binary_dir).resolve()
    rootfs  = args.rootfs or str(bindir)

    if _check_paths(dep_map=str(dep_map), binary_dir=str(bindir)) != 0:
        return 1

    prompt = (
        f"执行 Phase 2 Qiling 动态仿真。\n\n"
        f"二进制依赖映射: {dep_map}\n"
        f"Binary 目录: {bindir}\n"
        f"Rootfs: {rootfs}\n\n"
        f"任务：\n"
        f"1. 读取 {dep_map} 获取调用链、架构、所有 binary 路径\n"
        f"2. 编写 Qiling Framework 仿真脚本，从入口函数模拟执行到漏洞点\n"
        f"3. 真实执行路径上每个函数，仅在必要时 patch，记录 patch 原因\n"
        f"4. 记录所有条件分支决策 (地址/指令/条件/值)\n"
        f"5. 输出到 {output}/:\n"
        f"   - poc_result.json — 验证结果\n"
        f"   - poc_result.md — 人类可读报告\n"
        f"   - patch_log.json — patch 记录\n"
        f"   - branch_decisions.json — 分支记录\n"
    )
    rc = _invoke_pi("poc-phase2-qiling-emulation", prompt, output, model=getattr(args, 'model', None))

    result = output / "poc_result.json"
    if rc == 0 and result.exists():
        print(f"\n  Phase 2 完成 → {result}\n")
    else:
        print(f"\n  Phase 2 未成功完成 (exit={rc})\n", file=sys.stderr)
    return rc
