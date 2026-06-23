"""poc-dynamic-verify — 调用 pi agent 执行 PoC 验证流水线。

每次运行都会真启动 pi agent(除了 --dry-run 模式),同时把所有:
  - 输入文件存在性检查
  - 构造的 pi 子进程完整命令行(可以直接复制粘贴)
  - 写出的 state / input 文件路径
  - 完成后应该读哪些产出

全部 echo 到 stderr,让你实时观察流水线状态。

每次运行在 <project>/workspace/poc-verify-YYYYMMDD-HHMMSS/ 下建独立工作目录,避免污染。

执行模式:
  phase1  → 单次 subprocess 调用 pi(独立 session),跑 Phase 1 Skill
  phase2  → 单次 subprocess 调用 pi(独立 session),跑 Phase 2 Skill
  run     → 单 pi RPC 进程,整个 3 阶段流水线在同一个 session 内执行
            (由 Master Skill `poc-verify-pipeline` 通过 `read` 工具串联)
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

log = logging.getLogger(__name__)

SKILL_DIR = Path(__file__).resolve().parent.parent / "skills"
MASTER_SKILL_DIR = Path(__file__).resolve().parent.parent / ".pi" / "skills" / "poc-verify-pipeline"

# 默认在 <project>/workspace/poc-verify-<timestamp>/ 下建工作目录
DEFAULT_WORK_ROOT = Path(__file__).resolve().parent.parent / "workspace"


# ─────────────────────────────────────────────────────────────────────
# 入口
# ─────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="poc-dynamic-verify",
        description=(
            "POC 动态仿真验证 — 每次都真启动 pi agent(除非加 --dry-run)。\n"
            "\n"
            "子命令:\n"
            "  phase1   阶段一:二进制依赖分析(独立 pi session)\n"
            "  phase2   阶段二:PoC 生成 + Qiling 动态验证(独立 pi session)\n"
            "  phase3   阶段三:输出文件校验(纯本地,不需要 pi)\n"
            "  run      单 RPC session,Master Skill 串接三阶段\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
详细选项说明见 docs/USAGE.md,或运行 python3 run_phase1.py --help。

示例(分阶段真跑):
  python3 run_phase1.py \\
      --vuln-report /tmp/vuln.md --entry-func main \\
      --source-dir /tmp/src --binary-dir /tmp/bin

  python3 run_phase2.py \\
      --dep-map ./workspace/poc-verify-*/binary_dependency_map.json \\
      --binary-dir /tmp/bin

  python3 run_phase3.py -o ./workspace/poc-verify-*/

或作为模块运行(不便携):
  python3 -m app.cli phase1 ...

默认行为:每次都真启动 pi agent(预计 5–35 分钟,取决于阶段)。
加 --dry-run 只打印不真跑,方便预览。""")
    sub = p.add_subparsers(dest="command", required=True)

    # ── phase1 ────────────────────────────────────────────────────
    p1 = sub.add_parser("phase1", help="阶段一:二进制依赖分析(审计,不真跑)")
    p1.add_argument("--vuln-report", required=True)
    p1.add_argument("--entry-func", required=True)
    p1.add_argument("--source-dir", required=True)
    p1.add_argument("--binary-dir", required=True)
    p1.add_argument("-o", "--output-dir",
                    help="工作目录;若不指定则在 ./workspace/poc-verify-<timestamp>/ 创建")
    p1.add_argument("--model",
                    help="透传给 pi 的 --model 参数(不传则用 settings.json 的 defaultModel)")
    p1.add_argument("--thinking", default=None,
                    help="透传给 pi 的 --thinking 参数,可选 off/minimal/low/medium/high")
    p1.add_argument("-v", "--verbose", action="count", default=0,
                    help="verbose, -v INFO, -vv DEBUG")
    p1.add_argument("--dry-run", action="store_true",
                    help="只打印不真跑(默认会真启动 pi)")

    # ── phase2 ────────────────────────────────────────────────────
    p2 = sub.add_parser("phase2", help="阶段二:PoC 生成 + 动态验证(真跑 pi)")
    p2.add_argument("--dep-map", required=True,
        help="Phase 1 产出的 binary_dependency_map.json 路径")
    p2.add_argument("--binary-dir", required=True,
        help="固件 binary 根目录(含 main 可执行 + 所有 .so)")
    p2.add_argument("--rootfs",
        help="Qiling rootfs 路径(默认同 --binary-dir)")
    p2.add_argument("-o", "--output-dir",
        help="工作目录;若不指定则沿用 phase1 的目录")
    p2.add_argument("--model", help="透传给 pi 的 --model 参数")
    p2.add_argument("--thinking", default=None,
        help="透传给 pi 的 --thinking 参数")
    p2.add_argument("-v", "--verbose", action="count", default=0,
        help="verbose, -v INFO, -vv DEBUG")
    p2.add_argument("--dry-run", action="store_true",
        help="只打印不真跑")

    # ── run ───────────────────────────────────────────────────────
    pr = sub.add_parser("run",
        help="单 session RPC 流水线(Master Skill 串接,真跑 pi)")
    pr.add_argument("--vuln-report", required=True)
    pr.add_argument("--entry-func", required=True)
    pr.add_argument("--source-dir", required=True)
    pr.add_argument("--binary-dir", required=True)
    pr.add_argument("--rootfs")
    pr.add_argument("-o", "--output-dir")
    pr.add_argument("--model")
    pr.add_argument("--thinking")
    pr.add_argument("-v", "--verbose", action="count", default=0)
    pr.add_argument("--dry-run", action="store_true")

    # ── phase3 ───────────────────────────────────────────────────
    p3 = sub.add_parser("phase3", help="阶段三:输出校验(纯本地,不需要 pi)")
    p3.add_argument("-o", "--output-dir", required=True,
        help="Phase 2 的输出目录,应该含 poc_result.json 等 4 个文件")
    p3.add_argument("-v", "--verbose", action="count", default=0)

    args = p.parse_args(argv)
    _setup_logging(args.verbose)

    # 解析输出目录(若没指定,自动建时间戳目录)
    output = _resolve_output_dir(args)
    args.output_dir = str(output)

    try:
        if args.command == "phase1":
            return _run_phase1(args)
        if args.command == "phase2":
            return _run_phase2(args)
        if args.command == "phase3":
            return _run_phase3(args)
        if args.command == "run":
            return _run_pipeline_rpc(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        if args.verbose >= 1:
            import traceback; traceback.print_exc()
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1

    print("unknown command", file=sys.stderr)
    return 2


# ─────────────────────────────────────────────────────────────────────
# 日志 + 目录解析
# ─────────────────────────────────────────────────────────────────────


def _setup_logging(verbose: int) -> None:
    level = logging.DEBUG if verbose >= 2 else (logging.INFO if verbose >= 1 else logging.WARNING)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def _now_stamp() -> str:
    return _dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def _resolve_output_dir(args) -> Path:
    """根据 -o/--output-dir 或自动生成时间戳目录。"""
    if getattr(args, "output_dir", None):
        p = Path(args.output_dir).expanduser().resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p
    stamp = _now_stamp()
    p = DEFAULT_WORK_ROOT / f"poc-verify-{stamp}"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _section(title: str) -> None:
    bar = "═" * 72
    sys.stderr.write(f"\n{bar}\n  {title}\n{bar}\n")


def _kv(k: str, v: object) -> None:
    sys.stderr.write(f"  {k:<28} {v}\n")


def _check_paths(label: str, paths: dict[str, str]) -> bool:
    """检查多个文件/目录存在性,完整列出。返回 True = 全部存在。"""
    sys.stderr.write(f"\n  路径检查 ({label}):\n")
    ok = True
    for name, p in paths.items():
        exists = Path(p).exists()
        if not exists:
            ok = False
        marker = "✓" if exists else "✗"
        sys.stderr.write(f"    [{marker}] {name:<22} {p}\n")
    return ok


def _check_tool(name: str) -> str | None:
    path = shutil.which(name)
    if path:
        sys.stderr.write(f"    [✓] {name:<22} {path}\n")
        return path
    sys.stderr.write(f"    [✗] {name:<22} NOT FOUND\n")
    return None


def _check_pi() -> dict:
    """查 pi 版本、模型、配置信息,echo 给用户。"""
    info = {"binary": None, "version": None, "model": None, "thinking": None,
            "skills_dir": None, "session_dir": None}
    sys.stderr.write("\n  pi agent 自检:\n")

    pi_path = _check_tool("pi")
    if not pi_path:
        return info
    info["binary"] = pi_path

    # pi --version
    try:
        r = subprocess.run([pi_path, "--version"], capture_output=True, text=True, timeout=5)
        ver = (r.stdout or r.stderr).strip().split("\n")[-1]
        info["version"] = ver
        _kv("pi 版本", ver)
    except Exception as e:
        _kv("pi --version 失败", e)

    # pi --list-models(只列第一个)
    try:
        r = subprocess.run([pi_path, "--list-models"], capture_output=True, text=True, timeout=10)
        lines = [l.strip() for l in (r.stdout or "").splitlines() if l.strip()]
        first = lines[0] if lines else "(empty)"
        info["model"] = first
        _kv("默认模型", first)
    except Exception as e:
        _kv("pi --list-models 失败", e)

    # ~/.pi/agent/settings.json
    settings = Path.home() / ".pi" / "agent" / "settings.json"
    if settings.is_file():
        try:
            s = json.loads(settings.read_text())
            info["thinking"] = s.get("defaultThinkingLevel", "?")
            info["model"] = s.get("defaultModel", info["model"])
            _kv("settings.json", str(settings))
            _kv("  defaultProvider", s.get("defaultProvider"))
            _kv("  defaultModel", s.get("defaultModel"))
            _kv("  defaultThinkingLevel", s.get("defaultThinkingLevel"))
            _kv("  retry.enabled", s.get("retry", {}).get("enabled"))
        except Exception as e:
            _kv("settings.json 解析失败", e)
    else:
        _kv("settings.json", "(不存在)")

    # session 目录
    sess_dir = Path.home() / ".pi" / "agent" / "sessions"
    if sess_dir.is_dir():
        info["session_dir"] = str(sess_dir)
        _kv("session 根目录", str(sess_dir))
        # 当前 cwd 对应的子目录
        cwd = Path.cwd().resolve()
        sub = sess_dir / ("-" + str(cwd).lstrip("/").replace("/", "-"))
        if sub.is_dir():
            _kv("  当前 cwd 子目录", str(sub))
            sessions = list(sub.glob("session-*.jsonl"))
            _kv("  已有 session 数", len(sessions))

    # skills 目录
    sys.stderr.write("\n  Skill 目录:\n")
    for label, p in [
        ("子 Skill 目录 (skills/)",        Path(__file__).resolve().parent.parent / "skills"),
        ("Master Skill 目录 (.pi/skills/)", Path(__file__).resolve().parent.parent / ".pi" / "skills"),
    ]:
        sys.stderr.write(f"    {label}: {p}\n")
        if p.is_dir():
            for sub in sorted(p.iterdir()):
                if sub.is_dir() and (sub / "SKILL.md").is_file():
                    sys.stderr.write(f"      ├─ {sub.name}/SKILL.md\n")
    return info


# ─────────────────────────────────────────────────────────────────────
# 写 state / input 文件
# ─────────────────────────────────────────────────────────────────────


def _write_json(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    return path


def _write_state_file(output: Path, *, vuln: str, entry_func: str, src: str,
                      bindir: str, rootfs: str, model: str | None,
                      thinking: str | None) -> Path:
    state = {
        "pipeline_name": "poc-verify",
        "current_stage": "INIT",
        "stages": ["phase1_binary_dependency", "phase2_qiling_emulation", "phase3_verify_report"],
        "vuln_report": vuln,
        "entry_function": entry_func,
        "source_dir": src,
        "binary_dir": bindir,
        "output_dir": str(output),
        "rootfs": rootfs,
        "model": model,
        "thinking": thinking,
    }
    p = output / ".pipeline_state.json"
    _write_json(p, state)
    return p


# ─────────────────────────────────────────────────────────────────────
# 构造要执行的 pi 命令
# ─────────────────────────────────────────────────────────────────────


def _build_pi_command(skill_name: str | None, prompt: str,
                      model: str | None, thinking: str | None,
                      session_dir: Path | None = None,
                      session_name: str | None = None,
                      extra_skill_paths: list[Path] | None = None) -> list[str]:
    """构造完整的 pi 子进程命令行(不执行)。

    session_dir: 不传时 session 会存到 ~/.pi/agent/sessions/<cwd转义>/。
                传入后会传入 --session-dir 让 pi 把 session 存到这里。
    session_name: 可选,传入 --name 让 session 在 pi 的 session 浏览器里好找。
    """
    cmd = ["pi"]
    if skill_name:
        skill_md = SKILL_DIR / skill_name / "SKILL.md"
        cmd.extend(["--append-system-prompt", str(skill_md)])
    if extra_skill_paths:
        for p in extra_skill_paths:
            cmd.extend(["--skill", str(p)])
    if model:
        cmd.extend(["--model", model])
    if thinking:
        cmd.extend(["--thinking", thinking])
    if session_dir:
        cmd.extend(["--session-dir", str(session_dir)])
    if session_name:
        cmd.extend(["--name", session_name])
    cmd.extend(["--print", "-p", prompt])
    return cmd


def _build_rpc_command(model: str | None, thinking: str | None,
                        master_skill_path: Path,
                        session_dir: Path | None = None,
                        session_name: str | None = None) -> list[str]:
    """构造 RPC 模式的 pi 命令(用于 `run` 子命令)。

    RPC 模式仍要传入 --session-dir 以便 session 记录保留在 workspace 下,
    供后续 --resume / --continue 使用。
    显式加载 Master Skill (poc-verify-pipeline) 到 system prompt;
    子 Skill 由 Master 通过 `read` 工具加载,不使用 --skill 注入。
    """
    cmd = ["pi", "--mode", "rpc"]
    if model:
        cmd.extend(["--model", model])
    if thinking:
        cmd.extend(["--thinking", thinking])
    if session_dir:
        cmd.extend(["--session-dir", str(session_dir)])
    if session_name:
        cmd.extend(["--name", session_name])
    cmd.extend(["--skill", str(master_skill_path)])
    return cmd


def _print_command_block(label: str, cmd: list[str], cwd: Path) -> None:
    """把完整命令行(shell 风格)打印到 stderr。"""
    sys.stderr.write(f"\n  拟执行 ({label}):\n")
    sys.stderr.write(f"    cwd: {cwd}\n")
    # 用 repr/shell-quote 形式展示,避免空格/特殊字符混淆
    parts = []
    for a in cmd:
        if any(c in a for c in " \t\"'\\$;&|<>(){}[]*?#~") or not a:
            parts.append("'" + a.replace("'", "'\\''") + "'")
        else:
            parts.append(a)
    sys.stderr.write("    " + " ".join(parts) + "\n")


# ─────────────────────────────────────────────────────────────────────
# phase1 (审计)
# ─────────────────────────────────────────────────────────────────────


def _run_phase1(args) -> int:
    output = Path(args.output_dir).resolve()
    vuln   = Path(args.vuln_report).resolve()
    src    = Path(args.source_dir).resolve()
    bindir = Path(args.binary_dir).resolve()

    _section("PHASE 1 — 二进制依赖分析" + (" (dry-run 审计模式)" if args.dry_run else ""))
    _kv("工作目录", str(output))
    _kv("时间戳", _now_stamp())
    _kv("模型", args.model or "(settings.json default)")
    _kv("思考级别", args.thinking or "(settings.json default)")

    pi_info = _check_pi()

    if not _check_paths("输入", {
        "vuln_report": str(vuln),
        "source_dir": str(src),
        "binary_dir": str(bindir),
    }):
        sys.stderr.write("\n  ✗ 输入路径检查失败,中止。\n")
        return 1

    # 1. 写 phase1_input.json
    meta = {
        "vuln_report": str(vuln),
        "entry_function": args.entry_func,
        "source_dir": str(src),
        "binary_dir": str(bindir),
        "output_dir": str(output),
    }
    meta_f = output / "phase1_input.json"
    _write_json(meta_f, meta)
    sys.stderr.write(f"\n  写出: {meta_f}\n")

    # 2. 写 .pipeline_state.json(保留全量,Master Skill 也读这个)
    state_f = _write_state_file(
        output, vuln=str(vuln), entry_func=args.entry_func, src=str(src),
        bindir=str(bindir), rootfs=str(bindir),
        model=args.model, thinking=args.thinking,
    )
    sys.stderr.write(f"  写出: {state_f}\n")

    # 3. 构造 prompt
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
    prompt_f = output / "phase1.prompt.txt"
    prompt_f.write_text(prompt)
    sys.stderr.write(f"  写出: {prompt_f}\n")

    # 4. 构造并打印 pi 命令(session 存到 <output>/pi-sessions/phase1/)
    session_dir = output / "pi-sessions" / "phase1"
    session_dir.mkdir(parents=True, exist_ok=True)
    session_name = f"poc-verify-phase1-{output.name}"
    cmd = _build_pi_command(
        "poc-phase1-binary-dependency", prompt,
        args.model, args.thinking,
        session_dir=session_dir, session_name=session_name,
    )
    _print_command_block("phase1 pi subprocess", cmd, cwd=output)

    # 5. stdout/stderr 重定向
    stdout_f = output / "poc-phase1-binary-dependency.stdout"
    stderr_f = output / "poc-phase1-binary-dependency.stderr"
    sys.stderr.write(f"\n  stdout 重定向: {stdout_f}\n")
    sys.stderr.write(f"  stderr 重定向: {stderr_f}\n")
    sys.stderr.write(f"  session 存到:   {session_dir}  (--name {session_name})\n")

    if args.dry_run:
        sys.stderr.write("\n  ⚠ --dry-run 模式:打印完整命令后退出,不实际启动 pi。\n")
        sys.stderr.write("  去掉 --dry-run 即可真跑(会消耗较长时间,约 5–15 分钟)。\n")
        return 0

    # 真跑
    sys.stderr.write("\n  启动 pi 子进程...\n")
    log_path = output / "phase1.pi.log"
    with open(stdout_f, "w") as fo, open(stderr_f, "w") as fe, open(log_path, "a") as fl:
        fl.write(f"\n[{_now_stamp()}] starting: {' '.join(cmd)}\n")
        rc = subprocess.Popen(cmd, cwd=str(output), stdout=fo, stderr=fe).wait()
        fl.write(f"[{_now_stamp()}] exit={rc}\n")
    sys.stderr.write(f"  pi 退出 rc={rc}\n")
    sys.stderr.write(f"  日志: {log_path}\n")

    dep_map = output / "binary_dependency_map.json"
    if rc == 0 and dep_map.is_file():
        sys.stderr.write(f"\n  ✓ Phase 1 产出: {dep_map}\n")
        return 0
    sys.stderr.write(f"\n  ✗ Phase 1 未成功完成 (rc={rc})\n")
    return 1


# ─────────────────────────────────────────────────────────────────────
# phase2 (审计)
# ─────────────────────────────────────────────────────────────────────


def _run_phase2(args) -> int:
    output  = Path(args.output_dir).resolve()
    dep_map = Path(args.dep_map).resolve()
    bindir  = Path(args.binary_dir).resolve()
    rootfs  = args.rootfs or str(bindir)

    _section("PHASE 2 — PoC 生成 + 动态验证" + (" (dry-run 审计模式)" if args.dry_run else ""))
    _kv("工作目录", str(output))
    _kv("时间戳", _now_stamp())
    _kv("模型", args.model or "(settings.json default)")
    _kv("思考级别", args.thinking or "(settings.json default)")

    pi_info = _check_pi()

    if not _check_paths("输入", {
        "dep_map (Phase 1 产出)": str(dep_map),
        "binary_dir": str(bindir),
    }):
        sys.stderr.write("\n  ✗ 输入路径检查失败,中止。\n")
        return 1
    if args.rootfs and not Path(args.rootfs).exists():
        sys.stderr.write(f"\n  ✗ rootfs 不存在: {args.rootfs}\n")
        return 1

    # 1. 写 phase2_input.json
    meta = {
        "dep_map": str(dep_map),
        "binary_dir": str(bindir),
        "rootfs": rootfs,
        "output_dir": str(output),
    }
    meta_f = output / "phase2_input.json"
    _write_json(meta_f, meta)
    sys.stderr.write(f"\n  写出: {meta_f}\n")

    # 2. 写 .pipeline_state.json
    state_f = _write_state_file(
        output, vuln="(inherit from phase1)", entry_func="(inherit from phase1)",
        src="(inherit from phase1)", bindir=str(bindir), rootfs=rootfs,
        model=args.model, thinking=args.thinking,
    )
    sys.stderr.write(f"  写出: {state_f}\n")

    # 3. 构造 prompt
    prompt = (
        f"执行 Phase 2 PoC 生成与动态验证。\n\n"
        f"输入信息见 {meta_f}。\n\n"
        f"二阶段核心任务:\n"
        f"  A) PoC 生成: 读取 {dep_map} 与漏洞报告,推导能触发漏洞的输入/操作序列。\n"
        f"  B) 动态验证: 把 PoC 喂入 Qiling 仿真执行,确认漏洞在运行时是否真实可达、可触发。\n"
        f"  C) 仿真脚本只是运行环境,不是交付物。\n\n"
        f"前置条件(必须全部满足才会到达漏洞函数):\n"
        f"  1. 调用方已通过 web admin 认证 (NV_SID cookie)\n"
        f"  2. WPS 状态机处于 NEGOTIATING\n"
        f"  3. wps_active=1 且 wps_pin 长度 > 64 字节\n"
        f"  4. wps_retry >= 1\n"
        f"  5. PIN 中含非数字字符(绕过 nv_wps_pin_is_valid 的宽松校验)\n\n"
        f"Qiling 仿真脚本要点:\n"
        f"  - 根据 binary_dependency_map.json 中的架构选择 QL_ARCH (arm/aarch64/mips/x86/x86_64)\n"
        f"  - 用 entry_address 启动,从 ENTRY_ADDR 跑到 VULN_ADDR\n"
        f"  - 必须把 PoC 数据回放到 binary 入口(stdin/文件/socket 三选一)\n"
        f"  - 最多 20 个 patch,超出则表示固件对硬件依赖过强,无法仿真\n\n"
        f"输出到 {output}/:\n"
        f"  - poc_result.json — {{status, reach_vuln_point, poc_was_consumed, total_patches, total_branches, poc_input_path, vuln_function, entry_function, architecture, error}}\n"
        f"  - poc_result.md — 人类可读报告\n"
        f"  - patch_log.json — {{total, patches:[...]}}\n"
        f"  - branch_decisions.json — {{total, branches:[...]}}\n"
        f"  - emulate.py — 仿真脚本\n"
        f"  - poc_input/ — PoC 原始数据(请求/文件/参数)\n"
    )
    prompt_f = output / "phase2.prompt.txt"
    prompt_f.write_text(prompt)
    sys.stderr.write(f"  写出: {prompt_f}\n")

    # 4. 构造并打印 pi 命令(session 存到 <output>/pi-sessions/phase2/)
    session_dir = output / "pi-sessions" / "phase2"
    session_dir.mkdir(parents=True, exist_ok=True)
    session_name = f"poc-verify-phase2-{output.name}"
    cmd = _build_pi_command(
        "poc-phase2-qiling-emulation", prompt,
        args.model, args.thinking,
        session_dir=session_dir, session_name=session_name,
    )
    _print_command_block("phase2 pi subprocess", cmd, cwd=output)

    stdout_f = output / "poc-phase2-qiling-emulation.stdout"
    stderr_f = output / "poc-phase2-qiling-emulation.stderr"
    sys.stderr.write(f"\n  stdout 重定向: {stdout_f}\n")
    sys.stderr.write(f"  stderr 重定向: {stderr_f}\n")
    sys.stderr.write(f"  session 存到:   {session_dir}  (--name {session_name})\n")
    sys.stderr.write(f"\n  stdout 重定向: {stdout_f}\n")
    sys.stderr.write(f"  stderr 重定向: {stderr_f}\n")

    if args.dry_run:
        sys.stderr.write("\n  ⚠ --dry-run 模式:打印完整命令后退出,不实际启动 pi。\n")
        sys.stderr.write("  去掉 --dry-run 即可真跑(会消耗较长时间,约 10–20 分钟)。\n")
        return 0

    sys.stderr.write("\n  启动 pi 子进程...\n")
    log_path = output / "phase2.pi.log"
    with open(stdout_f, "w") as fo, open(stderr_f, "w") as fe, open(log_path, "a") as fl:
        fl.write(f"\n[{_now_stamp()}] starting: {' '.join(cmd)}\n")
        rc = subprocess.Popen(cmd, cwd=str(output), stdout=fo, stderr=fe).wait()
        fl.write(f"[{_now_stamp()}] exit={rc}\n")
    sys.stderr.write(f"  pi 退出 rc={rc}\n")
    sys.stderr.write(f"  日志: {log_path}\n")

    expected = ["poc_result.json", "poc_result.md", "patch_log.json",
                "branch_decisions.json"]
    missing = [e for e in expected if not (output / e).is_file()]
    if rc == 0 and not missing:
        sys.stderr.write(f"\n  ✓ Phase 2 全部产出到位: {output}\n")
        return 0
    if missing:
        sys.stderr.write(f"\n  ✗ Phase 2 缺少产出: {missing}\n")
    else:
        sys.stderr.write(f"\n  ✗ Phase 2 失败 (rc={rc})\n")
    return 1


# ─────────────────────────────────────────────────────────────────────
# run (单 session RPC,审计)
# ─────────────────────────────────────────────────────────────────────


def _run_pipeline_rpc(args) -> int:
    output = Path(args.output_dir).resolve()
    vuln   = Path(args.vuln_report).resolve()
    src    = Path(args.source_dir).resolve()
    bindir = Path(args.binary_dir).resolve()
    rootfs = str(Path(args.rootfs).resolve()) if args.rootfs else str(bindir)

    _section("RUN — 单 session RPC 流水线" + (" (dry-run 审计模式)" if args.dry_run else ""))
    _kv("工作目录", str(output))
    _kv("时间戳", _now_stamp())
    _kv("模型", args.model or "(settings.json default)")
    _kv("思考级别", args.thinking or "(settings.json default)")

    pi_info = _check_pi()

    if not _check_paths("输入", {
        "vuln_report": str(vuln),
        "source_dir": str(src),
        "binary_dir": str(bindir),
    }):
        sys.stderr.write("\n  ✗ 输入路径检查失败,中止。\n")
        return 1

    # 1. 写 phase1_input.json
    phase1_meta = {
        "vuln_report": str(vuln),
        "entry_function": args.entry_func,
        "source_dir": str(src),
        "binary_dir": str(bindir),
        "output_dir": str(output),
    }
    (output / "phase1_input.json").write_text(json.dumps(phase1_meta, indent=2, ensure_ascii=False))
    sys.stderr.write(f"\n  写出: {output / 'phase1_input.json'}\n")

    # 2. 写 .pipeline_state.json
    state_f = _write_state_file(
        output, vuln=str(vuln), entry_func=args.entry_func, src=str(src),
        bindir=str(bindir), rootfs=rootfs,
        model=args.model, thinking=args.thinking,
    )
    sys.stderr.write(f"  写出: {state_f}\n")

    # 3. 校验 Master Skill
    master_skill = MASTER_SKILL_DIR / "SKILL.md"
    if not master_skill.is_file():
        sys.stderr.write(f"\n  ✗ Master Skill 不存在: {master_skill}\n")
        return 1
    sys.stderr.write(f"  Master Skill: {master_skill} ✓\n")

    # 4. 构造 prompt
    prompt = (
        f"执行 /skill:poc-verify-pipeline\n\n"
        f"参数 (同时已写入 {output}/.pipeline_state.json):\n"
        f"  vuln_report:    {vuln}\n"
        f"  entry_function: {args.entry_func}\n"
        f"  source_dir:     {src}\n"
        f"  binary_dir:     {bindir}\n"
        f"  output_dir:     {output}\n"
        f"  rootfs:         {rootfs}\n"
    )
    prompt_f = output / "pipeline.prompt.txt"
    prompt_f.write_text(prompt)
    sys.stderr.write(f"  写出: {prompt_f}\n")

    # 5. 构造 RPC 模式 pi 命令(session 存到 <output>/pi-sessions/run/)
    # 创建 skills/ 符号链接,让 Master Skill 的 `read skills/...` 相对路径可解析
    skills_link = output / "skills"
    if not skills_link.exists():
        skills_link.symlink_to(SKILL_DIR)
        sys.stderr.write(f"  创建 symlink: {skills_link} -> {SKILL_DIR}\n")
    session_dir = output / "pi-sessions" / "run"
    session_dir.mkdir(parents=True, exist_ok=True)
    session_name = f"poc-verify-run-{output.name}"
    cmd = _build_rpc_command(
        args.model, args.thinking, master_skill,
        session_dir=session_dir, session_name=session_name,
    )
    _print_command_block("rpc pi subprocess", cmd, cwd=output)
    sys.stderr.write(f"\n  session 存到:   {session_dir}  (--name {session_name})\n")

    sys.stderr.write("\n  RPC 协议:\n")
    sys.stderr.write("    启动:  pi --mode rpc --session-dir <workspace>/pi-sessions/run/ [--model ...] [--thinking ...] [--skill ...] ...\n")
    sys.stderr.write("    stdin:  JSONL 命令序列\n")
    sys.stderr.write("            {\"id\":\"req-1\",\"type\":\"prompt\",\"message\":\"<上面的 prompt>\"}\n")
    sys.stderr.write("    stdout: JSONL 事件流\n")
    sys.stderr.write("            {\"type\":\"agent_start\"} / {\"type\":\"message_update\",...} / {\"type\":\"agent_end\",\"messages\":[...]}\n")
    sys.stderr.write("    等待: agent_end 事件 → 关闭 stdin → wait()\n")

    sys.stderr.write("\n  在 RPC 期间,pi 会做:\n")
    sys.stderr.write("    1) 加载 Master Skill (poc-verify-pipeline) 到 system prompt\n")
    sys.stderr.write("    2) 接收 prompt 触发 Master Skill\n")
    sys.stderr.write("    3) Master Skill 通过 'read' 工具依次读:\n")
    sys.stderr.write("       - skills/poc-phase1-binary-dependency/SKILL.md → 执行阶段一\n")
    sys.stderr.write("       - skills/poc-phase2-qiling-emulation/SKILL.md   → 执行阶段二\n")
    sys.stderr.write("       - skills/poc-phase3-verify-report/SKILL.md       → 执行阶段三\n")
    sys.stderr.write("    4) 状态通过 .pipeline_state.json 跨阶段传递\n")

    sys.stderr.write(f"\n  期望最终状态: {output}/.pipeline_state.json → current_stage == 'COMPLETED'\n")
    sys.stderr.write(f"  期望产出: {output}/{{binary_dependency_map,poc_result,poc_result.md,patch_log,branch_decisions}}.json\n")

    if args.dry_run:
        sys.stderr.write("\n  ⚠ --dry-run 模式:打印完整命令后退出,不实际启动 pi。\n")
        sys.stderr.write("  去掉 --dry-run 即可真跑(会消耗较长时间,约 15–35 分钟)。\n")
        return 0

    # 真跑
    sys.stderr.write("\n  启动 pi RPC 进程...\n")
    from app.rpc_runner import PiRpcClient, PiRpcError, default_event_printer

    client = PiRpcClient(
        cwd=output, model=args.model,
        no_session=False,                    # *存* session 到 workspace
        session_dir=session_dir,
        session_name=session_name,
        skill_paths=[master_skill],          # 显式加载 Master Skill
    )
    sys.stderr.write(f"  pi pid={client.proc.pid}\n")
    try:
        client.prompt(prompt, on_event=default_event_printer(sys.stderr))
    except PiRpcError as e:
        sys.stderr.write(f"\n  ✗ RPC 错误: {e}\n")
        return 1
    finally:
        rc = client.close()
        sys.stderr.write(f"  rpc 进程退出 rc={rc}\n")

    state_f = output / ".pipeline_state.json"
    final = "UNKNOWN"
    if state_f.is_file():
        try:
            final = json.loads(state_f.read_text()).get("current_stage", "UNKNOWN")
        except Exception:
            pass

    if final == "COMPLETED":
        sys.stderr.write(f"\n  ✓ 流水线完成 (current_stage=COMPLETED)\n")
        return 0
    if final == "FAILED":
        sys.stderr.write(f"\n  ✗ 流水线失败 (current_stage=FAILED)\n")
        return 2
    sys.stderr.write(f"\n  ? 流水线未正常结束 (current_stage={final})\n")
    return 3


# ─────────────────────────────────────────────────────────────────────
# phase3 (纯本地输出校验,不需要 pi)
# ─────────────────────────────────────────────────────────────────────


def _run_phase3(args) -> int:
    output = Path(args.output_dir).resolve()
    _section("PHASE 3 — 输出校验(纯本地)")
    _kv("工作目录", str(output))
    _kv("时间戳", _now_stamp())

    if not output.is_dir():
        sys.stderr.write(f"\n  ✗ 目录不存在: {output}\n")
        return 1

    from app.reporter import validate_phase2_outputs, summarize_result

    sys.stderr.write("\n  校验 Phase 2 产出文件:\n")
    checks = validate_phase2_outputs(output)
    for name, ok in checks.items():
        marker = "✓" if ok else "✗"
        sys.stderr.write(f"    [{marker}] {name}\n")

    summary = summarize_result(output)
    sys.stderr.write(f"\n  汇总: {summary}\n")

    state_f = output / ".pipeline_state.json"
    if state_f.is_file():
        try:
            s = json.loads(state_f.read_text())
            cur = s.get("current_stage", "UNKNOWN")
            _kv(".pipeline_state.json current_stage", cur)
        except Exception as e:
            sys.stderr.write(f"  ! state 解析失败: {e}\n")

    all_ok = all(checks.values())
    if all_ok:
        sys.stderr.write("\n  ✓ Phase 3 校验通过\n")
        return 0
    sys.stderr.write("\n  ✗ Phase 3 校验未通过(缺文件或 JSON 不合法)\n")
    return 1


if __name__ == '__main__':
    sys.exit(main())
