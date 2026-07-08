#!/usr/bin/env python3
"""poc_cli.py - PoC generation & verification orchestration CLI.

Wraps the `claude` (Claude Code) CLI: given a data-flow entry function, a
vulnerability report, and the unpacked firmware binary directory, it constructs
the /goal task prompt and drives `claude -p` (headless) to perform the full
PoC-generation-and-GDB-verification workflow (the same one done manually for
VULN-001). All artifacts land in `<workdir>/output/`.

Usage:
  ./poc -e IPSEC_SOCKI_PipeMsg -r /path/to/result_001.md -b /path/to/fw

The user's environment already provides: the `claude` CLI, the `tmux-mcp` MCP
server (user-level), the built-in `/goal` command, `auto` permission mode, and
the `glm-5.2` model - so a plain-shell invocation works as-is.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Prompt template (verbatim from the task spec; three substitutions).
# .replace (not .format) so Chinese punctuation / braces survive as-is.
PROMPT_TEMPLATE = """\
/goal 全二进制文件目录为{全二进制文件目录}，漏洞报告路径为{漏洞报告路径}，数据流入口函数为{数据流入口函数}。
  **PoC生成和验证任务**：
    1. 先编写一个C语言目标程序，其职责为针对漏洞报告的PoC验证harness，要求必须解决从数据流入口函数到目标漏洞点间涉及的数据流和控制流链中所有符号缺失和依赖问题，尽可能达到无限接近真机运行环境的验证harness。（解决方案为：当前固件二进制目录下/系统自身库文件中有定义和实现的就找到并真实链接使用；找不到并确定缺失的符号可以使用空stub填充解决。对链接真实so库后带来的新的符号缺失依赖也按照同样的方案：在当前固件二进制目录下/系统自身库文件中寻找存在真实有定义和实现的so库链接使用，确定缺失的符号用空stub填充，一直嵌套递归解决，直到没有任何符号缺失依赖问题。）
    2. 充分理解和分析漏洞报告，生成漏洞PoC，基于上一步的PoC验证harness进行真实的漏洞触发，借助tmux mcp server调用gdb进行程序调试，修正PoC，再触发验证，循环观察+修正直到真正触发漏洞，保存漏洞触发时的内存状态和最终的PoC代码。调试时可酌情使用ASAN(-fsanitize=address -g -fno-omit-frame-pointer 重新编译harness)辅助观察内存破坏类漏洞，ASAN崩溃报告也作为漏洞触发的补充证据一并保存到目录{输出目录}/output下，无法触发ASAN崩溃的漏洞(例如死循环类和逻辑错误类)仍然以gdb调试观察结果为准。
  
  **任务约束**：
    1.PoC验证harness必须要从数据流入口函数进行构造，以此模拟真实的攻击入口点，而不是直接调用漏洞点函数。
    2.PoC验证要基于gdb调试器，借助真实的PoC运行状态进行循环分析和纠偏，可以根据动态运行时的反馈继续对PoC harness进行调整和修正。
    3.对于一些基于硬件或其他因为环境导致的特殊情况等实在满足不了的初始化要求，可以酌情进行patch绕过，但是要进行patch原因和patch点、patch内容的记录。
    4.所有文档类产物的语言都使用简体中文。
    5.tmux/gdb进程管理（防止跨任务污染与误杀本进程，必须遵守）：
      a.会话命名：必须使用本任务专属的tmux会话名（由本任务工作目录名或session-id派生，如poc_<workdirbasename去特殊字符>），严禁使用"poc"/"poc008"等通用名，以免与其他并发任务撞会话、复用到他人残留的pane。
      b.启动前清理：启动gdb前若发现同名会话/pane残留，先`tmux kill-session -t <本任务会话名>`清掉再重建；绝不复用来历不明的pane（其内可能有上一轮任务残留的gdb/断点/cwd，会污染本次调试）。
      c.严禁模式匹配杀进程：本进程(claude)的命令行包含整段任务prompt(内含"gdb"/"harness"等字样)，因此`pkill`/`killall`配合`-f`或命令行模式(如`pkill -9 -f 'gdb.*harness'`、`pkill -f gdb`、`killall gdb`)会误匹配并SIGKILL本进程自身，导致任务在无任何错误输出的情况下被异常终止。清理gdb只能用以下精确方式之一：①`tmux kill-session -t <本任务会话名>`；②`tmux send-keys -t <pane> 'quit' Enter`让gdb正常退出；③按精确PID `kill <pid>`，且PID必须由`tmux list-panes -t <本任务会话名> -F '#{pane_pid}'`等定位得出，严禁用进程名/命令行模式匹配取PID。
      d.退出前清理：任务结束(无论成功/失败/证伪)前，主动`tmux kill-session -t <本任务会话名>`销毁自己创建的会话，避免残留污染下一次运行。
      e.gdb管道约束：不要用`gdb ... | head`之类管道启动gdb(管道破开会被SIGPIPE杀掉gdb)，改用gdb的`set logging`或tmux-mcp的capture-pane采集输出。

  **任务完成目标**（满足【路径A：确认触发】或【路径B：证伪/不可达】任一路径的全部条件方可结束；严禁编造证据，违反则任务判为失败）：
    【路径A：确认触发】（漏洞为真且可触发时）
    A1.PoC验证harness编译并链接成功（gcc/ld退出码为0，二进制产物存在）；
    A2.在gdb中于"数据流入口函数"与"漏洞点函数"所设断点均被命中，backtrace证明控制流由数据流入口函数到达漏洞点函数（不得直接调用漏洞点函数）；
    A3.漏洞被真实触发并留下可观测证据之一：a)进程在漏洞点函数处崩溃（SIGSEGV/SIGABRT等）且backtrace中可见该函数；或 b)死循环类：自终止前循环执行次数≥阈值(如1e7)且记录到不变量(如循环计数器/关键寄存器在多次迭代间不变)；或 c)内存破坏类：ASAN报告指向漏洞点函数的越界访问；
    A4.触发时的内存状态(寄存器+关键缓冲区)与最终PoC代码已保存；
    A5.以下产物全部存在于目录{输出目录}/output下：harness源码、harness二进制、PoC输入、gdb转录日志、触发时内存状态、ASAN报告(若适用)、简体中文验证报告；
    A6.所有patch(若有)已记录patch原因/patch点/patch内容。

    【路径B：证伪/不可达】（漏洞为误报、不可达或存在不可绕过检查/现实无法满足的前置条件时；须先尽力尝试触发，不得未经尝试即走此路径）
    B1.PoC验证harness编译并链接成功；且已沿"数据流入口函数→漏洞点函数"方向在gdb中推进，并系统尝试多种合理输入/路径（在gdb转录中记录每次尝试的输入与观察结果）；
    B2.均未触发漏洞，并在gdb中定位到具体阻断点之一：a)调用链不可达（分发/守卫条件使得到达漏洞点函数的路径对任何攻击者可控输入均不成立）；或 b)漏洞点处存在不可绕过的检查/校验（给出该检查位置与判定逻辑）；或 c)触发所需前置条件在真机/现实中无法满足（说明为何无法满足）；
    B3.给出该阻断点的gdb实证：阻断处寄存器/内存值、分支条件取值、以及"为何对所有攻击者可控输入恒不满足"的具体分析（引用反汇编/源码位置）；
    B4.产出简体中文《误报/不可达分析报告》：含结论(误报/不可达/不可绕过)、阻断点位置与gdb实证、已尝试的输入与路径清单及每次结果、判定依据；
    B5.以下产物全部存在于目录{输出目录}/output下：harness源码、harness二进制、gdb转录日志、(若适用)尝试用输入集、《误报/不可达分析报告》；
    B6.所有patch(若有)已记录patch原因/patch点/patch内容。

    【严禁编造证据】无论走哪条路径，所有gdb输出/崩溃/ASAN报告/寄存器与内存值必须来自真实运行并体现在gdb转录日志中；不得伪造调试输出、不得用stub绕过漏洞点本身的检查后冒充"真实触发"、不得编造PoC输入的执行效果。patch仅可用于绕过硬件/环境初始化类前置（见任务约束3），严禁用于绕过漏洞点本身的检查以伪造触发。违反本条则任务判为失败，不得据此结束。\
"""


def build_prompt(entry: str, report: str, bindir: str, output: str) -> str:
    p = PROMPT_TEMPLATE
    p = p.replace("{全二进制文件目录}", bindir)
    p = p.replace("{漏洞报告路径}", report)
    p = p.replace("{数据流入口函数}", entry)
    p = p.replace("{输出目录}", output)
    return p


def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        prog="poc",
        description="Drive Claude Code to generate & GDB-verify a PoC from a vuln report, "
                    "entering via a given data-flow function.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("-e", "--entry", required=True,
                    help="Data-flow entry function name (e.g. IPSEC_SOCKI_PipeMsg).")
    ap.add_argument("-r", "--report", required=True,
                    help="Path to the vulnerability report file (e.g. result_001.md).")
    ap.add_argument("-b", "--bindir", required=True,
                    help="Full unpacked firmware binary directory (searched for real .so libs).")
    ap.add_argument("-o", "--output", default=None,
                    help="Output directory for all artifacts (substituted as {输出目录} in the prompt). "
                         "If omitted, a dir named <entry>_<bindir-basename>_<timestamp> is created under the cwd.")
    ap.add_argument("-w", "--workdir", default=None,
                    help="Directory to run claude in (default: <output>). claude's cwd.")
    ap.add_argument("--model", default=None,
                    help="Model override, passed to `claude --model` (default: inherited from settings, glm-5.2).")
    ap.add_argument("--effort", default=None,
                    choices=["low", "medium", "high", "xhigh", "max"],
                    help="Effort level, passed to `claude --effort` (default: inherited from settings, xhigh).")
    ap.add_argument("--session-name", default=None,
                    help="Session display name, passed to `claude -n` (shown in the /resume picker + "
                         "terminal title). Lets you find this session later by name.")
    ap.add_argument("--session-id", default=None,
                    help="Specific session UUID, passed to `claude --session-id` (the transcript is "
                         "stored as <session-id>.jsonl in the project folder). Use to make a session "
                         "traceable/resumable by a known ID.")
    ap.add_argument("--session-dir", default=None,
                    help="Set CLAUDE_CONFIG_DIR for the claude subprocess: session transcripts (and "
                         "the claude config) are stored under this dir instead of ~/.claude. The baked "
                         "~/.claude.json + ~/.claude/settings.json are copied in on first use so the "
                         "GLM/MCP/permissions config travels with the session.")
    ap.add_argument("--output-format", choices=["text", "stream-json"], default="stream-json",
                    help="claude -p output format (default: stream-json for live progress).")
    ap.add_argument("--log", default=None,
                    help="Log file path (default: <workdir>/poc_cli_<timestamp>.log).")
    ap.add_argument("--no-skip-permissions", dest="skip_perms", action="store_false",
                    help="Do NOT pass --dangerously-skip-permissions.")
    ap.set_defaults(skip_perms=True)
    ap.add_argument("--dry-run", action="store_true",
                    help="Print the exact claude command + prompt and exit (no invocation).")
    ap.add_argument("--claude-bin", default="claude",
                    help="Path to claude executable (default: claude).")
    return ap.parse_args(argv)


def _default_output_dir(entry: str, bindir: str) -> str:
    """Default output dir under the cwd: <entry>_<bindir-basename>_<timestamp>."""
    def _s(x: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", x).strip("_") or "poc"
    base = os.path.basename(bindir.rstrip("/")) or "bindir"
    name = f"{_s(entry)}_{_s(base)}_{time.strftime('%Y%m%d_%H%M%S')}"
    return str(Path.cwd() / name)


def validate(opts) -> None:
    if not opts.entry.strip():
        sys.exit("error: --entry must be non-empty")
    rp = Path(opts.report)
    if not rp.is_file():
        sys.exit(f"error: --report not a file: {opts.report}")
    bp = Path(opts.bindir)
    if not bp.is_dir():
        sys.exit(f"error: --bindir not a directory: {opts.bindir}")
    opts.report = str(rp.resolve())
    opts.bindir = str(bp.resolve())
    if not opts.output:
        opts.output = _default_output_dir(opts.entry, opts.bindir)
    opts.output = str(Path(opts.output).resolve())
    Path(opts.output).mkdir(parents=True, exist_ok=True)
    opts.workdir = str(Path(opts.workdir).resolve()) if opts.workdir else opts.output
    Path(opts.workdir).mkdir(parents=True, exist_ok=True)
    if not opts.session_dir:
        opts.session_dir = str(Path(opts.workdir) / ".claude")
    opts.session_dir = str(Path(opts.session_dir).resolve())
    Path(opts.session_dir).mkdir(parents=True, exist_ok=True)


# Tools the headless claude subprocess must NEVER use, so it cannot look up
# public PoCs / advisories / writeups online and pass them off as its own
# analysis. Slash-command expansion (e.g. /goal) is harness-side preprocessing,
# so denying the Skill *tool* does NOT block /goal — it only stops the model
# from invoking skills (tavily-*, deep-research, …) mid-conversation.
WEB_DENY_TOOLS = ["WebSearch", "WebFetch", "Skill"]


def _lockdown_session_settings(session_dir: Path) -> None:
    """Inject web/skill deny rules into the session settings.json so the headless
    claude cannot web-search or skill-research PoC material — the PoC must be
    self-derived from the binary + vuln report only. Idempotent merge. Skip
    entirely if POC_ALLOW_WEB is set (escape hatch for runs that genuinely need web)."""
    if os.environ.get("POC_ALLOW_WEB"):
        return
    sf = session_dir / "settings.json"
    try:
        cfg = json.loads(sf.read_text(encoding="utf-8")) if sf.is_file() else {}
    except json.JSONDecodeError:
        cfg = {}
    perms = cfg.setdefault("permissions", {})
    perms.setdefault("defaultMode", "auto")
    deny = perms.setdefault("deny", [])
    if isinstance(deny, list):
        for t in WEB_DENY_TOOLS:
            if t not in deny:
                deny.append(t)
    else:
        perms["deny"] = list(WEB_DENY_TOOLS)
    sf.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")


def _setup_session_dir(opts) -> None:
    """Copy the baked claude config (~/.claude.json + ~/.claude/settings.json) into
    opts.session_dir so the GLM/MCP/permissions config travels with the session when
    CLAUDE_CONFIG_DIR is redirected there. Idempotent (skips files already present)."""
    if not opts.session_dir:
        return
    sd = Path(opts.session_dir)
    home = Path.home()
    for src, dst in [
        (home / ".claude.json", sd / ".claude.json"),
        (home / ".claude" / "settings.json", sd / "settings.json"),
    ]:
        if src.is_file() and not dst.exists():
            shutil.copy2(src, dst)
    (sd / "projects").mkdir(parents=True, exist_ok=True)
    _lockdown_session_settings(sd)   # block web/skill lookup so PoC must be self-derived


def _claude_env(opts) -> dict:
    """Build the env for the claude subprocess (CLAUDE_CONFIG_DIR if --session-dir)."""
    env = os.environ.copy()
    if opts.session_dir:
        env["CLAUDE_CONFIG_DIR"] = opts.session_dir
    return env


def build_claude_cmd(opts, prompt: str) -> list:
    cmd = [opts.claude_bin, "-p", prompt]
    cmd += ["--output-format", opts.output_format]
    if opts.skip_perms:
        cmd.append("--dangerously-skip-permissions")
    if opts.model:
        cmd += ["--model", opts.model]
    if opts.effort:
        cmd += ["--effort", opts.effort]
    if opts.session_name:
        cmd += ["-n", opts.session_name]
    if opts.session_id:
        cmd += ["--session-id", opts.session_id]
    for d in {opts.bindir, opts.output, opts.workdir, str(Path(opts.report).parent)}:
        cmd += ["--add-dir", d]
    return cmd


def render_stream_json(line: str, logfh) -> None:
    s = line.rstrip("\n")
    if s:
        logfh.write(s + "\n"); logfh.flush()
    if not s:
        return
    try:
        ev = json.loads(s)
    except json.JSONDecodeError:
        print(s, flush=True)
        return
    typ = ev.get("type")
    if typ == "system":
        if ev.get("subtype") == "init":
            print(f"[system] init  model={ev.get('model','')}", flush=True)
    elif typ == "assistant":
        for blk in ev.get("message", {}).get("content", []):
            if not isinstance(blk, dict):
                continue
            bt = blk.get("type")
            if bt == "text" and blk.get("text", "").strip():
                print(blk["text"], flush=True)
            elif bt == "tool_use":
                print(f"  -> tool: {blk.get('name','?')}  "
                      f"{json.dumps(blk.get('input',{}), ensure_ascii=False)[:160]}", flush=True)
    elif typ == "user":
        for blk in ev.get("message", {}).get("content", []):
            if isinstance(blk, dict) and blk.get("type") == "tool_result":
                c = blk.get("content", "")
                if isinstance(c, list):
                    c = " ".join(b.get("text", "") for b in c if isinstance(b, dict))
                print(f"  -> result: {str(c).replace(chr(10),' ')[:140]}", flush=True)
    elif typ == "result":
        print(f"\n[result] subtype={ev.get('subtype','')} duration_ms={ev.get('duration_ms','')}", flush=True)
        if ev.get("result"):
            print(ev["result"], flush=True)


def _short_cmd(cmd: list) -> str:
    parts, saw_p = [], False
    for a in cmd:
        if saw_p:
            parts.append(f"<prompt ({len(a)} chars)>"); saw_p = False; continue
        if a == "-p":
            saw_p = True
        parts.append(a)
    return shlex.join(parts)


def run_claude(cmd, opts, logfh) -> int:
    print(f"[poc] workdir : {opts.workdir}", flush=True)
    if opts.session_dir:
        print(f"[poc] session : {opts.session_dir}  (CLAUDE_CONFIG_DIR)", flush=True)
    print(f"[poc] log     : {opts.log}", flush=True)
    print(f"[poc] format  : {opts.output_format}", flush=True)
    print(f"[poc] cmd     : {_short_cmd(cmd)}", flush=True)
    print("-" * 78, flush=True)
    is_json = opts.output_format == "stream-json"
    try:
        proc = subprocess.Popen(
            cmd, cwd=opts.workdir, env=_claude_env(opts),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except FileNotFoundError:
        sys.exit(f"error: claude binary not found: {opts.claude_bin} (set --claude-bin)")
    rc = 1
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if is_json:
                render_stream_json(line, logfh)
            else:
                sys.stdout.write(line); sys.stdout.flush()
                logfh.write(line); logfh.flush()
        proc.wait()
        rc = proc.returncode if proc.returncode is not None else 1
    except KeyboardInterrupt:
        proc.kill()
        print("\n[poc] interrupted - killed claude.", flush=True)
        rc = 130
    return rc


def post_run_check(opts) -> dict:
    outdir = Path(opts.output) / "output"   # prompt tells claude to save under {输出目录}/output
    info = {"output_dir": str(outdir), "exists": outdir.is_dir(), "artifacts": []}
    if outdir.is_dir():
        info["artifacts"] = sorted(p.name for p in outdir.iterdir() if p.is_file())
    return info


def main(argv=None) -> int:
    opts = parse_args(argv)
    validate(opts)
    prompt = build_prompt(opts.entry, opts.report, opts.bindir, opts.output)
    ts = time.strftime("%Y%m%d_%H%M%S")
    opts.log = opts.log or str(Path(opts.workdir) / f"poc_cli_{ts}.log")
    Path(opts.workdir).joinpath("poc_prompt.txt").write_text(prompt, encoding="utf-8")
    cmd = build_claude_cmd(opts, prompt)

    if opts.dry_run:
        print("=== DRY RUN ===")
        print(f"workdir : {opts.workdir}")
        print(f"session : {opts.session_dir}  (CLAUDE_CONFIG_DIR; config copied on real run)")
        print(f"log     : {opts.log}")
        print(f"cmd     : {_short_cmd(cmd)}")
        print(f"env     : CLAUDE_CONFIG_DIR={opts.session_dir}")
        print("\n=== PROMPT (saved to poc_prompt.txt) ===")
        print(prompt)
        return 0

    if opts.session_dir:
        _setup_session_dir(opts)   # copy baked config into the session dir
    with open(opts.log, "w", encoding="utf-8") as logfh:
        logfh.write(f"# poc_cli log {ts}\n# workdir={opts.workdir}\n# entry={opts.entry}\n"
                    f"# report={opts.report}\n# bindir={opts.bindir}\n# cmd={_short_cmd(cmd)}\n"
                    f"# session_dir={opts.session_dir or ''}\n# prompt_bytes={len(prompt)}\n\n")
        rc = run_claude(cmd, opts, logfh)

    info = post_run_check(opts)
    print("-" * 78, flush=True)
    print(f"[poc] claude exit code: {rc}", flush=True)
    if info["exists"]:
        arts = info["artifacts"]
        print(f"[poc] output dir: {info['output_dir']}  ({len(arts)} files)")
        for a in arts[:30]:
            print(f"        - {a}")
        if len(arts) > 30:
            print(f"        ... ({len(arts)-30} more)")
    else:
        print(f"[poc] WARNING: output dir not created: {info['output_dir']}")
    print(f"[poc] log    : {opts.log}", flush=True)
    print(f"[poc] prompt : {Path(opts.workdir) / 'poc_prompt.txt'}", flush=True)
    return rc


if __name__ == "__main__":
    sys.exit(main())
