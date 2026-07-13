#!/usr/bin/env python3
"""poc_cli.py - PoC generation & verification orchestration CLI (v2.0, two-stage).

Wraps the `claude` (Claude Code) CLI. Given a data-flow entry function, a
vulnerability report, and the unpacked firmware binary directory, it drives
`claude -p` (headless) through a **two-stage, two-session** pipeline:

  Stage 1 (session <base>-stage1): construct a PoC-verification harness that
    enters via the data-flow entry function + a **benign reachability driver**
    that reaches the vuln-point function, and GDB-prove entry→vuln reachability.
    Produces: harness.c, harness, reach_driver.bin, gdb_reachability.log,
    harness_report.md (with "漏洞点函数:" + "可达性结论: 已确认" markers).

  Gate (deterministic, in this CLI — not LLM): verify the Stage-1 artifacts
    exist and the reachability transcript hits both entry and vuln-point
    functions. Fail → stop, do NOT run Stage 2.

  Stage 2 (session <base>-stage2, FRESH context): read Stage-1 artifacts (no
    re-RE), freely analyze the entry→vuln-point call chain (not limited to the
    path Stage 1's reachability driver took) and generate a malicious PoC,
    loop-debug-trigger via tmux-mcp/gdb until the vuln truly triggers (or is
    disproven). Produces: poc_input.bin, gdb_trigger.log, trigger_memory.txt,
    poc_report.md.

The two stages run in **separate claude sessions** (separate --session-id, same
--session-dir so transcripts co-locate on disk for on-demand grep). Stage 2
starts with a fresh context — it does not carry Stage 1's RE/thinking history —
which is the whole point: relief from context pressure, a reviewable Stage-1
checkpoint, and independent Stage-2 retry against a frozen harness.

Escape hatches:
  --single         run the v1.0 monolithic single-/goal prompt (one session).
                   Use for the degenerate case where the vuln-point function is
                   only reachable via the buggy path (reachability == trigger).
  --stage1-only    run only Stage 1 (+ gate), don't proceed to Stage 2.
  --stage2-only    skip Stage 1 (assume its artifacts already exist in
                   <output>/output/), gate on them, then run Stage 2 only.
                   Use to retry Stage 2 against a frozen Stage-1 harness.

The user's environment already provides: the `claude` CLI, the `tmux-mcp` MCP
server, the built-in `/goal` command, `auto` permission mode, the `glm-5.2`
model — so a plain-shell invocation works as-is.

Usage:
  ./poc -e IPSEC_SOCKI_PipeMsg -r /path/to/result_001.md -b /path/to/fw
  ./poc --single -e ...   # v1.0 monolithic
  ./poc --stage1-only -e ...   # only build+prove harness
  ./poc --stage2-only -e ...   # only trigger (Stage-1 artifacts must exist)
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
import uuid
from pathlib import Path

# .replace (not .format) so Chinese punctuation / braces survive as-is.
# Substitution placeholders shared by all three prompts:
#   {全二进制文件目录} {漏洞报告路径} {数据流入口函数} {输出目录}

# ---------------------------------------------------------------------------
# Stage 1 prompt: construct harness + benign reachability driver + GDB-prove
# entry→vuln-point reachability. Does NOT trigger the bug.
# ---------------------------------------------------------------------------
PROMPT_STAGE1 = """\
/goal 【阶段1：构造PoC验证harness并证明入口→漏洞点可达】全二进制文件目录为{全二进制文件目录}，漏洞报告路径为{漏洞报告路径}，数据流入口函数为{数据流入口函数}。本阶段只负责构造一个从数据流入口函数到达漏洞点函数的验证harness，并构造一个可达性驱动输入(可以基于正常业务逻辑良性构造，无需是恶意数据)，用gdb动态证明入口→漏洞点可达；**本阶段不负责触发漏洞**（触发是阶段2的事）。

  **阶段1任务**：
    1.阅读分析漏洞报告，确定漏洞点函数名（写入harness_report.md的"漏洞点函数:"字段）。
    2.构造C语言PoC验证harness，从{数据流入口函数}进入（不得直接调用漏洞点函数），解决入口→漏洞点链上所有符号缺失与依赖：当前固件二进制目录/系统库中有真实实现的就真实链接，确定缺失的用空弱符号stub填充，传递缺失递归同策略；环境/数据投递/前置条件类符号(收包、内存分配、AVL/表查找等)可interpose覆盖(直接链入可执行文件+-rdynamic使其在动态符号搜索序中优先)，但**漏洞点本身的代码必须原样运行、不得stub或patch**。
    3.构造的可达性驱动reach_driver.bin：只求穿过上游所有gate(分发、表查找、前置校验)让执行流走到漏洞点函数，不求触发bug；漏洞点函数若有正常可达路径，用最小合法输入即可。
    4.用tmux-mcp调用gdb跑harness+reach_driver.bin，在入口函数与漏洞点函数设断点，证明两者均命中、backtrace证明控制流由入口到达漏洞点(不得直接调用漏洞点函数)。gdb转录存为gdb_reachability.log。
    5.产出harness_report.md(简体中文)：含 调用链(入口→…→漏洞点,带地址)、stub策略(哪些真链接/弱stub/interpose及理由)、关键数据结构布局、可达性驱动构造方式、漏洞点函数名(单独一行"漏洞点函数: <name>")、可达性结论(单独一行"可达性结论: 已确认";未确认则写"可达性结论: 未确认"并说明阻断点)。

  **阶段1产物(必须以下列固定文件名存于{输出目录}/output下)**：
    - harness.c            harness源码
    - harness              harness二进制(gcc/ld退出码0)
    - reach_driver.bin     可达性驱动输入
    - gdb_reachability.log gdb可达性转录(含入口与漏洞点断点命中+backtrace)
    - harness_report.md    结构化报告(含上述字段)
    **所有产物(包括但不限于上述固定文件名、编译中间产物、.o/.so/临时二进制/生成的脚本/日志等)必须全部存放于{输出目录}/output目录下，严禁在该目录之外创建任何文件；如需临时文件也放在该目录内。**

  **任务约束**(必须遵守)：
    1.harness必须从数据流入口函数构造，模拟真实攻击入口，不得直接调用漏洞点函数。
    2.基于gdb做动态可达性证明。
    3.硬件/环境类前置可patch绕过，但须记录patch原因/点/内容；严禁patch漏洞点本身的检查。
    4.所有文档用简体中文。
    5.tmux/gdb进程管理(防止跨任务污染与误杀本进程)：
      a.会话命名:用本任务专属tmux会话名(如poc_<workdirbasename去特殊字符>)，禁用"poc"/"poc008"等通用名。
      b.启动前清理:发现同名会话/pane残留先`tmux kill-session -t <本任务会话名>`清掉再重建;不复用来历不明的pane。
      c.严禁模式匹配杀进程:本进程(claude)命令行含整段prompt(含"gdb"/"harness"等字样)，`pkill -f`/`killall`配合命令行模式(如`pkill -9 -f 'gdb.*harness'`)会误匹配并SIGKILL本进程自身导致任务无错误输出地异常终止。清理gdb只能:①`tmux kill-session -t <本任务会话名>`;②`tmux send-keys -t <pane> 'quit' Enter`;③精确PID `kill <pid>`(PID由`tmux list-panes -t <本任务会话名> -F '#{pane_pid}'`定位,禁模式匹配)。
      d.退出前主动`tmux kill-session -t <本任务会话名>`销毁自己创建的会话。
      e.禁用`gdb ... | head`之类管道(SIGPIPE杀gdb)，改用gdb的`set logging`或tmux-mcp的capture-pane。

  **完成目标**(全部满足方可结束;严禁编造证据)：
    1.harness.c与harness二进制均存在(编译链接成功);
    2.gdb_reachability.log中入口函数与漏洞点函数断点均命中，backtrace证明入口→漏洞点动态可达;
    3.漏洞点代码为真实固件代码未修改(interpose仅作用于环境/前置层);
    4.reach_driver.bin存在明确的输入;
    5.harness_report.md存在且含"漏洞点函数: <name>"与"可达性结论: 已确认"两行;
    6.所有patch(若有)已记录。
    【严禁编造证据】gdb输出/backtrace必须来自真实运行并体现在gdb_reachability.log中;不得伪造断点命中或backtrace;不得用stub绕过漏洞点检查。违者任务判失败。\
"""

# ---------------------------------------------------------------------------
# Stage 2 prompt: given a Stage-1-proven harness + reachability driver,
# specialize into a malicious PoC and loop-debug-trigger. Fresh session.
# ---------------------------------------------------------------------------
PROMPT_STAGE2 = """\
/goal 【阶段2：基于已可达性的harness生成PoC并循环调试触发漏洞】全二进制文件目录为{全二进制文件目录}，漏洞报告路径为{漏洞报告路径}，数据流入口函数为{数据流入口函数}。**阶段1已完成**:在{输出目录}/output下已有harness.c/harness/gdb_reachability.log/harness_report.md及可达性驱动reach_driver.bin（仅供参考其构造思路，本阶段不要求沿用)，harness已证明入口→漏洞点可达。**本阶段不许重做阶段1的可达性RE/harness构造**;基于阶段1的harness(harness.c/二进制)与harness_report.md(调用链/stub策略/关键结构布局)，由本阶段自由分析从入口函数到漏洞点函数的调用链并生成PoC，循环调试纠偏直到真正触发漏洞(或证伪)。

  **阶段2任务**：
    1.读harness_report.md与harness源码，理解阶段1已验证的调用链/stub策略/关键结构布局(不重新RE;reach_driver.bin仅供参考其构造思路，不要求沿用其路径)。
    2.分析漏洞报告，定位漏洞点的buggy条件/路径。
    3.自由分析从入口函数到漏洞点函数的调用链(可能有多条路径，不要限于阶段1可达性驱动走的路径)，生成恶意PoC输入poc_input.bin，使其在漏洞点函数处激发buggy条件。
    4.用tmux-mcp调用gdb跑harness+poc_input.bin，观察是否触发;未触发则根据动态反馈修正PoC(可酌情微调harness的stub/数据注入以塑形触发，但不得改动漏洞点代码本身)，再触发验证，循环直到真正触发。
    5.触发后保存触发时内存状态(寄存器+关键缓冲区)到trigger_memory.txt。
    6.产出poc_report.md(简体中文):含漏洞结论、触发证据(gdb)、PoC策略、调用链backtrace、触发时内存状态、patch记录(若有)。

  **阶段2产物(必须以下列固定文件名存于{输出目录}/output下)**：
    - poc_input.bin       恶意PoC输入
    - gdb_trigger.log     gdb触发循环转录
    - trigger_memory.txt  触发时内存状态(寄存器+关键缓冲区)
    - poc_report.md       简体中文验证报告(或误报/不可达分析报告)
    **所有产物(包括但不限于上述固定文件名、编译中间产物、.o/.so/临时二进制/生成的脚本/日志等)必须全部存放于{输出目录}/output目录下，严禁在该目录之外创建任何文件；如需临时文件也放在该目录内。**

  **任务约束**(必须遵守)：
    1.harness必须从数据流入口函数构造(阶段1已满足;本阶段若微调stub不得改为直接调用漏洞点函数)。
    2.基于gdb调试器做循环触发-观察-纠偏。
    3.硬件/环境类前置可patch绕过并记录;严禁patch漏洞点本身的检查。
    4.所有文档用简体中文。
    5.tmux/gdb进程管理(防止跨任务污染与误杀本进程)：
      a.会话命名:用本任务专属tmux会话名(如poc_<workdirbasename去特殊字符>)，禁用"poc"/"poc008"等通用名。
      b.启动前清理:发现同名会话/pane残留先`tmux kill-session -t <本任务会话名>`清掉再重建;不复用来历不明的pane。
      c.严禁模式匹配杀进程:本进程(claude)命令行含整段prompt(含"gdb"/"harness"等字样)，`pkill -f`/`killall`配合命令行模式会误匹配并SIGKILL本进程自身导致任务无错误输出地异常终止。清理gdb只能:①`tmux kill-session -t <本任务会话名>`;②`tmux send-keys -t <pane> 'quit' Enter`;③精确PID `kill <pid>`(PID由`tmux list-panes -t <本任务会话名> -F '#{pane_pid}'`定位,禁模式匹配)。
      d.退出前主动`tmux kill-session -t <本任务会话名>`销毁自己创建的会话。
      e.禁用`gdb ... | head`之类管道(SIGPIPE杀gdb)，改用gdb的`set logging`或tmux-mcp的capture-pane。

  **完成目标**(满足【路径A:确认触发】或【路径B:证伪/不可达】任一路径全部条件方可结束;严禁编造证据)：
    【路径A:确认触发】
    A1.harness编译链接成功(阶段1已满足);
    A2.gdb中入口与漏洞点断点均命中、backtrace证明入口→漏洞点(触发轮须在gdb_trigger.log中再现入口→漏洞点→触发的完整链);
    A3.漏洞被真实触发并留证之一:a)漏洞点函数处崩溃(SIGSEGV/SIGABRT等)且backtrace可见该函数;或 b)死循环类:自终止前循环执行次数≥1e7且记录到不变量;或 c)内存破坏类:gdb在漏洞点函数处观察到越界读写(对越界指针解引用、或写入破坏相邻内存)并在trigger_memory.txt记录越界地址与被破坏内存;
    A4.触发时内存状态(寄存器+关键缓冲区)与最终PoC代码已保存;
    A5.上述产物齐全于{输出目录}/output下;
    A6.patch(若有)已记录。
    【路径B:证伪/不可达】(须先尽力尝试触发，不得未经尝试即走此路径)
    B1.harness编译链接成功且已沿入口→漏洞点在gdb推进、系统尝试多种恶意输入/路径(在gdb_trigger.log记录每次尝试);
    B2.均未触发，在gdb中定位阻断点之一:a)调用链不可达;b)漏洞点处存在不可绕过检查;c)漏洞不存在/输入的漏洞报告分析错误;d)触发漏洞存在前置条件，真机/现实无法满足;
    B3.阻断点gdb实证(寄存器/内存/分支条件+为何对攻击者可控输入恒不满足);
    B4.poc_report.md作为简体中文《误报/不可达分析报告》:含结论、阻断点+gdb实证、已尝试输入/路径清单及结果、判定依据;
    B5.产物齐全;
    B6.patch(若有)已记录。
    【严禁编造证据】所有gdb输出/崩溃/寄存器内存值必须来自真实运行并体现在gdb_trigger.log中;不得伪造调试输出;不得用stub绕过漏洞点本身检查冒充触发;不得编造PoC执行效果。patch仅限硬件/环境前置,严禁绕过漏洞点检查伪造触发。违者任务判失败。
    【阶段边界】本阶段可微调harness stub/数据注入以塑形触发;但若发现可达性回退(调用链不再到达漏洞点)，说明阶段1产物有问题，应作为阻断点在poc_report.md中记录并走路径B报告，**不要在本阶段从头重做阶段1的harness构造**。\
"""

# ---------------------------------------------------------------------------
# Stage 0 prompt: read the vuln report + extract the data-flow entry function.
# Read-only — no binary/code analysis (that's Stage 1). Runs before Stage 1
# when -e/--entry is absent. Writes 入口函数: <name> to stage0_report.md.
# Placeholders: {漏洞报告路径} {输出目录}
# ---------------------------------------------------------------------------
PROMPT_STAGE0 = """\
/goal 【阶段0：从漏洞报告中提取数据流入口函数】漏洞报告路径为{漏洞报告路径}。本阶段**只阅读分析漏洞报告文本**，从中提取报告所述的数据流入口函数(即外部输入/数据进入受影响代码路径的源头函数，通常是收包/接收/管道/分发等入口函数，**不是漏洞点/sink函数**)，写入{输出目录}/output/stage0_report.md。

  **阶段0任务**：
    1.阅读漏洞报告全文，理解其描述的漏洞场景与数据流路径。
    2.提取"数据流入口函数"——即外部输入/数据进入受影响代码路径的**第一个**函数(入口/源端)。例如报告描述"IPSEC_SOCKI_PipeMsg接收报文后经…到达IPSEC_AH_HandleInputPktV4的漏洞点"，则入口函数是IPSEC_SOCKI_PipeMsg(而非漏洞点IPSEC_AH_HandleInputPktV4)。
    3.将提取结果写入{输出目录}/output/stage0_report.md，**单独一行**格式为"入口函数: <函数名>"(该行只有"入口函数: "前缀+函数名，无其他内容)。

  **阶段0约束**(必须遵守)：
    1.**只阅读漏洞报告**，不分析二进制/代码(代码分析是后续阶段的事)。
    2.入口函数必须是报告中**明确提及**的函数(不可臆测/编造/猜测)。
    3.若报告中**未提及任何入口函数**或无法确定数据流入口，则写"入口函数: "(留空)并在下一行用一句话说明原因(如"报告未描述数据流入口函数")。此时流程将拒绝继续执行。
    4.所有文本用简体中文。

  **完成目标**：
    {输出目录}/output/stage0_report.md 存在且含"入口函数: <name>"行(有则填函数名，无则留空+原因)。\
"""


# ---------------------------------------------------------------------------
# v1.0 monolithic prompt (kept verbatim for --single escape hatch).
# ---------------------------------------------------------------------------
PROMPT_SINGLE = """\
/goal 全二进制文件目录为{全二进制文件目录}，漏洞报告路径为{漏洞报告路径}，数据流入口函数为{数据流入口函数}。
  **PoC生成和验证任务**：
    1. 先编写一个C语言目标程序，其职责为针对漏洞报告的PoC验证harness，要求必须解决从数据流入口函数到目标漏洞点间涉及的数据流和控制流链中所有符号缺失和依赖问题，尽可能达到无限接近真机运行环境的验证harness。（解决方案为：当前固件二进制目录下/系统自身库文件中有定义和实现的就找到并真实链接使用；找不到并确定缺失的符号可以使用空stub填充解决。对链接真实so库后带来的新的符号缺失依赖也按照同样的方案：在当前固件二进制目录下/系统自身库文件中寻找存在真实有定义和实现的so库链接使用，确定缺失的符号用空stub填充，一直嵌套递归解决，直到没有任何符号缺失依赖问题。）
    2. 充分理解和分析漏洞报告，生成漏洞PoC，基于上一步的PoC验证harness进行真实的漏洞触发，借助tmux mcp server调用gdb进行程序调试，修正PoC，再触发验证，循环观察+修正直到真正触发漏洞，保存漏洞触发时的内存状态和最终的PoC代码。
  
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

    6.**产物存放约束**：所有产物(包括但不限于harness源码/二进制、PoC输入、gdb转录日志、内存状态、报告、以及编译中间产物、.o/.so/临时二进制/生成的脚本/日志等)必须**全部**存放于`{输出目录}/output`目录下，严禁在该目录之外创建任何文件；如需临时文件也放在该目录内。

  **任务完成目标**（满足【路径A：确认触发】或【路径B：证伪/不可达】任一路径的全部条件方可结束；严禁编造证据，违反则任务判为失败）：
    【路径A：确认触发】（漏洞为真且可触发时）
    A1.PoC验证harness编译并链接成功（gcc/ld退出码为0，二进制产物存在）；
    A2.在gdb中于"数据流入口函数"与"漏洞点函数"所设断点均被命中，backtrace证明控制流由数据流入口函数到达漏洞点函数（不得直接调用漏洞点函数）；
    A3.漏洞被真实触发并留下可观测证据之一：a)进程在漏洞点函数处崩溃（SIGSEGV/SIGABRT等）且backtrace中可见该函数；或 b)死循环类：自终止前循环执行次数≥阈值(如1e7)且记录到不变量(如循环计数器/关键寄存器在多次迭代间不变)；或 c)内存破坏类：gdb在漏洞点函数处观察到越界读写（对越界指针解引用、或写入破坏相邻内存）并在触发时内存状态中记录越界地址与被破坏内存；
    A4.触发时的内存状态(寄存器+关键缓冲区)与最终PoC代码已保存；
    A5.以下产物全部存在于目录{输出目录}/output下：harness源码、harness二进制、PoC输入、gdb转录日志、触发时内存状态、简体中文验证报告；
    A6.所有patch(若有)已记录patch原因/patch点/patch内容。

    【路径B：证伪/不可达】（漏洞为误报、不可达或存在不可绕过检查/现实无法满足的前置条件时；须先尽力尝试触发，不得未经尝试即走此路径）
    B1.PoC验证harness编译并链接成功；且已沿"数据流入口函数→漏洞点函数"方向在gdb中推进，并系统尝试多种合理输入/路径（在gdb转录中记录每次尝试的输入与观察结果）；
    B2.均未触发漏洞，并在gdb中定位到具体阻断点之一：a)调用链不可达（分发/守卫条件使得到达漏洞点函数的路径对任何攻击者可控输入均不成立）；或 b)漏洞点处存在不可绕过的检查/校验（给出该检查位置与判定逻辑）；或 c)触发所需前置条件在真机/现实中无法满足（说明为何无法满足）；
    B3.给出该阻断点的gdb实证：阻断处寄存器/内存值、分支条件取值、以及"为何对所有攻击者可控输入恒不满足"的具体分析（引用反汇编/源码位置）；
    B4.产出简体中文《误报/不可达分析报告》：含结论(误报/不可达/不可绕过)、阻断点位置与gdb实证、已尝试的输入与路径清单及每次结果、判定依据；
    B5.以下产物全部存在于目录{输出目录}/output下：harness源码、harness二进制、gdb转录日志、(若适用)尝试用输入集、《误报/不可达分析报告》；
    B6.所有patch(若有)已记录patch原因/patch点/patch内容。

    【严禁编造证据】无论走哪条路径，所有gdb输出/崩溃/寄存器与内存值必须来自真实运行并体现在gdb转录日志中；不得伪造调试输出、不得用stub绕过漏洞点本身的检查后冒充"真实触发"、不得编造PoC输入的执行效果。patch仅可用于绕过硬件/环境初始化类前置（见任务约束3），严禁用于绕过漏洞点本身的检查以伪造触发。违反本条则任务判为失败，不得据此结束。\
"""


def _substitute(p: str, entry: str, report: str, bindir: str, output: str) -> str:
    p = p.replace("{全二进制文件目录}", bindir)
    p = p.replace("{漏洞报告路径}", report)
    p = p.replace("{数据流入口函数}", entry)
    p = p.replace("{输出目录}", output)
    return p


def build_stage1_prompt(entry, report, bindir, output) -> str:
    return _substitute(PROMPT_STAGE1, entry, report, bindir, output)


def build_stage2_prompt(entry, report, bindir, output) -> str:
    return _substitute(PROMPT_STAGE2, entry, report, bindir, output)


def build_stage0_prompt(report, output) -> str:
    """Stage0 only substitutes {漏洞报告路径} + {输出目录} (it derives the entry, doesn't use it)."""
    p = PROMPT_STAGE0.replace("{漏洞报告路径}", report)
    return p.replace("{输出目录}", output)


def build_single_prompt(entry, report, bindir, output) -> str:
    return _substitute(PROMPT_SINGLE, entry, report, bindir, output)


def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        prog="poc",
        description="Drive Claude Code to generate & GDB-verify a PoC from a vuln report, "
                    "entering via a given data-flow function. v2.0 default = two-stage/two-session.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("-e", "--entry", required=False, default="",
                    help="Data-flow entry function name (e.g. IPSEC_SOCKI_PipeMsg). "
                         "If omitted, Stage 0 derives it from the vuln report.")
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
                    help="Base session display name (stage suffixes -stage1/-stage2 are appended in two-stage "
                         "mode; passed to `claude -n`). With --single, used verbatim.")
    ap.add_argument("--session-id", default=None,
                    help="Stage-1 session UUID (two-stage: stage1 uses this if given, stage2 auto-generates a "
                         "fresh UUID; with --single, passed verbatim to `claude --session-id`).")
    ap.add_argument("--session-dir", default=None,
                    help="Set CLAUDE_CONFIG_DIR for the claude subprocess: session transcripts (and "
                         "the claude config) are stored under this dir instead of ~/.claude. The baked "
                         "~/.claude.json + ~/.claude/settings.json are copied in on first use so the "
                         "GLM/MCP/permissions config travels with the session. Both stages share this dir "
                         "so Stage 2 can grep Stage 1's transcript on disk without loading it into context.")
    ap.add_argument("--output-format", choices=["text", "stream-json"], default="stream-json",
                    help="claude -p output format (default: stream-json for live progress).")
    ap.add_argument("--log", default=None,
                    help="Log file path (default: <workdir>/poc_cli_<timestamp>[_stageN].log).")
    ap.add_argument("--no-skip-permissions", dest="skip_perms", action="store_false",
                    help="Do NOT pass --dangerously-skip-permissions.")
    ap.set_defaults(skip_perms=True)
    ap.add_argument("--dry-run", action="store_true",
                    help="Print the exact claude commands + prompts (and the gate plan) and exit (no invocation).")
    ap.add_argument("--single", action="store_true",
                    help="Run the v1.0 monolithic single-/goal prompt in one session (escape hatch for the "
                         "degenerate case where the vuln-point function is only reachable via the buggy path).")
    ap.add_argument("--stage1-only", action="store_true",
                    help="Two-stage mode but run only Stage 1 (+ gate); don't proceed to Stage 2. "
                         "Use to build+prove a harness in isolation.")
    ap.add_argument("--stage2-only", action="store_true",
                    help="Two-stage mode but skip Stage 1 (its artifacts must already exist in <output>/output/); "
                         "gate on them, then run Stage 2 only. Use to retry Stage 2 against a frozen harness.")
    ap.add_argument("--claude-bin", default="claude",
                    help="Path to claude executable (default: claude).")
    args = ap.parse_args(argv)
    if args.single and (args.stage1_only or args.stage2_only):
        ap.error("--single is mutually exclusive with --stage1-only/--stage2-only")
    if args.stage1_only and args.stage2_only:
        ap.error("--stage1-only and --stage2-only are mutually exclusive")
    return args


def _default_output_dir(entry: str, bindir: str, report: str = "") -> str:
    """Default output dir under the cwd: <entry|report-basename>_<bindir-basename>_<timestamp>."""
    def _s(x: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", x).strip("_") or "poc"
    base = os.path.basename(bindir.rstrip("/")) or "bindir"
    # when entry is absent (Stage 0 will derive it), name the dir from the report basename
    head = entry.strip() or (os.path.basename(report.rstrip("/")) or "poc")
    name = f"{_s(head)}_{_s(base)}_{time.strftime('%Y%m%d_%H%M%S')}"
    return str(Path.cwd() / name)


def validate(opts) -> None:
    # entry may be empty — Stage 0 derives it from the report when absent.
    rp = Path(opts.report)
    if not rp.is_file():
        sys.exit(f"error: --report not a file: {opts.report}")
    bp = Path(opts.bindir)
    if not bp.is_dir():
        sys.exit(f"error: --bindir not a directory: {opts.bindir}")
    opts.report = str(rp.resolve())
    opts.bindir = str(bp.resolve())
    if not opts.output:
        opts.output = _default_output_dir(opts.entry, opts.bindir, opts.report)
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


def build_claude_cmd(opts, prompt: str, session_id=None, session_name=None) -> list:
    """Build the claude -p command. session_id/session_name override opts.* so
    two-stage mode can pass per-stage ids without mutating opts."""
    cmd = [opts.claude_bin, "-p", prompt]
    cmd += ["--output-format", opts.output_format]
    if opts.skip_perms:
        cmd.append("--dangerously-skip-permissions")
    if opts.model:
        cmd += ["--model", opts.model]
    if opts.effort:
        cmd += ["--effort", opts.effort]
    sid = session_id if session_id is not None else opts.session_id
    sname = session_name if session_name is not None else opts.session_name
    if sname:
        cmd += ["-n", sname]
    if sid:
        cmd += ["--session-id", sid]
    for d in {opts.bindir, opts.output, opts.workdir, str(Path(opts.report).parent)}:
        cmd += ["--add-dir", d]
    return cmd


def _tee(msg: str, logfh) -> None:
    """Print to the terminal AND write to the log file (so the .log mirrors the
    terminal's rendered human-readable output, not just the raw stream-json)."""
    print(msg, flush=True)
    logfh.write(msg + "\n"); logfh.flush()


def render_stream_json(line: str, logfh, jsonlfh=None) -> None:
    """Render one stream-json line to the terminal (human-readable) AND to logfh
    (the .log mirror). The raw json line goes to jsonlfh (.jsonl) if given, so the
    machine-readable stream is preserved separately for programmatic grep/analysis."""
    s = line.rstrip("\n")
    if s and jsonlfh is not None:
        jsonlfh.write(s + "\n"); jsonlfh.flush()
    if not s:
        return
    try:
        ev = json.loads(s)
    except json.JSONDecodeError:
        _tee(s, logfh)
        return
    typ = ev.get("type")
    if typ == "system":
        if ev.get("subtype") == "init":
            _tee(f"[system] init  model={ev.get('model','')}", logfh)
    elif typ == "assistant":
        for blk in ev.get("message", {}).get("content", []):
            if not isinstance(blk, dict):
                continue
            bt = blk.get("type")
            if bt == "text" and blk.get("text", "").strip():
                _tee(blk["text"], logfh)
            elif bt == "tool_use":
                _tee(f"  -> tool: {blk.get('name','?')}  "
                     f"{json.dumps(blk.get('input',{}), ensure_ascii=False)[:160]}", logfh)
    elif typ == "user":
        for blk in ev.get("message", {}).get("content", []):
            if isinstance(blk, dict) and blk.get("type") == "tool_result":
                c = blk.get("content", "")
                if isinstance(c, list):
                    c = " ".join(b.get("text", "") for b in c if isinstance(b, dict))
                _tee(f"  -> result: {str(c).replace(chr(10),' ')[:140]}", logfh)
    elif typ == "result":
        _tee(f"\n[result] subtype={ev.get('subtype','')} duration_ms={ev.get('duration_ms','')}", logfh)
        if ev.get("result"):
            _tee(ev["result"], logfh)


def _short_cmd(cmd: list) -> str:
    parts, saw_p = [], False
    for a in cmd:
        if saw_p:
            parts.append(f"<prompt ({len(a)} chars)>"); saw_p = False; continue
        if a == "-p":
            saw_p = True
        parts.append(a)
    return shlex.join(parts)


def run_claude(cmd, opts, logfh, label="poc", jsonlfh=None, prompt_path=None) -> int:
    # Preamble is tee'd to logfh so the .log opens with the same lines the terminal shows.
    _tee(f"[{label}] workdir : {opts.workdir}", logfh)
    if opts.session_dir:
        _tee(f"[{label}] session : {opts.session_dir}  (CLAUDE_CONFIG_DIR)", logfh)
    _tee(f"[{label}] log     : {opts.log}", logfh)
    if jsonlfh is not None:
        _tee(f"[{label}] jsonl   : {jsonlfh.name}", logfh)
    _tee(f"[{label}] format  : {opts.output_format}", logfh)
    if prompt_path:
        _tee(f"[{label}] prompt  : {prompt_path}", logfh)
    _tee(f"[{label}] session-id: {_cmd_session_id(cmd) or '(auto)'}", logfh)
    _tee(f"[{label}] cmd     : {_short_cmd(cmd)}", logfh)
    _tee("-" * 78, logfh)
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
                render_stream_json(line, logfh, jsonlfh)
            else:
                # text format: the raw line IS the terminal output; tee it.
                sys.stdout.write(line); sys.stdout.flush()
                logfh.write(line); logfh.flush()
        proc.wait()
        rc = proc.returncode if proc.returncode is not None else 1
    except KeyboardInterrupt:
        proc.kill()
        _tee(f"\n[{label}] interrupted - killed claude.", logfh)
        rc = 130
    return rc


def _run_claude_to_log(opts, cmd, prompt, log_path, prompt_path, label, ts) -> int:
    """Write prompt file, open the rendered .log + raw .jsonl, write header, run claude.
    The .log mirrors the terminal (human-readable); the .jsonl keeps the raw stream-json
    for programmatic grep/analysis. (jsonl only used in stream-json mode.)"""
    Path(prompt_path).write_text(prompt, encoding="utf-8")
    opts.log = log_path
    jsonl_path = log_path[:-4] + ".jsonl" if log_path.endswith(".log") else log_path + ".jsonl"
    is_json = opts.output_format == "stream-json"
    logfh_ctx = open(log_path, "w", encoding="utf-8")
    jsonlfh_ctx = open(jsonl_path, "w", encoding="utf-8") if is_json else open(os.devnull, "w", encoding="utf-8")
    with logfh_ctx as logfh, jsonlfh_ctx as jsonlfh:
        logfh.write(f"# poc_cli {label} log {ts} (rendered terminal output; raw stream-json in the .jsonl sibling)\n"
                    f"# workdir={opts.workdir}\n# entry={opts.entry}\n"
                    f"# report={opts.report}\n# bindir={opts.bindir}\n# cmd={_short_cmd(cmd)}\n"
                    f"# session_id={_cmd_session_id(cmd) or ''}\n# session_dir={opts.session_dir or ''}\n"
                    f"# prompt_bytes={len(prompt)}\n# prompt_file={prompt_path}\n"
                    f"# jsonl={jsonl_path if is_json else '(off: non-json format)'}\n\n")
        rc = run_claude(cmd, opts, logfh, label=label,
                        jsonlfh=jsonlfh if is_json else None, prompt_path=prompt_path)
    return rc


def _cmd_session_id(cmd: list) -> str | None:
    """Extract the --session-id value from a built claude cmd (for logging)."""
    for i, a in enumerate(cmd):
        if a == "--session-id" and i + 1 < len(cmd):
            return cmd[i + 1]
    return None


# ---------------------------------------------------------------------------
# Stage-1 gate (deterministic, CLI-side — not LLM judgment).
# ---------------------------------------------------------------------------
STAGE1_REQUIRED_FILES = {
    "harness.c": "harness源码",
    "harness": "harness二进制",
    "reach_driver.bin": "可达性驱动",
    "gdb_reachability.log": "gdb可达性转录",
    "harness_report.md": "harness报告",
}

STAGE2_REQUIRED_FILES = {
    "poc_input.bin": "恶意PoC输入",
    "gdb_trigger.log": "gdb触发转录",
    "trigger_memory.txt": "触发时内存状态",
    "poc_report.md": "简体中文验证/误报报告",
}


def gate_stage1(opts) -> tuple[bool, list[str], str, bool]:
    """Verify Stage 1 produced a proven-reaching harness. Returns
    (passed, missing, vuln_func, blocked).

    Three outcomes:
      - passed=True                       → reachability confirmed (已确认); proceed to Stage 2.
      - passed=False, blocked=True        → Stage 1 honestly reported 未确认 (reachability blocked,
                                            an honest negative result — the reachability analog of
                                            Path B). Don't proceed to Stage 2; exit 3. The blocker
                                            explanation is surfaced via _extract_blocker().
      - passed=False, blocked=False       → contract violation (missing files/markers, or transcript
                                            inconsistency with the claimed 已确认); exit 2.

    Transcript cross-check (entry+vuln_func+backtrace in gdb_reachability.log) is only applied
    when reachability is claimed 已确认 — if 未确认, the vuln-point function not being hit is the
    expected outcome, not a failure."""
    outdir = Path(opts.output) / "output"
    missing: list[str] = []
    if not outdir.is_dir():
        return False, [f"output dir not created: {outdir}"], "", False

    for fn, desc in STAGE1_REQUIRED_FILES.items():
        if not (outdir / fn).exists():
            missing.append(f"{desc} ({fn})")

    report_path = outdir / "harness_report.md"
    vuln_func = ""
    reachability = ""  # "confirmed" | "blocked" | "" (absent/ambiguous)
    if report_path.is_file():
        txt = report_path.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"漏洞点函数\s*[:：]\s*([A-Za-z0-9_]+)", txt)
        if m:
            vuln_func = m.group(1)
        else:
            missing.append("harness_report.md 缺少 '漏洞点函数: <name>' 行")
        if "可达性结论" in txt:
            if "已确认" in txt:
                reachability = "confirmed"
            elif "未确认" in txt:
                reachability = "blocked"
            else:
                missing.append("harness_report.md 的 '可达性结论' 行既非 '已确认' 也非 '未确认'")
        else:
            missing.append("harness_report.md 缺少 '可达性结论:' 行")
    # if report missing, the file check above already flagged it

    # Transcript cross-check ONLY when reachability is claimed confirmed.
    # For 未确认 (blocked), the vuln-point function not appearing in the transcript is expected.
    if reachability == "confirmed":
        trans_path = outdir / "gdb_reachability.log"
        if trans_path.is_file():
            trans = trans_path.read_text(encoding="utf-8", errors="replace")
            if opts.entry not in trans:
                missing.append(f"gdb_reachability.log 中未找到入口函数 {opts.entry}")
            if vuln_func and vuln_func not in trans:
                missing.append(f"gdb_reachability.log 中未找到漏洞点函数 {vuln_func}")
            if "backtrace" not in trans.lower() and "#0" not in trans:
                missing.append("gdb_reachability.log 中未找到 backtrace 证据")

    # Contract violations (missing files/markers/inconsistency) take precedence over blocked.
    if missing:
        return False, missing, vuln_func, False
    if reachability == "blocked":
        return False, [], vuln_func, True
    if reachability == "confirmed":
        return True, [], vuln_func, False
    # reachability == "" with no missing — shouldn't happen (absent marker is in missing); defensive:
    return False, ["harness_report.md 可达性结论状态未知"], vuln_func, False


def _extract_blocker(report_path: Path) -> str:
    """Extract the blocker explanation from a Stage-1 report that wrote '可达性结论: 未确认'.
    Grabs the 可达性结论 line + up to 6 following explanatory lines (until a blank line or a
    markdown/header boundary). Returns a compact string for terminal/logging."""
    if not report_path.is_file():
        return ""
    lines = report_path.read_text(encoding="utf-8", errors="replace").splitlines()
    for i, ln in enumerate(lines):
        if re.match(r"\s*可达性结论\s*[:：]", ln):
            block = [ln.strip()]
            for nxt in lines[i + 1:i + 7]:
                if not nxt.strip():
                    break
                if re.match(r"^\s*#{1,6}\s", nxt) or re.match(r"^\s*\*\*[^*]+\*\*\s*[:：]?", nxt):
                    break
                block.append(nxt.strip())
            return " / ".join(block)[:500]
    return ""


def post_run_check(opts) -> dict:
    """General artifact listing (used by --single and as a helper)."""
    outdir = Path(opts.output) / "output"
    info = {"output_dir": str(outdir), "exists": outdir.is_dir(), "artifacts": []}
    if outdir.is_dir():
        info["artifacts"] = sorted(p.name for p in outdir.iterdir() if p.is_file())
    return info


def post_run_check_stage2(opts) -> dict:
    """Check Stage 2 required artifacts."""
    outdir = Path(opts.output) / "output"
    present, missing = [], []
    for fn, desc in STAGE2_REQUIRED_FILES.items():
        if (outdir / fn).exists():
            present.append(fn)
        else:
            missing.append(f"{desc} ({fn})")
    return {"output_dir": str(outdir), "present": present, "missing": missing,
            "all": sorted(p.name for p in outdir.iterdir()) if outdir.is_dir() else []}


def _print_artifacts(opts) -> None:
    info = post_run_check(opts)
    print("-" * 78, flush=True)
    if info["exists"]:
        arts = info["artifacts"]
        print(f"[poc] output dir: {info['output_dir']}  ({len(arts)} files)")
        for a in arts[:30]:
            print(f"        - {a}")
        if len(arts) > 30:
            print(f"        ... ({len(arts)-30} more)")
    else:
        print(f"[poc] WARNING: output dir not created: {info['output_dir']}")


# ---------------------------------------------------------------------------
# Orchestration: --single (v1.0) and two-stage (v2.0 default).
# ---------------------------------------------------------------------------
def run_single(opts, ts) -> int:
    """v1.0 monolithic single-/goal path (one session)."""
    if not opts.entry:
        entry = _run_stage0(opts, ts)
        if entry is None:
            return 4
        opts.entry = entry
    prompt = build_single_prompt(opts.entry, opts.report, opts.bindir, opts.output)
    log_path = opts.log or str(Path(opts.workdir) / f"poc_cli_{ts}.log")
    prompt_path = str(Path(opts.workdir) / "poc_prompt.txt")
    cmd = build_claude_cmd(opts, prompt, opts.session_id, opts.session_name)

    if opts.dry_run:
        print("=== DRY RUN (--single) ===")
        print(f"workdir : {opts.workdir}")
        print(f"session : {opts.session_dir}  (CLAUDE_CONFIG_DIR; config copied on real run)")
        print(f"log     : {log_path}")
        print(f"cmd     : {_short_cmd(cmd)}")
        Path(prompt_path).write_text(prompt, encoding="utf-8")
        print(f"\n=== PROMPT (saved to {prompt_path}) ===")
        print(prompt)
        return 0

    if opts.session_dir:
        _setup_session_dir(opts)
    rc = _run_claude_to_log(opts, cmd, prompt, log_path, prompt_path, "poc", ts)
    _print_artifacts(opts)
    print(f"[poc] claude exit code: {rc}", flush=True)
    print(f"[poc] log    : {log_path}", flush=True)
    print(f"[poc] prompt : {Path(opts.workdir) / 'poc_prompt.txt'}", flush=True)
    return rc


def _run_stage0(opts, ts) -> str | None:
    """Stage 0: read the vuln report + extract the data-flow entry function.
    Returns the entry name, or None if the report mentions no entry function (refuse)."""
    s0_sid = str(uuid.uuid4())
    s0_name = f"{opts.session_name or 'poc'}-stage0"
    s0_prompt = build_stage0_prompt(opts.report, opts.output)
    s0_log = str(Path(opts.workdir) / f"poc_cli_{ts}_stage0.log")
    s0_prompt_path = str(Path(opts.workdir) / "poc_prompt_stage0.txt")
    s0_cmd = build_claude_cmd(opts, s0_prompt, s0_sid, s0_name)
    Path(opts.output).joinpath("output").mkdir(parents=True, exist_ok=True)
    print("[poc] === Stage 0: extract data-flow entry function from the vuln report ===", flush=True)
    rc0 = _run_claude_to_log(opts, s0_cmd, s0_prompt, s0_log, s0_prompt_path, "poc:stage0", ts)
    print(f"[poc:stage0] claude exit code: {rc0}", flush=True)
    report_path = Path(opts.output) / "output" / "stage0_report.md"
    entry = ""
    if report_path.is_file():
        txt = report_path.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"入口函数\s*[:：]\s*([A-Za-z0-9_]+)", txt)
        if m:
            entry = m.group(1).strip()
    if not entry:
        print("[poc:stage0] *** 漏洞报告未提及任何入口函数，拒绝执行 ***", flush=True)
        print(f"[poc:stage0] stage0 log   : {s0_log}", flush=True)
        print(f"[poc:stage0] stage0 report : {report_path}", flush=True)
        return None
    print(f"[poc:stage0] extracted entry function: {entry}", flush=True)
    return entry


def run_two_stage(opts, ts) -> int:
    """v2.0 two-stage/two-session path."""
    s1_sid = opts.session_id or str(uuid.uuid4())
    s2_sid = str(uuid.uuid4())
    base_name = opts.session_name or "poc"
    s1_name = f"{base_name}-stage1"
    s2_name = f"{base_name}-stage2"

    # --- Stage 0: derive the entry function from the report (if not given; skip in dry-run) ---
    if not opts.entry and not opts.dry_run:
        entry = _run_stage0(opts, ts)
        if entry is None:
            return 4
        opts.entry = entry

    s1_prompt = build_stage1_prompt(opts.entry, opts.report, opts.bindir, opts.output)
    s2_prompt = build_stage2_prompt(opts.entry, opts.report, opts.bindir, opts.output)
    s1_log = str(Path(opts.workdir) / f"poc_cli_{ts}_stage1.log")
    s2_log = str(Path(opts.workdir) / f"poc_cli_{ts}_stage2.log")
    s1_prompt_path = str(Path(opts.workdir) / "poc_prompt_stage1.txt")
    s2_prompt_path = str(Path(opts.workdir) / "poc_prompt_stage2.txt")
    s1_cmd = build_claude_cmd(opts, s1_prompt, s1_sid, s1_name)
    s2_cmd = build_claude_cmd(opts, s2_prompt, s2_sid, s2_name)

    if opts.dry_run:
        return _dry_run_two_stage(opts, s1_prompt, s2_prompt, s1_cmd, s2_cmd,
                                  s1_sid, s2_sid, s1_name, s2_name,
                                  s1_log, s2_log, s1_prompt_path, s2_prompt_path)

    if opts.session_dir:
        _setup_session_dir(opts)

    # --- Stage 1 (skip if --stage2-only) ---
    if not opts.stage2_only:
        print(f"[poc] === Stage 1: harness + benign reachability driver + gdb reachability proof ===",
              flush=True)
        rc1 = _run_claude_to_log(opts, s1_cmd, s1_prompt, s1_log, s1_prompt_path, "poc:stage1", ts)
        print(f"[poc:stage1] claude exit code: {rc1}", flush=True)

    # --- Gate (always run; --stage2-only gates on pre-existing artifacts) ---
    print(f"[poc:gate] checking Stage 1 artifacts (deterministic, CLI-side)...", flush=True)
    passed, missing, vuln_func, blocked = gate_stage1(opts)
    out_dir = Path(opts.output) / "output"
    if blocked:
        print(f"[poc:gate] *** Stage 1 reachability BLOCKED (honest negative: 可达性结论=未确认) ***",
              flush=True)
        blocker = _extract_blocker(out_dir / "harness_report.md")
        if blocker:
            print(f"[poc:gate] blocker: {blocker}", flush=True)
        print(f"[poc:gate] Not proceeding to Stage 2 — no proven entry→vuln-point reachability.",
              flush=True)
        print(f"[poc:gate] This is a legitimate Stage-1 negative result (the reachability analog of Path B),",
              flush=True)
        print(f"[poc:gate] not a contract violation. Retry Stage 1 (new strategy) or inspect the report/transcript.",
              flush=True)
        print(f"[poc:gate] Stage 1 log: {s1_log}", flush=True)
        print(f"[poc:gate] report    : {out_dir / 'harness_report.md'}", flush=True)
        print(f"[poc:gate] transcript: {out_dir / 'gdb_reachability.log'}", flush=True)
        return 3
    if not passed:
        print(f"[poc:gate] *** Stage 1 gate FAILED (contract violation) ***", flush=True)
        for m in missing:
            print(f"[poc:gate]   missing/failed: {m}", flush=True)
        print(f"[poc:gate] Not proceeding to Stage 2.", flush=True)
        print(f"[poc:gate] Stage 1 log: {s1_log}", flush=True)
        print(f"[poc:gate] output   : {out_dir}", flush=True)
        print(f"[poc:gate] Fix Stage 1 (or re-run with --stage1-only) before retrying Stage 2.", flush=True)
        return 2
    print(f"[poc:gate] Stage 1 gate PASSED (vuln_func={vuln_func}).", flush=True)

    if opts.stage1_only:
        print(f"[poc] --stage1-only: stopping after Stage 1 (gate passed).", flush=True)
        _print_artifacts(opts)
        print(f"[poc] stage1 log: {s1_log}", flush=True)
        return 0

    # --- Stage 2 (fresh session) ---
    print(f"[poc] === Stage 2: malicious PoC + loop-debug-trigger (fresh session) ===", flush=True)
    rc2 = _run_claude_to_log(opts, s2_cmd, s2_prompt, s2_log, s2_prompt_path, "poc:stage2", ts)
    print(f"[poc:stage2] claude exit code: {rc2}", flush=True)

    s2 = post_run_check_stage2(opts)
    print("-" * 78, flush=True)
    print(f"[poc:stage2] present: {s2['present']}", flush=True)
    if s2["missing"]:
        print(f"[poc:stage2] missing: {s2['missing']}", flush=True)
    print(f"[poc] stage1 log: {s1_log}", flush=True)
    print(f"[poc] stage2 log: {s2_log}", flush=True)
    print(f"[poc] output    : {Path(opts.output) / 'output'}", flush=True)
    return rc2


def _dry_run_two_stage(opts, s1_prompt, s2_prompt, s1_cmd, s2_cmd,
                       s1_sid, s2_sid, s1_name, s2_name,
                       s1_log, s2_log, s1_prompt_path, s2_prompt_path) -> int:
    Path(s1_prompt_path).write_text(s1_prompt, encoding="utf-8")
    Path(s2_prompt_path).write_text(s2_prompt, encoding="utf-8")
    print("=== DRY RUN (two-stage, v2.0) ===")
    print(f"workdir     : {opts.workdir}")
    print(f"session-dir : {opts.session_dir}  (CLAUDE_CONFIG_DIR; both stages share it)")
    print()
    print(f"--- Stage 1 (session-id {s1_sid}, name '{s1_name}') ---")
    print(f"  log    : {s1_log}")
    print(f"  prompt : {s1_prompt_path}  ({len(s1_prompt)} chars)")
    print(f"  cmd    : {_short_cmd(s1_cmd)}")
    print()
    print("--- Gate (deterministic, CLI-side, between stages) ---")
    print(f"  required files in {Path(opts.output) / 'output'}: {list(STAGE1_REQUIRED_FILES.keys())}")
    print("  report must contain: '漏洞点函数: <name>' + '可达性结论: 已确认|未确认'")
    print(f"  gdb_reachability.log must mention entry '{opts.entry}' and the reported vuln-point func")
    print("  three outcomes: 已确认→pass(→Stage2, exit 0) | 未确认→blocked(exit 3, print blocker) |")
    print("                   contract violation/missing→fail(exit 2, no Stage 2)")
    print()
    print(f"--- Stage 2 (FRESH session-id {s2_sid}, name '{s2_name}') ---")
    print(f"  log    : {s2_log}")
    print(f"  prompt : {s2_prompt_path}  ({len(s2_prompt)} chars)")
    print(f"  cmd    : {_short_cmd(s2_cmd)}")
    print()
    if opts.stage1_only:
        print("(--stage1-only: would stop after Stage 1 + gate)")
    if opts.stage2_only:
        print("(--stage2-only: would skip Stage 1, gate on existing artifacts, then run Stage 2)")
    print("\n=== STAGE 1 PROMPT ===")
    print(s1_prompt)
    print("\n=== STAGE 2 PROMPT ===")
    print(s2_prompt)
    return 0


def main(argv=None) -> int:
    opts = parse_args(argv)
    validate(opts)
    ts = time.strftime("%Y%m%d_%H%M%S")
    if opts.single:
        return run_single(opts, ts)
    return run_two_stage(opts, ts)


if __name__ == "__main__":
    sys.exit(main())
