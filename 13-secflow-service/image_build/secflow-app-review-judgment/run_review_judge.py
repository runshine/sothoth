#!/usr/bin/env python3
"""
评审研判便捷启动器

用法:
  cd <work_dir>   # 工作目录也是源码目录
  python ../run_review_judge.py \\
    --session-dir ./session/worker-vuln-scan \\
    --vuln-report ./results/result_001.md \\
    [--run-name my_review] \\
    [--model anthropic/claude-opus-4-5] \\
    [--keep-workspace]

功能:
  1. 使用 pi --mode rpc 启动长驻进程，通过 stdin/stdout JSONL 通信
  2. Phase 1: Reviewer Agent — 新 RPC 会话，独立客观审查漏洞报告
     system prompt 动态填入漏洞报告路径和源码/工作目录路径
  3. Phase 2: Worker Agent — 新 RPC 进程，--continue 复用原始会话
     不传新 system prompt，只发送评审反馈作为 user message
  4. Worker 基于原始上下文做最终研判
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path

from app.review_judge.runner import run_review_judgment

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_MODEL = "anthropic/claude-opus-4-5"


def _read_vuln_report(report_path: str | Path) -> str:
    report_path = Path(report_path)
    if not report_path.is_file():
        raise FileNotFoundError(f"漏洞报告文件不存在: {report_path}")
    return report_path.read_text(encoding="utf-8", errors="replace")


async def _async_main(args: argparse.Namespace) -> int:
    work_dir = Path(args.work_dir).resolve()
    session_dir = Path(args.session_dir).resolve()
    vuln_report_path = Path(args.vuln_report).resolve()
    dataflow_report_path = Path(args.dataflow_report).resolve()
    run_name = args.run_name or f"review_{uuid.uuid4().hex[:8]}"
    model = args.model or DEFAULT_MODEL

    # source_dir == work_dir (生产环境中源码位于工作目录内)
    # vuln_report 也在 work_dir 下

    # Validate
    if not vuln_report_path.is_file():
        print(f"[ERROR] 漏洞报告不存在: {vuln_report_path}")
        return 1
    if not dataflow_report_path.is_file():
        print(f"[ERROR] 数据流报告不存在: {dataflow_report_path}")
        return 1
    if not session_dir.is_dir():
        print(f"[ERROR] 会话目录不存在: {session_dir}")
        return 1

    # Prepare work directory
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / "reviews").mkdir(exist_ok=True)
    (work_dir / "judgments").mkdir(exist_ok=True)
    (work_dir / "output").mkdir(exist_ok=True)

    vuln_report_content = _read_vuln_report(vuln_report_path)

    print(f"\n{'='*60}")
    print(f"  评审研判任务")
    print(f"{'='*60}")
    print(f"  运行名称:     {run_name}")
    print(f"  工作/源码目录: {work_dir}")
    print(f"  原始会话:     {session_dir}")
    print(f"  漏洞报告:     {vuln_report_path}")
    print(f"  数据流报告:   {dataflow_report_path}")
    print(f"  报告大小:     {len(vuln_report_content)} 字符")
    print(f"  模型:         {model}")
    print(f"  thinking:     {args.thinking}")
    print(f"{'='*60}\n")

    try:
        result = await run_review_judgment(
            work_dir=str(work_dir),
            session_dir=str(session_dir),
            vuln_report_path=str(vuln_report_path),
            dataflow_report_path=str(dataflow_report_path),
            run_name=run_name,
            model=model,
            thinking=args.thinking,
        )

        output_path = work_dir / "output" / "judgment_result.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(result.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        print(f"\n{'='*60}")
        print(f"  评审研判完成")
        print(f"{'='*60}")
        print(f"  判定结果:     {result.verdict}")
        print(f"  严重程度:     {result.severity}")
        print(f"  置信度:       {result.confidence}")
        print(f"  一致观点:     {len(result.points_of_agreement)} 项")
        print(f"  分歧观点:     {len(result.points_of_disagreement)} 项")
        print(f"  输出文件:     {output_path}")
        print(f"{'='*60}\n")

        return 0

    except Exception as exc:
        print(f"\n[ERROR] 评审研判失败: {exc}\n")
        import traceback
        traceback.print_exc()
        return 1


def cli_entry() -> None:
    parser = argparse.ArgumentParser(
        description="评审研判 — 双 Agent RPC 协同评审判定",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  cd /path/to/work_dir

  # 完整评审
  python ../run_review_judge.py \\
    --session-dir ./session/worker-vuln-scan \\
    --vuln-report ./results/result_001.md \\
    --model anthropic/claude-opus-4-5 \\
    --keep-workspace

  # 不指定 work-dir 则默认为当前目录
  python ../run_review_judge.py \\
    --work-dir . \\
    --session-dir ./session/worker-vuln-scan \\
    --vuln-report ./results/result_001.md
""")

    parser.add_argument(
        "--work-dir", "-w",
        default=".",
        help="工作目录路径（也是源码目录，默认为当前目录）")

    parser.add_argument(
        "--session-dir", "-s",
        required=True,
        help="原始漏洞发现的 pi 会话目录（Worker Agent 将 --continue 复用此会话）")

    parser.add_argument(
        "--vuln-report", "-r",
        required=True,
        help="待评审的漏洞报告文件路径")

    parser.add_argument(
        "--dataflow-report", "-d",
        required=True,
        help="数据流报告文件路径（供 Reviewer 验证数据流路径）")

    parser.add_argument(
        "--run-name", "-n",
        default=None,
        help="运行名称（默认自动生成）")

    parser.add_argument(
        "--model", "-m",
        default=DEFAULT_MODEL,
        help=f"使用的模型 (默认: {DEFAULT_MODEL})")

    parser.add_argument(
        "--thinking",
        default="high",
        choices=["low", "medium", "high"],
        help="thinking level (默认: high)")

    parser.add_argument(
        "--keep-workspace",
        action="store_true",
        default=False,
        help="保留 work_dir 中的 trace 和中间产物（调试模式）")

    args = parser.parse_args()
    exit_code = asyncio.run(_async_main(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    cli_entry()