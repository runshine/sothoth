"""
评审研判核心引擎

流程:
  Phase 1 (Reviewer Agent): 独立客观审查漏洞报告 → 结构化评审意见
    使用 pi --mode rpc，启动长驻进程，通过 stdin/stdout JSONL 通信
    新会话，可 read 漏洞报告和源码
  Phase 2 (Worker Agent):  复用原会话，接收评审反馈 → 二次判定 → 最终研判结果
    复用原始 pi --mode rpc 长驻进程的会话目录
    通过 --continue 在新进程中继续已有会话
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from app.review_judge.models import (
    JudgmentResult,
    ReviewOpinion,
)
from app.review_judge.config import get_config

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# ── RPC 常量 ─────────────────────────────────────────────────
_DEFAULT_HEARTBEAT_SECONDS = 30.0
_DEFAULT_MAX_STDOUT_BYTES = 64 * 1024 * 1024
_DEFAULT_MAX_STDERR_BYTES = 8 * 1024 * 1024
_DEFAULT_MAX_SINGLE_LINE_BYTES = 8 * 1024 * 1024
_DEFAULT_NO_PROGRESS_TIMEOUT = 600.0


# ── Prompt helpers ───────────────────────────────────────────

def _load_prompt(name: str, prompts_dir: str | Path) -> str:
    path = Path(prompts_dir) / name
    if not path.is_file():
        path = PROJECT_ROOT / "prompts" / "review_judge" / name
    if path.is_file():
        return path.read_text(encoding="utf-8")
    raise FileNotFoundError(f"Prompt file not found: {path}")


def _build_reviewer_system_prompt() -> str:
    """加载评审 Agent 的 system prompt（静态，不含动态占位符）"""
    return _load_prompt("reviewer_system.md", PROJECT_ROOT / "prompts" / "review_judge")


def _build_reviewer_user_prompt(vuln_report_path: str, dataflow_report_path: str, source_dir: str) -> str:
    """Reviewer Agent 的 user prompt

    从 reviewer_user.md 加载模板，填入动态路径。
    漏洞报告全文不内联——Reviewer 通过 read 工具自行读取。
    """
    template = _load_prompt("reviewer_user.md", PROJECT_ROOT / "prompts" / "review_judge")
    return template.format(
        vuln_report_path=vuln_report_path,
        dataflow_report_path=dataflow_report_path,
        source_dir=source_dir,
    )


def _build_worker_reassessment_prompt(review_opinion: ReviewOpinion) -> str:
    """Worker Agent 二次判定的 user prompt

    从 worker_reassessment_user.md 加载模板，填入评审反馈。
    Worker 通过 --continue 复用原始会话的完整上下文，
    不使用新的 system prompt。
    """
    template = _load_prompt("worker_reassessment_user.md", PROJECT_ROOT / "prompts" / "review_judge")

    # 构建任务点
    points = []
    if review_opinion.verdict == "confirmed":
        points.append("评审 Agent **确认了漏洞的真实性**。你需要基于原始分析上下文复核评审意见的正确性。")
        if review_opinion.evidence_gaps:
            points.append(f"评审发现了以下证据缺口，请尝试补充：\n" + "\n".join(f"  - {g}" for g in review_opinion.evidence_gaps))
    elif review_opinion.verdict == "suspicious":
        points.append("评审 Agent 认为该漏洞**疑似但不确信**。请基于你的原始分析经验，判断评审意见中提到的疑点是否成立。")
    elif review_opinion.verdict == "false_positive":
        points.append("评审 Agent 判定该漏洞为**误报**。请核实评审依据，如果认为评审有误，请提供反驳证据。")
    else:
        points.append("评审 Agent **无法做出明确判定**。请基于你的原始分析经验，尝试给出更明确的结论。")

    return template.format(
        verdict=review_opinion.verdict,
        verdict_rationale=review_opinion.verdict_rationale,
        reachability="可达" if review_opinion.reachable else "不可达或不确定",
        reachability_analysis=review_opinion.reachability_analysis,
        confidence=review_opinion.confidence,
        confidence_rationale=review_opinion.confidence_rationale,
        severity=review_opinion.severity,
        severity_justification=review_opinion.severity_justification,
        evidence_quality=review_opinion.evidence_quality,
        evidence_gaps="\n".join(f"  - {g}" for g in review_opinion.evidence_gaps) if review_opinion.evidence_gaps else "无",
        suggestions="\n".join(f"  - {s}" for s in review_opinion.suggestions) if review_opinion.suggestions else "无",
        additional_checks="\n".join(f"  - {c}" for c in review_opinion.additional_checks) if review_opinion.additional_checks else "无",
        task_points="\n".join(f"- {p}" for p in points),
    )


# ── RPC pi-agent invocation ──────────────────────────────────

async def _start_rpc_process(
    *,
    model: str,
    thinking: str,
    tools: str,
    working_dir: str,
    session_dir: str,
    label: str,
    continue_session: bool = False,
    append_system_prompt: str | None = None,
) -> asyncio.subprocess.Process:
    """启动 pi --mode rpc 长驻进程

    返回 asyncio.subprocess.Process 对象。
    进程保持运行，后续通过 stdin JSONL 发送 prompt，stdout JSONL 读取响应。
    """
    cmd = [
        "pi",
        "--mode", "rpc",
        "--model", model,
        "--thinking", thinking,
        "--session-dir", str(session_dir),
        "--tools", tools,
    ]
    if continue_session:
        cmd.append("--continue")
    if append_system_prompt:
        cmd.extend(["--append-system-prompt", append_system_prompt])

    print(f"  [{label}] rpc spawn: pi --mode rpc --model {model}")
    print(f"  [{label}]         session={Path(session_dir).name} {'--continue' if continue_session else '(new)'}")

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=working_dir,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    return proc


async def _rpc_send(proc: asyncio.subprocess.Process, command: dict[str, Any]) -> None:
    """向 RPC 进程发送 JSONL 命令"""
    if proc.stdin is None:
        raise RuntimeError("RPC stdin unavailable")
    line = json.dumps(command, ensure_ascii=False) + "\n"
    proc.stdin.write(line.encode("utf-8"))
    await proc.stdin.drain()


async def _rpc_read_line(proc: asyncio.subprocess.Process, max_bytes: int = _DEFAULT_MAX_SINGLE_LINE_BYTES) -> str | None:
    """从 RPC 进程 stdout 读取一行 JSONL"""
    if proc.stdout is None:
        return None
    buf = b""
    while True:
        chunk = await proc.stdout.read(65536)
        if not chunk:
            return buf.decode("utf-8", errors="replace").rstrip() if buf else None
        buf += chunk
        if b"\n" in buf:
            idx = buf.index(b"\n")
            line = buf[:idx].decode("utf-8", errors="replace").rstrip("\r")
            return line
        if len(buf) > max_bytes:
            raise RuntimeError(f"Single-line stdout limit exceeded: {len(buf)}>{max_bytes}")


async def _rpc_send_prompt(
    proc: asyncio.subprocess.Process,
    prompt_text: str,
    trace_dir: str,
    call_id: str,
    label: str,
    timeout_seconds: float = 3600.0,
) -> str:
    """通过 RPC 发送 prompt 并等待 agent_end 响应

    返回 assistant 最终文本内容。
    """
    trace_path = Path(trace_dir)
    trace_path.mkdir(parents=True, exist_ok=True)

    # Save trace
    (trace_path / f"request_{call_id}.json").write_text(
        json.dumps({"prompt": prompt_text}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # Send prompt command via RPC
    prompt_cmd = {
        "type": "prompt",
        "id": call_id,
        "message": prompt_text,
    }
    await _rpc_send(proc, prompt_cmd)

    # Read events until agent_end
    started = time.monotonic()
    events: list[dict] = []
    assistant_texts: list[str] = []
    all_stdout_lines: list[str] = []
    final_error: str | None = None

    print(f"  [{label}] prompt sent, waiting for response...")

    while True:
        elapsed = time.monotonic() - started
        if elapsed > timeout_seconds:
            print(f"  [{label}] TIMEOUT after {elapsed:.0f}s")
            final_error = f"timeout after {timeout_seconds}s"
            break

        line = await _rpc_read_line(proc)
        if line is None:
            print(f"  [{label}] EOF from pi process")
            break

        all_stdout_lines.append(line)

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        events.append(event)
        event_type = event.get("type", "")

        # Collect assistant text
        if event_type == "message" and event.get("message", {}).get("role") == "assistant":
            content = event.get("message", {}).get("content", [])
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    t = block.get("text", "")
                    if t.strip():
                        assistant_texts.append(t)

        # Check for errors
        if event_type in ("message_end", "agent_end"):
            stop_reason = event.get("message", {}).get("stopReason") or event.get("stopReason", "")
            error_msg = event.get("errorMessage") or event.get("message", {}).get("errorMessage", "")
            if stop_reason == "error" or error_msg:
                final_error = error_msg or f"stop_reason=error"
            if event_type == "agent_end":
                break

        if event_type == "turn_end":
            stop_reason = event.get("message", {}).get("stopReason", "")
            error_msg = event.get("message", {}).get("errorMessage", "")
            if error_msg:
                final_error = error_msg

        # Periodic status
        if len(events) % 20 == 0:
            print(f"  [{label}] received {len(events)} events, {elapsed:.0f}s elapsed")

    # Save full trace
    (trace_path / f"events_{call_id}.jsonl").write_text(
        "\n".join(all_stdout_lines), encoding="utf-8",
    )

    if final_error:
        print(f"  [{label}] ERROR: {final_error[:200]}")

    full_text = "\n".join(assistant_texts)
    print(f"  [{label}] response: {len(full_text)} chars, {len(events)} events, {time.monotonic()-started:.0f}s")

    return full_text


async def _stop_rpc_process(proc: asyncio.subprocess.Process, label: str) -> None:
    """优雅停止 RPC 进程"""
    try:
        if proc.returncode is None:
            await _rpc_send(proc, {"type": "exit"})
            try:
                await asyncio.wait_for(proc.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                proc.terminate()
                await proc.wait()
    except Exception:
        if proc.returncode is None:
            proc.kill()
    print(f"  [{label}] rpc process stopped")


# ── Response parsing ─────────────────────────────────────────

def _extract_json_from_text(text: str) -> dict | None:
    m = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    return None


def _parse_review_opinion(text: str) -> ReviewOpinion:
    data = _extract_json_from_text(text) or {}
    return ReviewOpinion(
        verdict=data.get("verdict", "inconclusive"),
        verdict_rationale=data.get("verdict_rationale", text[:500]),
        reachable=bool(data.get("reachable", False)),
        reachability_analysis=data.get("reachability_analysis", ""),
        confidence=data.get("confidence", "low"),
        confidence_rationale=data.get("confidence_rationale", ""),
        severity=data.get("severity", "info"),
        severity_justification=data.get("severity_justification", ""),
        evidence_quality=data.get("evidence_quality", ""),
        evidence_gaps=data.get("evidence_gaps", []),
        suggestions=data.get("suggestions", []),
        additional_checks=data.get("additional_checks", []),
        raw_output=text,
    )


def _parse_judgment_result(
    review_opinion: ReviewOpinion,
    worker_output: str,
    run_name: str,
    work_dir: str,
    started_at: str,
) -> JudgmentResult:
    data = _extract_json_from_text(worker_output) or {}
    return JudgmentResult(
        verdict=data.get("final_verdict", review_opinion.verdict),
        severity=data.get("final_severity", review_opinion.severity),
        confidence=data.get("final_confidence", review_opinion.confidence),
        review_opinion=review_opinion,
        worker_reassessment=data.get("reassessment", ""),
        points_of_agreement=data.get("points_of_agreement", []),
        points_of_disagreement=data.get("points_of_disagreement", []),
        final_summary=data.get("final_summary", ""),
        recommended_actions=data.get("recommended_actions", []),
        run_name=run_name,
        work_dir=work_dir,
        started_at=started_at,
        finished_at=datetime.utcnow().isoformat(),
        raw_worker_output=worker_output,
    )


# ── Main runner ──────────────────────────────────────────────

async def run_review_judgment(
    *,
    work_dir: str,
    session_dir: str,
    vuln_report_path: str,
    dataflow_report_path: str,
    run_name: str,
    model: str = "anthropic/claude-opus-4-5",
    thinking: str = "high",
    keep_workspace: bool = False,
) -> JudgmentResult:
    """执行完整的评审研判流程

    Phase 1: Reviewer Agent — 新会话 (pi --mode rpc)，独立评审
    Phase 2: Worker Agent — 复用原始会话 (pi --mode rpc --continue)，二次判定

    Args:
        work_dir: 工作目录（也是源码目录）
        session_dir: 原始 Worker 会话目录（含已有发现上下文）
        vuln_report_path: 漏洞报告文件路径
        dataflow_report_path: 数据流报告文件路径
        run_name: 运行名称
        model: 模型名称
        thinking: thinking level
        keep_workspace: 是否保留工作目录
    """
    started_at = datetime.utcnow().isoformat()
    config = get_config()

    vuln_report_path_abs = str(Path(vuln_report_path).resolve())
    dataflow_report_path_abs = str(Path(dataflow_report_path).resolve())
    work_dir_abs = str(Path(work_dir).resolve())

    # source_dir 与 work_dir 等价
    source_dir = work_dir_abs

    # Phase 1: Reviewer Agent — 新 RPC 进程，独立会话
    print("=" * 60)
    print("  Phase 1: Reviewer Agent — 独立评审 (新 RPC 会话)")
    print("=" * 60)

    # 构建 prompt
    reviewer_system = _build_reviewer_system_prompt()
    reviewer_user = _build_reviewer_user_prompt(
        vuln_report_path=vuln_report_path_abs,
        dataflow_report_path=dataflow_report_path_abs,
        source_dir=source_dir,
    )

    # 写 system prompt 到文件
    rj_prompts_dir = Path(work_dir) / ".rj_prompts"
    rj_prompts_dir.mkdir(parents=True, exist_ok=True)
    reviewer_sys_file = rj_prompts_dir / "reviewer_system.md"
    reviewer_sys_file.write_text(reviewer_system, encoding="utf-8")

    reviewer_session = str(Path(work_dir) / "sessions" / "reviewer")
    reviewer_trace = str(Path(work_dir) / ".trace" / "reviewer")

    # 启动 RPC 进程
    reviewer_proc = await _start_rpc_process(
        model=config.reviewer.model or model,
        thinking=config.reviewer.thinking or thinking,
        tools=config.reviewer.tools or "read,bash",
        working_dir=work_dir_abs,
        session_dir=reviewer_session,
        label="reviewer",
        continue_session=False,
        append_system_prompt=str(reviewer_sys_file),
    )

    try:
        reviewer_output = await _rpc_send_prompt(
            proc=reviewer_proc,
            prompt_text=reviewer_user,
            trace_dir=reviewer_trace,
            call_id="review_001",
            label="reviewer",
            timeout_seconds=float(config.reviewer.timeout_seconds),
        )
    finally:
        await _stop_rpc_process(reviewer_proc, "reviewer")

    review_opinion = _parse_review_opinion(reviewer_output)

    print(f"\n  [Reviewer Opinion]")
    print(f"    判定:     {review_opinion.verdict}")
    print(f"    可达:     {review_opinion.reachable}")
    print(f"    置信度:   {review_opinion.confidence}")
    print(f"    严重程度: {review_opinion.severity}")

    opinion_path = Path(work_dir) / "reviews" / "reviewer_opinion.json"
    opinion_path.parent.mkdir(parents=True, exist_ok=True)
    opinion_path.write_text(
        json.dumps(review_opinion.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"    已保存:   {opinion_path}")

    # Phase 2: Worker Agent — 新 RPC 进程，--continue 复用原始会话
    print(f"\n{'='*60}")
    print(f"  Phase 2: Worker Agent — 二次判定 (--continue 复用原始会话)")
    print(f"{'='*60}")

    worker_user = _build_worker_reassessment_prompt(review_opinion)
    worker_trace = str(Path(work_dir) / ".trace" / "worker")

    # 启动新 RPC 进程 --continue 复用原始会话
    worker_proc = await _start_rpc_process(
        model=config.worker.model or model,
        thinking=config.worker.thinking or thinking,
        tools=config.worker.tools or "read,bash,edit,write",
        working_dir=work_dir_abs,
        session_dir=session_dir,  # 复用原始会话！
        label="worker",
        continue_session=True,
        append_system_prompt=None,  # 不传新的 system prompt
    )

    try:
        worker_output = await _rpc_send_prompt(
            proc=worker_proc,
            prompt_text=worker_user,
            trace_dir=worker_trace,
            call_id="worker_001",
            label="worker",
            timeout_seconds=float(config.worker.timeout_seconds),
        )
    finally:
        await _stop_rpc_process(worker_proc, "worker")

    result = _parse_judgment_result(
        review_opinion=review_opinion,
        worker_output=worker_output,
        run_name=run_name,
        work_dir=work_dir,
        started_at=started_at,
    )

    print(f"\n  [Final Judgment]")
    print(f"    最终判定:     {result.verdict}")
    print(f"    最终严重程度: {result.severity}")
    print(f"    最终置信度:   {result.confidence}")

    judgment_path = Path(work_dir) / "judgments" / "final_judgment.json"
    judgment_path.parent.mkdir(parents=True, exist_ok=True)
    judgment_path.write_text(
        json.dumps(result.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"    已保存:       {judgment_path}")

    return result