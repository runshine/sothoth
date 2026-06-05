#!/usr/bin/env python3
"""
Dataflow Vuln Scanner Evolver - 交互式 CLI

用法:
  python cli.py --project-id <id> --case-ids <id1,id2,...>
  python cli.py --resume <session_dir>
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from core.preprocess import Preprocessor, PreprocessError, SourceTask
from core.replay import ReplayManager, ReplayResult
from core.workspace import Workspace

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("evolver")

DOC_SPECS: tuple[dict[str, str], ...] = (
    {
        "key": "pi-worker/evolution-strategy.md",
        "agent_id": "pi-worker",
        "path": "evolution-strategy.md",
        "role_name": "worker",
        "title": "漏洞挖掘执行策略",
        "purpose": "指导 worker 在本轮 replay 中怎样沿着已有任务背景和已有漏洞结果继续挖掘。",
        "focus": "写清本轮优先追哪些数据流、哪些函数族、哪些危险操作,以及遇到什么情况应该补证据或扩路径。",
    },
    {
        "key": "pi-advisor/evolution-completeness-review.md",
        "agent_id": "pi-advisor",
        "path": "evolution-completeness-review.md",
        "role_name": "global_completeness",
        "title": "全面性评审策略",
        "purpose": "指导 advisor 从覆盖面角度审 worker。",
        "focus": "重点看是否遗漏分支、遗漏同类 sink、遗漏跨函数传播、遗漏与已出结果相邻的可疑路径。",
    },
    {
        "key": "pi-advisor/evolution-depth-review.md",
        "agent_id": "pi-advisor",
        "path": "evolution-depth-review.md",
        "role_name": "global_depth",
        "title": "深入性评审策略",
        "purpose": "指导 advisor 从论证深度和漏洞机理角度审 worker。",
        "focus": "重点看数据流是否真正闭环、边界条件是否说透、清洗/约束是否被核实、可利用性证据是否扎实。",
    },
    {
        "key": "pi-advisor/evolution-result-review.md",
        "agent_id": "pi-advisor",
        "path": "evolution-result-review.md",
        "role_name": "result_fp_check",
        "title": "结果评审策略",
        "purpose": "指导 advisor 对新结果做误报与证据质量检查。",
        "focus": "重点看 result 是否只是理论风险、路径是否可达、前置约束是否真实存在,以及证据不足时该如何要求补充。",
    },
)


# ─── 配置加载 ───────────────────────────────────────────────────────────────

def load_config(config_path: str = "config.yaml") -> dict[str, Any]:
    candidates = [
        config_path,
        Path(__file__).parent / "config.yaml",
    ]
    for path in candidates:
        p = Path(path)
        if p.exists():
            with open(p, encoding="utf-8") as f:
                return yaml.safe_load(f)
    print("[ERROR] 找不到 config.yaml")
    sys.exit(1)


# ─── 终端输出工具 ────────────────────────────────────────────────────────────

def print_header(text: str) -> None:
    print(f"\n{'═' * 60}")
    print(f"  {text}")
    print(f"{'═' * 60}\n")


def print_section(text: str) -> None:
    print(f"\n── {text} {'─' * max(0, 50 - len(text))}\n")


def print_task_list(source_tasks: list[SourceTask]) -> None:
    for i, task in enumerate(source_tasks, 1):
        agents = ", ".join(task.agent_state_dirs.keys()) or "(无 agent 信息)"
        print(f"  {i}. {task.title}")
        print(f"     task_id: {task.task_id}")
        print(f"     cases: {len(task.case_ids)} 个")
        print(f"     agents: {agents}")
        print()


def print_replay_results(results: list[ReplayResult], source_tasks: list[SourceTask]) -> None:
    """展示 replay 结果摘要。"""
    total_expected = sum(len(t.case_ids) for t in source_tasks)
    total_found = sum(r.results_summary.get("result_count", 0) for r in results)
    succeeded = [r for r in results if r.status in ("completed", "succeeded")]
    failed = [r for r in results if r.status not in ("completed", "succeeded")]

    print_section("Replay 结果")

    for r in results:
        status_icon = "✓" if r.status in ("completed", "succeeded") else "✗"
        duration = f"{r.duration_seconds:.1f}s" if r.duration_seconds else "-"
        result_count = r.results_summary.get("result_count", "?")
        print(f"  {status_icon} {r.source_task_id}")
        print(f"    派生任务: {r.derived_task_id}")
        print(f"    状态: {r.status} ({duration})")
        print(f"    发现结果数: {result_count}")
        if r.error:
            print(f"    错误: {r.error}")
        print()

    print_section("综合统计")
    print(f"  任务总数: {len(results)}")
    print(f"  成功: {len(succeeded)}")
    print(f"  失败: {len(failed)}")
    print(f"  原始案例总数: {total_expected}")
    print(f"  本轮发现结果数: {total_found}")
    if total_expected > 0:
        coverage = total_found / total_expected * 100
        print(f"  覆盖率: {coverage:.1f}%")


def print_agent_docs(workspace: Workspace) -> None:
    """展示当前 agent 目录中的 MD 文档。"""
    print_section("当前 Agent 文档")
    for agent_dir in sorted(workspace.agents_dir.iterdir()):
        if not agent_dir.is_dir():
            continue
        print(f"  [{agent_dir.name}]")
        for subdir_name in ("skills", "memory"):
            subdir = agent_dir / subdir_name
            if not subdir.is_dir():
                continue
            md_files = sorted(subdir.glob("*.md"))
            if md_files:
                for md_file in md_files:
                    size = md_file.stat().st_size
                    print(f"    {subdir_name}/{md_file.name} ({size} bytes)")
        print()


def progress_callback(task_id: str, status: str, message: str) -> None:
    """Replay 进度回调。"""
    icon = "⟳" if status not in ("completed", "succeeded", "failed", "error") else "●"
    print(f"  {icon} [{task_id[:12]}...] {message}", flush=True)


# ─── 交互式 Agent 会话 ──────────────────────────────────────────────────────

def interactive_generate_docs(
    workspace: Workspace,
    evolution_goal: str,
    round_no: int,
    previous_results: list[ReplayResult] | None = None,
    adjustment_direction: str = "",
) -> None:
    """
    交互式生成/修改 agent 文档。

    按 4 个逻辑角色分别生成:
      - pi-worker: 工作者(实际执行漏洞挖掘)
      - pi-advisor (global_completeness): 全面性评审
      - pi-advisor (global_depth): 深入性评审
      - pi-advisor (result_fp_check): 结果评审(误报检测)
    """
    agent_ids = [d.name for d in workspace.agents_dir.iterdir() if d.is_dir()]

    if round_no == 1:
        print_section(f"Round {round_no}: 生成初始进化文档")
        print(f"  进化目标: {evolution_goal}")
        print(f"  目标 agents: {', '.join(agent_ids)}")
    else:
        print_section(f"Round {round_no}: 根据反馈调整文档")
        print(f"  调整方向: {adjustment_direction}")
    print()

    generated_docs = _generate_agent_docs_via_llm(
        workspace=workspace,
        evolution_goal=evolution_goal,
        round_no=round_no,
        previous_results=previous_results,
        adjustment_direction=adjustment_direction,
    )

    # pi agent 已直接写入文件，这里只需展示确认
    for spec in DOC_SPECS:
        action = "已写入" if round_no == 1 else "已更新"
        print(f"  {action}: {spec['agent_id']}/skills/{spec['path']} ({spec['title']})")

    print()
    print("  提示: 你可以在确认 replay 前手动编辑上述文件。")
    print(f"  文件位置: {workspace.agents_dir}")


def _format_prev_results(previous_results: list[ReplayResult] | None) -> str:
    if not previous_results:
        return ""
    succeeded = [r for r in previous_results if r.status in ("completed", "succeeded")]
    failed = [r for r in previous_results if r.status not in ("completed", "succeeded")]
    total_results = sum(r.results_summary.get("result_count", 0) for r in previous_results)
    return f"""
## 上轮结果回顾

- 成功任务: {len(succeeded)}/{len(previous_results)}
- 发现结果数: {total_results}
- 失败任务: {len(failed)}
"""


def _generate_agent_docs_via_llm(
    *,
    workspace: Workspace,
    evolution_goal: str,
    round_no: int,
    previous_results: list[ReplayResult] | None,
    adjustment_direction: str,
) -> dict[str, str]:
    context = _build_generation_context(
        workspace=workspace,
        evolution_goal=evolution_goal,
        round_no=round_no,
        previous_results=previous_results,
        adjustment_direction=adjustment_direction,
    )
    payload = _invoke_pi_for_docs(context=context, working_dir=workspace.root, workspace=workspace)
    return _validate_generated_docs(payload)


def _build_generation_context(
    *,
    workspace: Workspace,
    evolution_goal: str,
    round_no: int,
    previous_results: list[ReplayResult] | None,
    adjustment_direction: str,
) -> dict[str, Any]:
    return {
        "session_id": workspace.session_id,
        "project_id": workspace.project_id,
        "round_no": round_no,
        "evolution_goal": evolution_goal,
        "adjustment_direction": adjustment_direction,
        "previous_results_summary": _summarize_previous_results(previous_results),
        "target_docs": [
            {
                "key": spec["key"],
                "agent_id": spec["agent_id"],
                "path": spec["path"],
                "role_name": spec["role_name"],
                "title": spec["title"],
                "purpose": spec["purpose"],
                "focus": spec["focus"],
            }
            for spec in DOC_SPECS
        ],
        "source_tasks": [_build_source_task_context(task) for task in workspace.source_tasks],
    }


def _build_source_task_context(task: SourceTask) -> dict[str, Any]:
    detail = task.task_detail or {}
    metadata = detail.get("task_metadata") or {}
    request = metadata.get("dataflow_scan_request") if isinstance(metadata, dict) else {}
    run_info = detail.get("run") if isinstance(detail.get("run"), dict) else {}
    latest_run = detail.get("latest_run") if isinstance(detail.get("latest_run"), dict) else {}
    task_markdown = str(detail.get("task_markdown") or "").strip()
    report_status = detail.get("vuln_report_status") if isinstance(detail.get("vuln_report_status"), dict) else {}
    return {
        "task_id": task.task_id,
        "execution_id": task.execution_id,
        "title": task.title,
        "run_name": detail.get("run_name") or run_info.get("name") or latest_run.get("name") or "",
        "status": detail.get("status") or "",
        "review_profile": (
            request.get("review_profile")
            or latest_run.get("review_profile")
            or run_info.get("review_profile")
            or ""
        ),
        "result_count": (
            latest_run.get("result_count")
            or run_info.get("result_count")
            or report_status.get("total")
            or len(task.case_ids)
        ),
        "task_markdown_summary": _truncate_text(task_markdown, 1400),
        "task_markdown_key_points": _extract_markdown_key_points(task_markdown),
        "scan_request_summary": _summarize_scan_request(request),
        "existing_findings": _summarize_case_details(task.case_details),
    }


def _extract_markdown_key_points(task_markdown: str) -> list[str]:
    points: list[str] = []
    for raw_line in task_markdown.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("- "):
            points.append(line[2:].strip())
        elif line[:2].isdigit() and ". " in line:
            _, _, tail = line.partition(". ")
            points.append(tail.strip())
        if len(points) >= 8:
            break
    return points


def _summarize_scan_request(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict):
        return {}
    summary: dict[str, Any] = {}
    for key in (
        "review_profile",
        "run_name",
        "resume_run_dir",
        "resume_extra_cycles",
        "clean_workspace",
    ):
        value = request.get(key)
        if value not in (None, "", [], {}):
            summary[key] = value
    for key in ("data_flow_dir", "source_dir"):
        value = request.get(key)
        if isinstance(value, dict):
            path = str(value.get("path") or "").strip()
            if path:
                summary[key] = path
        elif value not in (None, ""):
            summary[key] = value
    return summary


def _summarize_case_details(case_details: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for case in case_details[:12]:
        if not isinstance(case, dict):
            continue
        display = case.get("display_summary") if isinstance(case.get("display_summary"), dict) else {}
        source = (case.get("metadata") or {}).get("source") if isinstance(case.get("metadata"), dict) else {}
        subject = case.get("subject") if isinstance(case.get("subject"), dict) else {}
        evidence = case.get("evidence") if isinstance(case.get("evidence"), dict) else {}
        findings.append(
            {
                "case_id": case.get("id") or "",
                "title": case.get("title") or display.get("title") or "",
                "severity": case.get("severity") or display.get("severity") or "",
                "confidence": case.get("confidence") or display.get("confidence") or "",
                "summary": _truncate_text(
                    str(case.get("summary") or evidence.get("summary") or ""),
                    260,
                ),
                "result_file": source.get("result_file") or "",
                "review_verdict": ((case.get("metadata") or {}).get("dataflow_vuln_scanner") or {}).get("review_verdict") if isinstance(case.get("metadata"), dict) else "",
                "subject_name": subject.get("name") or "",
                "subject_locator": subject.get("locator") or "",
            }
        )
    return findings


def _summarize_previous_results(previous_results: list[ReplayResult] | None) -> dict[str, Any]:
    if not previous_results:
        return {}
    succeeded = [r for r in previous_results if r.status in ("completed", "succeeded")]
    failed = [r for r in previous_results if r.status not in ("completed", "succeeded")]
    return {
        "total_tasks": len(previous_results),
        "succeeded": len(succeeded),
        "failed": len(failed),
        "total_results_found": sum(r.results_summary.get("result_count", 0) for r in previous_results),
        "items": [
            {
                "source_task_id": r.source_task_id,
                "derived_task_id": r.derived_task_id,
                "status": r.status,
                "result_count": r.results_summary.get("result_count", 0),
                "error": r.error or "",
            }
            for r in previous_results
        ],
    }


def _truncate_text(text: str, limit: int) -> str:
    normalized = " ".join((text or "").split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: max(0, limit - 3)].rstrip() + "..."


def _invoke_pi_for_docs(*, context: dict[str, Any], working_dir: Path, workspace: Workspace) -> dict[str, Any]:
    prompt_dir = working_dir / "doc_generation"
    prompt_dir.mkdir(parents=True, exist_ok=True)
    system_path = prompt_dir / "system.md"
    user_path = prompt_dir / "user.md"
    system_path.write_text(_build_doc_generation_system_prompt(), encoding="utf-8")
    user_prompt = _build_doc_generation_user_prompt(context, workspace)
    user_path.write_text(user_prompt, encoding="utf-8")

    model = _resolve_doc_generation_model()
    # 不使用 --mode json，让 pi agent 直接使用工具读写文件
    cmd = [
        "pi",
        "--model",
        model,
        "--no-session",
        "--append-system-prompt",
        str(system_path),
        "-p",
        f"@{user_path}",
    ]
    env = os.environ.copy()
    if not env.get("PI_MODELS_JSON"):
        explicit_pi_dir = str(env.get("PI_CODING_AGENT_DIR") or "/root/.pi/agent").strip()
        if explicit_pi_dir:
            env["PI_MODELS_JSON"] = str(Path(explicit_pi_dir) / "models.json")
    logger.info("调用 pi 生成 4 个 agent 文档: model=%s", model)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(working_dir),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("未找到 pi CLI,无法生成 agent 文档") from exc

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    output_path = prompt_dir / "pi_stdout.txt"
    output_path.write_text(stdout, encoding="utf-8")
    if stderr:
        (prompt_dir / "pi_stderr.txt").write_text(stderr, encoding="utf-8")

    if proc.returncode != 0:
        message = stderr.strip() or stdout.strip() or f"pi exit code={proc.returncode}"
        raise RuntimeError(f"大模型生成 4 个 agent 文档失败: {message[:800]}")

    payload = _read_generated_docs_from_files(workspace)
    if not isinstance(payload, dict) or not payload:
        raise RuntimeError("大模型未成功写入 4 个 agent 文档")
    return payload


def _read_generated_docs_from_files(workspace: Workspace) -> dict[str, Any]:
    """从 workspace 的 agent skills 目录中读取已生成的 4 份文档。
    返回格式与 _validate_generated_docs 兼容: {"docs": {"key": "text", ...}}
    """
    docs: dict[str, str] = {}
    for spec in DOC_SPECS:
        skills_dir = workspace.get_agent_skills_dir(spec["agent_id"])
        file_path = skills_dir / spec["path"]
        if file_path.is_file():
            docs[spec["key"]] = file_path.read_text(encoding="utf-8").strip()
        else:
            docs[spec["key"]] = ""
    return {"docs": docs}


def _resolve_doc_generation_model() -> str:
    env_model = str(os.environ.get("EVOLVER_DOC_MODEL") or "").strip()
    if env_model:
        return env_model
    explicit = str(os.environ.get("PI_DEFAULT_MODEL") or "").strip()
    if explicit:
        return explicit
    return "local_minimax/MiniMax/MiniMax-M2.5"


_PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"


def _build_doc_generation_system_prompt() -> str:
    """从 prompts/doc_generation_system.md 加载系统提示词。"""
    path = _PROMPTS_DIR / "doc_generation_system.md"
    if path.is_file():
        return path.read_text(encoding="utf-8")
    # fallback: 内联精简版
    return """你是 dataflow-vuln-scanner 的进化策略师。
生成 4 份短 MD:pi-worker/evolution-strategy.md、pi-advisor/evolution-completeness-review.md、
pi-advisor/evolution-depth-review.md、pi-advisor/evolution-result-review.md。
中文,具体,只输出 JSON。"""


def _build_doc_generation_user_prompt(
    context: dict[str, Any],
    workspace: Workspace,
) -> str:
    """从 prompts/doc_generation_user.md 加载用户提示词模板并填充占位符。"""
    path = _PROMPTS_DIR / "doc_generation_user.md"
    if path.is_file():
        template = path.read_text(encoding="utf-8")
    else:
        template = "## 一、原始任务信息\n\n{task_dirs}\n\n## 二、进化目标\n\n{evolution_goal}\n\n## 三、生成进化文档\n\n请写入 4 份文档到:\n- `{skills_worker_dir}/evolution-strategy.md`\n- `{skills_advisor_dir}/evolution-completeness-review.md`\n- `{skills_advisor_dir}/evolution-depth-review.md`\n- `{skills_advisor_dir}/evolution-result-review.md`\n"

    # ── task_dirs: 为每个 source_task 构建工作目录路径 ──
    project_id = context.get("project_id", "")
    source_tasks = context.get("source_tasks") or []
    task_dir_parts: list[str] = []
    for task in source_tasks:
        if not isinstance(task, dict):
            continue
        task_id = task.get("task_id", "")
        run_name = task.get("run_name", "")
        title = task.get("title", "")
        if not run_name:
            continue
        run_dir = f"/data/files/{project_id}/DATAFLOW_VULN_SCANNER/runs/{run_name}"
        task_dir_parts.append(f"- **{title or task_id}** (task_id: `{task_id}`)")
        task_dir_parts.append(f"  工作目录: `{run_dir}/`")
        task_dir_parts.append(f"  请先 `ls {run_dir}/run/workspace/` 找到 pipeline_* 子目录,")
        task_dir_parts.append(f"  再进入 stage_01_vuln_scan/vuln_scan_*/ 读取 input/task.md、summary.md、results/")
        task_dir_parts.append("")
    task_dirs = "\n".join(task_dir_parts) if task_dir_parts else "(无可用任务)"

    evolution_goal = str(context.get("evolution_goal") or "").strip()
    skills_worker_dir = str(workspace.get_agent_skills_dir("pi-worker"))
    skills_advisor_dir = str(workspace.get_agent_skills_dir("pi-advisor"))

    return (
        template
        .replace("{task_dirs}", task_dirs)
        .replace("{evolution_goal}", evolution_goal)
        .replace("{skills_worker_dir}", skills_worker_dir)
        .replace("{skills_advisor_dir}", skills_advisor_dir)
    )


def _extract_pi_json_response(stdout: str) -> Any:
    lines = [line for line in stdout.splitlines() if line.strip()]
    assistant_text = ""
    for raw_line in lines:
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        if event.get("type") == "message_end" and isinstance(event.get("message"), dict):
            message = event["message"]
            if message.get("role") == "assistant":
                assistant_text = _extract_text_from_pi_message(message)
    if not assistant_text:
        assistant_text = stdout.strip()
    assistant_text = assistant_text.strip()
    if assistant_text.startswith("```"):
        assistant_text = assistant_text.strip("`").strip()
        if assistant_text.lower().startswith("json"):
            assistant_text = assistant_text[4:].strip()
    return json.loads(assistant_text)


def _extract_text_from_pi_message(message: dict[str, Any]) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    parts: list[str] = []
    if isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            if isinstance(block.get("text"), str):
                parts.append(block["text"])
            elif isinstance(block.get("content"), str):
                parts.append(block["content"])
    return "\n".join(parts).strip()


def _validate_generated_docs(payload: dict[str, Any]) -> dict[str, str]:
    docs = payload.get("docs")
    if not isinstance(docs, dict):
        raise RuntimeError("大模型输出缺少 docs 对象")
    normalized: dict[str, str] = {}
    for spec in DOC_SPECS:
        raw = docs.get(spec["key"])
        text = str(raw or "").strip()
        if not text:
            raise RuntimeError(f"大模型未生成 {spec['key']}")
        normalized[spec["key"]] = text
    return normalized


# ─── 主流程 ──────────────────────────────────────────────────────────────────

async def run_evolution(
    config: dict[str, Any],
    project_id: str,
    case_ids: list[str],
) -> None:
    """主进化流程。"""

    print_header("Dataflow Vuln Scanner Evolver")
    print(f"  项目: {project_id}")
    print(f"  案例数: {len(case_ids)}")

    # ─── Step 0: 预处理 ───
    print_section("Step 0: 预处理")
    preprocessor = Preprocessor(config)

    try:
        source_tasks = await preprocessor.extract_source_tasks(project_id, case_ids)
    except PreprocessError as exc:
        print(f"  [ERROR] 预处理失败: {exc}")
        return

    print(f"  提取到 {len(source_tasks)} 个可 replay 的原始任务:\n")
    print_task_list(source_tasks)

    # ─── Step 1: 初始化 Workspace ───
    print_section("Step 1: 初始化进化会话")
    evolution_goal = input("  进化目标: ").strip()
    if not evolution_goal:
        print("  [ERROR] 进化目标不能为空")
        return

    workspace = Workspace(config, project_id, source_tasks)
    workspace.create(evolution_goal)
    print(f"\n  会话 ID: {workspace.session_id}")
    print(f"  工作目录: {workspace.root}")

    # ─── 进化循环 ───
    replay_manager = ReplayManager(config)
    previous_results: list[ReplayResult] | None = None
    round_no = 0

    while True:
        round_no = workspace.start_round()

        # 生成/修改 agent 文档
        if round_no == 1:
            interactive_generate_docs(workspace, evolution_goal, round_no)
        else:
            direction = input("\n  调整方向: ").strip()
            if direction.lower() == "done":
                break
            interactive_generate_docs(
                workspace, evolution_goal, round_no,
                previous_results=previous_results,
                adjustment_direction=direction,
            )

        # 展示当前文档
        print_agent_docs(workspace)

        # 确认 replay
        confirm = input("  确认开始 replay? [Y/n]: ").strip()
        if confirm.lower() == "n":
            print("  跳过本轮 replay。")
            direction = input("\n  输入 'done' 结束,或输入调整方向继续: ").strip()
            if direction.lower() == "done":
                break
            continue

        # 执行 replay
        print_section(f"Round {round_no}: Replaying")
        agent_roots = workspace.get_agent_roots()

        results = await replay_manager.replay_all(
            source_tasks=source_tasks,
            agent_roots=agent_roots,
            project_id=project_id,
            evolution_session_id=workspace.session_id,
            round_no=round_no,
            on_progress=progress_callback,
        )

        # 保存结果
        workspace.save_round_results(
            round_no,
            [
                {
                    "source_task_id": r.source_task_id,
                    "derived_task_id": r.derived_task_id,
                    "status": r.status,
                    "run_id": r.run_id,
                    "duration_seconds": r.duration_seconds,
                    "results_summary": r.results_summary,
                    "error": r.error,
                }
                for r in results
            ],
        )

        # 写入 memory
        round_summary = _build_round_summary(round_no, results, source_tasks)
        workspace.write_round_memory(round_no, round_summary)

        # 展示结果
        print_replay_results(results, source_tasks)
        previous_results = results

        # 询问下一步
        print("\n  输入 'done' 结束进化,或输入调整方向进入下一轮。")
        next_input = input("  > ").strip()
        if next_input.lower() == "done":
            break
        # 如果用户直接输入了调整方向,保存到下一轮使用
        # 下一轮循环开始时会再次询问

    # ─── 完成 ───
    workspace.finish()
    print_header("进化会话完成")
    print(f"  总轮次: {round_no}")
    print(f"  会话目录: {workspace.root}")
    print(f"  可通过 --resume {workspace.root} 恢复会话")


async def run_evolution_from_tasks(
    config: dict[str, Any],
    project_id: str,
    task_ids: list[str],
) -> None:
    """直接从 dfvs task_ids 启动进化(跳过 vuln case 反查)。"""
    import httpx

    print_header("Dataflow Vuln Scanner Evolver")
    print(f"  项目: {project_id}")
    print(f"  直接指定任务: {', '.join(task_ids)}")

    print_section("Step 0: 验证任务")
    source_tasks: list[SourceTask] = []

    dfvs_base = (
        config["dataflow_vuln_scanner"]["base_url"].rstrip("/")
        + config["dataflow_vuln_scanner"]["api_prefix"]
    )
    vuln_base = (
        config["vuln_service"]["base_url"].rstrip("/")
        + config["vuln_service"]["api_prefix"]
    )
    token = config["auth"]["machine_token"]
    if not token.lower().startswith("bearer "):
        token = f"Bearer {token}"
    headers: dict[str, str] = {"Authorization": token}
    dfvs_headers = dict(headers)
    dfvs_host_header = config["dataflow_vuln_scanner"].get("host_header", "")
    if dfvs_host_header:
        dfvs_headers["Host"] = dfvs_host_header
    vuln_headers = dict(headers)
    vuln_host_header = config["vuln_service"].get("host_header", "")
    if vuln_host_header:
        vuln_headers["Host"] = vuln_host_header
    timeout = config["dataflow_vuln_scanner"].get("timeout", 60)

    async with httpx.AsyncClient(timeout=timeout) as client:
        for task_id in task_ids:
            # 获取任务详情
            resp = await client.get(f"{dfvs_base}/tasks/{task_id}", headers=dfvs_headers)
            if resp.status_code != 200:
                print(f"  [WARN] 任务 {task_id} 不存在或不可访问: {resp.status_code}")
                continue
            detail = resp.json()

            # 检查 replay-ready
            resp2 = await client.get(
                f"{dfvs_base}/tasks/{task_id}/replay-ready", headers=dfvs_headers
            )
            if resp2.status_code != 200:
                print(f"  [WARN] 任务 {task_id} replay-ready 检查失败: {resp2.status_code}")
                continue
            replay_info = resp2.json()

            if not replay_info.get("replay_ready"):
                reason = replay_info.get("reason") or "未知原因"
                print(f"  [WARN] 任务 {task_id} 不可 replay: {reason}")
                continue

            agent_state_dirs = replay_info.get("agent_state_dirs") or {}
            case_ids = _extract_case_ids_from_task_detail(detail)
            case_details = _extract_case_details_from_task_detail(detail)
            if (not case_ids) or _case_details_are_sparse(case_details):
                fetched_case_details = await _fetch_case_details_for_task(
                    client,
                    vuln_base,
                    vuln_headers,
                    project_id,
                    task_id,
                )
                if fetched_case_details:
                    case_details = fetched_case_details
                case_ids = _extract_case_ids_from_case_details(case_details)
            source_tasks.append(
                SourceTask(
                    task_id=task_id,
                    execution_id=detail.get("latest_execution_id") or "",
                    title=detail.get("title") or task_id,
                    case_ids=case_ids,
                    agent_state_dirs=agent_state_dirs,
                    task_detail=detail,
                    case_details=case_details,
                )
            )
            print(f"  ✓ {task_id}: {detail.get('title', '')} (replay_ready)")

    if not source_tasks:
        print("\n  [ERROR] 没有可用的 replay 任务")
        return

    print(f"\n  共 {len(source_tasks)} 个任务可用于进化\n")
    print_task_list(source_tasks)

    # 后续流程与 run_evolution 相同
    print_section("Step 1: 初始化进化会话")
    evolution_goal = input("  进化目标: ").strip()
    if not evolution_goal:
        print("  [ERROR] 进化目标不能为空")
        return

    workspace = Workspace(config, project_id, source_tasks)
    workspace.create(evolution_goal)
    print(f"\n  会话 ID: {workspace.session_id}")
    print(f"  工作目录: {workspace.root}")

    replay_manager = ReplayManager(config)
    previous_results: list[ReplayResult] | None = None
    round_no = 0

    while True:
        round_no = workspace.start_round()

        if round_no == 1:
            interactive_generate_docs(workspace, evolution_goal, round_no)
        else:
            direction = input("\n  调整方向 (输入 'done' 结束): ").strip()
            if direction.lower() == "done":
                break
            interactive_generate_docs(
                workspace, evolution_goal, round_no,
                previous_results=previous_results,
                adjustment_direction=direction,
            )

        print_agent_docs(workspace)

        confirm = input("  确认开始 replay? [Y/n]: ").strip()
        if confirm.lower() == "n":
            print("  跳过本轮 replay。")
            direction = input("\n  输入 'done' 结束,或输入调整方向继续: ").strip()
            if direction.lower() == "done":
                break
            continue

        print_section(f"Round {round_no}: Replaying")
        agent_roots = workspace.get_agent_roots()

        results = await replay_manager.replay_all(
            source_tasks=source_tasks,
            agent_roots=agent_roots,
            project_id=project_id,
            evolution_session_id=workspace.session_id,
            round_no=round_no,
            on_progress=progress_callback,
        )

        workspace.save_round_results(
            round_no,
            [
                {
                    "source_task_id": r.source_task_id,
                    "derived_task_id": r.derived_task_id,
                    "status": r.status,
                    "run_id": r.run_id,
                    "duration_seconds": r.duration_seconds,
                    "results_summary": r.results_summary,
                    "error": r.error,
                }
                for r in results
            ],
        )

        round_summary = _build_round_summary(round_no, results, source_tasks)
        workspace.write_round_memory(round_no, round_summary)
        print_replay_results(results, source_tasks)
        previous_results = results

        print("\n  输入 'done' 结束进化,或输入调整方向进入下一轮。")
        next_input = input("  > ").strip()
        if next_input.lower() == "done":
            break

    workspace.finish()
    print_header("进化会话完成")
    print(f"  总轮次: {round_no}")
    print(f"  会话目录: {workspace.root}")


def _extract_case_ids_from_task_detail(detail: dict[str, Any]) -> list[str]:
    case_ids: list[str] = []
    seen: set[str] = set()
    items = ((detail.get("vuln_report_status") or {}).get("items") or [])
    for item in items:
        if not isinstance(item, dict):
            continue
        case_id = str(item.get("case_id") or "").strip()
        if case_id and case_id not in seen:
            seen.add(case_id)
            case_ids.append(case_id)
    return case_ids


def _extract_case_details_from_task_detail(detail: dict[str, Any]) -> list[dict[str, Any]]:
    items = ((detail.get("vuln_report_status") or {}).get("items") or [])
    if not isinstance(items, list):
        return []
    case_map = {
        str(item.get("case_id") or "").strip(): item
        for item in items
        if isinstance(item, dict) and str(item.get("case_id") or "").strip()
    }
    if not case_map:
        return []
    return [
        {
            "id": case_id,
            "title": "",
            "summary": "",
            "severity": "",
            "confidence": "",
            "subject": {},
            "evidence": {},
            "display_summary": {},
            "metadata": {
                "source": {
                    "result_file": item.get("result_file") or "",
                },
                "dataflow_vuln_scanner": {
                    "review_verdict": "",
                },
            },
        }
        for case_id, item in case_map.items()
    ]


def _extract_case_ids_from_case_details(case_details: list[dict[str, Any]]) -> list[str]:
    case_ids: list[str] = []
    seen: set[str] = set()
    for item in case_details:
        if not isinstance(item, dict):
            continue
        case_id = str(item.get("id") or "").strip()
        if case_id and case_id not in seen:
            seen.add(case_id)
            case_ids.append(case_id)
    return case_ids


def _case_details_are_sparse(case_details: list[dict[str, Any]]) -> bool:
    if not case_details:
        return True
    for item in case_details:
        if not isinstance(item, dict):
            continue
        if str(item.get("title") or "").strip():
            return False
    return True


async def _fetch_case_details_for_task(
    client: Any,
    vuln_base: str,
    headers: dict[str, str],
    project_id: str,
    task_id: str,
) -> list[dict[str, Any]]:
    resp = await client.get(
        f"{vuln_base}/cases",
        headers=headers,
        params={
            "project_id": project_id,
            "source_task_id": task_id,
        },
    )
    if resp.status_code != 200:
        logger.warning("获取任务 %s 的案例列表失败: %s", task_id, resp.status_code)
        return []

    payload = resp.json()
    items = payload.get("items") if isinstance(payload, dict) else []
    case_details: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items or []:
        if not isinstance(item, dict):
            continue
        case_id = str(item.get("id") or "").strip()
        if case_id and case_id not in seen:
            seen.add(case_id)
            case_details.append(item)
    return case_details


def _build_round_summary(
    round_no: int,
    results: list[ReplayResult],
    source_tasks: list[SourceTask],
) -> str:
    """构建轮次摘要,写入 memory/。"""
    total_expected = sum(len(t.case_ids) for t in source_tasks)
    total_found = sum(r.results_summary.get("result_count", 0) for r in results)
    succeeded = len([r for r in results if r.status in ("completed", "succeeded")])

    lines = [
        f"# Evolution Round {round_no} Summary",
        "",
        f"- 任务成功率: {succeeded}/{len(results)}",
        f"- 原始案例总数: {total_expected}",
        f"- 本轮发现结果数: {total_found}",
    ]
    if total_expected > 0:
        lines.append(f"- 覆盖率: {total_found / total_expected * 100:.1f}%")

    lines.append("")
    lines.append("## 各任务详情")
    lines.append("")
    for r in results:
        status_icon = "✓" if r.status in ("completed", "succeeded") else "✗"
        lines.append(
            f"- {status_icon} {r.source_task_id}: "
            f"status={r.status}, results={r.results_summary.get('result_count', '?')}"
        )
        if r.error:
            lines.append(f"  error: {r.error}")

    return "\n".join(lines) + "\n"


# ─── CLI 入口 ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Dataflow Vuln Scanner Evolver - 交互式进化工具"
    )
    parser.add_argument("--project-id", required=True, help="项目 ID")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--case-ids",
        help="案例 ID 列表,逗号分隔(从 vuln cases 反查原始任务)",
    )
    group.add_argument(
        "--task-ids",
        help="直接指定 dataflow-vuln-scanner 的 scan task ID 列表,逗号分隔",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="配置文件路径 (默认: config.yaml)",
    )
    parser.add_argument(
        "--resume",
        help="恢复已有会话 (传入 session 目录路径)",
    )

    args = parser.parse_args()
    config = load_config(args.config)

    if args.task_ids:
        task_ids = [tid.strip() for tid in args.task_ids.split(",") if tid.strip()]
        if not task_ids:
            print("[ERROR] task-ids 不能为空")
            sys.exit(1)
        asyncio.run(run_evolution_from_tasks(config, args.project_id, task_ids))
    else:
        case_ids = [cid.strip() for cid in args.case_ids.split(",") if cid.strip()]
        if not case_ids:
            print("[ERROR] case-ids 不能为空")
            sys.exit(1)
        asyncio.run(run_evolution(config, args.project_id, case_ids))


if __name__ == "__main__":
    main()
