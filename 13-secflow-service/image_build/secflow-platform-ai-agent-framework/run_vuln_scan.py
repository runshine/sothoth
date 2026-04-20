#!/usr/bin/env python3
"""
漏洞挖掘便捷启动器

用法:
  python run_vuln_scan.py \
    --data-flow /path/to/data_flow_analysis.md \
    --source-dir /path/to/source_code/ \
    [--run-name my_scan] \
    [--model claude-sonnet-4-20250514] \
    [--provider anthropic] \
    [--max-cycles 3] \
    [--clean]

功能:
  1. 根据输入参数自动生成 task.md 和 config.json
  2. 调用框架主程序执行漏洞挖掘工作流
  3. 工作流包含: Worker分析 → 自我反思 → 总结 → 全局评审 → 结果评审 → (循环)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# 项目根目录
PROJECT_ROOT = Path(__file__).resolve().parent
PROMPTS_DIR = PROJECT_ROOT / "prompts" / "vuln_scan"
DEFAULT_CONFIG = PROJECT_ROOT / "config.vuln_scan_default.json"


def generate_task_md(data_flow_file: str, source_dir: str) -> str:
    """根据输入参数生成 task.md 内容"""

    # 从数据流文件中提取函数信息（如果可能）
    func_info = ""
    try:
        content = Path(data_flow_file).read_text(encoding="utf-8")
        for line in content.split("\n"):
            if line.startswith("# 数据流追踪：") or line.startswith("# 数据流追踪:"):
                func_name = line.split("：")[-1].split(":")[-1].strip()
                func_info = f"\n请**完整阅读**该文件，理解目标函数 `{func_name}` 的数据流结构。\n"
                break
    except Exception:
        pass

    # 统计源码文件
    source_stats = []
    if os.path.isdir(source_dir):
        c_files = list(Path(source_dir).rglob("*.c"))
        h_files = list(Path(source_dir).rglob("*.h"))
        asm_files = list(Path(source_dir).rglob("*.asm"))
        if c_files:
            source_stats.append(f"{len(c_files)} 个 .c 文件")
        if h_files:
            source_stats.append(f"{len(h_files)} 个 .h 文件")
        if asm_files:
            source_stats.append(f"{len(asm_files)} 个 .asm 文件")

    stats_line = f"包含 {', '.join(source_stats)}。" if source_stats else ""

    # 从数据流文件提取关键统计
    analysis_hints = _extract_analysis_hints(data_flow_file)

    return f"""# 漏洞挖掘任务

## 目标
基于数据流分析结果，对目标函数及其调用链进行深度安全漏洞挖掘。

## 数据流分析文件
`{os.path.abspath(data_flow_file)}`
{func_info}
## 源码目录
`{os.path.abspath(source_dir)}`

该目录包含数据流分析涉及的所有源码文件（.c, .h, .asm）。{stats_line}

{analysis_hints}
## 要求
1. 首先**完整阅读**数据流分析文件，理解目标函数的行为和所有数据流路径
2. 阅读源码目录中的相关代码文件，验证数据流分析的结论
3. 对每个 EXPORT 终点（数据传入外部函数），跟入源码继续追踪
4. 对每个 USED 终点（数据参与操作），检查操作安全性
5. 对数据流分析的关键发现（★ 标记），进行源码级验证
6. 对每个确认的漏洞，给出完整的证据链（从 INPUT 到危险操作）
"""


def _extract_analysis_hints(data_flow_file: str) -> str:
    """从数据流文件中提取分析提示"""
    try:
        content = Path(data_flow_file).read_text(encoding="utf-8")
    except Exception:
        return ""

    hints = []

    # 统计 INPUT 数量（去重: 只计唯一的 INPUT-N 编号）
    import re
    input_ids = set(re.findall(r'INPUT-(\d+)', content))
    if input_ids:
        hints.append(f"- 数据流分析已识别 {len(input_ids)} 个外部输入")

    # 从统计表中提取终点数量（更精确）
    export_count = 0
    used_count = 0
    cleaned_count = 0
    for line in content.split("\n"):
        line_stripped = line.strip()
        # 匹配统计表行: | 🟡 EXPORT | 5 | ...
        if "🟡 EXPORT" in line_stripped and "|" in line_stripped:
            parts = [p.strip() for p in line_stripped.split("|")]
            for p in parts:
                if p.isdigit():
                    export_count = max(export_count, int(p))
                    break
        elif "📌 USED" in line_stripped and "|" in line_stripped:
            parts = [p.strip() for p in line_stripped.split("|")]
            for p in parts:
                if p.isdigit():
                    used_count = max(used_count, int(p))
                    break
        elif "🟢 CLEANED" in line_stripped and "|" in line_stripped:
            parts = [p.strip() for p in line_stripped.split("|")]
            for p in parts:
                if p.isdigit():
                    cleaned_count = max(cleaned_count, int(p))
                    break

    if export_count > 0:
        hints.append(f"- 有 {export_count} 个 EXPORT 终点需要跟入源码分析")
    if used_count > 0:
        hints.append(f"- 有 {used_count} 个 USED 终点需要检查安全性")
    if cleaned_count == 0 and (export_count > 0 or used_count > 0):
        hints.append("- 无数据清洗操作（CLEANED=0），需评估整体安全风险")

    # 关键发现
    key_findings = []
    for line in content.split("\n"):
        if line.strip().startswith("### ★") or line.strip().startswith("★"):
            finding = line.strip().lstrip("#").lstrip("★").strip()
            if finding:
                key_findings.append(f"  - ★ {finding}")
    if key_findings:
        hints.append("- 关键发现：")
        hints.extend(key_findings)

    if hints:
        return "## 分析重点\n" + "\n".join(hints) + "\n"
    return ""


def generate_config(
    run_dir: str,
    task_file: str,
    run_name: str,
    model: str = "claude-sonnet-4-20250514",
    provider: str = "anthropic",
    max_cycles: int = 10,
    worker_timeout: int = 1800,
    advisor_timeout: int = 1800,
    thinking: str = "high",
    result_review_concurrency: int = 3,
) -> dict:
    """生成完整的配置字典"""

    prompts_dir = str(PROMPTS_DIR)

    return {
        "version": "1.0",
        "global": {
            "workspace_root": os.path.join(run_dir, "workspace"),
            "log_level": "INFO",
            "max_workflow_retry": 1,
            "max_review_cycles": max_cycles,
            "default_context_reset": True,
            "parallel_result_review": True,
            "parallel_result_review_limit": result_review_concurrency,
            "env_vars": {},
        },
        "agents": [
            {
                "id": "pi-worker",
                "name": "Pi Agent Worker",
                "type": "pi_agent",
                "reset_context": False,
                "runtime_config": {
                    "model": model,
                    "timeout_seconds": worker_timeout,
                    "sdk_specific": {
                        "provider": provider,
                        "thinking": thinking,
                    },
                },
            },
            {
                "id": "pi-advisor",
                "name": "Pi Agent Advisor",
                "type": "pi_agent",
                "reset_context": True,
                "runtime_config": {
                    "model": model,
                    "timeout_seconds": advisor_timeout,
                    "sdk_specific": {
                        "provider": provider,
                        "thinking": thinking,
                        "tools": "read,bash",
                    },
                },
            },
        ],
        "plugins": [
            {
                "id": "env_setup",
                "name": "环境变量设置",
                "module_path": "app.pi_vuln_core.plugins.builtin.env_setup",
                "class_name": "EnvSetupPlugin",
                "config": {},
            },
            {
                "id": "workspace_init",
                "name": "工作目录初始化",
                "module_path": "app.pi_vuln_core.plugins.builtin.workspace_init",
                "class_name": "WorkspaceInitPlugin",
                "config": {
                    "create_subdirs": [
                        "input", "working", "results", "reviews", "output",
                    ]
                },
            },
            {
                "id": "task_validator",
                "name": "输入任务校验",
                "module_path": "app.pi_vuln_core.plugins.builtin.task_validator",
                "class_name": "TaskValidatorPlugin",
                "config": {},
            },
            {
                "id": "result_archiver",
                "name": "结果归档",
                "module_path": "app.pi_vuln_core.plugins.builtin.result_archiver",
                "class_name": "ResultArchiverPlugin",
                "config": {"archive_format": "tar.gz"},
            },
            {
                "id": "final_output_collector",
                "name": "最终产出收集",
                "module_path":
                    "app.pi_vuln_core.plugins.builtin.final_output_collector",
                "class_name": "FinalOutputCollectorPlugin",
                "config": {"output_subdir": "final_output"},
            },
            {
                "id": "next_task_generator",
                "name": "下阶段任务生成器",
                "module_path": "app.pi_vuln_core.plugins.builtin.next_task_generator",
                "class_name": "NextTaskGeneratorPlugin",
                "config": {"output_subdir": "output"},
            },
        ],
        "workflows": {
            "atomic": [
                {
                    "id": "vuln_scan",
                    "name": "数据流驱动漏洞挖掘",
                    "type": "atomic",
                    "description": "基于数据流分析结果和源代码进行深度安全漏洞挖掘",
                    "working_dir_template": "vuln_scan_{task_id}",
                    "start_plugins": [
                        "env_setup", "workspace_init", "task_validator",
                    ],
                    "end_plugins": [
                        "result_archiver",
                        "final_output_collector",
                        "next_task_generator",
                    ],
                    "engine": {
                        "max_review_cycles": max_cycles,
                        "max_worker_turns_per_cycle": 1,
                    },
                    "roles": {
                        "worker": {
                            "agent_id": "pi-worker",
                            "new_session": False,
                            "prompts": {
                                "work": {
                                    "system_prompt_file": os.path.join(
                                        prompts_dir, "worker_system.md"),
                                    "user_prompt_file": os.path.join(
                                        prompts_dir, "worker_user.md"),
                                },
                                "reflection": [
                                    {
                                        "id": "reflect_completeness",
                                        "prompt_file": os.path.join(
                                            prompts_dir,
                                            "reflect_completeness.md"),
                                        "description":
                                            "检查数据流覆盖度和分析深度",
                                    },
                                ],
                                "summary": {
                                    "prompt_file": os.path.join(
                                        prompts_dir, "summary.md"),
                                    "output_summary_filename": "summary.md",
                                    "output_results_dir": "results",
                                },
                            },
                        },
                        "advisors": {
                            "global_review": [
                                {
                                    "instance_id": "global_quality",
                                    "agent_id": "pi-advisor",
                                    "role_name": "全面性与质量评审",
                                    "re_review_on_cycle": True,
                                    "system_prompt_file": os.path.join(
                                        prompts_dir, "global_review_sys.md"),
                                    "user_prompt_template": os.path.join(
                                        prompts_dir, "global_review_user.md"),
                                },
                            ],
                            "result_review": [
                                {
                                    "instance_id": "result_fp_check",
                                    "agent_id": "pi-advisor",
                                    "role_name": "误报检测",
                                    "re_review_on_cycle": False,
                                    "system_prompt_file": os.path.join(
                                        prompts_dir, "result_review_sys.md"),
                                    "user_prompt_template": os.path.join(
                                        prompts_dir, "result_review_user.md"),
                                },
                            ],
                        },
                    },
                },
            ],
            "composite": [
                {
                    "id": "vuln_scan_pipeline",
                    "name": "漏洞挖掘流水线",
                    "type": "composite",
                    "description":
                        "单阶段漏洞挖掘组合工作流",
                    "working_dir_template": "pipeline_{execution_id}",
                    "stages": [
                        {
                            "stage_id": "stage_01_vuln_scan",
                            "name": "数据流驱动漏洞挖掘",
                            "sequence": 1,
                            "workflow_ref": "vuln_scan",
                            "workflow_type": "atomic",
                            "on_error": "abort",
                        },
                    ],
                },
            ],
        },
        "execution": {
            "entry_workflow": "vuln_scan_pipeline",
            "entry_workflow_type": "composite",
            "input_task": {
                "task_file": task_file,
                "task_id": run_name,
            },
            "output_dir": os.path.join(run_dir, "output"),
            "execution_id": f"{run_name}_run_001",
            "runtime_mode": "local",
            "on_completion": {
                "exit_code_on_success": 0,
                "exit_code_on_failure": 1,
                "write_summary": True,
                "summary_file": os.path.join(
                    run_dir, "output", "execution_summary.json"),
            },
        },
    }


def load_user_config(
    config_path: str,
    run_dir: str,
    task_file: str,
    run_name: str,
) -> dict:
    """
    加载用户自定义配置文件，解析相对路径，覆盖执行路径。

    用户只需关心配置中的业务字段 (模型/超时/轮次/prompts 等),
    执行路径类字段 (workspace_root, task_file, output_dir 等) 由启动器自动覆盖。
    """
    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    # ═══ 解析相对 prompt 路径 → 绝对路径 ═══
    _resolve_prompt_paths(config)

    # ═══ 覆盖执行路径 (用户无需关心这些) ═══
    config.setdefault("global", {})
    config["global"]["workspace_root"] = os.path.join(run_dir, "workspace")

    config.setdefault("execution", {})
    config["execution"]["entry_workflow"] = config["execution"].get(
        "entry_workflow", "vuln_scan_pipeline")
    config["execution"]["entry_workflow_type"] = "composite"
    config["execution"]["input_task"] = {
        "task_file": task_file,
        "task_id": run_name,
    }
    config["execution"]["output_dir"] = os.path.join(run_dir, "output")
    config["execution"]["execution_id"] = f"{run_name}_run_001"
    config["execution"]["runtime_mode"] = "local"
    config["execution"]["on_completion"] = {
        "exit_code_on_success": 0,
        "exit_code_on_failure": 1,
        "write_summary": True,
        "summary_file": os.path.join(
            run_dir, "output", "execution_summary.json"),
    }

    # 删除说明字段 (以 _ 开头的 key, Pydantic 不认)
    for key in [k for k in config if k.startswith("_")]:
        del config[key]

    return config


def _resolve_prompt_paths(config: dict) -> None:
    """
    将配置中的相对 prompt 路径解析为绝对路径。

    规则: 以 'prompts/' 开头的路径视为相对于项目根目录。
    已是绝对路径的不动。
    """
    prompt_keys = (
        "system_prompt_file", "user_prompt_file", "user_prompt_template",
        "prompt_file",
    )

    def _walk_and_resolve(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in prompt_keys and isinstance(value, str):
                    if not os.path.isabs(value):
                        obj[key] = str(PROJECT_ROOT / value)
                else:
                    _walk_and_resolve(value)
        elif isinstance(obj, list):
            for item in obj:
                _walk_and_resolve(item)

    _walk_and_resolve(config)


def _format_model_display(provider: str | None, model: str | None) -> str:
    provider = (provider or "").strip()
    model = (model or "").strip()
    if not provider:
        return model
    if model.startswith(f"{provider}/"):
        return model
    return f"{provider}/{model}" if model else provider


def _extract_worker_runtime(config_obj) -> tuple[str, str, str]:
    for agent in getattr(config_obj, "agents", []):
        if getattr(agent, "id", "") != "pi-worker":
            continue
        runtime_cfg = agent.runtime_config
        sdk_cfg = runtime_cfg.get("sdk_specific", {})
        return (
            sdk_cfg.get("provider", ""),
            runtime_cfg.get("model", ""),
            sdk_cfg.get("thinking", ""),
        )
    return "", "", ""


def _load_latest_cycle_record(records_dir: str | Path) -> tuple[int, dict]:
    base = Path(records_dir)
    if not base.is_dir():
        return 0, {}

    latest_cycle = 0
    latest_path: Path | None = None
    for path in sorted(base.glob("cycle_*.json")):
        stem = path.stem
        parts = stem.split("_")
        if len(parts) != 2 or not parts[1].isdigit():
            continue
        cycle = int(parts[1])
        if cycle >= latest_cycle:
            latest_cycle = cycle
            latest_path = path

    if latest_path is None:
        return 0, {}

    try:
        return latest_cycle, json.loads(latest_path.read_text(encoding="utf-8"))
    except Exception:
        return latest_cycle, {}


def _collect_resume_diagnostics(
    atomic_work_dir: str,
    review_state=None,
) -> dict:
    atomic_dir = Path(atomic_work_dir)
    meta_dir = atomic_dir / "_meta"

    summary_cycle, summary_data = _load_latest_cycle_record(meta_dir / "review_summaries")
    metrics_cycle, metrics_data = _load_latest_cycle_record(meta_dir / "cycle_metrics")
    blockers_cycle, blockers_data = _load_latest_cycle_record(meta_dir / "blockers")

    latest_cycle = max(summary_cycle, metrics_cycle, blockers_cycle)
    plateau_status = (metrics_data.get("plateau_status") or {}) if isinstance(metrics_data, dict) else {}

    workflow_mode = ""
    for candidate in (
        summary_data.get("workflow_mode") if isinstance(summary_data, dict) else "",
        plateau_status.get("workflow_mode"),
        metrics_data.get("workflow_mode") if isinstance(metrics_data, dict) else "",
        getattr(review_state, "workflow_mode", "") if review_state is not None else "",
    ):
        candidate = str(candidate or "").strip()
        if candidate:
            workflow_mode = candidate
            break

    plateau_reason = str(
        plateau_status.get("reason")
        or getattr(review_state, "closure_reason", "") if review_state is not None else ""
    ).strip()

    open_blockers = []
    if isinstance(blockers_data, dict) and isinstance(blockers_data.get("blockers"), list):
        open_blockers = list(blockers_data.get("blockers") or [])
    elif isinstance(summary_data, dict):
        open_blockers = list(
            ((summary_data.get("global_review") or {}).get("open_blockers") or [])
        )
    elif review_state is not None and hasattr(review_state, "serialize_open_blockers"):
        open_blockers = list(review_state.serialize_open_blockers(limit=5))

    passed_results = []
    failed_results = []
    if review_state is not None:
        if hasattr(review_state, "get_passed_result_filenames"):
            passed_results = list(review_state.get_passed_result_filenames())
        if hasattr(review_state, "get_failed_results"):
            failed_results = list(review_state.get_failed_results())

    passed_count = len(passed_results)
    failed_count = len(failed_results)
    if passed_count == 0 and isinstance(summary_data, dict):
        passed_count = int(((summary_data.get("result_review") or {}).get("passed_count") or 0))
    if failed_count == 0 and isinstance(summary_data, dict):
        failed_count = int(((summary_data.get("result_review") or {}).get("failed_count") or 0))

    scores = {}
    if isinstance(metrics_data, dict):
        scores = dict(metrics_data.get("scores") or {})
    elif review_state is not None:
        scores = dict(getattr(review_state, "last_global_scores", {}) or {})

    blockers_preview = []
    for item in open_blockers[:3]:
        if not isinstance(item, dict):
            blockers_preview.append(str(item))
            continue
        blocker_id = str(item.get("id") or "").strip() or "(no-id)"
        target = str(item.get("target") or "").strip()
        action = str(item.get("required_action") or item.get("detail") or "").strip()
        preview = f"[{blocker_id}]"
        if target:
            preview += f" {target}"
        if action:
            preview += f" | {action}"
        blockers_preview.append(preview)

    return {
        "latest_cycle": latest_cycle,
        "latest_outcome": str(summary_data.get("outcome") or "").strip() if isinstance(summary_data, dict) else "",
        "workflow_mode": workflow_mode or "discovery",
        "passed_count": passed_count,
        "failed_count": failed_count,
        "open_blocker_count": len(open_blockers),
        "blockers_preview": blockers_preview,
        "plateau_status": {
            "stagnant": bool(plateau_status.get("stagnant", False)),
            "streak": int(plateau_status.get("streak") or 0),
            "abort": bool(plateau_status.get("abort", False)),
            "switched_to_closure": bool(plateau_status.get("switched_to_closure", False)),
        },
        "plateau_reason": plateau_reason,
        "scores": scores,
    }


def _format_resume_diagnostic_lines(diagnostics: dict, *, completed_cycles: int, extra_cycles: int) -> list[str]:
    total_cycle_limit = completed_cycles + extra_cycles
    lines = [
        f"  轮次窗口:   {completed_cycles} -> {total_cycle_limit}",
        f"  当前模式:   {diagnostics.get('workflow_mode') or 'discovery'}",
    ]

    latest_cycle = int(diagnostics.get("latest_cycle") or 0)
    latest_outcome = str(diagnostics.get("latest_outcome") or "").strip()
    if latest_cycle > 0:
        lines.append(
            f"  最近评审:   Cycle {latest_cycle} / {latest_outcome or 'unknown'}"
        )

    lines.append(f"  已通过结果: {int(diagnostics.get('passed_count') or 0)}")
    lines.append(f"  待修结果:   {int(diagnostics.get('failed_count') or 0)}")
    lines.append(f"  OpenBlockers: {int(diagnostics.get('open_blocker_count') or 0)}")

    scores = diagnostics.get("scores") or {}
    if scores:
        score_pairs = []
        for key in sorted(scores.keys()):
            try:
                score_pairs.append(f"{key}={float(scores[key]):.2f}")
            except (TypeError, ValueError):
                continue
        if score_pairs:
            lines.append(f"  最近评分:   {', '.join(score_pairs)}")

    plateau_status = diagnostics.get("plateau_status") or {}
    if plateau_status:
        stagnant = "yes" if plateau_status.get("stagnant") else "no"
        abort = "yes" if plateau_status.get("abort") else "no"
        switched = "yes" if plateau_status.get("switched_to_closure") else "no"
        streak = int(plateau_status.get("streak") or 0)
        lines.append(
            f"  Plateau:    stagnant={stagnant}, streak={streak}, closure_switch={switched}, abort={abort}"
        )

    plateau_reason = str(diagnostics.get("plateau_reason") or "").strip()
    if plateau_reason:
        lines.append(f"  Plateau原因: {plateau_reason}")

    blockers_preview = diagnostics.get("blockers_preview") or []
    if blockers_preview:
        lines.append("  主要Blocker:")
        for item in blockers_preview:
            lines.append(f"    - {item}")

    return lines


def _write_resume_preview_file(
    *,
    run_dir: str,
    atomic_work_dir: str,
    current_status: str,
    completed_cycles: int,
    extra_cycles: int,
    worker_session_id: str,
    model_display: str,
    thinking: str,
    task_file: str,
    diagnostics: dict,
) -> str:
    preview_path = Path(atomic_work_dir) / "_meta" / "resume_preview.json"
    preview_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now().isoformat(),
        "run_dir": run_dir,
        "atomic_work_dir": atomic_work_dir,
        "current_status": current_status,
        "completed_cycles": completed_cycles,
        "extra_cycles_requested": extra_cycles,
        "resume_total_cycle_limit": completed_cycles + extra_cycles,
        "worker_session_id": worker_session_id,
        "model": model_display,
        "thinking": thinking,
        "task_file": task_file,
        "diagnostics": diagnostics,
    }
    preview_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return str(preview_path)


def _print_run_outputs(run_dir: str, success: bool, exit_code: int) -> None:
    if success:
        print("\n" + "═" * 60)
        print("  ✅ 漏洞挖掘完成")
        print("═" * 60)
        print(f"  执行总结: {os.path.join(run_dir, 'output', 'execution_summary.json')}")
        workspace = os.path.join(run_dir, "workspace")
        if os.path.isdir(workspace):
            for root, dirs, files in os.walk(workspace):
                final_out = os.path.join(root, "final_output")
                if os.path.isdir(final_out):
                    print(f"  最终产出: {final_out}/")
                    if os.path.isfile(os.path.join(final_out, "summary.md")):
                        print("    - summary.md (综合工作报告)")
                    fr_dir = os.path.join(final_out, "results")
                    if os.path.isdir(fr_dir):
                        result_files = sorted(
                            f for f in os.listdir(fr_dir)
                            if f.endswith(".md"))
                        if result_files:
                            print(f"    - results/ ({len(result_files)} 个漏洞报告)")
                            for rf in result_files:
                                print(f"        {rf}")
                    break
        print("═" * 60)
    else:
        print(f"\n❌ 漏洞挖掘失败 (exit_code={exit_code})", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="数据流驱动漏洞挖掘启动器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 基本用法
  python run_vuln_scan.py \
    --data-flow /path/to/data_flow.md \
    --source-dir /path/to/source/

  # 继续已有 run 的当前进度，再追加 5 轮评审
  python run_vuln_scan.py \
    --resume-run-dir runs/my_previous_run \
    --extra-cycles 5

  # 仅查看当前 run 的收敛状态，不真正继续执行
  python run_vuln_scan.py \
    --resume-run-dir runs/my_previous_run \
    --extra-cycles 2 \
    --dry-run-resume

  # 使用自定义配置文件 (复制 config.vuln_scan_default.json 后修改)
  python run_vuln_scan.py \
    --data-flow /path/to/data_flow.md \
    --source-dir /path/to/source/ \
    -c my_config.json

  # 指定模型和运行名称
  python run_vuln_scan.py \
    --data-flow /path/to/data_flow.md \
    --source-dir /path/to/source/ \
    --run-name my_scan \
    --model claude-sonnet-4-20250514 \
    --provider anthropic

  # 使用 litellm 的其他模型
  python run_vuln_scan.py \
    --data-flow /path/to/data_flow.md \
    --source-dir /path/to/source/ \
    --model MiniMax/MiniMax-M2.5 \
    --provider litellm

  # 增加评审轮次
  python run_vuln_scan.py \
    --data-flow /path/to/data_flow.md \
    --source-dir /path/to/source/ \
    --max-cycles 5

  # 执行后清理工作目录
  python run_vuln_scan.py \
    --data-flow /path/to/data_flow.md \
    --source-dir /path/to/source/ \
    --clean
""")

    parser.add_argument(
        "--data-flow", "-d", default=None,
        help="数据流分析结果文件路径 (.md)")
    parser.add_argument(
        "--source-dir", "-s", default=None,
        help="源码目录路径（包含 .c, .h, .asm 文件）")
    parser.add_argument(
        "--resume-run-dir", default=None,
        help="继续已有 runs/<name> 目录的当前进度")
    parser.add_argument(
        "--extra-cycles", type=int, default=5,
        help="resume 模式下额外追加的评审轮次 (默认: 5)")
    parser.add_argument(
        "--dry-run-resume", "--explain-resume",
        dest="dry_run_resume",
        action="store_true",
        help="仅分析当前 run 的收敛状态并输出 resume 预览，不真正继续执行")
    parser.add_argument(
        "--config", "-c", default=None,
        help="自定义配置文件路径 (复制 config.vuln_scan_default.json 后修改; "
             "指定后 --model/--provider/--max-cycles 等参数将被忽略)")
    parser.add_argument(
        "--run-name", "-n", default=None,
        help="运行名称（默认: 根据数据流文件名自动生成）")
    parser.add_argument(
        "--model", "-m", default=None,
        help="AI 模型")
    parser.add_argument(
        "--provider", default=None,
        help="模型提供商 (默认: 从 --model 自动推断，如 github-copilot/gpt-5.4 → github-copilot)")
    parser.add_argument(
        "--thinking", default=None,
        choices=["off", "low", "medium", "high", "xhigh"],
        help="思考深度 (可选: off/low/medium/high/xhigh)")
    parser.add_argument(
        "--max-cycles", type=int, default=10,
        help="最大评审循环次数 (默认: 10)")
    parser.add_argument(
        "--worker-timeout", type=int, default=1800,
        help="Worker 超时时间/秒 (默认: 1800)")
    parser.add_argument(
        "--advisor-timeout", type=int, default=1800,
        help="Advisor 超时时间/秒 (默认: 1800)")
    parser.add_argument(
        "--result-review-concurrency", type=int, default=3,
        help="结果评审并发上限 (默认: 3，仅未指定 -c 时生效)")
    parser.add_argument(
        "--clean", action="store_true",
        help="执行完毕后删除工作目录")

    args = parser.parse_args()

    if args.dry_run_resume and not args.resume_run_dir:
        parser.error("--dry-run-resume/--explain-resume 必须与 --resume-run-dir 一起使用")

    from app.pi_vuln_core.utils.logger import attach_log_file, detach_log_file

    if args.resume_run_dir:
        if args.extra_cycles < 1:
            print("❌ --extra-cycles 必须 >= 1", file=sys.stderr)
            sys.exit(1)

        resume_run_dir = Path(args.resume_run_dir)
        if not resume_run_dir.is_absolute():
            resume_run_dir = PROJECT_ROOT / resume_run_dir
        run_dir = str(resume_run_dir.resolve())
        if not os.path.isdir(run_dir):
            print(f"❌ run 目录不存在: {run_dir}", file=sys.stderr)
            sys.exit(1)

        if args.model and args.provider is None and "/" in args.model:
            args.provider = args.model.split("/")[0]

        from app.pi_vuln_core.resume import (
            build_resume_plan,
            rebuild_review_state,
            resume_run,
        )

        try:
            config_obj, plan = build_resume_plan(run_dir)
            review_state = rebuild_review_state(plan.atomic_work_dir)
            resume_diagnostics = _collect_resume_diagnostics(
                plan.atomic_work_dir,
                review_state=review_state,
            )
        except Exception as e:
            print(f"❌ 无法恢复该 run: {e}", file=sys.stderr)
            sys.exit(1)

        current_provider, current_model, current_thinking = _extract_worker_runtime(config_obj)
        display_provider = args.provider or current_provider
        display_model = args.model or current_model
        display_thinking = args.thinking or current_thinking
        model_display = _format_model_display(display_provider, display_model)

        preview_path = _write_resume_preview_file(
            run_dir=run_dir,
            atomic_work_dir=plan.atomic_work_dir,
            current_status=plan.current_status or "unknown",
            completed_cycles=plan.completed_cycles,
            extra_cycles=args.extra_cycles,
            worker_session_id=plan.worker_session_id,
            model_display=model_display,
            thinking=display_thinking,
            task_file=plan.task_file,
            diagnostics=resume_diagnostics,
        )

        print("═" * 60)
        print("  继续已有漏洞挖掘进度")
        print("═" * 60)
        print(f"  运行目录:   {run_dir}")
        print(f"  工作目录:   {plan.atomic_work_dir}")
        print(f"  当前状态:   {plan.current_status or 'unknown'}")
        print(f"  已完成轮次: {plan.completed_cycles}")
        print(f"  追加轮次:   {args.extra_cycles}")
        for line in _format_resume_diagnostic_lines(
            resume_diagnostics,
            completed_cycles=plan.completed_cycles,
            extra_cycles=args.extra_cycles,
        ):
            print(line)
        print(f"  Worker会话: {plan.worker_session_id}")
        print(f"  模型:       {model_display}")
        if display_thinking:
            print(f"  Thinking:   {display_thinking}")
        print(f"  任务文件:   {plan.task_file}")
        print(f"  预览文件:   {preview_path}")
        print("═" * 60)

        if plan.current_status == "completed":
            print(f"✅ 该 run 已完成，无需继续: {run_dir}")
            sys.exit(0)

        if args.dry_run_resume:
            print("ℹ️ dry-run-resume: 已生成 resume 预览，未实际继续执行。")
            sys.exit(0)

        log_file = os.path.join(run_dir, "run.log")
        actual_log_path = attach_log_file(log_file)
        print(f"  日志文件:   {actual_log_path}")

        exit_code = 1
        try:
            artifacts = asyncio.run(
                resume_run(
                    run_dir=run_dir,
                    extra_cycles=args.extra_cycles,
                    model=args.model,
                    provider=args.provider,
                    thinking=args.thinking,
                    clean_workspace=args.clean,
                )
            )
            exit_code = (
                artifacts.config.execution.on_completion.exit_code_on_success
                if artifacts.result.success
                else artifacts.config.execution.on_completion.exit_code_on_failure
            )
            _print_run_outputs(run_dir, artifacts.result.success, exit_code)
        finally:
            detach_log_file()
            print(f"  完整日志: {actual_log_path}")

        sys.exit(exit_code)

    if not args.data_flow or not args.source_dir:
        parser.error("正常运行模式必须同时提供 --data-flow 和 --source-dir")

    if args.model is None:
        args.model = "claude-sonnet-4-20250514"
    if args.thinking is None:
        args.thinking = "high"
    if args.provider is None:
        if "/" in args.model:
            args.provider = args.model.split("/")[0]
        else:
            args.provider = "anthropic"

    if not os.path.isfile(args.data_flow):
        print(f"❌ 数据流文件不存在: {args.data_flow}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(args.source_dir):
        print(f"❌ 源码目录不存在: {args.source_dir}", file=sys.stderr)
        sys.exit(1)

    if args.result_review_concurrency < 1:
        print("❌ --result-review-concurrency 必须 >= 1", file=sys.stderr)
        sys.exit(1)

    if args.run_name is None:
        stem = Path(args.data_flow).stem
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.run_name = f"{stem}_{timestamp}"

    run_dir = str(PROJECT_ROOT / "runs" / args.run_name)
    os.makedirs(os.path.join(run_dir, "input"), exist_ok=True)
    os.makedirs(os.path.join(run_dir, "output"), exist_ok=True)

    task_content = generate_task_md(args.data_flow, args.source_dir)
    task_file = os.path.join(run_dir, "input", "task.md")
    with open(task_file, "w", encoding="utf-8") as f:
        f.write(task_content)

    if args.config:
        if not os.path.isfile(args.config):
            print(f"❌ 配置文件不存在: {args.config}", file=sys.stderr)
            sys.exit(1)
        config = load_user_config(
            config_path=args.config,
            run_dir=run_dir,
            task_file=task_file,
            run_name=args.run_name,
        )
        config_source = os.path.abspath(args.config)
    else:
        config = generate_config(
            run_dir=run_dir,
            task_file=task_file,
            run_name=args.run_name,
            model=args.model,
            provider=args.provider,
            max_cycles=args.max_cycles,
            worker_timeout=args.worker_timeout,
            advisor_timeout=args.advisor_timeout,
            thinking=args.thinking,
            result_review_concurrency=args.result_review_concurrency,
        )
        config_source = "自动生成"

    config_file = os.path.join(run_dir, "config.json")
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    log_file = os.path.join(run_dir, "run.log")
    actual_log_path = attach_log_file(log_file)

    print("═" * 60)
    print("  数据流驱动漏洞挖掘")
    print("═" * 60)
    print(f"  数据流文件: {os.path.abspath(args.data_flow)}")
    print(f"  源码目录:   {os.path.abspath(args.source_dir)}")
    print(f"  运行名称:   {args.run_name}")
    print(f"  模型:       {_format_model_display(args.provider, args.model)}")
    print(f"  Thinking:   {args.thinking}")
    print(f"  评审轮次:   {args.max_cycles}")
    print(f"  运行目录:   {run_dir}")
    print(f"  配置文件:   {config_file}")
    print(f"  配置来源:   {config_source}")
    print(f"  任务文件:   {task_file}")
    print(f"  日志文件:   {actual_log_path}")
    print("═" * 60)

    from app.pi_vuln_core.main import main as framework_main
    from app.pi_vuln_core.utils.logger import setup_logging

    setup_logging("INFO")
    exit_code = 1
    try:
        exit_code = asyncio.run(
            framework_main(config_file, clean_workspace=args.clean))
        _print_run_outputs(run_dir, exit_code == 0, exit_code)
    finally:
        detach_log_file()
        print(f"  完整日志: {actual_log_path}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
