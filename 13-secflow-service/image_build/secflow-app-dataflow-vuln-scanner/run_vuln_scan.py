#!/usr/bin/env python3
"""
漏洞挖掘便捷启动器

用法:
  python run_vuln_scan.py \
    --data-flow /path/to/data_flow_analysis.md \
    --source-dir /path/to/source_code/ \
    [--run-name my_scan] \
    [--model icsl/zai-org/GLM-5] \
    [--max-cycles 6] \
    [--clean]

功能:
  1. 根据输入参数自动生成 task.md 和 config.json
  2. 调用框架主程序执行漏洞挖掘工作流
  3. 工作流包含: Worker分析 → 自我反思 → 总结 → 全局评审 → 结果评审 → (循环)
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from app.pi_vuln_core.review.profile import (
    apply_profile_runtime_policy_to_config,
    apply_profile_thinking_to_config,
    get_review_profile_policy,
    get_review_score_threshold_policy,
    normalize_review_profile,
    resolve_profile_thinking,
)
from app.pi_vuln_core.utils.win_compat import IS_WINDOWS, ensure_event_loop_policy, from_msys_path
from app.time_utils import isoformat_local, now_local

# 项目根目录
PROJECT_ROOT = Path(__file__).resolve().parent
PROMPTS_DIR = PROJECT_ROOT / "prompts" / "vuln_scan"
DEFAULT_CONFIG = PROJECT_ROOT / "config.vuln_scan_default.json"
DEFAULT_MODEL = "icsl/zai-org/GLM-5"
DEFAULT_PROVIDER = "icsl"
def _now_iso() -> str:
    return isoformat_local(now_local()) or ""


def _run_timestamps_path(run_dir: str | Path) -> Path:
    return Path(run_dir) / "_meta" / "run_timestamps.json"


def _load_run_timestamps(run_dir: str | Path) -> dict:
    path = _run_timestamps_path(run_dir)
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _write_run_timestamps(run_dir: str | Path, **updates) -> dict:
    path = _run_timestamps_path(run_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _load_run_timestamps(run_dir)
    for key, value in updates.items():
        payload[key] = value
    payload["last_updated_at"] = _now_iso()
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload


def _mark_run_started(run_dir: str | Path, *, mode: str) -> None:
    payload = _load_run_timestamps(run_dir)
    started_at = payload.get("started_at") or _now_iso()
    updates = {
        "started_at": started_at,
        "status": "running",
        "last_mode": mode,
        "finished_at": None,
        "exit_code": None,
    }
    if mode == "resume":
        updates["resumed_at"] = _now_iso()
    _write_run_timestamps(run_dir, **updates)


def _mark_run_finished(run_dir: str | Path, *, status: str, exit_code: int) -> None:
    _write_run_timestamps(
        run_dir,
        status=status,
        exit_code=exit_code,
        finished_at=_now_iso(),
    )


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


def _windows_short_ids(run_name: str) -> tuple[str, str]:
    """Windows 路径长度兜底：缩短 workspace 内部目录名。"""
    digest = hashlib.sha1(run_name.encode("utf-8", errors="ignore")).hexdigest()[:10]
    return f"run_{digest}", "initial_001"


def _workspace_root_for_run(run_dir: str) -> str:
    # Windows 默认路径长度限制较严格，使用更短的 ws 目录名。
    return os.path.join(run_dir, "ws" if IS_WINDOWS else "workspace")


def generate_config(
    run_dir: str,
    task_file: str,
    run_name: str,
    model: str = DEFAULT_MODEL,
    provider: str | None = None,
    max_cycles: int | None = 6,
    worker_timeout: int | None = None,  # deprecated; RPC mode does not use framework watchdogs
    advisor_timeout: int | None = None,  # deprecated; kept for external callers/tests
    thinking: str = "high",  # deprecated: resolved from model + review_profile
    result_review_concurrency: int = 3,
    review_profile: str = "balanced",
    timeout_max_retries: int = 3,
    timeout_retry_interval_seconds: int = 30,
) -> dict:
    """生成完整的配置字典"""

    prompts_dir = str(PROMPTS_DIR)
    model = _normalize_model_name(model, provider)
    normalized_review_profile = normalize_review_profile(review_profile)
    profile_policy = get_review_profile_policy(normalized_review_profile)
    resolved_thinking = resolve_profile_thinking(model, profile_policy.name)
    completeness_score_policy = get_review_score_threshold_policy(
        profile_policy.name,
        "global_completeness",
    )
    depth_score_policy = get_review_score_threshold_policy(
        profile_policy.name,
        "global_depth",
    )
    effective_max_cycles = (
        int(max_cycles)
        if max_cycles is not None else
        profile_policy.default_max_review_cycles
    )
    if not profile_policy.review_enabled:
        effective_max_cycles = 1
    execution_id, task_id = _windows_short_ids(run_name) if IS_WINDOWS else (f"{run_name}_run_001", run_name)
    worker_sdk_specific = {"thinking": resolved_thinking} if resolved_thinking else {}
    advisor_sdk_specific = {"tools": "read,bash"}
    effective_timeout_max_retries = max(int(timeout_max_retries), 1)
    effective_timeout_retry_interval_seconds = max(int(timeout_retry_interval_seconds), 0)
    if resolved_thinking:
        advisor_sdk_specific["thinking"] = resolved_thinking

    return {
        "version": "1.0",
        "global": {
            "workspace_root": _workspace_root_for_run(run_dir),
            "log_level": "INFO",
            "max_workflow_retry": 1,
            "max_review_cycles": effective_max_cycles,
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
                    "transport": "rpc",
                    "api_max_retries": 0,
                    "api_retry_delay": 10,
                    "pi_max_retries": 0,
                    "pi_retry_delay": 10,
                    "timeout_max_retries": effective_timeout_max_retries,
                    "timeout_retry_delay": effective_timeout_retry_interval_seconds,
                    "timeout_retry_interval_seconds": effective_timeout_retry_interval_seconds,
                    "max_internal_turns": 0,
                    "rpc_stdout_trace_bytes": profile_policy.worker_rpc_stdout_trace_bytes,
                    "rpc_stdout_abort_bytes": profile_policy.worker_rpc_stdout_abort_bytes,
                    "sdk_specific": worker_sdk_specific,
                },
            },
            {
                "id": "pi-advisor",
                "name": "Pi Agent Advisor",
                "type": "pi_agent",
                "reset_context": True,
                "runtime_config": {
                    "model": model,
                    "transport": "rpc",
                    "api_max_retries": 0,
                    "api_retry_delay": 10,
                    "pi_max_retries": 0,
                    "pi_retry_delay": 10,
                    "advisor_runtime_retries": 0,
                    "timeout_max_retries": effective_timeout_max_retries,
                    "timeout_retry_delay": effective_timeout_retry_interval_seconds,
                    "timeout_retry_interval_seconds": effective_timeout_retry_interval_seconds,
                    "max_internal_turns": 0,
                    "rpc_stdout_trace_bytes": profile_policy.advisor_rpc_stdout_trace_bytes,
                    "rpc_stdout_abort_bytes": profile_policy.advisor_rpc_stdout_abort_bytes,
                    "sdk_specific": advisor_sdk_specific,
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
                        "max_review_cycles": effective_max_cycles,
                        "review_profile": profile_policy.name,
                        "review_enabled": profile_policy.review_enabled,
                        "max_worker_turns_per_cycle": profile_policy.max_worker_turns_per_cycle,
                        "reflection_passes_per_cycle": profile_policy.reflection_passes_per_cycle,
                        "reflection_max_internal_turns": 0,
                        "reflection_rpc_stdout_trace_bytes": profile_policy.reflection_rpc_stdout_trace_bytes,
                        "reflection_rpc_stdout_abort_bytes": profile_policy.reflection_rpc_stdout_abort_bytes,
                        "min_discovery_cycles_before_pass": profile_policy.min_discovery_cycles_before_pass,
                        "progress_required_after_cycle": profile_policy.progress_required_after_cycle,
                        "progress_no_signal_closure_streak": profile_policy.progress_no_signal_closure_streak,
                        "progress_no_signal_abort_streak": profile_policy.progress_no_signal_abort_streak,
                        "min_evidence_artifacts": profile_policy.min_evidence_artifacts,
                        "required_pattern_families": list(profile_policy.required_pattern_families),
                        "reset_worker_session_per_cycle": False,
                        "plateau_closure_streak": profile_policy.progress_no_signal_closure_streak,
                        "plateau_abort_streak": profile_policy.progress_no_signal_abort_streak,
                        "same_issue_stagnation_threshold": 2,
                        "same_issue_abort_threshold": 3,
                        "per_issue_attempt_budget": 2,
                        "summary_repair_attempt_budget": 2,
                        "analysis_closure_cycles": 1,
                        "issue_churn_closure_window": 2,
                        "issue_churn_abort_window": 3,
                        "score_min_delta": 0.03,
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
                                    "rework_prompt_file": os.path.join(
                                        prompts_dir, "worker_rework.md"),
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
                                    "instance_id": "global_completeness",
                                    "agent_id": "pi-advisor",
                                    "role_name": "全面性审计",
                                    "re_review_on_cycle": True,
                                    "system_prompt_file": os.path.join(
                                        prompts_dir, "global_review_completeness_sys.md"),
                                    "user_prompt_template": os.path.join(
                                        prompts_dir, "global_review_completeness_user.md"),
                                    "score_fields": list(completeness_score_policy.score_fields),
                                    "score_thresholds_start": completeness_score_policy.score_thresholds_start,
                                    "score_thresholds": completeness_score_policy.score_thresholds,
                                    "score_threshold_ramp_cycles": completeness_score_policy.score_threshold_ramp_cycles,
                                },
                                {
                                    "instance_id": "global_depth",
                                    "agent_id": "pi-advisor",
                                    "role_name": "深入性审计",
                                    "re_review_on_cycle": True,
                                    "system_prompt_file": os.path.join(
                                        prompts_dir, "global_review_depth_sys.md"),
                                    "user_prompt_template": os.path.join(
                                        prompts_dir, "global_review_depth_user.md"),
                                    "score_fields": list(depth_score_policy.score_fields),
                                    "score_thresholds_start": depth_score_policy.score_thresholds_start,
                                    "score_thresholds": depth_score_policy.score_thresholds,
                                    "score_threshold_ramp_cycles": depth_score_policy.score_threshold_ramp_cycles,
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
                "task_id": task_id,
            },
            "output_dir": os.path.join(run_dir, "output"),
            "execution_id": execution_id,
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
    execution_id, task_id = _windows_short_ids(run_name) if IS_WINDOWS else (f"{run_name}_run_001", run_name)

    config.setdefault("global", {})
    config["global"]["workspace_root"] = _workspace_root_for_run(run_dir)

    config.setdefault("execution", {})
    config["execution"]["entry_workflow"] = config["execution"].get(
        "entry_workflow", "vuln_scan_pipeline")
    config["execution"]["entry_workflow_type"] = "composite"
    config["execution"]["input_task"] = {
        "task_file": task_file,
        "task_id": task_id,
    }
    config["execution"]["output_dir"] = os.path.join(run_dir, "output")
    config["execution"]["execution_id"] = execution_id
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

    _apply_profile_resolution_to_config(config)
    return config


def _iter_atomic_workflows(config: dict):
    for workflow in ((config.get("workflows") or {}).get("atomic") or []):
        if isinstance(workflow, dict):
            yield workflow


def _extract_review_profile_from_config(config: dict) -> str:
    for workflow in _iter_atomic_workflows(config):
        engine = workflow.get("engine")
        if isinstance(engine, dict) and (engine.get("review_profile") or workflow.get("id") == "vuln_scan"):
            return normalize_review_profile(engine.get("review_profile"))
    return "balanced"


def _apply_profile_resolution_to_config(config: dict) -> None:
    profile_policy = get_review_profile_policy(_extract_review_profile_from_config(config))
    if not profile_policy.review_enabled:
        config.setdefault("global", {})["max_review_cycles"] = 1
    for workflow in _iter_atomic_workflows(config):
        engine = workflow.setdefault("engine", {})
        if "review_profile" in engine or workflow.get("id") == "vuln_scan":
            engine["review_profile"] = profile_policy.name
            engine["review_enabled"] = profile_policy.review_enabled
            if not profile_policy.review_enabled:
                engine["max_review_cycles"] = 1
            engine.setdefault(
                "progress_required_after_cycle",
                profile_policy.progress_required_after_cycle,
            )
            engine.setdefault(
                "progress_no_signal_closure_streak",
                profile_policy.progress_no_signal_closure_streak,
            )
            engine.setdefault(
                "progress_no_signal_abort_streak",
                profile_policy.progress_no_signal_abort_streak,
            )
    apply_profile_runtime_policy_to_config(config, profile_policy.name)
    apply_profile_thinking_to_config(config, profile_policy.name)


def _apply_cli_timeout_retry_to_config(
    config: dict,
    *,
    timeout_max_retries: int | None,
    timeout_retry_interval_seconds: int | None,
) -> None:
    if timeout_max_retries is None and timeout_retry_interval_seconds is None:
        return
    effective_max_retries = max(int(timeout_max_retries if timeout_max_retries is not None else 3), 1)
    effective_interval_seconds = max(int(timeout_retry_interval_seconds if timeout_retry_interval_seconds is not None else 30), 0)
    for agent in config.get("agents") or []:
        if not isinstance(agent, dict) or agent.get("type") != "pi_agent":
            continue
        runtime_config = agent.setdefault("runtime_config", {})
        runtime_config["timeout_max_retries"] = effective_max_retries
        runtime_config["timeout_retry_delay"] = effective_interval_seconds
        runtime_config["timeout_retry_interval_seconds"] = effective_interval_seconds


def _resolve_prompt_paths(config: dict) -> None:
    """
    将配置中的相对 prompt 路径解析为绝对路径。

    规则: 以 'prompts/' 开头的路径视为相对于项目根目录。
    已是绝对路径的不动。
    """
    prompt_keys = (
        "system_prompt_file", "user_prompt_file", "rework_prompt_file",
        "user_prompt_template", "prompt_file",
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


def _normalize_model_name(model: str | None, provider: str | None = None) -> str:
    model = (model or "").strip()
    provider = (provider or "").strip()
    if not model:
        model = DEFAULT_MODEL
    if "/" in model:
        return model
    if provider:
        return f"{provider}/{model}"
    return f"{DEFAULT_PROVIDER}/{model}"


def _format_model_display(model: str | None) -> str:
    return _normalize_model_name(model)


def _extract_worker_runtime(config_obj) -> tuple[str, str]:
    for agent in getattr(config_obj, "agents", []):
        if getattr(agent, "id", "") != "pi-worker":
            continue
        runtime_cfg = agent.runtime_config
        sdk_cfg = runtime_cfg.get("sdk_specific", {})
        model = runtime_cfg.get("model", "")
        legacy_provider = sdk_cfg.get("provider", "")
        return _normalize_model_name(model, legacy_provider), sdk_cfg.get("thinking", "")
    return "", ""


def _extract_review_profile_from_config_obj(config_obj) -> str:
    for workflow in getattr(getattr(config_obj, "workflows", None), "atomic", []) or []:
        engine = getattr(workflow, "engine", None)
        if engine is not None:
            return normalize_review_profile(getattr(engine, "review_profile", "balanced"))
    return "balanced"


def _extract_worker_runtime_from_config_dict(config: dict) -> tuple[str, str]:
    for agent in config.get("agents") or []:
        if not isinstance(agent, dict) or agent.get("id") != "pi-worker":
            continue
        runtime_cfg = agent.get("runtime_config") or {}
        sdk_cfg = runtime_cfg.get("sdk_specific") or {}
        model = runtime_cfg.get("model", "")
        legacy_provider = sdk_cfg.get("provider", "")
        return _normalize_model_name(model, legacy_provider), str(sdk_cfg.get("thinking") or "")
    return "", ""


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
    feedback_cycle, feedback_data = _load_latest_cycle_record(meta_dir / "review_feedback")

    latest_cycle = max(summary_cycle, metrics_cycle, feedback_cycle)
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

    issues = []
    if isinstance(feedback_data, dict) and isinstance(feedback_data.get("issues"), list):
        issues = list(feedback_data.get("issues") or [])
    elif isinstance(summary_data, dict):
        issues = list(
            ((summary_data.get("global_review") or {}).get("issues") or [])
        )
    elif review_state is not None and hasattr(review_state, "get_recent_issues"):
        issues = list(review_state.get_recent_issues(last_n=1))

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

    issues_preview = []
    for item in issues[:3]:
        if not isinstance(item, dict):
            issues_preview.append(str(item))
            continue
        issue_id = str(item.get("id") or "").strip() or "(no-id)"
        target = str(item.get("target") or "").strip()
        action = str(item.get("required_action") or item.get("detail") or "").strip()
        preview = f"[{issue_id}]"
        if target:
            preview += f" {target}"
        if action:
            preview += f" | {action}"
        issues_preview.append(preview)

    global_review_summary = (summary_data.get("global_review") or {}) if isinstance(summary_data, dict) else {}
    return {
        "latest_cycle": latest_cycle,
        "latest_outcome": str(summary_data.get("outcome") or "").strip() if isinstance(summary_data, dict) else "",
        "workflow_mode": workflow_mode or "discovery",
        "passed_count": passed_count,
        "failed_count": failed_count,
        "issue_count": len(issues),
        "issues_preview": issues_preview,
        "failed_global_advisor_id": str(global_review_summary.get("failed_advisor_id") or "").strip(),
        "failed_global_role_name": str(global_review_summary.get("failed_role_name") or "").strip(),
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
    failed_global_advisor_id = str(diagnostics.get("failed_global_advisor_id") or "").strip()
    failed_global_role_name = str(diagnostics.get("failed_global_role_name") or "").strip()
    if failed_global_advisor_id:
        failed_label = failed_global_advisor_id
        if failed_global_role_name:
            failed_label += f" / {failed_global_role_name}"
        lines.append(f"  失败层级:   {failed_label}")

    lines.append(f"  已通过结果: {int(diagnostics.get('passed_count') or 0)}")
    lines.append(f"  待修结果:   {int(diagnostics.get('failed_count') or 0)}")
    lines.append(f"  Issues: {int(diagnostics.get('issue_count') or 0)}")

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

    issues_preview = diagnostics.get("issues_preview") or []
    if issues_preview:
        lines.append("  主要Issue:")
        for item in issues_preview:
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
    timeout_detected: bool = False,
    timeout_call_dir: str = "",
    timeout_agent_id: str = "",
    timeout_error: str = "",
    resume_state: str = "",
    checkpoint_cycle: int = 0,
    checkpoint_phase: str = "",
    checkpoint_step_key: str = "",
    checkpoint_status: str = "",
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
        "resume_state": resume_state,
        "step_checkpoint": {
            "cycle": checkpoint_cycle,
            "phase": checkpoint_phase,
            "step_key": checkpoint_step_key,
            "status": checkpoint_status,
        },
        "timeout_resume": {
            "detected": timeout_detected,
            "call_dir": timeout_call_dir,
            "agent_id": timeout_agent_id,
            "error": timeout_error,
        },
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
        workspace_candidates = [
            _workspace_root_for_run(run_dir),
            os.path.join(run_dir, "workspace"),  # legacy
        ]
        for workspace in dict.fromkeys(workspace_candidates):
            if not os.path.isdir(workspace):
                continue
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
                    print("═" * 60)
                    return
        print("═" * 60)
    else:
        print(f"\n❌ 漏洞挖掘失败 (exit_code={exit_code})", file=sys.stderr)


def main(argv: list[str] | None = None):
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
    --model icsl/zai-org/GLM-5

  # 使用 litellm 的其他模型
  python run_vuln_scan.py \
    --data-flow /path/to/data_flow.md \
    --source-dir /path/to/source/ \
    --model litellm/MiniMax/MiniMax-M2.5

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
             "指定后 --model/--max-cycles 等参数将被忽略)")
    parser.add_argument(
        "--run-name", "-n", default=None,
        help="运行名称（默认: 根据数据流文件名自动生成）")
    parser.add_argument(
        "--runs-root", default=None,
        help="runs 根目录（默认: run_vuln_scan.py 同目录下的 runs/）")
    parser.add_argument(
        "--model", "-m", default=None,
        help="AI 模型，必须使用 provider/model 格式，例如 icsl/zai-org/GLM-5")
    parser.add_argument(
        "--provider", default=None, help=argparse.SUPPRESS)
    parser.add_argument(
        "--thinking", default=None,
        choices=["off", "low", "medium", "high", "xhigh"],
        help="兼容旧参数；最终 thinking 由后端按 model + review-profile 自动解析")
    parser.add_argument(
        "--max-cycles", type=int, default=None,
        help="最大评审循环次数 (默认随 --review-profile: fast=1, balanced=6, audit=10；strict 映射 audit)")
    parser.add_argument(
        "--timeout-max-retries", type=int, default=None,
        help="Pi/provider 自身返回 timeout 时的最大处理次数 (默认: 3；服务启动会显式传入)")
    parser.add_argument(
        "--timeout-retry-interval-seconds", type=int, default=None,
        help="Pi/provider 自身返回 timeout 后再次发送同一提示词前的等待秒数 (默认: 30；服务启动会显式传入)")
    parser.add_argument(
        "--result-review-concurrency", type=int, default=3,
        help="结果评审并发上限 (默认: 3，仅未指定 -c 时生效)")
    parser.add_argument(
        "--review-profile",
        choices=["fast", "balanced", "strict", "audit"],
        default="balanced",
        help="评审强度档位: fast/balanced/audit；strict 兼容映射为 audit (默认: balanced，仅未指定 -c 时生效)")
    parser.add_argument(
        "--clean", action="store_true",
        help="执行完毕后删除工作目录")

    args = parser.parse_args(argv)

    # Git Bash 会转换命令行路径，但 JSON/某些调用链可能仍传入 /c/... 形式；这里兜底规范化。
    for _path_arg in ("data_flow", "source_dir", "resume_run_dir", "config", "runs_root"):
        _value = getattr(args, _path_arg, None)
        if _value:
            setattr(args, _path_arg, from_msys_path(_value))

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

        if args.provider:
            args.model = _normalize_model_name(args.model, args.provider)

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

        current_model, current_thinking = _extract_worker_runtime(config_obj)
        display_model = _normalize_model_name(args.model, args.provider) if args.model else current_model
        display_thinking = resolve_profile_thinking(
            display_model,
            _extract_review_profile_from_config_obj(config_obj),
        ) or current_thinking
        model_display = _format_model_display(display_model)

        preview_path = _write_resume_preview_file(
            run_dir=run_dir,
            atomic_work_dir=plan.atomic_work_dir,
            current_status=plan.current_status or "unknown",
            completed_cycles=plan.completed_cycles,
            extra_cycles=args.extra_cycles,
            worker_session_id=plan.worker_session_id,
            timeout_detected=plan.timeout_detected,
            timeout_call_dir=plan.timeout_call_dir,
            timeout_agent_id=plan.timeout_agent_id,
            timeout_error=plan.timeout_error,
            resume_state=plan.resume_state,
            checkpoint_cycle=plan.checkpoint_cycle,
            checkpoint_phase=plan.checkpoint_phase,
            checkpoint_step_key=plan.checkpoint_step_key,
            checkpoint_status=plan.checkpoint_status,
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
        if plan.checkpoint_phase:
            print(
                f"  Step检查点: cycle={plan.checkpoint_cycle}, "
                f"phase={plan.checkpoint_phase}, step={plan.checkpoint_step_key or '-'}, "
                f"status={plan.checkpoint_status or '-'}"
            )
        if plan.timeout_detected:
            print(f"  超时恢复点: {plan.resume_state or 'unknown'}")
            print(f"  超时调用:   {plan.timeout_call_dir}")
            if plan.timeout_error:
                print(f"  超时错误:   {plan.timeout_error}")
        print(f"  模型:       {model_display}")
        if display_thinking:
            print(f"  Thinking:   {display_thinking}")
        print(f"  任务文件:   {plan.task_file}")
        print(f"  预览文件:   {preview_path}")
        print("═" * 60)

        if args.dry_run_resume:
            print("ℹ️ dry-run-resume: 已生成 resume 预览，未实际继续执行。")
            sys.exit(0)

        _mark_run_started(run_dir, mode="resume")
        log_file = os.path.join(run_dir, "run.log")
        actual_log_path = attach_log_file(log_file)
        print(f"  日志文件:   {actual_log_path}")

        exit_code = 1
        try:
            ensure_event_loop_policy()
            artifacts = asyncio.run(
                resume_run(
                    run_dir=run_dir,
                    extra_cycles=args.extra_cycles,
                    model=_normalize_model_name(args.model, args.provider) if args.model else None,
                    provider=None,
                    thinking=None,
                    clean_workspace=args.clean,
                )
            )
            exit_code = (
                artifacts.config.execution.on_completion.exit_code_on_success
                if artifacts.result.success
                else artifacts.config.execution.on_completion.exit_code_on_failure
            )
            _print_run_outputs(run_dir, artifacts.result.success, exit_code)
        except KeyboardInterrupt:
            exit_code = 130
            print("⚠️ 恢复执行被用户中断，已保留 workspace，并写入 abnormal_exit 记录。", file=sys.stderr)
        finally:
            _mark_run_finished(
                run_dir,
                status=("completed" if exit_code == 0 else "interrupted" if exit_code == 130 else "failed"),
                exit_code=exit_code,
            )
            detach_log_file()
            print(f"  完整日志: {actual_log_path}")

        sys.exit(exit_code)

    if not args.data_flow or not args.source_dir:
        parser.error("正常运行模式必须同时提供 --data-flow 和 --source-dir")

    if args.model is None:
        args.model = DEFAULT_MODEL
    else:
        args.model = _normalize_model_name(args.model, args.provider)

    if not os.path.isfile(args.data_flow):
        print(f"❌ 数据流文件不存在: {args.data_flow}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(args.source_dir):
        print(f"❌ 源码目录不存在: {args.source_dir}", file=sys.stderr)
        sys.exit(1)

    if args.timeout_max_retries is not None and args.timeout_max_retries < 1:
        print("❌ --timeout-max-retries 必须 >= 1", file=sys.stderr)
        sys.exit(1)

    if args.timeout_retry_interval_seconds is not None and args.timeout_retry_interval_seconds < 0:
        print("❌ --timeout-retry-interval-seconds 必须 >= 0", file=sys.stderr)
        sys.exit(1)

    if args.result_review_concurrency < 1:
        print("❌ --result-review-concurrency 必须 >= 1", file=sys.stderr)
        sys.exit(1)

    if args.run_name is None:
        stem = Path(args.data_flow).stem
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.run_name = f"{stem}_{timestamp}"

    profile_policy = get_review_profile_policy(args.review_profile)
    effective_max_cycles = (
        args.max_cycles
        if args.max_cycles is not None else
        profile_policy.default_max_review_cycles
    )
    if not profile_policy.review_enabled:
        effective_max_cycles = 1

    runs_root = Path(args.runs_root).resolve() if args.runs_root else PROJECT_ROOT / "runs"
    run_dir = str(runs_root / args.run_name)
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
        _apply_cli_timeout_retry_to_config(
            config,
            timeout_max_retries=args.timeout_max_retries,
            timeout_retry_interval_seconds=args.timeout_retry_interval_seconds,
        )
        config_source = os.path.abspath(args.config)
    else:
        config = generate_config(
            run_dir=run_dir,
            task_file=task_file,
            run_name=args.run_name,
            model=args.model,
            provider=None,
            max_cycles=effective_max_cycles,
            thinking=args.thinking,
            result_review_concurrency=args.result_review_concurrency,
            review_profile=args.review_profile,
            timeout_max_retries=args.timeout_max_retries if args.timeout_max_retries is not None else 3,
            timeout_retry_interval_seconds=args.timeout_retry_interval_seconds if args.timeout_retry_interval_seconds is not None else 30,
        )
        config_source = "自动生成"

    model_display, resolved_thinking_display = _extract_worker_runtime_from_config_dict(config)
    resolved_review_profile_display = _extract_review_profile_from_config(config)

    config_file = os.path.join(run_dir, "config.json")
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    _mark_run_started(run_dir, mode="fresh")
    log_file = os.path.join(run_dir, "run.log")
    actual_log_path = attach_log_file(log_file)

    print("═" * 60)
    print("  数据流驱动漏洞挖掘")
    print("═" * 60)
    print(f"  数据流文件: {os.path.abspath(args.data_flow)}")
    print(f"  源码目录:   {os.path.abspath(args.source_dir)}")
    print(f"  运行名称:   {args.run_name}")
    print(f"  模型:       {model_display or _format_model_display(args.model)}")
    print(f"  Thinking:   {resolved_thinking_display or '不支持/未启用'}")
    print(f"  评审轮次:   {((config.get('global') or {}).get('max_review_cycles') or effective_max_cycles)}")
    print(f"  评审档位:   {resolved_review_profile_display if not args.config else f'配置文件指定({resolved_review_profile_display})'}")
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
        ensure_event_loop_policy()
        exit_code = asyncio.run(
            framework_main(config_file, clean_workspace=args.clean))
        _print_run_outputs(run_dir, exit_code == 0, exit_code)
    except KeyboardInterrupt:
        exit_code = 130
        print("⚠️ 执行被用户中断，已保留 workspace，并写入 abnormal_exit 记录。", file=sys.stderr)
    finally:
        _mark_run_finished(
            run_dir,
            status=("completed" if exit_code == 0 else "interrupted" if exit_code == 130 else "failed"),
            exit_code=exit_code,
        )
        detach_log_file()
        print(f"  完整日志: {actual_log_path}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
