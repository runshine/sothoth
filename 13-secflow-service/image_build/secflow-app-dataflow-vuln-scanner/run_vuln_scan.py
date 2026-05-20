#!/usr/bin/env python3
"""
漏洞挖掘便捷启动器

用法:
  python run_vuln_scan.py \
    --data-flow /path/to/dataflows/ \
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
import re
import sys
import uuid
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


def _runtime_dir_for_run(run_dir: str | Path) -> Path:
    root = Path(run_dir)
    runtime = root / "run"
    if (root / "config.json").exists() and not (runtime / "config.json").exists():
        return root
    return runtime


def _run_timestamps_path(run_dir: str | Path) -> Path:
    return _runtime_dir_for_run(run_dir) / "_meta" / "run_timestamps.json"


def _load_run_timestamps(run_dir: str | Path) -> dict:
    path = _run_timestamps_path(run_dir)
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        tmp_path.write_text(content, encoding="utf-8")
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _write_run_timestamps(run_dir: str | Path, **updates) -> dict:
    path = _run_timestamps_path(run_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _load_run_timestamps(run_dir)
    for key, value in updates.items():
        payload[key] = value
    payload["last_updated_at"] = _now_iso()
    _atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2))
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


DATA_FLOW_FILE_SUFFIXES = {".md", ".txt"}


def discover_data_flow_files(data_flow_path: str | Path) -> list[Path]:
    """Return data-flow result files from a directory, with legacy file support."""
    path = Path(data_flow_path)
    if path.is_file():
        return [path]
    if not path.is_dir():
        return []
    return sorted(
        item
        for item in path.rglob("*")
        if item.is_file() and item.suffix.lower() in DATA_FLOW_FILE_SUFFIXES
    )


def data_flow_manifest_input(data_flow_path: str | Path) -> dict[str, object]:
    path = Path(data_flow_path)
    data_flow_dir = path if path.is_dir() else path.parent
    return {
        "data_flow_dir": os.path.abspath(data_flow_dir),
        "data_flow_files": [os.path.abspath(item) for item in discover_data_flow_files(path)],
    }


def generate_task_md(dataflow_dir: str, source_dir: str) -> str:
    """根据数据流污点分析目录和源码目录生成 task.md 内容。"""

    dataflow_root = Path(dataflow_dir)
    source_root = Path(source_dir)
    dataflow_files = discover_data_flow_files(dataflow_root)
    final_report = _find_final_report(dataflow_root, dataflow_files)
    sub_reports = _find_sub_dataflow_reports(dataflow_root, dataflow_files)
    overview = _extract_dataflow_overview(final_report, dataflow_files)
    marker_counts = _extract_analysis_marker_counts(final_report, dataflow_files)
    source_files = _discover_source_files(source_root)

    root_name = str(overview.get("root_function") or "").strip()
    tracked_count = overview.get("tracked_count")
    if root_name and tracked_count:
        target_scope = f"入口函数 `{root_name}` 及调用链中共 {tracked_count} 个跟踪函数"
    elif root_name:
        target_scope = f"入口函数 `{root_name}` 及其调用链函数"
    elif tracked_count:
        target_scope = f"入口函数及调用链中共 {tracked_count} 个跟踪函数"
    else:
        target_scope = "入口函数及其调用链函数"
    dataflow_lines = [f"`{os.path.abspath(dataflow_root)}`", ""]
    if final_report:
        dataflow_lines.append(
            f"- `{os.path.abspath(final_report)}`：从入口函数开始的整体污点分析报告，"
            "包含根函数、调用链函数列表、污点源、传播路径、DIRECT_SINK/USED/EXPORT/CLEANED "
            "终点和安全备注。"
        )
    elif dataflow_root.is_file():
        dataflow_lines.append(
            f"- `{os.path.abspath(dataflow_root)}`：数据流污点分析结果文件，用于定位入口、污点源、传播路径和终点。"
        )
    else:
        dataflow_lines.append("- 未发现 `final_report.md`，需要从目录中的数据流结果文件建立入口和调用链视图。")

    if sub_reports:
        dataflow_subdir = dataflow_root / "dataflow"
        subdir_label = os.path.abspath(dataflow_subdir) if dataflow_subdir.is_dir() else "dataflow/"
        dataflow_lines.append(
            f"- `{subdir_label}`：子函数级污点分析结果，共 {len(sub_reports)} 个 `.md` 文件。"
            "每个文件对应一个被跟入函数，记录该函数接收的污点、内部传播、导入对象、终点和高危操作。"
        )
    elif dataflow_root.is_dir():
        dataflow_lines.append("- `dataflow/`：未发现子函数级 `.md` 报告，请以整体报告和源码为准。")

    dataflow_lines.append("")
    dataflow_lines.append("数据流标记含义：")
    dataflow_lines.extend(_format_marker_meaning_lines())

    marker_lines = _format_marker_counts(marker_counts)
    if marker_lines:
        dataflow_lines.append("")
        dataflow_lines.append("分析概览：")
        dataflow_lines.extend(marker_lines)

    source_lines = [f"`{os.path.abspath(source_root)}`", ""]
    if source_files:
        source_lines.append("该目录包含反编译源码和辅助文件：")
        source_lines.extend(_format_source_file_lines(source_root, source_files))
        source_lines.append("")
        source_lines.append(
            "源码用于验证数据流报告中的函数签名、行号、条件判断、内存访问、拷贝长度、"
            "指针偏移、外部调用和清洗逻辑。"
        )
    else:
        source_lines.append("当前未枚举到 `.c`、`.h` 或 `.asm` 文件，请确认源码目录路径是否正确。")

    return f"""# 漏洞挖掘任务

## 任务目标
基于数据流污点分析结果，对{target_scope}进行漏洞挖掘。重点验证污点从入口参数、派生对象、网络或管道数据进入后，在源码中的传播、边界检查、清洗、外部调用和危险内存操作是否形成可利用问题。

## 输入目录

### 数据流污点分析结果目录
{chr(10).join(dataflow_lines)}

### 源码目录
{chr(10).join(source_lines)}

## 分析要求
1. 先阅读 `final_report.md`，建立入口函数、调用链和高危传播路径的整体视图。
2. 再按需要阅读 `dataflow/` 中对应的子函数报告，补齐跨函数传播、导入污点对象和终点语义。
3. 对照源码目录中的反编译源码按数据流污点传播路径进行漏洞挖掘和报告生成。
4. 输出漏洞时必须给出从污点源到危险操作的证据链，并引用数据流报告文件和源码位置。
"""


def _read_text_if_exists(path: Path | None) -> str:
    if not path or not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _find_final_report(dataflow_root: Path, dataflow_files: list[Path]) -> Path | None:
    if dataflow_root.is_file():
        return dataflow_root
    candidate = dataflow_root / "final_report.md"
    if candidate.is_file():
        return candidate
    for item in dataflow_files:
        if item.name == "final_report.md":
            return item
    return dataflow_files[0] if len(dataflow_files) == 1 else None


def _find_sub_dataflow_reports(dataflow_root: Path, dataflow_files: list[Path]) -> list[Path]:
    dataflow_subdir = dataflow_root / "dataflow"
    if dataflow_subdir.is_dir():
        return sorted(
            item
            for item in dataflow_subdir.glob("*.md")
            if item.is_file()
        )
    return sorted(
        item
        for item in dataflow_files
        if item.parent.name == "dataflow" and item.suffix.lower() == ".md"
    )


def _extract_dataflow_overview(
    final_report: Path | None,
    dataflow_files: list[Path],
) -> dict[str, object]:
    text = _read_text_if_exists(final_report)
    if not text:
        for item in dataflow_files:
            text = _read_text_if_exists(item)
            if text:
                break

    root_function = ""
    tracked_count = 0
    functions: list[str] = []
    if text:
        root_match = re.search(r"\*\*根函数\*\*\s*[:：]\s*`?([^`\n]+?)`?\s*$", text, re.M)
        if not root_match:
            root_match = re.search(r"^#\s*完整数据流分析\s*[:：]\s*`?([^`\n]+?)`?\s*$", text, re.M)
        if not root_match:
            root_match = re.search(r"^#\s*数据流追踪\s*[:：]\s*`?([^`\n]+?)`?\s*$", text, re.M)
        if root_match:
            root_function = root_match.group(1).strip()

        count_match = re.search(r"\*\*跟踪函数总数\*\*\s*[:：]\s*(\d+)", text)
        if count_match:
            tracked_count = int(count_match.group(1))

        functions = re.findall(r"^\s*\d+\.\s*`([^`\n]+)`", text, re.M)

    return {
        "root_function": root_function,
        "tracked_count": tracked_count,
        "functions": functions,
        "function_samples": functions[:12],
    }


def _extract_analysis_marker_counts(
    final_report: Path | None,
    dataflow_files: list[Path],
) -> dict[str, int]:
    text = _read_text_if_exists(final_report)
    if not text:
        text = "\n".join(_read_text_if_exists(item) for item in dataflow_files)
    lines = [line.strip() for line in text.splitlines()]
    return {
        "input": len(set(re.findall(r"\bINPUT-(\d+)\b", text))),
        "direct_sink": sum(1 for line in lines if "DIRECT_SINK" in line),
        "export": sum(1 for line in lines if "EXPORT" in line),
        "used": sum(1 for line in lines if "USED" in line),
        "cleaned": sum(1 for line in lines if "CLEANED" in line),
    }


def _format_marker_counts(marker_counts: dict[str, int]) -> list[str]:
    lines = []
    if marker_counts.get("input"):
        lines.append(f"- 数据流分析已识别 {marker_counts['input']} 个外部输入")
    if marker_counts.get("direct_sink"):
        lines.append(f"- 有 {marker_counts['direct_sink']} 处 DIRECT_SINK 标记")
    if marker_counts.get("used"):
        lines.append(f"- 有 {marker_counts['used']} 个 USED 标记")
    if marker_counts.get("export"):
        lines.append(f"- 有 {marker_counts['export']} 个 EXPORT 标记")
    if marker_counts.get("cleaned"):
        lines.append(f"- 有 {marker_counts['cleaned']} 个 CLEANED 标记")
    return lines


def _format_marker_meaning_lines() -> list[str]:
    return [
        "- `DIRECT_SINK`：污点在当前函数内直接进入高危操作（最高优先级核查点。比如污点控制 memcpy/strcpy/sprintf 的大小或指针、整数截断、污点下标、污点偏移、污点控制循环边界等。它表示“这里可能直接形成漏洞”，但仍需源码验证。）",
        "- `USED`：污点被当前函数最终消费（表示数据流到这里结束或被用于某个操作，但不一定是危险操作。常见如返回值、比较、日志、统计计数、格式化参数、普通状态处理等。需要看具体用途判断是否有安全影响。）",
        "- `EXPORT`：污点被传出当前分析边界（通常是传给找不到定义的函数、外部库函数、标准 C/C++ 库函数等。后端会把 EXPORT/extern/未找到定义 过滤掉，不再递归跟入。它不是“安全”或“危险”的结论，而是“污点流出去了，当前系统无法继续展开”。）",
        "- `CLEANED`：污点被清洗或验证，需要确认清洗逻（表示分析认为污点已被切断或变成安全值。例如长度被上限约束、偏移被边界校验、输出被常量赋值。这个标记也需要验证：检查是否真的支配后续使用、检查条件是否充分。）",
    ]


def _discover_source_files(source_root: Path) -> list[Path]:
    if not source_root.is_dir():
        return []
    suffix_order = {".c": 0, ".h": 1, ".asm": 2}
    return sorted(
        (
            item
            for item in source_root.rglob("*")
            if item.is_file() and item.suffix.lower() in suffix_order
        ),
        key=lambda item: (suffix_order[item.suffix.lower()], str(item.relative_to(source_root))),
    )


def _format_source_file_lines(source_root: Path, source_files: list[Path]) -> list[str]:
    descriptions = {
        ".c": "反编译 C 代码，主要用于验证函数实现、条件判断、污点传播和危险操作。",
        ".h": "头文件，主要用于查看结构体、类型、宏和函数声明。",
        ".asm": "汇编/反汇编结果，主要用于在反编译代码不明确时核对指令和地址。"
    }
    lines = []
    for item in source_files[:30]:
        try:
            rel = item.relative_to(source_root)
        except ValueError:
            rel = item
        desc = descriptions.get(item.suffix.lower(), "源码辅助文件。")
        lines.append(f"- `{rel}`：{desc}")
    if len(source_files) > 30:
        lines.append(f"- 其余 {len(source_files) - 30} 个源码文件按需查阅。")
    return lines


def _windows_short_ids(run_name: str) -> tuple[str, str]:
    """Windows 路径长度兜底：缩短 workspace 内部目录名。"""
    digest = hashlib.sha1(run_name.encode("utf-8", errors="ignore")).hexdigest()[:10]
    return f"run_{digest}", "initial_001"


def _workspace_root_for_run(run_dir: str) -> str:
    # Windows 默认路径长度限制较严格，使用更短的 ws 目录名。
    return os.path.join(run_dir, "run", "ws" if IS_WINDOWS else "workspace")


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
                        "summary_repair_attempt_budget": 2,
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
                                    "system_prompt_file": "",
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
                                    "system_prompt_file": "",
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
                if key in prompt_keys and isinstance(value, str) and value.strip():
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
    vulnerability_status_counts = {}
    vulnerability_list_file = atomic_dir / "_meta" / "vulnerability_list.json"
    if vulnerability_list_file.is_file():
        try:
            vulnerability_payload = json.loads(vulnerability_list_file.read_text(encoding="utf-8"))
            vulnerability_status_counts = dict(vulnerability_payload.get("counts") or {})
        except Exception:
            vulnerability_status_counts = {}
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
        "vulnerability_status_counts": vulnerability_status_counts,
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

    vuln_counts = diagnostics.get("vulnerability_status_counts") or {}
    if vuln_counts:
        lines.append(
            "  漏洞状态:   "
            f"确认={int(vuln_counts.get('confirmed') or 0)}, "
            f"误报={int(vuln_counts.get('false_positive') or 0)}, "
            f"待评审={int(vuln_counts.get('pending_review') or 0)}"
        )
    else:
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
    resume_cursor: dict | None = None,
    resume_start_cycle: int | None = None,
    resume_target_node: dict | None = None,
    node_resume_policy: str = "rerun_current_node",
) -> str:
    preview_path = Path(atomic_work_dir) / "_meta" / "resume_preview.json"
    preview_path.parent.mkdir(parents=True, exist_ok=True)
    effective_start_cycle = completed_cycles if resume_start_cycle is None else int(resume_start_cycle)
    payload = {
        "generated_at": datetime.now().isoformat(),
        "run_dir": run_dir,
        "atomic_work_dir": atomic_work_dir,
        "current_status": current_status,
        "completed_cycles": completed_cycles,
        "extra_cycles_requested": extra_cycles,
        "resume_start_cycle": effective_start_cycle,
        "resume_total_cycle_limit": max(completed_cycles, effective_start_cycle) + extra_cycles,
        "worker_session_id": worker_session_id,
        "resume_state": resume_state,
        "resume_cursor": resume_cursor or None,
        "resume_target_node": resume_target_node or None,
        "node_resume_policy": node_resume_policy,
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
    --data-flow /path/to/dataflows/ \
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
    --data-flow /path/to/dataflows/ \
    --source-dir /path/to/source/ \
    -c my_config.json

  # 指定模型和运行名称
  python run_vuln_scan.py \
    --data-flow /path/to/dataflows/ \
    --source-dir /path/to/source/ \
    --run-name my_scan \
    --model icsl/zai-org/GLM-5

  # 使用 litellm 的其他模型
  python run_vuln_scan.py \
    --data-flow /path/to/dataflows/ \
    --source-dir /path/to/source/ \
    --model litellm/MiniMax/MiniMax-M2.5

  # 增加评审轮次
  python run_vuln_scan.py \
    --data-flow /path/to/dataflows/ \
    --source-dir /path/to/source/ \
    --max-cycles 5

  # 执行后清理工作目录
  python run_vuln_scan.py \
    --data-flow /path/to/dataflows/ \
    --source-dir /path/to/source/ \
    --clean
""")

    parser.add_argument(
        "--data-flow", "-d", default=None,
        help="数据流分析结果目录路径（兼容旧的单文件路径）")
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
            resume_cursor=plan.resume_cursor,
            resume_start_cycle=plan.resume_start_cycle,
            resume_target_node={
                "cycle": int((plan.resume_cursor or {}).get("cycle") or 0),
                "phase": plan.resume_target_phase,
                "step_key": plan.resume_target_step_key,
                "node_id": str((plan.resume_cursor or {}).get("node_id") or ""),
                "node_kind": str((plan.resume_cursor or {}).get("node_kind") or ""),
            } if plan.resume_target_phase else None,
            node_resume_policy=plan.node_resume_policy,
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
        if plan.resume_cursor:
            print(
                f"  节点恢复:   cycle={(plan.resume_cursor or {}).get('cycle')}, "
                f"phase={plan.resume_target_phase or '-'}, "
                f"step={plan.resume_target_step_key or '-'}, "
                f"policy={plan.node_resume_policy}"
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
        log_file = os.path.join(str(_runtime_dir_for_run(run_dir)), "run.log")
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

    if not (os.path.isdir(args.data_flow) or os.path.isfile(args.data_flow)):
        print(f"❌ 数据流目录不存在: {args.data_flow}", file=sys.stderr)
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
        data_flow_path = Path(args.data_flow)
        stem = data_flow_path.name if data_flow_path.is_dir() else data_flow_path.stem
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
    runtime_dir = str(_runtime_dir_for_run(run_dir))
    os.makedirs(os.path.join(run_dir, "input"), exist_ok=True)
    os.makedirs(os.path.join(run_dir, "output"), exist_ok=True)
    os.makedirs(os.path.join(runtime_dir, "input"), exist_ok=True)

    task_content = generate_task_md(args.data_flow, args.source_dir)
    task_file = os.path.join(runtime_dir, "input", "task.md")
    with open(task_file, "w", encoding="utf-8") as f:
        f.write(task_content)
    with open(os.path.join(run_dir, "input", "input_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(
            {
                "schema_version": 1,
                "task": {"run_name": args.run_name},
                "input": {
                    **data_flow_manifest_input(args.data_flow),
                    "source_dir": os.path.abspath(args.source_dir),
                },
                "prompt": {
                    "task_file": task_file,
                    "content_length": len(task_content),
                    "content_sha256": hashlib.sha256(task_content.encode("utf-8")).hexdigest(),
                },
            },
            f,
            ensure_ascii=False,
            indent=2,
        )

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

    config_file = os.path.join(runtime_dir, "config.json")
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    _mark_run_started(run_dir, mode="fresh")
    log_file = os.path.join(runtime_dir, "run.log")
    actual_log_path = attach_log_file(log_file)

    print("═" * 60)
    print("  数据流驱动漏洞挖掘")
    print("═" * 60)
    print(f"  数据流目录: {os.path.abspath(Path(args.data_flow) if Path(args.data_flow).is_dir() else Path(args.data_flow).parent)}")
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
