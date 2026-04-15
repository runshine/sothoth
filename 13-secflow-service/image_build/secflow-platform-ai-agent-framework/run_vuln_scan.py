#!/usr/bin/env python3
"""
漏洞挖掘便捷启动器

用法:
  python run_vuln_scan.py \\
    --data-flow /path/to/data_flow_analysis.md \\
    --source-dir /path/to/source_code/ \\
    [--run-name my_scan] \\
    [--model claude-sonnet-4-20250514] \\
    [--provider anthropic] \\
    [--max-cycles 3] \\
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
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "vuln_scan_default.json"


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

def main():
    parser = argparse.ArgumentParser(
        description="数据流驱动漏洞挖掘启动器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 基本用法
  python run_vuln_scan.py \\
    --data-flow /path/to/data_flow.md \\
    --source-dir /path/to/source/

  # 使用自定义配置文件 (复制 config.vuln_scan_default.json 后修改)
  python run_vuln_scan.py \\
    --data-flow /path/to/data_flow.md \\
    --source-dir /path/to/source/ \\
    -c my_config.json

  # 指定模型和运行名称
  python run_vuln_scan.py \\
    --data-flow /path/to/data_flow.md \\
    --source-dir /path/to/source/ \\
    --run-name my_scan \\
    --model claude-sonnet-4-20250514 \\
    --provider anthropic

  # 使用 litellm 的其他模型
  python run_vuln_scan.py \\
    --data-flow /path/to/data_flow.md \\
    --source-dir /path/to/source/ \\
    --model MiniMax/MiniMax-M2.5 \\
    --provider litellm

  # 增加评审轮次
  python run_vuln_scan.py \\
    --data-flow /path/to/data_flow.md \\
    --source-dir /path/to/source/ \\
    --max-cycles 5

  # 执行后清理工作目录
  python run_vuln_scan.py \\
    --data-flow /path/to/data_flow.md \\
    --source-dir /path/to/source/ \\
    --clean
""")

    parser.add_argument(
        "--data-flow", "-d", required=True,
        help="数据流分析结果文件路径 (.md)")
    parser.add_argument(
        "--source-dir", "-s", required=True,
        help="源码目录路径（包含 .c, .h, .asm 文件）")
    parser.add_argument(
        "--config", "-c", default=None,
        help="自定义配置文件路径 (复制 config.vuln_scan_default.json 后修改; "
             "指定后 --model/--provider/--max-cycles 等参数将被忽略)")
    parser.add_argument(
        "--run-name", "-n", default=None,
        help="运行名称（默认: 根据数据流文件名自动生成）")
    parser.add_argument(
        "--model", "-m", default="claude-sonnet-4-20250514",
        help="AI 模型 (默认: claude-sonnet-4-20250514)")
    parser.add_argument(
        "--provider", default=None,
        help="模型提供商 (默认: 从 --model 自动推断，如 github-copilot/gpt-5.4 → github-copilot)")
    parser.add_argument(
        "--thinking", default="high",
        choices=["off", "low", "medium", "high"],
        help="思考深度 (默认: high)")
    parser.add_argument(
        "--max-cycles", type=int, default=10,
        help="最大评审循环次数 (默认: 3)")
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

    # ═══ 自动推断 provider ═══
    if args.provider is None:
        if "/" in args.model:
            # 模型格式为 "provider/model"，如 github-copilot/gpt-5.4
            args.provider = args.model.split("/")[0]
        else:
            args.provider = "anthropic"

    # ═══ 校验输入 ═══
    if not os.path.isfile(args.data_flow):
        print(f"❌ 数据流文件不存在: {args.data_flow}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(args.source_dir):
        print(f"❌ 源码目录不存在: {args.source_dir}", file=sys.stderr)
        sys.exit(1)

    if args.result_review_concurrency < 1:
        print("❌ --result-review-concurrency 必须 >= 1", file=sys.stderr)
        sys.exit(1)

    # ═══ 生成运行名称 ═══
    if args.run_name is None:
        stem = Path(args.data_flow).stem
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.run_name = f"{stem}_{timestamp}"

    # ═══ 创建运行目录 ═══
    run_dir = str(PROJECT_ROOT / "runs" / args.run_name)
    os.makedirs(os.path.join(run_dir, "input"), exist_ok=True)
    os.makedirs(os.path.join(run_dir, "output"), exist_ok=True)

    # ═══ 生成 task.md ═══
    task_content = generate_task_md(args.data_flow, args.source_dir)
    task_file = os.path.join(run_dir, "input", "task.md")
    with open(task_file, "w", encoding="utf-8") as f:
        f.write(task_content)

    # ═══ 生成或加载 config.json ═══
    if args.config:
        # 用户指定了自定义配置
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
        # 从 CLI 参数自动生成
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

    # ═══ 启动日志文件记录 ═══
    log_file = os.path.join(run_dir, "run.log")
    from app.pi_vuln_core.utils.logger import attach_log_file, detach_log_file
    actual_log_path = attach_log_file(log_file)

    # ═══ 打印信息 ═══
    print("═" * 60)
    print("  数据流驱动漏洞挖掘")
    print("═" * 60)
    print(f"  数据流文件: {os.path.abspath(args.data_flow)}")
    print(f"  源码目录:   {os.path.abspath(args.source_dir)}")
    print(f"  运行名称:   {args.run_name}")
    print(f"  模型:       {args.provider}/{args.model}")
    print(f"  评审轮次:   {args.max_cycles}")
    print(f"  运行目录:   {run_dir}")
    print(f"  配置文件:   {config_file}")
    print(f"  配置来源:   {config_source}")
    print(f"  任务文件:   {task_file}")
    print(f"  日志文件:   {actual_log_path}")
    print("═" * 60)

    # ═══ 启动框架 ═══
    from app.pi_vuln_core.main import main as framework_main
    from app.pi_vuln_core.utils.logger import setup_logging

    setup_logging("INFO")
    exit_code = asyncio.run(
        framework_main(config_file, clean_workspace=args.clean))

    # ═══ 打印结果位置 ═══
    if exit_code == 0:
        print("\n" + "═" * 60)
        print("  ✅ 漏洞挖掘完成")
        print("═" * 60)
        print(f"  执行总结: {os.path.join(run_dir, 'output', 'execution_summary.json')}")
        # 查找工作目录中的结果
        workspace = os.path.join(run_dir, "workspace")
        if os.path.isdir(workspace):
            for root, dirs, files in os.walk(workspace):
                # 优先找 final_output
                final_out = os.path.join(root, "final_output")
                if os.path.isdir(final_out):
                    print(f"  最终产出: {final_out}/")
                    if os.path.isfile(os.path.join(final_out, "summary.md")):
                        print(f"    - summary.md (综合工作报告)")
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

    # ═══ 停止日志文件记录 ═══
    detach_log_file()
    print(f"  完整日志: {actual_log_path}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
