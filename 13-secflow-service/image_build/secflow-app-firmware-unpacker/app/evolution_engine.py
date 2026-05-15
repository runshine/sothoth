"""Manual firmware evolution job runner."""

from __future__ import annotations

import json
import logging
import re
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from app.preprocess import detect_format
from app.tool_store import compute_family_id, parse_tool_metadata
from app.unpacker_engine_config import (
    EVOLUTION_EXEC_AGENT_DEF,
    EVOLUTION_EXEC_PROMPT_TMPL,
    EVOLUTION_REVIEW_PROMPT_TMPL,
    TOOLS_DIR,
    VAL_AGENT_DEF,
    load_agent_def,
    render_template,
)
from app.unpacker_engine_logs import (
    append_stage_log as _append_stage_log,
    append_stream_delta as _append_stream_delta,
    get_round_dir as _get_round_dir,
    save_agent_log as _save_agent_log,
    write_json_log as _write_json_log,
)
from app.unpacker_engine_pi import PiRpcClient
from app.unpacker_engine_session import build_session_artifacts


log = logging.getLogger("unpacker.evolution")
DEFAULT_EVOLUTION_MAX_ROUNDS = 3


def evolution_job_root(output_path: str, job_id: str) -> Path:
    output_dir = Path(str(output_path or "").strip())
    if output_dir.name != "output":
        raise ValueError(f"invalid unpack output path: {output_path}")
    job_root = output_dir.parent / "run" / "evolution_jobs" / str(job_id).strip()
    job_root.mkdir(parents=True, exist_ok=True)
    return job_root


def evolution_job_workspace_output(job_root: Path) -> Path:
    path = job_root / "workspace" / "output"
    path.mkdir(parents=True, exist_ok=True)
    return path


def evolution_job_sessions_root(job_root: Path) -> Path:
    path = job_root / "sessions"
    path.mkdir(parents=True, exist_ok=True)
    return path


def evolution_round_dir(job_root: Path, round_id: int) -> Path:
    return _get_round_dir(job_root, round_id) or (job_root / f"round_{int(round_id):03d}")


def evolution_working_tool_path(job_root: Path, source_tool_path: str) -> Path:
    working_dir = job_root / "working_tool"
    working_dir.mkdir(parents=True, exist_ok=True)
    source = Path(source_tool_path)
    return working_dir / source.name


def evolution_working_tool_dir(job_root: Path) -> Path:
    path = job_root / "working_tool"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _main_run_dir(output_path: str) -> Path:
    output_dir = Path(str(output_path or "").strip())
    return output_dir.parent / "run"


def _copy_tool_to_working(job_root: Path, source_tool_path: str) -> Path:
    source = Path(source_tool_path)
    if not source.exists():
        raise FileNotFoundError(f"tool not found: {source_tool_path}")
    target = evolution_working_tool_path(job_root, source_tool_path)
    shutil.copy2(source, target)
    return target


def _canonical_family_tool_name(firmware_path: str, source_tool_path: str | None = None) -> str:
    family_id = ""
    if source_tool_path:
        try:
            meta = parse_tool_metadata(Path(source_tool_path))
            family_id = str(meta.get("format_id") or meta.get("name") or "").strip().lower()
        except Exception:
            family_id = ""
    if not family_id:
        info = detect_format(firmware_path)
        family_id = compute_family_id(
            {
                "fmt": info.get("fmt"),
                "ext": info.get("ext"),
                "magic_hex": str((info.get("magic") or b"").hex()),
                "binwalk_sigs": info.get("binwalk_sigs") or [],
            }
        )
    family_id = str(family_id or "generic-firmware").strip().lower().replace("/", "-").replace(" ", "-")
    return f"{family_id}.py"


def _normalize_working_tool_name(job_root: Path, firmware_path: str, source_tool_path: str | None = None) -> Path:
    working_dir = evolution_working_tool_dir(job_root)
    if source_tool_path:
        source_name = Path(source_tool_path).name
        preferred_path = working_dir / source_name
        if preferred_path.exists():
            return preferred_path
        existing_tools = sorted(working_dir.glob("*.py"))
        if existing_tools:
            return existing_tools[0]
    canonical_path = working_dir / _canonical_family_tool_name(firmware_path, source_tool_path)
    if canonical_path.exists():
        return canonical_path
    for tool_path in sorted(working_dir.glob("*.py")):
        if tool_path == canonical_path:
            return canonical_path
        shutil.move(str(tool_path), str(canonical_path))
        pycache_dir = working_dir / "__pycache__"
        if pycache_dir.exists():
            shutil.rmtree(pycache_dir, ignore_errors=True)
        return canonical_path
    return canonical_path


def _create_initial_working_tool(job_root: Path, firmware_path: str) -> Path:
    working_dir = evolution_working_tool_dir(job_root)
    features = detect_format(firmware_path)
    family_id = compute_family_id(
        {
            "fmt": features.get("fmt"),
            "ext": features.get("ext"),
            "magic_hex": str((features.get("magic") or b"").hex()),
            "binwalk_sigs": features.get("binwalk_sigs") or [],
        }
    )
    target = working_dir / f"{family_id or 'generated-initial'}.py"
    target.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                f"# name: {family_id or 'generated-initial'}",
                f"# format_id: {family_id or 'generated-initial'}",
                f"# description: Evolution working unpack tool for {Path(firmware_path).name}",
                "",
                "def main() -> int:",
                "    raise NotImplementedError('implement unpack workflow here')",
                "",
                "",
                "if __name__ == '__main__':",
                "    raise SystemExit(main())",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return _normalize_working_tool_name(job_root, firmware_path, None)


def _reset_workspace_output(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)


def _extract_path_only(text: str) -> Path | None:
    raw = str(text or "").strip().splitlines()
    for line in reversed(raw):
        value = line.strip().strip("`")
        if value.endswith(".py") and value.startswith("/"):
            return Path(value)
    return None


def _validate_working_tool_path(path: Path, working_dir: Path) -> Path:
    resolved = path.resolve()
    resolved_working_dir = working_dir.resolve()
    try:
        resolved.relative_to(resolved_working_dir)
    except ValueError as exc:
        raise RuntimeError(f"工具进化器返回了非法路径: {resolved}") from exc
    if resolved.suffix.lower() != ".py":
        raise RuntimeError(f"工具进化器返回了非法路径: {resolved}")
    if not resolved.exists():
        raise RuntimeError(f"工具进化器返回的工具文件不存在: {resolved}")
    source = resolved.read_text(encoding="utf-8")
    if not source.strip():
        raise RuntimeError(f"工具进化器返回的工具文件为空: {resolved}")
    try:
        compile(source, str(resolved), "exec")
    except SyntaxError as exc:
        raise RuntimeError(f"工具进化器生成的 Python 脚本语法错误: {resolved}: {exc}") from exc
    return resolved


def _derive_family_id(firmware_path: str, final_tool_path: Path) -> str:
    try:
        meta = parse_tool_metadata(final_tool_path)
        family_id = str(meta.get("format_id") or meta.get("name") or "").strip().lower()
        if family_id:
            return family_id.replace(" ", "-").replace("/", "-")
    except Exception:
        pass
    info = detect_format(firmware_path)
    return compute_family_id(
        {
            "fmt": info.get("fmt"),
            "ext": info.get("ext"),
            "magic_hex": str((info.get("magic") or b"").hex()),
            "binwalk_sigs": info.get("binwalk_sigs") or [],
        }
    ) or "generic-firmware"


def _next_generated_tool_version(tools_dir: Path, family_id: str) -> int:
    pattern = re.compile(rf"^{re.escape(family_id)}__v(\d+)(?:__|\.py$)")
    max_version = 0
    for tool_path in tools_dir.glob(f"{family_id}*.py"):
        match = pattern.match(tool_path.name)
        if not match:
            continue
        try:
            max_version = max(max_version, int(match.group(1)))
        except Exception:
            continue
    return max_version + 1


def _build_versioned_tool_path(directory: Path, family_id: str, version: int, *, suffix: str) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return directory / f"{family_id}__v{version}__{suffix}__{timestamp}.py"


def _rename_working_tool_if_changed(
    *,
    firmware_path: str,
    working_tool: Path,
    source_tool: Path | None,
    tool_changed: bool,
) -> Path:
    if not tool_changed:
        return working_tool
    family_id = _derive_family_id(firmware_path, working_tool)
    version = _next_generated_tool_version(TOOLS_DIR, family_id)
    renamed_path = _build_versioned_tool_path(
        working_tool.parent,
        family_id,
        version,
        suffix="evolved",
    )
    if renamed_path.resolve() == working_tool.resolve():
        return working_tool
    shutil.move(str(working_tool), str(renamed_path))
    pycache_dir = renamed_path.parent / "__pycache__"
    if pycache_dir.exists():
        shutil.rmtree(pycache_dir, ignore_errors=True)
    return renamed_path


def _save_generated_tool_to_repo(
    *,
    firmware_path: str,
    working_tool: Path,
    source_tool: Path | None,
) -> tuple[str, str | None, bool]:
    _validate_working_tool_path(working_tool, working_tool.parent)
    if source_tool is not None:
        shutil.copy2(working_tool, source_tool)
        return str(source_tool), str(source_tool), False

    family_id = _derive_family_id(firmware_path, working_tool)
    version = _next_generated_tool_version(TOOLS_DIR, family_id)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    target = TOOLS_DIR / f"{family_id}__v{version}__generated__{timestamp}.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(working_tool, target)
    return str(target), None, True


def _save_generated_tool_to_run(
    *,
    job_root: Path,
    firmware_path: str,
    working_tool: Path,
    source_tool: Path | None,
) -> tuple[str, str | None, bool]:
    _validate_working_tool_path(working_tool, working_tool.parent)
    family_id = _derive_family_id(firmware_path, working_tool)
    version = _next_generated_tool_version(TOOLS_DIR, family_id)
    generated_dir = job_root / "generated_tools"
    generated_dir.mkdir(parents=True, exist_ok=True)
    target = _build_versioned_tool_path(generated_dir, family_id, version, suffix="generated")
    shutil.copy2(working_tool, target)
    if source_tool is not None and source_tool.resolve() == working_tool.resolve():
        shutil.copy2(working_tool, source_tool)
        return str(target), str(source_tool), False
    if source_tool is not None:
        return str(target), str(source_tool), True
    return str(target), None, True


def _publish_tool_to_repo(
    *,
    firmware_path: str,
    working_tool: Path,
    source_tool: Path | None,
    tool_changed: bool,
) -> str:
    _validate_working_tool_path(working_tool, working_tool.parent)
    if source_tool is not None and not tool_changed:
        source_tool.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(working_tool, source_tool)
        return str(source_tool)
    family_id = _derive_family_id(firmware_path, working_tool)
    version = _next_generated_tool_version(TOOLS_DIR, family_id)
    suffix = "evolved" if source_tool is not None else "generated"
    target = _build_versioned_tool_path(TOOLS_DIR, family_id, version, suffix=suffix)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(working_tool, target)
    return str(target)


def _review_passed(review_result: str) -> bool:
    lowered = str(review_result or "").strip().lower()
    return '"result":"success"' in lowered or '"result": "success"' in lowered


def _sync_report_aliases(output_dir: Path) -> None:
    aliases = {
        "summary.md": "summary.txt",
        "reason.md": "reason.txt",
    }
    for canonical_name, alias_name in aliases.items():
        canonical_path = output_dir / canonical_name
        alias_path = output_dir / alias_name
        if canonical_path.exists():
            alias_path.write_text(canonical_path.read_text(encoding="utf-8"), encoding="utf-8")
        elif alias_path.exists():
            canonical_path.write_text(alias_path.read_text(encoding="utf-8"), encoding="utf-8")


def _load_token_stats(round_dir: Path, agent_name: str) -> dict[str, Any]:
    token_path = round_dir / f"{agent_name}_tokens.json"
    if not token_path.exists():
        return {}
    try:
        payload = json.loads(token_path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _augment_tool_summary(
    *,
    output_dir: Path,
    elapsed_seconds: float,
    token_stats: dict[str, Any],
) -> None:
    summary_md = output_dir / "summary.md"
    summary_txt = output_dir / "summary.txt"
    base_text = ""
    if summary_md.exists():
        base_text = summary_md.read_text(encoding="utf-8")
    elif summary_txt.exists():
        base_text = summary_txt.read_text(encoding="utf-8")
    base_text = base_text.rstrip()

    metrics_lines = [
        "",
        "## Evolution Metrics",
        f"- elapsed_seconds: {max(0.0, float(elapsed_seconds)):.2f}",
        f"- token_input: {int(token_stats.get('input') or 0)}",
        f"- token_output: {int(token_stats.get('output') or 0)}",
        f"- token_cache_read: {int(token_stats.get('cacheRead') or 0)}",
        f"- token_cache_write: {int(token_stats.get('cacheWrite') or 0)}",
        f"- token_total: {int(token_stats.get('total') or 0)}",
    ]
    merged = (base_text + "\n" + "\n".join(metrics_lines)).strip() + "\n"
    summary_md.write_text(merged, encoding="utf-8")
    summary_txt.write_text(merged, encoding="utf-8")


def _build_tool_prompt(
    *,
    round_id: int,
    firmware_path: str,
    workspace_output: Path,
    working_tool: Path,
) -> str:
    if int(round_id) <= 1:
        return "\n".join(
            [
                f"从 `{TOOLS_DIR}` 中查找最合适的 Python 解包工具，并优先使用当前 working tool：`{working_tool}`。",
                f"目标固件：`{firmware_path}`。",
                f"输出目录：`{workspace_output}`。",
                "",
                "要求：",
                "1. 先检查 tools 目录和当前 working tool。",
                "2. 选择一个最合适的工具；如果没有更合适的现成工具，则使用并完善当前 working tool。",
                "3. 使用该工具完成本轮解包，不允许在工具之外手工解包。",
                "4. 解包完成后立刻停止，不要额外执行手工的 dd、unsquashfs、cp、tar、rsync 等后处理。",
                "5. 写出 `summary.txt`，并同步更新 `summary.md`。内容至少包含：",
                "   - 本轮使用的工具路径",
                "   - 关键执行步骤",
                "   - 主要输出产物",
                "   - 剩余问题或可疑缺口",
                "   - 本轮耗时和 token 数量（若无法精确得出，也要预留该字段）",
            ]
        )
    return "\n".join(
        [
            "上一轮评审未通过，请先阅读当前输出目录下的 `reason.txt` 和 `reason.md`。",
            f"然后完善当前工具：`{working_tool}`，并使用完善后的工具重新对固件 `{firmware_path}` 进行解包，输出到 `{workspace_output}`。",
            "",
            "要求：",
            "1. 必须先根据 reason 中的问题修改或替换当前 working tool。",
            "2. 修改后使用工具重新完成本轮解包，不允许在工具之外手工解包。",
            "3. 解包完成后立刻停止，不要额外执行手工的 dd、unsquashfs、cp、tar、rsync 等后处理。",
            "4. 写出更新后的 `summary.txt`，并同步更新 `summary.md`。内容至少包含：",
            "   - 当前工具路径",
            "   - 本轮修复了哪些问题",
            "   - 仍然存在的问题",
            "   - 本轮耗时和 token 数量（若无法精确得出，也要预留该字段）",
        ]
    )


def _create_client(
    *,
    agent_def_path: str,
    provider_role: str,
    session_role: str,
    session_name: str,
    session_phase: str,
    session_round: int | None,
    task_id: str,
    llm_binding_snapshot: dict[str, Any] | None,
    session_root: Path,
) -> PiRpcClient:
    agent_def = load_agent_def(agent_def_path)
    session_artifacts = build_session_artifacts(
        session_root,
        role=session_role,
        name=session_name,
        provider_role=provider_role,
        phase=session_phase,
        round_id=session_round,
    )
    return PiRpcClient(
        system_prompt_file=agent_def_path,
        model=agent_def.get("model"),
        tools=agent_def.get("tools"),
        provider_role=provider_role,
        llm_binding_snapshot=llm_binding_snapshot,
        session_dir=session_artifacts["session_dir"],
        session_path=session_artifacts["session_path"],
        session_role=session_artifacts["session_role"],
        session_name=session_artifacts["session_name"],
        session_phase=session_artifacts["phase"],
        session_round=session_artifacts["round"],
        session_skill_name=session_artifacts["skill_name"],
        task_id=task_id,
    )


def run_evolution_job(
    *,
    task_id: str,
    evolution_job_id: str,
    firmware_path: str,
    unpack_output_path: str,
    active_skill_path: str,
    llm_binding_snapshot: dict[str, Any] | None = None,
    max_rounds: int = DEFAULT_EVOLUTION_MAX_ROUNDS,
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> dict[str, Any]:
    job_root = evolution_job_root(unpack_output_path, evolution_job_id)
    session_root = evolution_job_sessions_root(job_root)
    workspace_output = evolution_job_workspace_output(job_root)
    working_dir = evolution_working_tool_dir(job_root)
    source_tool_text = str(active_skill_path or "").strip()
    source_tool = Path(source_tool_text) if source_tool_text else None
    started_without_matched_skill = source_tool is None
    if source_tool is not None and not source_tool.exists():
        raise RuntimeError("当前任务没有可用的 Python 工具，无法发起进化")
    initial_working_tool = (
        _copy_tool_to_working(job_root, str(source_tool))
        if source_tool is not None
        else _create_initial_working_tool(job_root, firmware_path)
    )
    initial_working_tool = _normalize_working_tool_name(job_root, firmware_path, str(source_tool) if source_tool is not None else None)
    working_tool = initial_working_tool
    final_tool_path: str | None = None
    replaced_tool_path: str | None = str(source_tool) if source_tool is not None else None
    review_passed = False
    generated_new_tool = False
    round_items: list[dict[str, Any]] = []
    tool_client = _create_client(
        agent_def_path=EVOLUTION_EXEC_AGENT_DEF,
        provider_role="skill_executor",
        session_role="skill-executor",
        session_name="shared",
        session_phase="tool_execute",
        session_round=None,
        task_id=task_id,
        llm_binding_snapshot=llm_binding_snapshot,
        session_root=job_root,
    )

    try:
        for round_id in range(1, max(1, int(max_rounds)) + 1):
            round_dir = evolution_round_dir(job_root, round_id)
            _reset_workspace_output(workspace_output)
            before_path = working_tool
            before_text = before_path.read_text(encoding="utf-8") if before_path.exists() else ""
            executed_tool = False
            tool_result = ""
            review_result = ""
            review_round_passed = False

            if progress_callback:
                progress_callback(round_id, "tool_execute")
            tool_prompt = _build_tool_prompt(
                round_id=round_id,
                firmware_path=firmware_path,
                workspace_output=workspace_output,
                working_tool=working_tool,
            )
            rendered_tool_prompt = render_template(
                EVOLUTION_EXEC_PROMPT_TMPL,
                {
                    "$input": firmware_path,
                    "$output": str(workspace_output),
                    "$tools": str(TOOLS_DIR),
                    "$working_tool": str(working_tool),
                },
            )
            tool_round_started_at = time.monotonic()
            try:
                _append_stage_log(
                    round_dir,
                    "tool_executor.log",
                    "starting evolution tool execution",
                    round=round_id,
                    source_tool_path=str(source_tool) if source_tool is not None else None,
                    working_tool_path=str(working_tool),
                    workspace_output=str(workspace_output),
                )

                def _stream_tool_event(event: dict[str, Any]) -> None:
                    _append_stream_delta(
                        round_dir,
                        "tool_executor.log",
                        f"tool_executor:round_{round_id}",
                        event,
                    )

                tool_result = tool_client.prompt(
                    f"{rendered_tool_prompt}\n\n{tool_prompt}",
                    stream_callback=_stream_tool_event,
                )
                _save_agent_log(tool_client, log, round_dir, "tool_executor")
                executed_tool = True
                _append_stage_log(
                    round_dir,
                    "tool_executor.log",
                    "evolution tool execution completed",
                    round=round_id,
                    response_preview=tool_result[:1000] if tool_result else None,
                )
            finally:
                pass
            working_tool = _normalize_working_tool_name(job_root, firmware_path, str(source_tool) if source_tool else None)
            working_tool = _validate_working_tool_path(working_tool, working_dir)
            _augment_tool_summary(
                output_dir=workspace_output,
                elapsed_seconds=time.monotonic() - tool_round_started_at,
                token_stats=_load_token_stats(round_dir, "tool_executor"),
            )
            _sync_report_aliases(workspace_output)

            if progress_callback:
                progress_callback(round_id, "review")
            review_client = _create_client(
                agent_def_path=VAL_AGENT_DEF,
                provider_role="reviewer",
                session_role="reviewer",
                session_name=f"round-{round_id}",
                session_phase="review",
                session_round=round_id,
                task_id=task_id,
                llm_binding_snapshot=llm_binding_snapshot,
                session_root=job_root,
            )
            try:
                review_prompt = render_template(
                    EVOLUTION_REVIEW_PROMPT_TMPL,
                    {
                        "$input": firmware_path,
                        "$output": str(workspace_output),
                    },
                )
                _append_stage_log(
                    round_dir,
                    "reviewer.log",
                    "starting evolution review",
                    round=round_id,
                    workspace_output=str(workspace_output),
                    working_tool_path=str(working_tool),
                )

                def _stream_review_event(event: dict[str, Any]) -> None:
                    _append_stream_delta(
                        round_dir,
                        "reviewer.log",
                        f"reviewer:round_{round_id}",
                        event,
                    )

                review_result = review_client.prompt(
                    review_prompt,
                    stream_callback=_stream_review_event,
                )
                _save_agent_log(review_client, log, round_dir, "reviewer")
                review_round_passed = _review_passed(review_result)
                _append_stage_log(
                    round_dir,
                    "reviewer.log",
                    "evolution review completed",
                    round=round_id,
                    review_passed=review_round_passed,
                    review_preview=review_result[:1000] if review_result else None,
                )
            finally:
                review_client.close()
            _sync_report_aliases(workspace_output)

            tool_changed = before_text != (working_tool.read_text(encoding="utf-8") if working_tool.exists() else "")
            working_tool = _rename_working_tool_if_changed(
                firmware_path=firmware_path,
                working_tool=working_tool,
                source_tool=source_tool,
                tool_changed=tool_changed,
            )
            tool_changed = before_text != (working_tool.read_text(encoding="utf-8") if working_tool.exists() else "")

            summary_path = workspace_output / "summary.md"
            reason_path = workspace_output / "reason.md"
            round_status = "review_passed" if review_round_passed else "review_failed"
            round_item: dict[str, Any] = {
                "round": round_id,
                "status": round_status,
                "tool_skill_path_before": str(before_path),
                "tool_skill_path_after": str(working_tool),
                "tool_path_before": str(before_path),
                "tool_path_after": str(working_tool),
                "tool_changed": tool_changed,
                "review_result": review_result,
                "summary_path": str(summary_path) if summary_path.exists() else None,
                "reason_path": str(reason_path) if reason_path.exists() else None,
                "log_root": str(round_dir),
                "log_files": {
                    "tool_executor": str(round_dir / "tool_executor_transcript.log"),
                    "reviewer": str(round_dir / "reviewer_transcript.log"),
                },
                "source_skill_path": str(source_tool) if source_tool is not None else None,
                "source_tool_path": str(source_tool) if source_tool is not None else None,
                "started_without_matched_skill": started_without_matched_skill,
                "generated_new_skill": False,
                "generated_new_tool": False,
                "executed_tool": executed_tool,
                "tool_response_preview": tool_result[:2000] if tool_result else None,
                "created_at": datetime.now().isoformat(),
                "completed_at": datetime.now().isoformat(),
            }

            if review_round_passed:
                review_passed = True
                run_tool_path, replaced_tool_path, generated_new_tool = _save_generated_tool_to_run(
                    job_root=job_root,
                    firmware_path=firmware_path,
                    working_tool=working_tool,
                    source_tool=source_tool,
                )
                final_tool_path = _publish_tool_to_repo(
                    firmware_path=firmware_path,
                    working_tool=working_tool,
                    source_tool=source_tool,
                    tool_changed=tool_changed,
                )
                round_item["generated_new_skill"] = generated_new_tool
                round_item["generated_new_tool"] = generated_new_tool
                round_item["run_tool_path_after"] = run_tool_path
                round_item["tool_skill_path_after"] = final_tool_path
                round_item["tool_path_after"] = final_tool_path
                _append_stage_log(
                    round_dir,
                    "tool_executor.log",
                    "published evolution tool result",
                    round=round_id,
                    run_tool_path=run_tool_path,
                    final_tool_path=final_tool_path,
                    replaced_tool_path=replaced_tool_path,
                    generated_new_tool=generated_new_tool,
                )
                round_items.append(round_item)
                _write_json_log(round_dir, "evolution_round.json", round_item)
                break

            round_items.append(round_item)
            _append_stage_log(
                round_dir,
                "reviewer.log",
                "review did not pass, evolution round will continue if budget remains",
                round=round_id,
                max_rounds=max_rounds,
            )
            _write_json_log(round_dir, "evolution_round.json", round_item)
            if round_id >= max_rounds:
                continue
    finally:
        tool_client.close()

    final_status = "success" if review_passed else "failed"
    replacement_required = bool(
        review_passed
        and generated_new_tool
        and source_tool is not None
        and final_tool_path
        and replaced_tool_path
        and str(final_tool_path).strip() != str(replaced_tool_path).strip()
    )
    payload = {
        "status": final_status,
        "review_passed": review_passed,
        "current_round": len(round_items),
        "max_rounds": max_rounds,
        "final_skill_path": final_tool_path,
        "final_tool_path": final_tool_path,
        "replaced_skill_path": replaced_tool_path if review_passed else None,
        "replaced_tool_path": replaced_tool_path if review_passed else None,
        "job_root": str(job_root),
        "session_root": str(session_root),
        "rounds": round_items,
        "working_skill_path": str(working_tool),
        "working_tool_path": str(working_tool),
        "source_skill_path": str(source_tool) if source_tool is not None else None,
        "source_tool_path": str(source_tool) if source_tool is not None else None,
        "started_without_matched_skill": started_without_matched_skill,
        "generated_new_skill": generated_new_tool,
        "generated_new_tool": generated_new_tool,
        "replacement_required": replacement_required,
        "replacement_confirmed": not replacement_required,
        "effective_tool_path": (
            str(replaced_tool_path)
            if replacement_required and replaced_tool_path
            else str(final_tool_path or replaced_tool_path or "")
        ) or None,
    }
    (job_root / "evolution_result.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload
