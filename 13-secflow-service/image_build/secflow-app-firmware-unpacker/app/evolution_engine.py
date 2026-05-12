"""Manual firmware evolution job runner."""

from __future__ import annotations

import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from app.preprocess import detect_format
from app.skill_store import parse_skill_metadata, validate_skill_document
from app.unpacker_engine_config import (
    EVOLUTION_EXEC_AGENT_DEF,
    EVOLUTION_EXEC_PROMPT_TMPL,
    EVOLUTION_IMPROVER_AGENT_DEF,
    EVOLUTION_IMPROVER_PROMPT_TMPL,
    EVOLUTION_REVIEW_PROMPT_TMPL,
    TOOLS_DIR,
    VAL_AGENT_DEF,
    load_agent_def,
    render_template,
)
from app.unpacker_engine_logs import (
    append_stage_log as _append_stage_log,
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


def evolution_working_skill_path(job_root: Path, source_skill_path: str) -> Path:
    working_dir = job_root / "working_skill"
    working_dir.mkdir(parents=True, exist_ok=True)
    source = Path(source_skill_path)
    return working_dir / source.name


def evolution_working_skill_dir(job_root: Path) -> Path:
    path = job_root / "working_skill"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _main_run_dir(output_path: str) -> Path:
    output_dir = Path(str(output_path or "").strip())
    return output_dir.parent / "run"


def _copy_skill_to_working(job_root: Path, source_skill_path: str) -> Path:
    source = Path(source_skill_path)
    if not source.exists():
        raise FileNotFoundError(f"SKILL not found: {source_skill_path}")
    target = evolution_working_skill_path(job_root, source_skill_path)
    shutil.copy2(source, target)
    return target


def _create_initial_working_skill(job_root: Path) -> Path:
    working_dir = evolution_working_skill_dir(job_root)
    target = working_dir / "generated-initial.md"
    target.write_text("", encoding="utf-8")
    return target


def _reset_workspace_output(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)


def _extract_path_only(text: str) -> Path | None:
    raw = str(text or "").strip().splitlines()
    for line in reversed(raw):
        value = line.strip().strip("`")
        if value.endswith(".md") and value.startswith("/"):
            return Path(value)
    return None


def _validate_working_skill_path(path: Path, working_dir: Path) -> Path:
    resolved = path.resolve()
    resolved_working_dir = working_dir.resolve()
    try:
        resolved.relative_to(resolved_working_dir)
    except ValueError as exc:
        raise RuntimeError(f"工具进化器返回了非法路径: {resolved}") from exc
    if resolved.suffix.lower() != ".md":
        raise RuntimeError(f"工具进化器返回了非法路径: {resolved}")
    if not resolved.exists():
        raise RuntimeError(f"工具进化器返回的工具文件不存在: {resolved}")
    return resolved


def _derive_family_id(firmware_path: str, final_skill_path: Path) -> str:
    try:
        meta = parse_skill_metadata(final_skill_path, include_prompt=True)
        family_id = str(meta.get("family_id") or "").strip().lower()
        if family_id:
            return family_id
    except Exception:
        pass
    info = detect_format(firmware_path)
    parts = [
        str(info.get("fmt") or "").strip().lower(),
        str(info.get("ext") or "").strip().lower(),
        str((info.get("magic") or b"").hex()[:8]).strip().lower(),
    ]
    compact = "-".join([part for part in parts if part and part != "unknown"]).strip("-")
    return compact or "generic-firmware"


def _save_generated_skill_to_repo(
    *,
    firmware_path: str,
    working_skill: Path,
    source_skill: Path | None,
) -> tuple[str, str | None, bool]:
    validate_skill_document(working_skill.read_text(encoding="utf-8"))
    if source_skill is not None:
        shutil.copy2(working_skill, source_skill)
        return str(source_skill), str(source_skill), False

    family_id = _derive_family_id(firmware_path, working_skill)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    target = TOOLS_DIR / f"{family_id}__generated__{timestamp}.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(working_skill, target)
    return str(target), None, True


def _review_passed(review_result: str) -> bool:
    lowered = str(review_result or "").strip().lower()
    return '"result":"success"' in lowered or '"result": "success"' in lowered


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
    working_dir = evolution_working_skill_dir(job_root)
    main_run = _main_run_dir(unpack_output_path)
    source_skill_text = str(active_skill_path or "").strip()
    source_skill = Path(source_skill_text) if source_skill_text else None
    started_without_matched_skill = source_skill is None
    if source_skill is not None and not source_skill.exists():
        raise RuntimeError("当前任务没有可用的 SKILL，无法发起进化")
    initial_working_skill = (
        _copy_skill_to_working(job_root, str(source_skill))
        if source_skill is not None
        else _create_initial_working_skill(job_root)
    )
    working_skill = initial_working_skill
    final_skill_path: str | None = None
    replaced_skill_path: str | None = str(source_skill) if source_skill is not None else None
    review_passed = False
    generated_new_skill = False
    round_items: list[dict[str, Any]] = []

    for round_id in range(1, max(1, int(max_rounds)) + 1):
        round_dir = evolution_round_dir(job_root, round_id)
        _reset_workspace_output(workspace_output)
        before_path = working_skill
        before_text = before_path.read_text(encoding="utf-8") if before_path.exists() else ""
        executed_tool = False
        tool_result = ""
        review_result = ""
        review_round_passed = False

        if source_skill is None:
            if progress_callback:
                progress_callback(round_id, "evolve")
            evolver_client = _create_client(
                agent_def_path=EVOLUTION_IMPROVER_AGENT_DEF,
                provider_role="evolution_improver",
                session_role="evolver",
                session_name=f"round-{round_id}",
                session_phase="evolve",
                session_round=round_id,
                task_id=task_id,
                llm_binding_snapshot=llm_binding_snapshot,
                session_root=job_root,
            )
            try:
                evolve_prompt = render_template(
                    EVOLUTION_IMPROVER_PROMPT_TMPL,
                    {
                        "$input": firmware_path,
                        "$output": str(workspace_output),
                        "$tools": str(TOOLS_DIR),
                        "$main_run": str(main_run),
                        "$evolution_run": str(job_root),
                        "$working_skill": str(working_skill),
                    },
                )
                _append_stage_log(round_dir, "evolver.log", "starting tool evolution", round=round_id)
                evolve_result = evolver_client.prompt(evolve_prompt)
                _save_agent_log(evolver_client, log, round_dir, "evolver")
            finally:
                evolver_client.close()
            updated_path = _extract_path_only(evolve_result)
            if updated_path is None:
                raise RuntimeError("工具进化器未返回更新后的 working skill 路径")
            working_skill = _validate_working_skill_path(updated_path, working_dir)
            before_text = working_skill.read_text(encoding="utf-8")

        if progress_callback:
            progress_callback(round_id, "tool_execute")
        tool_client = _create_client(
            agent_def_path=EVOLUTION_EXEC_AGENT_DEF,
            provider_role="skill_executor",
            session_role="skill-executor",
            session_name=f"round-{round_id}",
            session_phase="tool_execute",
            session_round=round_id,
            task_id=task_id,
            llm_binding_snapshot=llm_binding_snapshot,
            session_root=job_root,
        )
        try:
            tool_prompt = render_template(
                EVOLUTION_EXEC_PROMPT_TMPL,
                {
                    "$input": firmware_path,
                    "$output": str(workspace_output),
                    "$tools": str(TOOLS_DIR),
                    "$working_skill": str(working_skill),
                },
            )
            _append_stage_log(round_dir, "tool_executor.log", "starting evolution tool execution", round=round_id)
            tool_result = tool_client.prompt(tool_prompt)
            _save_agent_log(tool_client, log, round_dir, "tool_executor")
            executed_tool = True
        finally:
            tool_client.close()

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
            _append_stage_log(round_dir, "reviewer.log", "starting evolution review", round=round_id)
            review_result = review_client.prompt(review_prompt)
            _save_agent_log(review_client, log, round_dir, "reviewer")
            review_round_passed = _review_passed(review_result)
        finally:
            review_client.close()

        summary_path = workspace_output / "summary.md"
        reason_path = workspace_output / "reason.md"
        round_status = "review_passed" if review_round_passed else "review_failed"
        round_item: dict[str, Any] = {
            "round": round_id,
            "status": round_status,
            "tool_skill_path_before": str(before_path),
            "tool_skill_path_after": str(working_skill),
            "tool_changed": False,
            "review_result": review_result,
            "summary_path": str(summary_path) if summary_path.exists() else None,
            "reason_path": str(reason_path) if reason_path.exists() else None,
            "log_root": str(round_dir),
            "log_files": {
                "tool_executor": str(round_dir / "tool_executor_transcript.log"),
                "reviewer": str(round_dir / "reviewer_transcript.log"),
                "evolver": str(round_dir / "evolver_transcript.log"),
            },
            "source_skill_path": str(source_skill) if source_skill is not None else None,
            "started_without_matched_skill": started_without_matched_skill,
            "generated_new_skill": False,
            "executed_tool": executed_tool,
            "tool_response_preview": tool_result[:2000] if tool_result else None,
            "created_at": datetime.now().isoformat(),
            "completed_at": datetime.now().isoformat(),
        }

        if review_round_passed:
            review_passed = True
            final_skill_path, replaced_skill_path, generated_new_skill = _save_generated_skill_to_repo(
                firmware_path=firmware_path,
                working_skill=working_skill,
                source_skill=source_skill,
            )
            round_item["generated_new_skill"] = generated_new_skill
            round_item["tool_skill_path_after"] = final_skill_path
            round_items.append(round_item)
            _write_json_log(round_dir, "evolution_round.json", round_item)
            break

        if round_id >= max_rounds:
            round_items.append(round_item)
            _write_json_log(round_dir, "evolution_round.json", round_item)
            continue

        if progress_callback:
            progress_callback(round_id, "evolve")
        evolver_client = _create_client(
            agent_def_path=EVOLUTION_IMPROVER_AGENT_DEF,
            provider_role="evolution_improver",
            session_role="evolver",
            session_name=f"round-{round_id}",
            session_phase="evolve",
            session_round=round_id,
            task_id=task_id,
            llm_binding_snapshot=llm_binding_snapshot,
            session_root=job_root,
        )
        try:
            evolve_prompt = render_template(
                EVOLUTION_IMPROVER_PROMPT_TMPL,
                {
                    "$input": firmware_path,
                    "$output": str(workspace_output),
                    "$tools": str(TOOLS_DIR),
                    "$main_run": str(main_run),
                    "$evolution_run": str(job_root),
                    "$working_skill": str(working_skill),
                },
            )
            _append_stage_log(round_dir, "evolver.log", "starting tool evolution", round=round_id)
            evolve_result = evolver_client.prompt(evolve_prompt)
            _save_agent_log(evolver_client, log, round_dir, "evolver")
        finally:
            evolver_client.close()

        updated_path = _extract_path_only(evolve_result)
        if updated_path is None:
            raise RuntimeError("工具进化器未返回更新后的 working skill 路径")
        updated_working_skill = _validate_working_skill_path(updated_path, working_dir)
        after_text = updated_working_skill.read_text(encoding="utf-8")
        round_item["status"] = "evolve_completed"
        round_item["tool_changed"] = before_text != after_text or updated_working_skill != before_path
        round_item["tool_skill_path_after"] = str(updated_working_skill)
        round_item["generated_new_skill"] = updated_working_skill != before_path
        round_items.append(round_item)
        _write_json_log(round_dir, "evolution_round.json", round_item)
        working_skill = updated_working_skill

    final_status = "success" if review_passed else "failed"
    payload = {
        "status": final_status,
        "review_passed": review_passed,
        "current_round": len(round_items),
        "max_rounds": max_rounds,
        "final_skill_path": final_skill_path,
        "replaced_skill_path": replaced_skill_path if review_passed else None,
        "job_root": str(job_root),
        "session_root": str(session_root),
        "rounds": round_items,
        "working_skill_path": str(working_skill),
        "source_skill_path": str(source_skill) if source_skill is not None else None,
        "started_without_matched_skill": started_without_matched_skill,
        "generated_new_skill": generated_new_skill,
    }
    (job_root / "evolution_result.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload
