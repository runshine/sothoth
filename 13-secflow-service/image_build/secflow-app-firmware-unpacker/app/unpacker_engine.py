"""Firmware unpacking execution engine used by the task manager."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from app.logging_utils import log_event
from app.preprocess import detect_format, run_preprocess
from app.skill_store import (
    DEFAULT_PROMOTION_THRESHOLD,
    compute_family_id,
    match_skill,
    register_skill_success,
    save_candidate_skill,
)
from app.unpacker_engine_config import (
    AUTHOR_AGENT_DEF,
    AUTHOR_PROMPT_TMPL,
    CLEAN_AGENT_DEF,
    CLEAN_PROMPT_TMPL,
    EXEC_AGENT_DEF,
    EXEC_FIRST_TMPL,
    EXEC_RETRY_TMPL,
    LOG_OUTPUT_DIR,
    PI_AGENT_DIR_ENV,
    ROLE_CONFIG_FILE_KEYS,
    ROLE_MODEL_CONFIG_KEYS,
    TOOLS_DIR,
    VAL_AGENT_DEF,
    VAL_PROMPT_TMPL,
    build_settings_json as _build_settings_json,
    get_max_retries as _get_max_retries,
    load_agent_def,
    preview_text as _preview_text,
    render_prompt,
    render_template,
    resolve_provider_model as _resolve_provider_model,
    resolve_provider_selector as _resolve_provider_selector,
    slug_session_part as _slug_session_part,
)
from app.unpacker_engine_logs import (
    append_stage_log as _append_stage_log,
    append_stream_delta as _append_stream_delta,
    copy_optional_text_file as _copy_optional_text_file,
    get_log_dir,
    get_round_dir as _get_round_dir,
    is_review_success as _is_review_success,
    kill_process_tree as _kill_process_tree,
    read_json_file as _read_json_file,
    round_dir_name as _round_dir_name,
    save_agent_log as _save_agent_log,
    write_round_result as _write_round_result,
    write_json_log as _write_json_log,
    write_token_summary as _write_token_summary,
)
from app.unpacker_engine_pi import PiRpcClient
from app.unpacker_engine_session import build_session_artifacts, update_session_index


log = logging.getLogger("unpacker.engine")
debug_mode = True


def _reviewer_session_name(suffix: str) -> tuple[str, int | None]:
    normalized = str(suffix or "").strip().replace("_", "-")
    import re

    match = re.fullmatch(r"round-(\d+)", normalized)
    if match:
        return normalized, int(match.group(1))
    return normalized or "default", None


def _write_system_prompt(content: str, prefix: str) -> str:
    temp_file = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix=prefix,
        suffix=".md",
        delete=False,
    )
    temp_file.write(content)
    temp_file.flush()
    temp_file.close()
    return temp_file.name


def _copy_round_report(output_path: str, round_dir: Path | None, filename: str) -> str | None:
    if round_dir is None:
        return None
    source = Path(output_path) / filename
    target = round_dir / filename
    return str(target) if _copy_optional_text_file(source, target) else None


def _preview_markdown(path: Path, limit: int = 1000) -> str | None:
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8").strip()
    except Exception:
        return None
    if not text:
        return ""
    return text[:limit]


def _normalize_output_reports(output_path: str) -> None:
    output_root = Path(output_path)
    for legacy_name, canonical_name in (("summary.txt", "summary.md"), ("reason.txt", "reason.md")):
        legacy_path = output_root / legacy_name
        canonical_path = output_root / canonical_name
        if legacy_path.exists():
            if canonical_path.exists():
                legacy_path.unlink(missing_ok=True)
            else:
                shutil.move(str(legacy_path), str(canonical_path))


def extract_firmware_features(
    firmware_path: str,
    cancel_check: Optional[Callable[[], bool]] = None,
    register_cancel_hook: Optional[Callable[[Callable[[], None] | None], None]] = None,
) -> dict:
    path = Path(firmware_path)
    info = detect_format(firmware_path)
    features = {
        "filename": path.name,
        "ext": info["ext"],
        "ext2": info["ext2"],
        "fmt": info["fmt"] or "unknown",
        "size": 0,
        "magic_hex": info["magic"].hex()[:8] if info["magic"] else "",
        "binwalk_sigs": [],
    }
    try:
        features["size"] = os.path.getsize(firmware_path)
    except RuntimeError:
        raise
    except Exception:
        pass
    try:
        proc = subprocess.Popen(
            ["binwalk", "-B", firmware_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        if register_cancel_hook is not None:
            register_cancel_hook(lambda: _kill_process_tree(proc))
        while True:
            if cancel_check and cancel_check():
                _kill_process_tree(proc)
                raise RuntimeError("__CANCELLED__")
            if proc.poll() is not None:
                stdout, _stderr = proc.communicate()
                break
            time.sleep(0.2)
        for line in stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("DECIMAL") and not line.startswith("-"):
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    features["binwalk_sigs"].append(parts[2][:100].lower())
    except Exception:
        pass
    finally:
        if register_cancel_hook is not None:
            register_cancel_hook(None)
    return features


def _run_reviewer(
    task_id: str,
    firmware_path: str,
    output_path: str,
    log_dir: Path | None,
    round_dir: Path | None,
    suffix: str,
    val_def: dict[str, Any],
    val_sp: str,
    llm_binding_snapshot: dict[str, Any] | None = None,
    bind_cancel_client: Optional[Callable[[PiRpcClient | None], None]] = None,
    heartbeat_callback: Optional[Callable[[], None]] = None,
) -> tuple[bool, str, dict[str, Any]]:
    stage_log_dir = _get_round_dir(log_dir, 0)
    _append_stage_log(
        stage_log_dir,
        "stage4_llm_review.log",
        "starting review round",
        suffix=suffix,
        firmware_path=firmware_path,
        output_path=output_path,
    )
    session_name, round_id = _reviewer_session_name(suffix)
    session_artifacts = build_session_artifacts(
        log_dir,
        role="reviewer",
        name=session_name,
        provider_role="reviewer",
        phase="review",
        round_id=round_id,
    )
    validator = PiRpcClient(
        system_prompt_file=val_sp,
        model=val_def["model"],
        tools=val_def["tools"],
        provider_role="reviewer",
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
    if bind_cancel_client:
        bind_cancel_client(validator)
    try:
        started_at = datetime.utcnow().isoformat()
        started_monotonic = time.perf_counter()
        verify_result = validator.prompt(
            render_prompt(VAL_PROMPT_TMPL, firmware_path, output_path),
            stream_callback=lambda event: _append_stream_delta(
                stage_log_dir,
                "stage4_llm_review.log",
                f"reviewer:{suffix}",
                event,
            ),
            heartbeat_callback=heartbeat_callback,
        )
        token_stats = _save_agent_log(validator, log, round_dir, "reviewer")
        completed_at = datetime.utcnow().isoformat()
        return _is_review_success(verify_result), verify_result, {
            "started_at": started_at,
            "completed_at": completed_at,
            "duration_seconds": round(time.perf_counter() - started_monotonic, 3),
            "token_stats": token_stats,
            "session_file": session_artifacts["session_path"].name,
            "session_role": session_artifacts["session_role"],
            "session_name": session_artifacts["session_name"],
            "provider_role": session_artifacts["provider_role"],
        }
    finally:
        if bind_cancel_client:
            bind_cancel_client(None)
        validator.close()


def _run_skill_unpack(
    task_id: str,
    skill_meta: dict[str, Any],
    firmware_path: str,
    output_path: str,
    log_dir: Path | None,
    val_def: dict[str, Any],
    val_sp: str,
    llm_binding_snapshot: dict[str, Any] | None = None,
    bind_cancel_client: Optional[Callable[[PiRpcClient | None], None]] = None,
    heartbeat_callback: Optional[Callable[[], None]] = None,
) -> dict[str, Any]:
    global_round_dir = _get_round_dir(log_dir, 0)
    _append_stage_log(
        global_round_dir,
        "skill_exec.log",
        "starting skill execution",
        skill=skill_meta.get("path"),
        family_id=skill_meta.get("family_id"),
        skill_version=skill_meta.get("skill_version"),
        firmware_path=firmware_path,
        output_path=output_path,
    )
    skill_sp = _write_system_prompt(str(skill_meta.get("system_prompt") or ""), "firmware-skill-")
    skill_name = _slug_session_part(Path(str(skill_meta.get("path") or "skill")).stem, fallback="skill")
    session_artifacts = build_session_artifacts(
        log_dir,
        role="skill-executor",
        name=skill_name,
        provider_role="skill_executor",
        phase="tool_match",
        skill_name=skill_name,
    )
    executor = PiRpcClient(
        system_prompt_file=skill_sp,
        model=skill_meta.get("model"),
        tools=skill_meta.get("tools"),
        provider_role="skill_executor",
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
    if bind_cancel_client:
        bind_cancel_client(executor)
    try:
        exec_result = executor.prompt(
            render_prompt(EXEC_FIRST_TMPL, firmware_path, output_path),
            heartbeat_callback=heartbeat_callback,
        )
        _save_agent_log(executor, log, global_round_dir, "skill_executor")
        passed, review_result, _review_meta = _run_reviewer(
            task_id,
            firmware_path,
            output_path,
            log_dir,
            global_round_dir,
            "skill",
            val_def,
            val_sp,
            llm_binding_snapshot=llm_binding_snapshot,
            bind_cancel_client=bind_cancel_client,
            heartbeat_callback=heartbeat_callback,
        )
        result = {
            "success": passed,
            "method": f"skill:{skill_meta.get('filename')}",
            "response": exec_result,
            "review": review_result,
        }
        _append_stage_log(
            global_round_dir,
            "skill_exec.log",
            "skill execution completed",
            success=passed,
            response_preview=_preview_text(exec_result),
            review_preview=_preview_text(review_result),
        )
        _write_json_log(
            global_round_dir,
            "skill_exec.json",
            {
                "skill": skill_meta.get("path"),
                "family_id": skill_meta.get("family_id"),
                "skill_version": skill_meta.get("skill_version"),
                "success": passed,
                "response_preview": _preview_text(exec_result),
                "review_preview": _preview_text(review_result),
            },
        )
        return result
    finally:
        if bind_cancel_client:
            bind_cancel_client(None)
        executor.close()
        try:
            Path(skill_sp).unlink()
        except FileNotFoundError:
            pass


def _run_generic_unpack(
    task_id: str,
    firmware_path: str,
    output_path: str,
    log_dir: Path | None,
    cancel_check: Callable[[PiRpcClient | None], None],
    exec_def: dict[str, Any],
    val_def: dict[str, Any],
    exec_sp: str,
    val_sp: str,
    llm_binding_snapshot: dict[str, Any] | None = None,
    event_callback: Optional[Callable[[str, str], None]] = None,
    unpack_heartbeat_callback: Optional[Callable[[], None]] = None,
    review_heartbeat_callback: Optional[Callable[[], None]] = None,
) -> tuple[bool, int, str]:
    stage_log_dir = _get_round_dir(log_dir, 0)
    _append_stage_log(
        stage_log_dir,
        "stage3_llm_unpack.log",
        "starting generic llm unpack",
        firmware_path=firmware_path,
        output_path=output_path,
    )
    max_retries = _get_max_retries()
    session_artifacts = build_session_artifacts(
        log_dir,
        role="executor",
        name="round-1",
        provider_role="executor",
        phase="llm_unpack",
        round_id=1,
    )
    executor = PiRpcClient(
        system_prompt_file=exec_sp,
        model=exec_def["model"],
        tools=exec_def["tools"],
        provider_role="executor",
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
    cancel_check(executor)
    passed = False
    final_round = 0
    last_reason = ""
    try:
        for attempt in range(1, max_retries + 1):
            round_dir = _get_round_dir(log_dir, attempt)
            cancel_check(executor)
            final_round = attempt
            if attempt > 1:
                round_artifacts = build_session_artifacts(
                    log_dir,
                    role="executor",
                    name=f"round-{attempt}",
                    provider_role="executor",
                    phase="llm_unpack",
                    round_id=attempt,
                )
                executor.close()
                executor = PiRpcClient(
                    system_prompt_file=exec_sp,
                    model=exec_def["model"],
                    tools=exec_def["tools"],
                    provider_role="executor",
                    llm_binding_snapshot=llm_binding_snapshot,
                    session_dir=round_artifacts["session_dir"],
                    session_path=round_artifacts["session_path"],
                    session_role=round_artifacts["session_role"],
                    session_name=round_artifacts["session_name"],
                    session_phase=round_artifacts["phase"],
                    session_round=round_artifacts["round"],
                    session_skill_name=round_artifacts["skill_name"],
                    task_id=task_id,
                )
                session_artifacts = round_artifacts
                cancel_check(executor)
            exec_msg = render_prompt(
                EXEC_FIRST_TMPL if attempt == 1 else EXEC_RETRY_TMPL,
                firmware_path,
                output_path,
            )
            executor_started_at = datetime.utcnow().isoformat()
            executor_started_monotonic = time.perf_counter()
            exec_result = executor.prompt(
                exec_msg,
                stream_callback=lambda event, round_id=attempt: _append_stream_delta(
                    stage_log_dir,
                    "stage3_llm_unpack.log",
                    f"executor:round_{round_id}",
                    event,
                ),
                heartbeat_callback=unpack_heartbeat_callback,
            )
            executor_token_stats = _save_agent_log(executor, log, round_dir, "executor")
            executor_completed_at = datetime.utcnow().isoformat()
            executor_duration_seconds = round(time.perf_counter() - executor_started_monotonic, 3)
            _append_stage_log(
                stage_log_dir,
                "stage3_llm_unpack.log",
                "executor round completed",
                attempt=attempt,
                response_preview=_preview_text(exec_result),
            )
            if event_callback:
                event_callback(
                    "executor_round_completed",
                    f"执行轮次 {attempt} 已完成",
                    stage_key="llm_unpack",
                    status="running",
                    detail={
                        "round": attempt,
                        "response_preview": _preview_text(exec_result),
                    },
                )
            if round_dir is not None:
                transcript_path = round_dir / "executor_transcript.log"
                if transcript_path.exists():
                    _append_stage_log(
                        stage_log_dir,
                        "stage3_llm_unpack.log",
                        "executor conversation transcript captured",
                        attempt=attempt,
                        transcript_file=transcript_path.name,
                    )
            passed, verify_result, reviewer_meta = _run_reviewer(
                task_id,
                firmware_path,
                output_path,
                log_dir,
                round_dir,
                f"round_{attempt}",
                val_def,
                val_sp,
                llm_binding_snapshot=llm_binding_snapshot,
                bind_cancel_client=cancel_check,
                heartbeat_callback=review_heartbeat_callback,
            )
            log_event(
                log,
                logging.INFO,
                "executor attempt completed",
                event="executor_attempt_complete",
                attempt=attempt,
                response_preview=_preview_text(exec_result),
            )
            log_event(
                log,
                logging.INFO,
                "verifier attempt completed",
                event="verifier_attempt_complete",
                attempt=attempt,
                response_preview=_preview_text(verify_result),
            )
            _append_stage_log(
                stage_log_dir,
                "stage4_llm_review.log",
                "review round completed",
                attempt=attempt,
                passed=passed,
                review_preview=_preview_text(verify_result),
            )
            if event_callback:
                event_callback(
                    "review_round_completed",
                    f"评审轮次 {attempt} 已完成",
                    stage_key="review",
                    status="success" if passed else "running",
                    detail={
                        "round": attempt,
                        "passed": passed,
                        "review_preview": _preview_text(verify_result),
                    },
                )
            if round_dir is not None:
                _normalize_output_reports(output_path)
                reviewer_transcript_path = round_dir / "reviewer_transcript.log"
                if reviewer_transcript_path.exists():
                    _append_stage_log(
                        stage_log_dir,
                        "stage4_llm_review.log",
                        "reviewer conversation transcript captured",
                        attempt=attempt,
                        transcript_file=reviewer_transcript_path.name,
                    )
                summary_round_path = _copy_round_report(output_path, round_dir, "summary.md")
                reason_round_path = _copy_round_report(output_path, round_dir, "reason.md")
                executor_tokens = dict(executor_token_stats or {})
                reviewer_tokens = dict(reviewer_meta.get("token_stats") or {})
                round_total_tokens = {
                    field: int(executor_tokens.get(field, 0) or 0) + int(reviewer_tokens.get(field, 0) or 0)
                    for field in ("input", "output", "cacheRead", "cacheWrite", "total")
                }
                warnings: list[str] = []
                if not summary_round_path:
                    warnings.append("summary.md not generated yet")
                if not reason_round_path:
                    warnings.append("reason.md not generated yet")
                _write_round_result(
                    round_dir,
                    task_id=task_id,
                    round_id=attempt,
                    status="review_passed" if passed else "review_failed",
                    created_at=reviewer_meta["completed_at"],
                    started_at=executor_started_at,
                    completed_at=reviewer_meta["completed_at"],
                    duration_seconds=round(
                        executor_duration_seconds + float(reviewer_meta.get("duration_seconds") or 0.0),
                        3,
                    ),
                    output_root=Path(output_path),
                    paths={
                        "run_root": str(log_dir) if log_dir is not None else None,
                        "round_root": str(round_dir),
                        "output_root": output_path,
                        "executor_messages_path": str(round_dir / "executor_messages.json"),
                        "executor_transcript_path": str(round_dir / "executor_transcript.log"),
                        "executor_tokens_path": str(round_dir / "executor_tokens.json"),
                        "reviewer_messages_path": str(round_dir / "reviewer_messages.json"),
                        "reviewer_transcript_path": str(round_dir / "reviewer_transcript.log"),
                        "reviewer_tokens_path": str(round_dir / "reviewer_tokens.json"),
                        "summary_path": summary_round_path,
                        "reason_path": reason_round_path,
                        "output_manifest_path": str(round_dir / "output_manifest.json"),
                    },
                    executor={
                        "provider_role": session_artifacts["provider_role"],
                        "session_role": session_artifacts["session_role"],
                        "session_name": session_artifacts["session_name"],
                        "session_file": session_artifacts["session_path"].name,
                        "prompt_type": "initial" if attempt == 1 else "retry",
                        "response_preview": _preview_text(exec_result),
                        "duration_seconds": executor_duration_seconds,
                        "tokens": executor_tokens,
                        "started_at": executor_started_at,
                        "completed_at": executor_completed_at,
                    },
                    reviewer={
                        "provider_role": reviewer_meta["provider_role"],
                        "session_role": reviewer_meta["session_role"],
                        "session_name": reviewer_meta["session_name"],
                        "session_file": reviewer_meta["session_file"],
                        "passed": passed,
                        "review_result": verify_result,
                        "review_preview": _preview_text(verify_result),
                        "duration_seconds": reviewer_meta["duration_seconds"],
                        "tokens": reviewer_tokens,
                        "started_at": reviewer_meta["started_at"],
                        "completed_at": reviewer_meta["completed_at"],
                    },
                    tokens={
                        "executor": executor_tokens,
                        "reviewer": reviewer_tokens,
                        "round_total": round_total_tokens,
                    },
                    artifacts={
                        "summary_present": bool(summary_round_path),
                        "summary_preview": _preview_markdown(Path(summary_round_path)) if summary_round_path else None,
                        "reason_present": bool(reason_round_path),
                        "reason_preview": _preview_markdown(Path(reason_round_path)) if reason_round_path else None,
                        "tokens_summary_present": False,
                        "warnings": warnings,
                    },
                    context={
                        "matched_skill": None,
                        "fallback_to_llm": True,
                        "executor_rounds_planned": max_retries,
                        "firmware_path": firmware_path,
                        "output_path": output_path,
                    },
                )
            if passed:
                break
            last_reason = verify_result
        return passed, final_round, last_reason
    finally:
        cancel_check(None)
        executor.close()


def _extract_markdown_document(text: str) -> str:
    import re

    raw = str(text or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-zA-Z0-9_-]*\n", "", raw)
        raw = re.sub(r"\n```$", "", raw)
    return raw.strip()


def _generate_candidate_skill(
    task_id: str,
    firmware_path: str,
    output_path: str,
    features: dict[str, Any],
    review_result: str,
    log_dir: Path | None,
    llm_binding_snapshot: dict[str, Any] | None = None,
    bind_cancel_client: Optional[Callable[[PiRpcClient | None], None]] = None,
) -> dict[str, Any] | None:
    _append_stage_log(
        log_dir,
        "stage5_skill_generate.log",
        "starting candidate skill generation",
        firmware_path=firmware_path,
        output_path=output_path,
        family_id=compute_family_id(features),
    )
    try:
        author_def = load_agent_def(AUTHOR_AGENT_DEF)
        summary_path = Path(output_path) / "summary.md"
        summary_text = summary_path.read_text(encoding="utf-8") if summary_path.exists() else ""
        prompt = render_template(
            AUTHOR_PROMPT_TMPL,
            {
                "$input": firmware_path,
                "$output": output_path,
                "$summary": summary_text,
                "$features": json.dumps(features, ensure_ascii=False, indent=2),
                "$review_result": review_result,
                "$family_id": compute_family_id(features),
                "$promotion_threshold": str(DEFAULT_PROMOTION_THRESHOLD),
            },
        )
        author_sp = _write_system_prompt(author_def["system_prompt"], "firmware-skill-author-")
        session_artifacts = build_session_artifacts(
            log_dir,
            role="skill-author",
            name="default",
            provider_role="skill_author",
            phase="skill_author",
        )
        author = PiRpcClient(
            system_prompt_file=author_sp,
            model=author_def["model"],
            tools=author_def["tools"],
            provider_role="skill_author",
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
        if bind_cancel_client:
            bind_cancel_client(author)
        try:
            raw_doc = author.prompt(prompt)
            _save_agent_log(author, log, log_dir, "skill_author")
        finally:
            if bind_cancel_client:
                bind_cancel_client(None)
            author.close()
            try:
                Path(author_sp).unlink()
            except FileNotFoundError:
                pass
        saved = save_candidate_skill(
            TOOLS_DIR,
            _extract_markdown_document(raw_doc),
            {"family_id": compute_family_id(features)},
        )
        _write_json_log(
            log_dir,
            "stage5_skill_generate.json",
            {
                "generated_skill_path": saved.get("path"),
                "family_id": saved.get("family_id"),
                "skill_version": saved.get("skill_version"),
                "skill_status": saved.get("skill_status"),
            },
        )
        _append_stage_log(
            log_dir,
            "stage5_skill_generate.log",
            "candidate skill generated",
            generated_skill_path=saved.get("path"),
            skill_status=saved.get("skill_status"),
            promotion_success_count=saved.get("promotion_success_count"),
        )
        return saved
    except Exception as exc:
        _write_json_log(
            log_dir,
            "stage5_skill_generate.json",
            {"error": str(exc), "family_id": compute_family_id(features)},
        )
        _append_stage_log(
            log_dir,
            "stage5_skill_generate.log",
            "candidate skill generation failed",
            error=str(exc),
        )
        return None


def _run_cleaner(
    task_id: str,
    output_path: str,
    log_dir: Path | None = None,
    llm_binding_snapshot: dict[str, Any] | None = None,
    bind_cancel_client: Optional[Callable[[PiRpcClient | None], None]] = None,
    event_callback: Optional[Callable[[str, str], None]] = None,
    heartbeat_callback: Optional[Callable[[], None]] = None,
) -> str:
    _append_stage_log(
        log_dir,
        "cleaner.log",
        "starting cleanup",
        output_path=output_path,
    )
    clean_def = load_agent_def(CLEAN_AGENT_DEF)
    clean_sp = "/tmp/firmware-extract-cleanup.md"
    Path(clean_sp).write_text(clean_def["system_prompt"])
    session_artifacts = build_session_artifacts(
        log_dir,
        role="cleaner",
        name="default",
        provider_role="cleaner",
        phase="cleanup",
    )
    cleaner = PiRpcClient(
        system_prompt_file=clean_sp,
        model=clean_def["model"],
        tools=clean_def["tools"],
        provider_role="cleaner",
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
    if bind_cancel_client:
        bind_cancel_client(cleaner)
    try:
        clean_msg = render_prompt(CLEAN_PROMPT_TMPL, output_path, "")
        log_event(log, logging.INFO, "cleanup started", event="cleanup_start")
        if event_callback:
            event_callback(
                "cleanup_started",
                "开始执行清理收尾",
                stage_key="cleanup",
                status="running",
                detail={"output_path": output_path},
            )
        result = cleaner.prompt(
            clean_msg,
            heartbeat_callback=heartbeat_callback,
        )
        _save_agent_log(cleaner, log, log_dir, "cleaner")
        log_event(
            log,
            logging.INFO,
            "cleanup completed",
            event="cleanup_complete",
            response_preview=_preview_text(result),
        )
        _append_stage_log(
            log_dir,
            "cleaner.log",
            "cleanup completed",
            response_preview=_preview_text(result),
        )
        if event_callback:
            event_callback(
                "cleanup_completed",
                "清理收尾已完成",
                stage_key="cleanup",
                status="success",
                detail={"response_preview": _preview_text(result)},
            )
        return result
    finally:
        if bind_cancel_client:
            bind_cancel_client(None)
        cleaner.close()


def run_unpack(
    task_id: str,
    firmware_path: str,
    output_path: str,
    llm_binding_snapshot: dict[str, Any] | None = None,
    cancel_check: Optional[Callable[[], bool]] = None,
    register_cancel_hook: Optional[Callable[[Callable[[], None] | None], None]] = None,
    progress_callback: Optional[Callable[[str], None]] = None,
    event_callback: Optional[Callable[..., None]] = None,
) -> dict:
    """Execute the firmware unpacking pipeline."""

    active_client: PiRpcClient | None = None

    def _bind_cancel_client(client: PiRpcClient | None) -> None:
        nonlocal active_client
        active_client = client
        if register_cancel_hook is None:
            return
        if client is None:
            register_cancel_hook(None)
            return
        register_cancel_hook(lambda: client.close())

    def _check_cancel(executor: PiRpcClient | None = None) -> None:
        if executor is not None:
            _bind_cancel_client(executor)
        elif executor is None and active_client is None:
            _bind_cancel_client(None)
        if cancel_check and cancel_check():
            target = executor or active_client
            if target is not None:
                target.close()
            _bind_cancel_client(None)
            raise RuntimeError("__CANCELLED__")

    def _report_progress(stage: str) -> None:
        if progress_callback is None:
            return
        try:
            progress_callback(stage)
        except Exception:
            pass

    def _stage_heartbeat(stage: str) -> Callable[[], None]:
        return lambda: _report_progress(stage)

    os.makedirs(output_path, exist_ok=True)
    try:
        log_dir = get_log_dir(output_path)
    except Exception:
        log_dir = None
    global_round_dir = _get_round_dir(log_dir, 0)

    _check_cancel()
    _report_progress("preprocess")

    try:
        pre_result = run_preprocess(
            firmware_path,
            output_path,
            log_dir=global_round_dir,
            cancel_check=cancel_check,
            register_cancel_hook=register_cancel_hook,
        )
    except Exception as exc:
        pre_result = {"success": False, "method": None}
        log_event(
            log,
            logging.WARNING,
            "quick pre-process exception",
            event="quick_preprocess_exception",
            error=str(exc),
        )

    if pre_result.get("success"):
        return {
            "status": "success",
            "message": f"Extracted by quick pre-process: {pre_result['method']}",
            "rounds": 0,
        }

    _check_cancel()
    _report_progress("feature_extract")

    features: dict[str, Any] = {}
    try:
        features = extract_firmware_features(
            firmware_path,
            cancel_check=cancel_check,
            register_cancel_hook=register_cancel_hook,
        )
        features["family_id"] = compute_family_id(features)
        skill_meta, skill_score, skill_match = match_skill(features, TOOLS_DIR)
    except RuntimeError as exc:
        if str(exc) == "__CANCELLED__":
            raise
        skill_meta = None
        skill_score = 0
        skill_match = {"matched_status": None, "reasons": []}
        log_event(
            log,
            logging.WARNING,
            "fast mode feature extraction exception",
            event="fast_mode_exception",
            error=str(exc),
        )
    except Exception as exc:
        skill_meta = None
        skill_score = 0
        skill_match = {"matched_status": None, "reasons": []}
        log_event(
            log,
            logging.WARNING,
            "fast mode feature extraction exception",
            event="fast_mode_exception",
            error=str(exc),
        )
    _append_stage_log(
        global_round_dir,
        "skill_match.log",
        "feature extraction and skill match completed",
        features=features,
        matched_skill=skill_meta.get("path") if skill_meta else None,
        matched_skill_score=skill_score,
        matched_status=skill_match.get("matched_status"),
        reasons=skill_match.get("reasons"),
    )

    _write_json_log(
        global_round_dir,
        "skill_match.json",
        {
            "features": features,
            "matched_skill": skill_meta.get("path") if skill_meta else None,
            "matched_skill_version": skill_meta.get("skill_version") if skill_meta else None,
            "matched_skill_score": skill_score,
            "matched_status": skill_match.get("matched_status"),
            "reasons": skill_match.get("reasons"),
        },
    )

    _check_cancel()
    _report_progress("skill_match")

    try:
        exec_def = load_agent_def(EXEC_AGENT_DEF)
        val_def = load_agent_def(VAL_AGENT_DEF)
    except Exception as exc:
        return {
            "status": "failed",
            "message": f"Agent definition load failed: {exc}",
            "rounds": 0,
        }

    exec_sp = "/tmp/firmware-unpacker.md"
    val_sp = "/tmp/firmware-unpack-reviewer.md"
    Path(exec_sp).write_text(exec_def["system_prompt"])
    Path(val_sp).write_text(val_def["system_prompt"])

    passed = False
    final_round = 0
    last_reason = ""
    fallback_to_llm = False
    generated_skill = None
    matched_skill = skill_meta
    promotion_success_count = None

    try:
        if skill_meta:
            if event_callback:
                event_callback(
                    "tool_matched",
                    f"命中工具：{Path(str(skill_meta.get('path') or '')).name}",
                    stage_key="tool_match",
                    status="running",
                    detail={
                        "matched_skill": skill_meta.get("path"),
                        "skill_version": skill_meta.get("skill_version"),
                        "matched_skill_score": skill_score,
                    },
                )
            _check_cancel()
            _report_progress("tool_match")
            _append_stage_log(
                global_round_dir,
                "skill_match.log",
                "matched skill selected for execution",
                skill=skill_meta.get("path"),
                skill_version=skill_meta.get("skill_version"),
                family_id=skill_meta.get("family_id"),
            )
            skill_result = _run_skill_unpack(
                task_id,
                skill_meta,
                firmware_path,
                output_path,
                log_dir,
                val_def,
                val_sp,
                llm_binding_snapshot=llm_binding_snapshot,
                bind_cancel_client=_bind_cancel_client,
                heartbeat_callback=_stage_heartbeat("tool_match"),
            )
            if skill_result.get("success"):
                passed = True
                final_round = 0
                updated_skill = register_skill_success(TOOLS_DIR, str(skill_meta.get("path")))
                promotion_success_count = updated_skill.get("promotion_success_count")
                matched_skill = updated_skill
            else:
                fallback_to_llm = True
                last_reason = str(skill_result.get("review") or skill_result.get("response") or "")
                if event_callback:
                    event_callback(
                        "tool_fallback_to_llm",
                        "工具执行失败，已回退到 LLM 解包",
                        stage_key="tool_match",
                        status="running",
                        detail={
                            "matched_skill": skill_meta.get("path"),
                            "reason": _preview_text(last_reason, 400),
                        },
                    )
                _append_stage_log(
                    global_round_dir,
                    "stage3_llm_unpack.log",
                    "fallback to llm triggered after skill failure",
                    matched_skill=skill_meta.get("path"),
                    reason_preview=_preview_text(last_reason, 400),
                )
                _write_json_log(
                    global_round_dir,
                    "fallback.json",
                    {
                        "matched_skill": skill_meta.get("path"),
                        "reason": _preview_text(last_reason, 400),
                    },
                )

        if not passed:
            _report_progress("llm_unpack")
            generic_passed, final_round, last_reason = _run_generic_unpack(
                task_id,
                firmware_path,
                output_path,
                log_dir,
                _check_cancel,
                exec_def,
                val_def,
                exec_sp,
                val_sp,
                llm_binding_snapshot=llm_binding_snapshot,
                event_callback=event_callback,
                unpack_heartbeat_callback=_stage_heartbeat("llm_unpack"),
                review_heartbeat_callback=_stage_heartbeat("review"),
            )
            passed = generic_passed
            if passed:
                _report_progress("review")
                generated_skill = _generate_candidate_skill(
                    task_id,
                    firmware_path,
                    output_path,
                    features,
                    last_reason or '{"result":"success"}',
                    global_round_dir,
                    llm_binding_snapshot=llm_binding_snapshot,
                    bind_cancel_client=_bind_cancel_client,
                )
            else:
                _append_stage_log(
                    global_round_dir,
                    "stage3_llm_unpack.log",
                    "generic llm unpack finished without verified success",
                    rounds=final_round,
                    last_reason_preview=_preview_text(last_reason, 400),
                )

        _check_cancel()
        _report_progress("cleanup")
        _run_cleaner(
            task_id,
            output_path,
            log_dir=global_round_dir,
            llm_binding_snapshot=llm_binding_snapshot,
            bind_cancel_client=_bind_cancel_client,
            event_callback=event_callback,
            heartbeat_callback=_stage_heartbeat("cleanup"),
        )
        _normalize_output_reports(output_path)
        _write_token_summary(log_dir)

    except RuntimeError as exc:
        if str(exc) == "__CANCELLED__":
            return {
                "status": "cancelled",
                "message": "Task was cancelled",
                "rounds": final_round,
            }
        raise
    finally:
        _bind_cancel_client(None)

    return {
        "status": "success" if passed else "max_retries_reached",
        "message": (
            "Unpacking verified successfully"
            if passed
            else f"Max retries reached. Last reason: {last_reason}"
        ),
        "rounds": final_round,
        "matched_skill": matched_skill.get("path") if matched_skill else None,
        "matched_skill_version": matched_skill.get("skill_version") if matched_skill else None,
        "matched_skill_score": skill_score if matched_skill else None,
        "fallback_to_llm": fallback_to_llm,
        "generated_skill_path": generated_skill.get("path") if generated_skill else None,
        "generated_skill_status": generated_skill.get("skill_status") if generated_skill else None,
        "promotion_success_count": (
            promotion_success_count
            if promotion_success_count is not None
            else generated_skill.get("promotion_success_count") if generated_skill else None
        ),
    }


__all__ = [
    "AUTHOR_AGENT_DEF",
    "CLEAN_AGENT_DEF",
    "EXEC_AGENT_DEF",
    "LOG_OUTPUT_DIR",
    "PI_AGENT_DIR_ENV",
    "ROLE_CONFIG_FILE_KEYS",
    "ROLE_MODEL_CONFIG_KEYS",
    "build_session_artifacts",
    "TOOLS_DIR",
    "update_session_index",
    "VAL_AGENT_DEF",
    "PiRpcClient",
    "_build_settings_json",
    "_resolve_provider_model",
    "_resolve_provider_selector",
    "extract_firmware_features",
    "get_log_dir",
    "load_agent_def",
    "render_prompt",
    "render_template",
    "run_unpack",
]
