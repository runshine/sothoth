from __future__ import annotations

import json
import time
from pathlib import Path

from app.core.config import get_config
from app.core.time_utils import utc_now_z
from app.workers.poc_runtime import build_in_container_qemu_prompt, build_poc_qemu_instance_name
from app.workers.runner import (
    StageArtifact,
    StageContext,
    StageExecutionResult,
    StageHooks,
    append_file_to_log,
    build_agentflow_exec_command,
    build_agentflow_node,
    build_agentflow_process_env_and_summary,
    build_codex_exec_command,
    build_opencode_exec_command,
    build_process_env_and_summary,
    command_line_string,
    copy_file,
    discover_single_run_dir,
    extract_opencode_session_id,
    opencode_last_event_is_error,
    read_json_file,
    resolve_executor_mode,
    resolve_stage_primary_report_output_path,
    resolve_stage_executor_model,
    resolve_stage_work_dir,
    run_logged_command,
    write_agentflow_events_from_trace,
    write_json_file,
    write_last_message_from_agentflow_result,
    write_last_message_from_jsonl,
    write_text_file,
)


def run_poc_stage(context: StageContext, hooks: StageHooks, *, source_audit_report: Path) -> StageExecutionResult:
    cfg = get_config().execution
    poc_skill = str(context.effective_config.get("poc_skill") or cfg.default_poc_skill)
    executor_mode = resolve_executor_mode(context.effective_config)
    executor_model = resolve_stage_executor_model(context)
    prompt_path = context.stage_session_file("prompt.txt")
    events_path = context.stage_session_file("events.jsonl")
    last_message_path = context.stage_session_file("last-message.md")
    final_report_path = resolve_stage_primary_report_output_path(
        context,
        "poc",
        default_path=context.stage_artifact_path("poc-report.md"),
    )
    final_json_path = context.stage_artifact_path("audited-result.json")
    log_path = context.stage_log_path()

    if executor_mode == "agentflow_cli":
        combined_result = _reuse_agentflow_combined_stage_result(
            context=context,
            prompt_path=prompt_path,
            events_path=events_path,
            last_message_path=last_message_path,
            final_report_path=final_report_path,
            final_json_path=final_json_path,
            log_path=log_path,
            poc_skill=poc_skill,
            executor_model=executor_model,
        )
        if combined_result is not None:
            return combined_result

    if not source_audit_report.exists():
        write_text_file(prompt_path, "")
        return StageExecutionResult(
            stage_name="poc",
            status="failed",
            message=f"audit report path unavailable for poc stage: {source_audit_report}",
            return_code=None,
            log_path=log_path,
            artifacts=[],
            session_files=[prompt_path],
            metadata={"executor_mode": executor_mode, "model": executor_model, "poc_skill": poc_skill},
        )

    stage_source_report = _stage_input_report(context, source_audit_report)
    copy_file(source_audit_report, stage_source_report)
    prompt = _build_prompt(
        poc_skill=poc_skill,
        repo_root=context.repo_root,
        source_report_path=stage_source_report,
        output_report_path=_attempt_output_report(context),
        output_json_path=_attempt_output_json(context),
        report_language=str(context.effective_config.get("report_language") or "zh-CN"),
        qemu_instance_name=_poc_qemu_instance_name(context),
    )
    write_text_file(prompt_path, prompt)

    if executor_mode == "mock":
        return _run_mock_stage(
            context=context,
            hooks=hooks,
            prompt=prompt,
            prompt_path=prompt_path,
            events_path=events_path,
            last_message_path=last_message_path,
            source_audit_report=source_audit_report,
            final_report_path=final_report_path,
            final_json_path=final_json_path,
            log_path=log_path,
            poc_skill=poc_skill,
        )
    if executor_mode == "opencode_cli":
        return _run_opencode_stage(
            context=context,
            hooks=hooks,
            prompt=prompt,
            prompt_path=prompt_path,
            events_path=events_path,
            last_message_path=last_message_path,
            source_report_path=stage_source_report,
            final_report_path=final_report_path,
            final_json_path=final_json_path,
            log_path=log_path,
            poc_skill=poc_skill,
            executor_model=executor_model,
        )
    if executor_mode == "agentflow_cli":
        return _run_agentflow_stage(
            context=context,
            hooks=hooks,
            prompt=prompt,
            prompt_path=prompt_path,
            events_path=events_path,
            last_message_path=last_message_path,
            source_report_path=stage_source_report,
            final_report_path=final_report_path,
            final_json_path=final_json_path,
            log_path=log_path,
            poc_skill=poc_skill,
            executor_model=executor_model,
        )
    return _run_codex_stage(
        context=context,
        hooks=hooks,
        prompt=prompt,
        prompt_path=prompt_path,
        events_path=events_path,
        last_message_path=last_message_path,
        source_report_path=stage_source_report,
        final_report_path=final_report_path,
        final_json_path=final_json_path,
        log_path=log_path,
        poc_skill=poc_skill,
        executor_model=executor_model,
    )


def _run_mock_stage(
    *,
    context: StageContext,
    hooks: StageHooks,
    prompt: str,
    prompt_path: Path,
    events_path: Path,
    last_message_path: Path,
    source_audit_report: Path,
    final_report_path: Path,
    final_json_path: Path,
    log_path: Path,
    poc_skill: str,
) -> StageExecutionResult:
    if _sleep_with_cancel(hooks):
        return StageExecutionResult(
            stage_name="poc",
            status="cancelled",
            message="poc stage cancelled",
            return_code=None,
            log_path=log_path,
            artifacts=[],
            session_files=[prompt_path],
            metadata={"executor_mode": "mock", "poc_skill": poc_skill},
        )
    write_text_file(
        log_path,
        "\n".join(
            [
                f"=== {poc_skill} ===",
                f"Generated at (UTC): {utc_now_z()}",
                f"Repo root: {context.repo_root}",
                f"Source report: {source_audit_report}",
                "=== prompt ===",
                prompt,
                "=== executor output ===",
                "[mock] poc stage completed",
                "",
            ]
        ),
    )
    write_text_file(events_path, "")
    write_text_file(
        final_report_path,
        "\n".join(
            [
                "# IPC PoC Report",
                "",
                "本报告由当前服务的 mock 执行器生成，用于打通任务状态、日志与产物链路。",
                "",
                f"- Task ID: `{context.task_id}`",
                f"- Attempt ID: `{context.attempt_id}`",
                f"- Source Audit Report: `{source_audit_report.name}`",
                "",
            ]
        ),
    )
    write_text_file(last_message_path, final_report_path.read_text(encoding="utf-8"))
    final_json_path.parent.mkdir(parents=True, exist_ok=True)
    final_json_path.write_text(
        json.dumps(
            {
                "project": context.project_path,
                "vulnerabilities_found": 0,
                "pocs_developed": 0,
                "info_findings": 0,
                "audit_findings_total": 0,
                "poc_confirmed_problem_count": 0,
                "poc_built_success_count": 0,
                "poc_built_success_but_no_crash_count": 0,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return StageExecutionResult(
        stage_name="poc",
        status="succeeded",
        message="poc stage completed",
        return_code=0,
        log_path=log_path,
        artifacts=[
            StageArtifact("poc_report", final_report_path, display_name=final_report_path.name),
            StageArtifact("audited_result_json", final_json_path, display_name=final_json_path.name),
        ],
        session_files=[prompt_path, events_path, last_message_path],
        output_path=final_report_path,
        metadata={"executor_mode": "mock", "poc_skill": poc_skill},
    )


def _run_codex_stage(
    *,
    context: StageContext,
    hooks: StageHooks,
    prompt: str,
    prompt_path: Path,
    events_path: Path,
    last_message_path: Path,
    source_report_path: Path,
    final_report_path: Path,
    final_json_path: Path,
    log_path: Path,
    poc_skill: str,
    executor_model: str | None,
) -> StageExecutionResult:
    workspace_output_report = _attempt_output_report(context)
    workspace_output_json = _attempt_output_json(context)
    cfg = get_config().execution
    process_env, provider_summary, provider_metadata = build_process_env_and_summary(context)
    cmd = build_codex_exec_command(
        prompt,
        repo_root=context.repo_root,
        sandbox_mode=str(context.effective_config.get("poc_sandbox_mode") or get_config().execution.poc_sandbox_mode),
        approval_policy=str(context.effective_config.get("poc_approval_policy") or get_config().execution.poc_approval_policy),
        network_access=bool(context.effective_config.get("poc_network_access", get_config().execution.poc_network_access)),
        model=executor_model,
        add_dirs=[context.attempt_root],
        json_output=cfg.codex_json_output,
        output_last_message_path=last_message_path if cfg.codex_capture_last_message else None,
    )
    log_header = "\n".join(
        [
            f"=== {poc_skill} ===",
            f"Generated at (UTC): {utc_now_z()}",
            f"Repo root: {context.repo_root}",
            f"Source report: {source_report_path}",
            f"Executor mode: codex_cli",
            f"Model: {executor_model or '(default)'}",
            f"Output PoC report path: {workspace_output_report}",
            f"Output audited result json path: {workspace_output_json}",
            "=== provider runtime ===",
            provider_summary,
            "=== command ===",
            command_line_string(cmd),
            "=== prompt ===",
            prompt,
            "=== codex output ===" if not cfg.codex_json_output else "=== codex jsonl events ===",
            "",
        ]
    )
    result = run_logged_command(
        cmd,
        cwd=context.repo_root,
        log_path=log_path,
        log_header=log_header,
        hooks=hooks,
        timeout_seconds=int(get_config().execution.task_timeout_seconds),
        mirror_output_paths=[events_path] if cfg.codex_json_output else None,
        process_env=process_env,
    )
    session_files = [prompt_path]
    if events_path.exists():
        session_files.append(events_path)
    if cfg.codex_capture_last_message and last_message_path.exists():
        session_files.append(last_message_path)
    metadata = {
        "executor_mode": "codex_cli",
        "model": executor_model,
        "poc_skill": poc_skill,
        "source_report_path": str(source_report_path),
        "output_report_path": str(workspace_output_report),
        "output_json_path": str(workspace_output_json),
        "duration_seconds": result.duration_seconds,
        **provider_metadata,
    }
    if result.cancelled:
        return StageExecutionResult(
            stage_name="poc",
            status="cancelled",
            message="poc stage cancelled",
            return_code=result.return_code,
            log_path=log_path,
            artifacts=[],
            session_files=session_files,
            metadata=metadata,
        )
    if result.timed_out:
        return StageExecutionResult(
            stage_name="poc",
            status="timed_out",
            message="poc stage timed out",
            return_code=result.return_code,
            log_path=log_path,
            artifacts=[],
            session_files=session_files,
            metadata=metadata,
        )
    if result.return_code != 0:
        return StageExecutionResult(
            stage_name="poc",
            status="failed",
            message=f"poc stage failed with return code {result.return_code}",
            return_code=result.return_code,
            log_path=log_path,
            artifacts=[],
            session_files=session_files,
            metadata=metadata,
        )
    if not workspace_output_report.exists() or workspace_output_report.stat().st_size == 0:
        return StageExecutionResult(
            stage_name="poc",
            status="failed",
            message=f"poc report not generated: {workspace_output_report}",
            return_code=result.return_code,
            log_path=log_path,
            artifacts=[],
            session_files=session_files,
            metadata=metadata,
        )
    if not workspace_output_json.exists() or workspace_output_json.stat().st_size == 0:
        return StageExecutionResult(
            stage_name="poc",
            status="failed",
            message=f"audited result json not generated: {workspace_output_json}",
            return_code=result.return_code,
            log_path=log_path,
            artifacts=[],
            session_files=session_files,
            metadata=metadata,
        )
    copy_file(workspace_output_report, final_report_path)
    copy_file(workspace_output_json, final_json_path)
    return StageExecutionResult(
        stage_name="poc",
        status="succeeded",
        message="poc stage completed",
        return_code=result.return_code,
        log_path=log_path,
        artifacts=[
            StageArtifact("poc_report", final_report_path, display_name=final_report_path.name),
            StageArtifact("audited_result_json", final_json_path, display_name=final_json_path.name),
        ],
        session_files=session_files,
        output_path=final_report_path,
        metadata=metadata,
    )


def _run_agentflow_stage(
    *,
    context: StageContext,
    hooks: StageHooks,
    prompt: str,
    prompt_path: Path,
    events_path: Path,
    last_message_path: Path,
    source_report_path: Path,
    final_report_path: Path,
    final_json_path: Path,
    log_path: Path,
    poc_skill: str,
    executor_model: str | None,
) -> StageExecutionResult:
    return _run_agentflow_single_node_stage(
        context=context,
        hooks=hooks,
        prompt=prompt,
        prompt_path=prompt_path,
        events_path=events_path,
        last_message_path=last_message_path,
        source_report_path=source_report_path,
        final_report_path=final_report_path,
        final_json_path=final_json_path,
        log_path=log_path,
        poc_skill=poc_skill,
        executor_model=executor_model,
    )


def _run_agentflow_single_node_stage(
    *,
    context: StageContext,
    hooks: StageHooks,
    prompt: str,
    prompt_path: Path,
    events_path: Path,
    last_message_path: Path,
    source_report_path: Path,
    final_report_path: Path,
    final_json_path: Path,
    log_path: Path,
    poc_skill: str,
    executor_model: str | None,
) -> StageExecutionResult:
    cfg = get_config().execution
    workspace_output_report = _attempt_output_report(context)
    workspace_output_json = _attempt_output_json(context)
    sandbox_mode = str(context.effective_config.get("poc_sandbox_mode") or cfg.poc_sandbox_mode)
    network_access = bool(context.effective_config.get("poc_network_access", cfg.poc_network_access))
    pipeline_path = context.stage_session_dir() / "agentflow-pipeline.json"
    runs_dir = context.stage_session_dir() / "agentflow-runs"
    agent_name = cfg.agentflow_agent
    work_dir = resolve_stage_work_dir(context)
    pipeline_payload: dict[str, object] = {
        "name": f"secflow-ipc-audit-{context.stage_name}",
        "working_dir": str(work_dir),
        "nodes": [
            build_agentflow_node(
                node_id=context.stage_name,
                prompt=prompt,
                repo_root=context.repo_root,
                work_dir=work_dir,
                attempt_root=context.attempt_root,
                model=executor_model,
                sandbox_mode=sandbox_mode,
                network_access=network_access,
                success_criteria=[
                    {
                        "kind": "file_nonempty",
                        "path": str(workspace_output_report),
                    },
                    {
                        "kind": "file_nonempty",
                        "path": str(workspace_output_json),
                    },
                    {
                        "kind": "json_valid",
                        "path": str(workspace_output_json),
                    },
                ],
            )
        ],
    }
    write_json_file(pipeline_path, pipeline_payload)
    process_env, provider_summary, provider_metadata = build_agentflow_process_env_and_summary(context)
    process_env["AGENTFLOW_RUNS_DIR"] = str(runs_dir)
    cmd = build_agentflow_exec_command(pipeline_path, runs_dir=runs_dir)
    log_header = "\n".join(
        [
            f"=== {poc_skill} ===",
            f"Generated at (UTC): {utc_now_z()}",
            f"Repo root: {context.repo_root}",
            f"AgentFlow work dir: {work_dir}",
            f"Source report: {source_report_path}",
            f"Executor mode: agentflow_cli",
            f"AgentFlow agent: {agent_name}",
            f"Model: {executor_model or '(default)'}",
            f"Output PoC report path: {workspace_output_report}",
            f"Output audited result json path: {workspace_output_json}",
            "=== provider runtime ===",
            provider_summary,
            "=== command ===",
            command_line_string(cmd),
            "=== prompt ===",
            prompt,
            "=== agentflow cli output ===",
            "",
        ]
    )
    result = run_logged_command(
        cmd,
        cwd=work_dir,
        log_path=log_path,
        log_header=log_header,
        hooks=hooks,
        timeout_seconds=int(cfg.task_timeout_seconds),
        process_env=process_env,
    )
    session_files = [prompt_path]
    run_dir = discover_single_run_dir(runs_dir)
    trace_path = run_dir / "artifacts" / context.stage_name / "trace.jsonl" if run_dir else None
    result_path = run_dir / "artifacts" / context.stage_name / "result.json" if run_dir else None
    stdout_path = run_dir / "artifacts" / context.stage_name / "stdout.log" if run_dir else None
    stderr_path = run_dir / "artifacts" / context.stage_name / "stderr.log" if run_dir else None
    if stdout_path and stdout_path.exists():
        append_file_to_log(log_path, stdout_path, "=== agentflow node stdout ===")
    if stderr_path and stderr_path.exists() and stderr_path.stat().st_size > 0:
        append_file_to_log(log_path, stderr_path, "=== agentflow node stderr ===")
    if trace_path and trace_path.exists():
        write_agentflow_events_from_trace(trace_path, events_path)
    else:
        write_text_file(events_path, "")
    if events_path.exists():
        session_files.append(events_path)
    if result_path and result_path.exists():
        write_last_message_from_agentflow_result(result_path, last_message_path, trace_path=trace_path)
    if last_message_path.exists():
        session_files.append(last_message_path)
    metadata = {
        "executor_mode": "agentflow_cli",
        "agentflow_agent": agent_name,
        "model": executor_model,
        "poc_skill": poc_skill,
        "source_report_path": str(source_report_path),
        "output_report_path": str(workspace_output_report),
        "output_json_path": str(workspace_output_json),
        "duration_seconds": result.duration_seconds,
        "agentflow_pipeline_path": str(pipeline_path),
        "agentflow_run_dir": str(run_dir) if run_dir else None,
        **provider_metadata,
    }
    if result.cancelled:
        return StageExecutionResult(
            stage_name="poc",
            status="cancelled",
            message="poc stage cancelled",
            return_code=result.return_code,
            log_path=log_path,
            artifacts=[],
            session_files=session_files,
            metadata=metadata,
        )
    if result.timed_out:
        return StageExecutionResult(
            stage_name="poc",
            status="timed_out",
            message="poc stage timed out",
            return_code=result.return_code,
            log_path=log_path,
            artifacts=[],
            session_files=session_files,
            metadata=metadata,
        )
    if result.return_code != 0:
        return StageExecutionResult(
            stage_name="poc",
            status="failed",
            message=f"poc stage failed with return code {result.return_code}",
            return_code=result.return_code,
            log_path=log_path,
            artifacts=[],
            session_files=session_files,
            metadata=metadata,
        )
    if not workspace_output_report.exists() or workspace_output_report.stat().st_size == 0:
        return StageExecutionResult(
            stage_name="poc",
            status="failed",
            message=f"poc report not generated: {workspace_output_report}",
            return_code=result.return_code,
            log_path=log_path,
            artifacts=[],
            session_files=session_files,
            metadata=metadata,
        )
    if not workspace_output_json.exists() or workspace_output_json.stat().st_size == 0:
        return StageExecutionResult(
            stage_name="poc",
            status="failed",
            message=f"audited result json not generated: {workspace_output_json}",
            return_code=result.return_code,
            log_path=log_path,
            artifacts=[],
            session_files=session_files,
            metadata=metadata,
        )
    copy_file(workspace_output_report, final_report_path)
    copy_file(workspace_output_json, final_json_path)
    return StageExecutionResult(
        stage_name="poc",
        status="succeeded",
        message="poc stage completed",
        return_code=result.return_code,
        log_path=log_path,
        artifacts=[
            StageArtifact("poc_report", final_report_path, display_name=final_report_path.name),
            StageArtifact("audited_result_json", final_json_path, display_name=final_json_path.name),
        ],
        session_files=session_files,
        output_path=final_report_path,
        metadata=metadata,
    )


def _reuse_agentflow_combined_stage_result(
    *,
    context: StageContext,
    prompt_path: Path,
    events_path: Path,
    last_message_path: Path,
    final_report_path: Path,
    final_json_path: Path,
    log_path: Path,
    poc_skill: str,
    executor_model: str | None,
) -> StageExecutionResult | None:
    if context.pipeline_mode != "audit_then_poc":
        return None
    manifest_path = _agentflow_manifest_path(context)
    manifest = read_json_file(manifest_path)
    if not isinstance(manifest, dict) or str(manifest.get("kind") or "") != "combined_stage_pipeline":
        return None
    stages = manifest.get("stages")
    if not isinstance(stages, dict):
        return None
    stage_data = stages.get("poc")
    if not isinstance(stage_data, dict):
        return None

    stage_log_path_value = str(stage_data.get("log_path") or "").strip()
    stage_log_path = Path(stage_log_path_value) if stage_log_path_value else log_path
    session_files = [path for path in (prompt_path, events_path, last_message_path) if path.exists()]
    output_paths_value = stage_data.get("output_paths")
    output_paths = (
        [Path(str(item)) for item in output_paths_value if str(item).strip()]
        if isinstance(output_paths_value, list)
        else []
    )
    workspace_output_report = output_paths[0] if len(output_paths) > 0 else _attempt_output_report(context)
    workspace_output_json = output_paths[1] if len(output_paths) > 1 else _attempt_output_json(context)
    status = str(stage_data.get("status") or "failed")
    message = str(stage_data.get("message") or "poc stage failed")
    return_code = stage_data.get("return_code")
    process_data = manifest.get("process") if isinstance(manifest.get("process"), dict) else {}
    metadata = {
        "executor_mode": "agentflow_cli",
        "reused_combined_pipeline": True,
        "model": executor_model,
        "poc_skill": poc_skill,
        "output_report_path": str(workspace_output_report),
        "output_json_path": str(workspace_output_json),
        "duration_seconds": process_data.get("duration_seconds"),
        "agentflow_pipeline_path": manifest.get("pipeline_path"),
        "agentflow_run_dir": manifest.get("run_dir"),
        "agentflow_manifest_path": str(manifest_path),
    }
    if status != "succeeded":
        return StageExecutionResult(
            stage_name="poc",
            status=status,
            message=message,
            return_code=return_code,
            log_path=stage_log_path,
            artifacts=[],
            session_files=session_files,
            metadata=metadata,
        )
    if _missing_output(workspace_output_report):
        return StageExecutionResult(
            stage_name="poc",
            status="failed",
            message=f"poc report not generated: {workspace_output_report}",
            return_code=return_code,
            log_path=stage_log_path,
            artifacts=[],
            session_files=session_files,
            metadata=metadata,
        )
    if _missing_output(workspace_output_json):
        return StageExecutionResult(
            stage_name="poc",
            status="failed",
            message=f"audited result json not generated: {workspace_output_json}",
            return_code=return_code,
            log_path=stage_log_path,
            artifacts=[],
            session_files=session_files,
            metadata=metadata,
        )
    copy_file(workspace_output_report, final_report_path)
    copy_file(workspace_output_json, final_json_path)
    return StageExecutionResult(
        stage_name="poc",
        status="succeeded",
        message="poc stage completed",
        return_code=return_code,
        log_path=stage_log_path,
        artifacts=[
            StageArtifact("poc_report", final_report_path, display_name=final_report_path.name),
            StageArtifact("audited_result_json", final_json_path, display_name=final_json_path.name),
        ],
        session_files=session_files,
        output_path=final_report_path,
        metadata=metadata,
    )


def _run_opencode_stage(
    *,
    context: StageContext,
    hooks: StageHooks,
    prompt: str,
    prompt_path: Path,
    events_path: Path,
    last_message_path: Path,
    source_report_path: Path,
    final_report_path: Path,
    final_json_path: Path,
    log_path: Path,
    poc_skill: str,
    executor_model: str | None,
) -> StageExecutionResult:
    workspace_output_report = _attempt_output_report(context)
    workspace_output_json = _attempt_output_json(context)
    process_env, provider_summary, provider_metadata = build_process_env_and_summary(context)
    cmd = build_opencode_exec_command(
        prompt,
        repo_root=context.repo_root,
        model=executor_model,
        json_output=True,
    )
    log_header = "\n".join(
        [
            f"=== {poc_skill} ===",
            f"Generated at (UTC): {utc_now_z()}",
            f"Repo root: {context.repo_root}",
            f"Source report: {source_report_path}",
            f"Executor mode: opencode_cli",
            f"Model: {executor_model or '(default)'}",
            f"Output PoC report path: {workspace_output_report}",
            f"Output audited result json path: {workspace_output_json}",
            "=== provider runtime ===",
            provider_summary,
            "=== command ===",
            command_line_string(cmd),
            "=== prompt ===",
            prompt,
            "=== opencode jsonl events ===",
            "",
        ]
    )
    result = run_logged_command(
        cmd,
        cwd=context.repo_root,
        log_path=log_path,
        log_header=log_header,
        hooks=hooks,
        timeout_seconds=int(get_config().execution.task_timeout_seconds),
        mirror_output_paths=[events_path],
        process_env=process_env,
    )
    retry_count = 0
    total_duration = result.duration_seconds
    session_id = extract_opencode_session_id(events_path)
    max_retries = max(int(get_config().execution.opencode_missing_output_max_retries), 0)
    while (
        not result.cancelled
        and not result.timed_out
        and session_id
        and retry_count < max_retries
    ):
        output_missing = _missing_output(workspace_output_report) or _missing_output(workspace_output_json)
        last_event_error = opencode_last_event_is_error(events_path)
        if not ((result.return_code == 0 and output_missing) or last_event_error):
            break
        retry_count += 1
        retry_reason = "opencode_last_error" if last_event_error else "missing_output"
        previous_return_code = result.return_code
        retry_prompt = _build_missing_poc_output_retry_prompt(
            source_report_path=source_report_path,
            output_report_path=workspace_output_report,
            output_json_path=workspace_output_json,
            retry_count=retry_count,
            max_retries=max_retries,
            retry_reason=retry_reason,
        )
        retry_cmd = build_opencode_exec_command(
            retry_prompt,
            repo_root=context.repo_root,
            model=executor_model,
            json_output=True,
            session_id=session_id,
        )
        retry_header = "\n".join(
            [
                "",
                f"=== opencode recovery retry {retry_count}/{max_retries} ===",
                f"Generated at (UTC): {utc_now_z()}",
                f"Session ID: {session_id}",
                f"Retry reason: {retry_reason}",
                f"Previous return code: {previous_return_code}",
                f"Output PoC report path: {workspace_output_report}",
                f"Output audited result json path: {workspace_output_json}",
                "=== provider runtime ===",
                provider_summary,
                "=== command ===",
                command_line_string(retry_cmd),
                "=== retry prompt ===",
                retry_prompt,
                "=== opencode jsonl events ===",
                "",
            ]
        )
        result = run_logged_command(
            retry_cmd,
            cwd=context.repo_root,
            log_path=log_path,
            log_header=retry_header,
            hooks=hooks,
            timeout_seconds=int(get_config().execution.task_timeout_seconds),
            mirror_output_paths=[events_path],
            append=True,
            process_env=process_env,
        )
        total_duration += result.duration_seconds
    session_files = [prompt_path]
    if events_path.exists():
        session_files.append(events_path)
    if write_last_message_from_jsonl(events_path, last_message_path) is not None:
        session_files.append(last_message_path)
    metadata = {
        "executor_mode": "opencode_cli",
        "model": executor_model,
        "poc_skill": poc_skill,
        "source_report_path": str(source_report_path),
        "output_report_path": str(workspace_output_report),
        "output_json_path": str(workspace_output_json),
        "duration_seconds": total_duration,
        "opencode_session_id": session_id,
        "opencode_recovery_retry_count": retry_count,
        "missing_output_retry_count": retry_count,
        "opencode_last_event_error": opencode_last_event_is_error(events_path),
        **provider_metadata,
    }
    if result.cancelled:
        return StageExecutionResult(
            stage_name="poc",
            status="cancelled",
            message="poc stage cancelled",
            return_code=result.return_code,
            log_path=log_path,
            artifacts=[],
            session_files=session_files,
            metadata=metadata,
        )
    if result.timed_out:
        return StageExecutionResult(
            stage_name="poc",
            status="timed_out",
            message="poc stage timed out",
            return_code=result.return_code,
            log_path=log_path,
            artifacts=[],
            session_files=session_files,
            metadata=metadata,
        )
    if result.return_code != 0:
        return StageExecutionResult(
            stage_name="poc",
            status="failed",
            message=f"poc stage failed with return code {result.return_code}",
            return_code=result.return_code,
            log_path=log_path,
            artifacts=[],
            session_files=session_files,
            metadata=metadata,
        )
    if not workspace_output_report.exists() or workspace_output_report.stat().st_size == 0:
        retry_suffix = f" after {retry_count} same-session retries" if retry_count else ""
        session_suffix = "" if session_id else " (opencode session id unavailable)"
        return StageExecutionResult(
            stage_name="poc",
            status="failed",
            message=f"poc report not generated{retry_suffix}{session_suffix}: {workspace_output_report}",
            return_code=result.return_code,
            log_path=log_path,
            artifacts=[],
            session_files=session_files,
            metadata=metadata,
        )
    if not workspace_output_json.exists() or workspace_output_json.stat().st_size == 0:
        retry_suffix = f" after {retry_count} same-session retries" if retry_count else ""
        session_suffix = "" if session_id else " (opencode session id unavailable)"
        return StageExecutionResult(
            stage_name="poc",
            status="failed",
            message=f"audited result json not generated{retry_suffix}{session_suffix}: {workspace_output_json}",
            return_code=result.return_code,
            log_path=log_path,
            artifacts=[],
            session_files=session_files,
            metadata=metadata,
        )
    copy_file(workspace_output_report, final_report_path)
    copy_file(workspace_output_json, final_json_path)
    return StageExecutionResult(
        stage_name="poc",
        status="succeeded",
        message="poc stage completed",
        return_code=result.return_code,
        log_path=log_path,
        artifacts=[
            StageArtifact("poc_report", final_report_path, display_name=final_report_path.name),
            StageArtifact("audited_result_json", final_json_path, display_name=final_json_path.name),
        ],
        session_files=session_files,
        output_path=final_report_path,
        metadata=metadata,
    )


def _build_prompt(
    *,
    poc_skill: str,
    repo_root: Path,
    source_report_path: Path,
    output_report_path: Path,
    output_json_path: Path,
    report_language: str,
    qemu_instance_name: str,
) -> str:
    language_line = "PoC report language: 简体中文."
    if report_language and report_language.lower() not in {"zh-cn", "zh_hans", "zh"}:
        language_line = f"PoC report language: {report_language}."
    return "\n".join(
        [
            "OpenHarmony IPC audit report PoC validation task.",
            f"Embedded workflow profile: {poc_skill}",
            f"Repo root: {repo_root}",
            f"Project report: {source_report_path}",
            f"Output PoC report path: {output_report_path}",
            f"Output audited result json path: {output_json_path}",
            language_line + " Do not translate code blocks, paths, identifiers, or classification tokens.",
            "",
            _build_in_container_qemu_prompt(qemu_instance_name),
            "",
            _POC_WORKFLOW_PROMPT,
        ]
    )


def _build_missing_poc_output_retry_prompt(
    *,
    source_report_path: Path,
    output_report_path: Path,
    output_json_path: Path,
    retry_count: int,
    max_retries: int,
    retry_reason: str,
) -> str:
    reason_text = "The previous command exited successfully, but one or more required output files were not created."
    if retry_reason == "opencode_last_error":
        reason_text = "The previous OpenCode command ended with an error event in its JSONL stream, so the stage did not finish cleanly."
    return "\n".join(
        [
            "Continue the same OpenHarmony IPC PoC validation session.",
            f"Retry: {retry_count}/{max_retries}",
            f"Retry reason: {retry_reason}",
            f"Project report: {source_report_path}",
            f"Required output PoC report path: {output_report_path}",
            f"Required output audited result json path: {output_json_path}",
            "",
            reason_text,
            "Do not restart the task or ask for clarification. Continue from the existing session context.",
            "Keep using the in-container QEMU/HDC workflow from the original prompt; do not call ohemu-container.sh, docker run, docker exec, or docker compose.",
            "Inspect or build more only if needed, then create parent directories and write both required output files exactly to the required paths.",
            "Before your final response, verify that both files exist and are non-empty.",
            "The JSON file must include the required per-project statistics fields, even when all counts are zero.",
        ]
    )


def _poc_qemu_instance_name(context: StageContext) -> str:
    return build_poc_qemu_instance_name(context.task_id)


def _build_in_container_qemu_prompt(qemu_instance_name: str) -> str:
    return build_in_container_qemu_prompt(qemu_instance_name)


def _stage_input_report(context: StageContext, source_audit_report: Path) -> Path:
    return context.stage_session_dir() / "inputs" / source_audit_report.name


def _attempt_output_report(context: StageContext) -> Path:
    return context.stage_session_dir() / "outputs" / "poc-report.md"


def _attempt_output_json(context: StageContext) -> Path:
    return context.stage_session_dir() / "outputs" / "audited-result.json"


def _agentflow_manifest_path(context: StageContext) -> Path:
    return context.runtime_root / "agentflow-stage-pipeline-manifest.json"


def _missing_output(path: Path) -> bool:
    return not path.exists() or path.stat().st_size == 0


def _sleep_with_cancel(hooks: StageHooks) -> bool:
    delay = max(float(get_config().execution.mock_stage_delay_seconds), 0.0)
    if delay <= 0:
        return hooks.is_cancel_requested()
    started = time.monotonic()
    while time.monotonic() - started < delay:
        hooks.heartbeat()
        if hooks.is_cancel_requested():
            return True
        time.sleep(min(0.2, delay))
    return hooks.is_cancel_requested()


_POC_WORKFLOW_PROMPT = """\
This prompt is self-contained. Do not invoke, require, or assume any external Codex/OpenCode skill.

Goal:
- Validate the issues in Project report against the reported subproject code and exact referenced dependency files only.
- Always write a PoC report exactly to Output PoC report path. Create parent directories if needed.
- Always write a JSON stats file exactly to Output audited result json path. Create parent directories if needed.

Scope rules:
- Keep code validation scoped to the reported subproject and exact files already cited by the report, direct code references, or readtags.
- The process cwd is intended to be the Subproject path. Do not cd to Repo root or run bare rg/find there.
- Do not run broad rg/find searches from Repo root. If readtags resolves helper classes or implementations in another project, read those exact files directly as dependency context.
- If a reported sink cannot be triggered from OnRemoteRequest or an equivalent IPC stub dispatch into the service-side implementation, classify it as NOT_APPLICABLE and do not generate a PoC for it.
- For Lite system reports, issues based on Lite IPC IpcIo rather than MessageParcel-based IPC are NOT_APPLICABLE in this workflow.
- Do not patch the target service implementation to force a crash.

Validation workflow:
1. Load Project report and extract each issue's component, file/function, root cause, impact, transaction code/interface token hints, and prerequisites.
2. Confirm or refute each issue with code evidence:
- Reachability from IPC entrypoint to service-side implementation.
- Attacker control from IPC data such as MessageParcel fields, raw buffers, vectors, strings, fds, ashmem, or parcelized objects.
- The exact memory-safety hazard.
- Whether mitigations exist in helpers, callees, service guards, or permission gates.
3. Use these classification tokens exactly: CONFIRMED_POC_FEASIBLE, CONFIRMED_NO_POC, CONFIRMED_BUT_NOT_REPRODUCED, BLOCKED_ENV, NOT_APPLICABLE, NOT_CONFIRMED.
4. If all issues are NOT_CONFIRMED or NOT_APPLICABLE, skip PoC build/runtime work and still write the report and JSON stats.

PoC workflow when feasible:
1. Derive the minimal trigger details: target SA/service, how to obtain IRemoteObject, request code, interface token, parameter order, and malformed payload.
2. Prefer a small standalone native PoC source under a task-local or repo-local audit directory. Keep it focused and do not add/modify GN targets by default.
3. Prefer manual clang++ compilation inside the current container from existing out/<product> metadata when available. Use existing obj/**/<target>.ninja, *_module_info.json, packaged .so files, and generated sources instead of running GN.
4. If the current build outputs do not contain enough metadata/generated code/libraries, record BLOCKED_ENV or CONFIRMED_NO_POC with exact missing prerequisites instead of modifying BUILD.gn.
5. If runtime testing is possible, use the in-container QEMU helper from the runtime rules above to boot or reuse OHEMU/QEMU inside the current container, connect with hdc, deploy the PoC, run it, and collect stdout/stderr, hilog, tombstone/faultlogger, or service death/restart evidence.
6. If the PoC builds but does not crash after one minimal adjustment, classify as CONFIRMED_BUT_NOT_REPRODUCED and record evidence.

PoC report requirements:
- Write in the requested report language, normally 简体中文.
- Preserve code, paths, commands, logs, return codes, GN targets, identifiers, and classification tokens verbatim.
- Include Source report path and short summary.
- Include Issue validation for every issue with classification and code evidence.
- Include PoC design, build commands/results, runtime commands/results, selected in-container QEMU instance/HDC port if used, and limitations.
- If no PoC was attempted, explain why using the classification evidence.

JSON stats requirements:
- Write valid JSON to Output audited result json path.
- Use this stable schema:
{
  "vulnerabilities_found": 0,
  "pocs_developed": 0,
  "info_findings": 0,
  "report": {
    "project_report": "<Project report>",
    "poc_report": "<Output PoC report path>"
  },
  "counts": {
    "audit_findings_total": 0,
    "poc_confirmed_problem_count": 0,
    "poc_generated_count": 0,
    "poc_generated_crash_count": 0
  },
  "notes": []
}
- vulnerabilities_found counts confirmed real vulnerability findings, including CONFIRMED_POC_FEASIBLE, CONFIRMED_NO_POC, and CONFIRMED_BUT_NOT_REPRODUCED.
- pocs_developed counts generated PoC programs/scripts/binaries.
- info_findings counts informational findings, environmental blockers, unresolved items, or non-vulnerability observations worth surfacing.
- audit_findings_total counts issues described in Project report.
- poc_confirmed_problem_count counts confirmed real problems, including CONFIRMED_POC_FEASIBLE, CONFIRMED_NO_POC, and CONFIRMED_BUT_NOT_REPRODUCED.
- poc_generated_count counts generated PoC programs/scripts/binaries.
- poc_generated_crash_count counts generated PoCs that produced crash/service-death evidence.
"""
