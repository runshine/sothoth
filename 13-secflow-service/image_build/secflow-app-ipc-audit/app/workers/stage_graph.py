from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from jinja2 import Environment, StrictUndefined

from app.core.config import get_config
from app.core.time_utils import utc_now_z
from app.workers.poc_runtime import build_in_container_qemu_runtime, build_poc_qemu_instance_name
from app.workers.runner import (
    StageArtifact,
    StageContext,
    StageExecutionResult,
    StageHooks,
    append_file_to_log,
    build_agentflow_exec_command,
    build_agentflow_process_env_and_summary,
    command_line_string,
    discover_single_run_dir,
    ensure_parent,
    normalize_attempt_relative_path,
    read_json_file,
    resolve_attempt_relative_path,
    resolve_report_outputs_for_attempt,
    resolve_stage_work_dir,
    run_logged_command,
    write_json_file,
    write_last_message_from_agentflow_result,
    write_text_file,
)


@dataclass(frozen=True)
class GraphExecutionResult:
    stage_results: list[StageExecutionResult]
    attempt_artifacts: list[StageArtifact] = field(default_factory=list)
    overall_status: str = "failed"
    overall_message: str = "graph execution failed"


SECFLOW_TEMPLATE_ENV = Environment(
    undefined=StrictUndefined,
    autoescape=False,
    variable_start_string="[[",
    variable_end_string="]]",
    block_start_string="[%",  # Prevent accidental parsing of AgentFlow/runtime Jinja blocks.
    block_end_string="%]",
    comment_start_string="[#",
    comment_end_string="#]",
)
SECFLOW_PLACEHOLDER_PATTERN = re.compile(r"\[\[\s*.+?\s*\]\]")


def run_graph(context: StageContext, hooks: StageHooks) -> GraphExecutionResult:
    graph_source = context.effective_config.get("graph_source")
    stage_names = _declared_stage_names(context)
    if not isinstance(graph_source, dict):
        return _build_failed_graph_result(
            context,
            stage_names=stage_names,
            message="graph_source is required for custom_graph",
        )

    graph_runtime_dir = context.runtime_root / "graph"
    graph_context_path = graph_runtime_dir / "graph-context.json"
    pipeline_path = graph_runtime_dir / "agentflow-pipeline.json"
    builder_log_path = graph_runtime_dir / "graph-builder.log"
    cli_log_path = graph_runtime_dir / "agentflow-cli.log"
    graph_manifest_path = graph_runtime_dir / "graph-manifest.json"
    runs_dir = graph_runtime_dir / "agentflow-runs"
    work_dir = resolve_stage_work_dir(context)

    report_outputs = resolve_report_outputs_for_attempt(context.attempt_root, context.effective_config)
    template_context = _build_template_context(context, report_outputs)
    write_json_file(graph_context_path, template_context)

    pipeline_payload, builder_metadata, prep_error = _materialize_pipeline(
        context=context,
        graph_source=graph_source,
        template_context=template_context,
        graph_context_path=graph_context_path,
        pipeline_path=pipeline_path,
        builder_log_path=builder_log_path,
        hooks=hooks,
    )
    if prep_error is not None or pipeline_payload is None:
        failure_message = prep_error or "failed to build graph pipeline"
        return _build_failed_graph_result(
            context,
            stage_names=stage_names,
            message=failure_message,
            extra_log_path=builder_log_path if builder_log_path.exists() else None,
        )

    actual_node_ids = [str(item["id"]) for item in pipeline_payload["nodes"]]
    if stage_names and set(actual_node_ids) != set(stage_names):
        return _build_failed_graph_result(
            context,
            stage_names=stage_names,
            message=f"declared stage names {stage_names} do not match graph nodes {actual_node_ids}",
            extra_log_path=builder_log_path if builder_log_path.exists() else None,
        )
    if not stage_names:
        stage_names = actual_node_ids

    if hooks.graph_prepared is not None:
        hooks.graph_prepared(_build_materialized_graph_source_payload(pipeline_payload))

    prompt_paths = _materialize_node_prompts(context, pipeline_payload)
    progress_tick = _build_graph_progress_tick(
        context=context,
        stage_names=stage_names,
        pipeline_payload=pipeline_payload,
        report_outputs=report_outputs,
        runs_dir=runs_dir,
        hooks=hooks,
    )

    process_env, provider_summary, provider_metadata = build_agentflow_process_env_and_summary(context)
    process_env["AGENTFLOW_RUNS_DIR"] = str(runs_dir)
    cmd = build_agentflow_exec_command(pipeline_path, runs_dir=runs_dir)
    log_header = "\n".join(
        [
            "=== custom_graph ===",
            f"Generated at (UTC): {utc_now_z()}",
            f"Repo root: {context.repo_root}",
            f"AgentFlow work dir: {work_dir}",
            f"Task ID: {context.task_id}",
            f"Attempt ID: {context.attempt_id}",
            "Executor mode: agentflow_cli",
            "=== provider runtime ===",
            provider_summary,
            "=== command ===",
            command_line_string(cmd),
            "=== pipeline ===",
            json.dumps(pipeline_payload, ensure_ascii=False, indent=2),
            "=== agentflow cli output ===",
            "",
        ]
    )
    process_result = run_logged_command(
        cmd,
        cwd=work_dir,
        log_path=cli_log_path,
        log_header=log_header,
        hooks=hooks,
        timeout_seconds=int(get_config().execution.task_timeout_seconds),
        process_env=process_env,
        progress_tick=progress_tick,
    )
    run_dir = discover_single_run_dir(runs_dir)
    node_map = {str(item["id"]): item for item in pipeline_payload["nodes"]}
    stage_results = [
        _materialize_graph_stage_result(
            context=context,
            stage_name=stage_name,
            node_payload=node_map.get(stage_name, {"id": stage_name}),
            prompt_path=prompt_paths.get(stage_name, context.runtime_root / stage_name / "prompt.txt"),
            cli_log_path=cli_log_path,
            run_dir=run_dir,
            process_result=process_result,
            report_outputs=[item for item in report_outputs if str(item.get("node_id") or "") == stage_name],
            metadata={
                **builder_metadata,
                **provider_metadata,
                "executor_mode": "agentflow_cli",
                "graph_source_type": str(graph_source.get("type") or ""),
                "agentflow_pipeline_path": str(pipeline_path),
                "agentflow_run_dir": str(run_dir) if run_dir else None,
            },
        )
        for stage_name in stage_names
    ]
    graph_manifest = _build_graph_manifest(
        context=context,
        stage_results=stage_results,
        report_outputs=report_outputs,
        pipeline_payload=pipeline_payload,
        pipeline_path=pipeline_path,
        run_dir=run_dir,
        process_result=process_result,
    )
    write_json_file(graph_manifest_path, graph_manifest)
    overall_status, overall_message = _summarize_overall_status(stage_results)
    return GraphExecutionResult(
        stage_results=stage_results,
        attempt_artifacts=[StageArtifact("graph_manifest", graph_manifest_path, display_name=graph_manifest_path.name)],
        overall_status=overall_status,
        overall_message=overall_message,
    )


def _declared_stage_names(context: StageContext) -> list[str]:
    stage_names_value = context.effective_config.get("stage_names")
    if not isinstance(stage_names_value, list):
        return []
    return [str(item).strip() for item in stage_names_value if str(item).strip()]


def _build_template_context(context: StageContext, report_outputs: list[dict[str, Any]]) -> dict[str, Any]:
    report_output_map: dict[str, dict[str, Any]] = {}
    report_output_list: list[dict[str, Any]] = []
    for item in sorted(report_outputs, key=lambda value: (int(value.get("order") or 0), str(value.get("output_id") or ""))):
        relative_path = normalize_attempt_relative_path(str(item["path"])).as_posix()
        absolute_path = resolve_attempt_relative_path(context.attempt_root, relative_path)
        payload = {
            "output_id": str(item["output_id"]),
            "node_id": str(item["node_id"]),
            "title": str(item["title"]),
            "relative_path": relative_path,
            "absolute_path": str(absolute_path),
            "format": str(item.get("format") or "markdown"),
            "required": bool(item.get("required", True)),
            "order": int(item.get("order") or 0),
        }
        report_output_map[payload["output_id"]] = payload
        report_output_list.append(payload)
    poc_runtime = build_in_container_qemu_runtime(build_poc_qemu_instance_name(context.task_id))
    work_dir = resolve_stage_work_dir(context)
    project_absolute_path = str(work_dir) if context.project_path else None
    task_context = {
        "task_id": context.task_id,
        "attempt_id": context.attempt_id,
        "workspace_id": context.workspace_id,
        "input_kind": context.input_kind,
        "input_ref": {
            "kind": context.input_kind,
            "project_path": context.project_path,
            "report_path": context.report_path,
        },
        "project_path": project_absolute_path,
        "project_relative_path": context.project_path,
        "project_absolute_path": project_absolute_path,
        "report_path": context.report_path,
        "repo_root": str(context.repo_root),
        "work_dir": str(work_dir),
        "attempt_root": str(context.attempt_root),
        "runtime_root": str(context.runtime_root),
        "stage_names": _declared_stage_names(context),
        "poc_runtime": poc_runtime,
        "report_outputs": report_output_map,
        "report_outputs_list": report_output_list,
    }
    return {
        **task_context,
        "task": task_context,
    }


def _materialize_pipeline(
    *,
    context: StageContext,
    graph_source: dict[str, Any],
    template_context: dict[str, Any],
    graph_context_path: Path,
    pipeline_path: Path,
    builder_log_path: Path,
    hooks: StageHooks,
) -> tuple[dict[str, Any] | None, dict[str, Any], str | None]:
    graph_type = str(graph_source.get("type") or "").strip()
    metadata: dict[str, Any] = {}
    if graph_type == "inline_json":
        content = graph_source.get("content")
        if not isinstance(content, dict):
            return None, metadata, "inline_json graph_source.content must be an object"
        try:
            rendered = _render_secflow_template_payload(
                content,
                template_context,
                source_label="inline_json graph source",
            )
            normalized = _normalize_pipeline_payload(context, rendered)
        except Exception as exc:  # noqa: BLE001
            return None, metadata, f"invalid inline_json graph source: {exc}"
        write_json_file(pipeline_path, normalized)
        metadata["graph_builder_mode"] = "inline_json"
        return normalized, metadata, None

    if graph_type != "python_builder":
        return None, metadata, f"unsupported graph source type: {graph_type}"

    builder_path = _materialize_builder_script(context, graph_source, builder_log_path.parent)
    if builder_path is None:
        return None, metadata, "python_builder requires a valid entry or code"
    metadata["graph_builder_mode"] = "python_builder"
    metadata["graph_builder_path"] = str(builder_path)
    process_env, provider_summary, provider_metadata = build_agentflow_process_env_and_summary(context)
    metadata.update(provider_metadata)
    cmd = [
        get_config().execution.agentflow_python_bin,
        str(builder_path),
        "--context",
        str(graph_context_path),
        "--output",
        str(pipeline_path),
    ]
    log_header = "\n".join(
        [
            "=== graph builder ===",
            f"Generated at (UTC): {utc_now_z()}",
            f"Repo root: {context.repo_root}",
            f"AgentFlow work dir: {resolve_stage_work_dir(context)}",
            "=== provider runtime ===",
            provider_summary,
            "=== command ===",
            command_line_string(cmd),
            "=== builder context ===",
            json.dumps(template_context, ensure_ascii=False, indent=2),
            "=== builder output ===",
            "",
        ]
    )
    result = run_logged_command(
        cmd,
        cwd=context.repo_root,
        log_path=builder_log_path,
        log_header=log_header,
        hooks=hooks,
        timeout_seconds=int(get_config().execution.task_timeout_seconds),
        process_env=process_env,
    )
    metadata["graph_builder_return_code"] = result.return_code
    metadata["graph_builder_duration_seconds"] = result.duration_seconds
    if result.cancelled:
        return None, metadata, "graph builder cancelled"
    if result.timed_out:
        return None, metadata, "graph builder timed out"
    if result.return_code != 0:
        return None, metadata, f"graph builder failed with return code {result.return_code}"
    payload = read_json_file(pipeline_path)
    if not isinstance(payload, dict):
        return None, metadata, "graph builder did not produce a valid JSON pipeline"
    try:
        rendered = _render_secflow_template_payload(
            payload,
            template_context,
            source_label="python_builder output",
        )
        normalized = _normalize_pipeline_payload(context, rendered)
    except Exception as exc:  # noqa: BLE001
        return None, metadata, f"invalid graph builder pipeline: {exc}"
    write_json_file(pipeline_path, normalized)
    return normalized, metadata, None


def _materialize_builder_script(context: StageContext, graph_source: dict[str, Any], output_dir: Path) -> Path | None:
    entry = str(graph_source.get("entry") or "").strip()
    inline_code = str(graph_source.get("code") or "")
    if entry:
        candidate = Path(entry)
        if not candidate.is_absolute():
            candidate = (context.repo_root / candidate).resolve()
        return candidate
    if not inline_code.strip():
        return None
    script_path = output_dir / "build_graph.py"
    write_text_file(script_path, inline_code)
    return script_path


def _render_inline_json_pipeline(content: dict[str, Any], template_context: dict[str, Any]) -> dict[str, Any]:
    payload = _render_secflow_template_payload(content, template_context, source_label="inline_json graph source")
    if not isinstance(payload, dict):
        raise TypeError("rendered pipeline must be a JSON object")
    return payload


def _render_secflow_template_payload(
    value: Any,
    template_context: dict[str, Any],
    *,
    source_label: str,
) -> dict[str, Any]:
    payload = _render_secflow_template_value(value, template_context)
    unresolved = _collect_unrendered_secflow_placeholders(payload)
    if unresolved:
        detail = "; ".join(unresolved[:5])
        raise ValueError(f"unrendered secflow placeholders remain in {source_label}: {detail}")
    if not isinstance(payload, dict):
        raise TypeError("rendered pipeline must be a JSON object")
    return payload


def _render_secflow_template_value(value: Any, template_context: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _render_secflow_template_value(item, template_context)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_render_secflow_template_value(item, template_context) for item in value]
    if isinstance(value, str):
        template = SECFLOW_TEMPLATE_ENV.from_string(value)
        return template.render(**template_context)
    return value


def _collect_unrendered_secflow_placeholders(value: Any, path: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            findings.extend(_collect_unrendered_secflow_placeholders(item, f"{path}.{key}"))
        return findings
    if isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_collect_unrendered_secflow_placeholders(item, f"{path}[{index}]"))
        return findings
    if isinstance(value, str) and SECFLOW_PLACEHOLDER_PATTERN.search(value):
        preview = value if len(value) <= 180 else f"{value[:177]}..."
        findings.append(f"{path}={preview}")
    return findings


def _normalize_pipeline_payload(context: StageContext, payload: dict[str, Any]) -> dict[str, Any]:
    nodes_value = payload.get("nodes")
    if not isinstance(nodes_value, list) or not nodes_value:
        raise ValueError("pipeline.nodes must be a non-empty array")
    normalized_nodes: list[dict[str, Any]] = []
    default_timeout_seconds = int(get_config().execution.task_timeout_seconds)
    work_dir = resolve_stage_work_dir(context)
    seen_ids: set[str] = set()
    for node in nodes_value:
        if not isinstance(node, dict):
            raise ValueError("pipeline node must be an object")
        node_id = str(node.get("id") or "").strip()
        if not node_id:
            raise ValueError("pipeline node id is required")
        if "/" in node_id or "\\" in node_id or ".." in node_id:
            raise ValueError(f"invalid node id: {node_id}")
        if node_id in seen_ids:
            raise ValueError(f"duplicate node id: {node_id}")
        seen_ids.add(node_id)
        normalized_node = dict(node)
        normalized_node.setdefault("agent", "opencode")
        target = normalized_node.get("target")
        if not isinstance(target, dict):
            normalized_node["target"] = {"kind": "local", "cwd": str(work_dir)}
        else:
            normalized_target = dict(target)
            target_kind = str(normalized_target.get("kind") or "local").strip() or "local"
            normalized_target["kind"] = target_kind
            if target_kind == "local":
                normalized_target.setdefault("cwd", str(work_dir))
            normalized_node["target"] = normalized_target
        normalized_node.setdefault("tools", "read_write")
        normalized_node.setdefault("timeout_seconds", default_timeout_seconds)
        normalized_nodes.append(normalized_node)
    normalized_payload = dict(payload)
    normalized_payload.setdefault("working_dir", str(work_dir))
    normalized_payload["nodes"] = normalized_nodes
    return normalized_payload


def _materialize_node_prompts(context: StageContext, pipeline_payload: dict[str, Any]) -> dict[str, Path]:
    prompt_paths: dict[str, Path] = {}
    for node in pipeline_payload["nodes"]:
        node_id = str(node["id"])
        prompt_path = context.runtime_root / node_id / "prompt.txt"
        write_text_file(prompt_path, str(node.get("prompt") or ""))
        prompt_paths[node_id] = prompt_path
    return prompt_paths


def _build_materialized_graph_source_payload(pipeline_payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "inline_json",
        "content": pipeline_payload,
    }


def _build_graph_progress_tick(
    *,
    context: StageContext,
    stage_names: list[str],
    pipeline_payload: dict[str, Any],
    report_outputs: list[dict[str, Any]],
    runs_dir: Path,
    hooks: StageHooks,
) -> Callable[[], None] | None:
    if hooks.graph_progress is None:
        return None

    last_signature: str | None = None

    def _tick() -> None:
        nonlocal last_signature
        snapshot = _build_graph_progress_snapshot(
            context=context,
            stage_names=stage_names,
            pipeline_payload=pipeline_payload,
            report_outputs=report_outputs,
            runs_dir=runs_dir,
        )
        signature = json.dumps(snapshot, ensure_ascii=False, sort_keys=True)
        if signature == last_signature:
            return
        last_signature = signature
        hooks.graph_progress(snapshot)

    return _tick


def _build_graph_progress_snapshot(
    *,
    context: StageContext,
    stage_names: list[str],
    pipeline_payload: dict[str, Any],
    report_outputs: list[dict[str, Any]],
    runs_dir: Path,
) -> dict[str, Any]:
    run_dir = discover_single_run_dir(runs_dir)
    run_record = _read_agentflow_run_record(run_dir)
    node_map = {
        str(node.get("id") or ""): node
        for node in (pipeline_payload.get("nodes") if isinstance(pipeline_payload.get("nodes"), list) else [])
        if isinstance(node, dict) and str(node.get("id") or "").strip()
    }
    progress_nodes: dict[str, dict[str, Any]] = {}
    for stage_name in stage_names:
        node_payload = node_map.get(stage_name, {"id": stage_name})
        node_report_outputs = [item for item in report_outputs if str(item.get("node_id") or "") == stage_name]
        raw_status = _read_live_agentflow_node_status(run_dir, run_record, stage_name)
        status, message = _map_live_graph_status(raw_status, stage_name, node_report_outputs)
        progress_nodes[stage_name] = {
            "status": status,
            "message": message,
        }

    current_stage = next(
        (
            stage_name
            for stage_name in stage_names
            if str(progress_nodes.get(stage_name, {}).get("status") or "") == "running"
        ),
        None,
    )
    if current_stage is None:
        current_stage = next(
            (
                stage_name
                for stage_name in stage_names
                if str(progress_nodes.get(stage_name, {}).get("status") or "") in {"queued", "pending"}
            ),
            None,
        )
    return {
        "current_stage": current_stage,
        "nodes": progress_nodes,
    }


def _read_live_agentflow_node_status(
    run_dir: Path | None,
    run_record: dict[str, Any] | None,
    stage_name: str,
) -> str:
    if run_dir is None:
        return _read_agentflow_node_status(run_record, stage_name) or "pending"
    artifact_dir = run_dir / "artifacts" / stage_name
    result_payload = read_json_file(artifact_dir / "result.json")
    if isinstance(result_payload, dict):
        result_status = str(result_payload.get("status") or "").strip().lower()
        if result_status:
            return result_status
    if any((artifact_dir / filename).exists() for filename in ("launch.json", "stdout.log", "stderr.log")):
        return "running"
    return _read_agentflow_node_status(run_record, stage_name) or "pending"


def _map_live_graph_status(
    raw_status: str,
    stage_name: str,
    report_outputs: list[dict[str, Any]],
) -> tuple[str, str]:
    normalized = str(raw_status or "").strip().lower()
    if normalized == "completed":
        missing_required_outputs = [
            item
            for item in report_outputs
            if bool(item.get("required", True))
            and not (Path(item["absolute_path"]).exists() and Path(item["absolute_path"]).stat().st_size > 0)
        ]
        if missing_required_outputs:
            return "failed", f"{stage_name} required report outputs not generated"
        return "succeeded", f"{stage_name} stage completed"
    if normalized in {"running", "retrying"}:
        return "running", f"{stage_name} stage running"
    if normalized in {"queued", "ready"}:
        return "queued", "waiting for upstream graph dependencies"
    if normalized == "skipped":
        return "skipped", f"{stage_name} stage skipped"
    if normalized == "cancelled":
        return "cancelled", f"{stage_name} stage cancelled"
    if normalized == "failed":
        return "failed", f"{stage_name} stage failed"
    return "pending", "waiting for upstream graph dependencies"


def _materialize_graph_stage_result(
    *,
    context: StageContext,
    stage_name: str,
    node_payload: dict[str, Any],
    prompt_path: Path,
    cli_log_path: Path,
    run_dir: Path | None,
    process_result,
    report_outputs: list[dict[str, Any]],
    metadata: dict[str, Any],
) -> StageExecutionResult:
    events_path = context.runtime_root / stage_name / "events.jsonl"
    last_message_path = context.runtime_root / stage_name / "last-message.md"
    stage_log_path = context.logs_dir / f"{stage_name}.codex.log"
    stage_artifact_dir = run_dir / "artifacts" / stage_name if run_dir else None
    trace_path = stage_artifact_dir / "trace.jsonl" if stage_artifact_dir else None
    result_path = stage_artifact_dir / "result.json" if stage_artifact_dir else None
    stdout_path = stage_artifact_dir / "stdout.log" if stage_artifact_dir else None
    stderr_path = stage_artifact_dir / "stderr.log" if stage_artifact_dir else None
    run_record = _read_agentflow_run_record(run_dir)
    if result_path and result_path.exists():
        write_last_message_from_agentflow_result(result_path, last_message_path)
    result_payload = read_json_file(result_path) if result_path else None
    node_status = str(result_payload.get("status") or "").strip().lower() if isinstance(result_payload, dict) else ""
    if not node_status:
        node_status = _read_agentflow_node_status(run_record, stage_name)
    return_code = (
        result_payload.get("exit_code")
        if isinstance(result_payload, dict) and result_payload.get("exit_code") is not None
        else (None if node_status == "skipped" else process_result.return_code)
    )
    existing_report_outputs = []
    missing_required_outputs = []
    for item in report_outputs:
        absolute_path = Path(item["absolute_path"])
        if absolute_path.exists() and absolute_path.stat().st_size > 0:
            existing_report_outputs.append(item)
        elif bool(item.get("required", True)):
            missing_required_outputs.append(item)
    if node_status == "completed":
        if missing_required_outputs:
            status = "failed"
            message = f"{stage_name} required report outputs not generated"
        else:
            status = "succeeded"
            message = f"{stage_name} stage completed"
    elif node_status == "skipped":
        status = "skipped"
        message = f"{stage_name} stage skipped"
    elif node_status == "cancelled" or process_result.cancelled:
        status = "cancelled"
        message = f"{stage_name} stage cancelled"
    elif process_result.timed_out:
        status = "timed_out"
        message = f"{stage_name} stage timed out"
    else:
        status = "failed"
        message = f"{stage_name} stage failed"
    prompt_text = prompt_path.read_text(encoding="utf-8", errors="replace") if prompt_path.exists() else ""
    write_text_file(
        stage_log_path,
        "\n".join(
            [
                f"=== {stage_name} ===",
                f"Generated at (UTC): {utc_now_z()}",
                f"Repo root: {context.repo_root}",
                "Executor mode: agentflow_cli",
                f"AgentFlow agent: {node_payload.get('agent') or get_config().execution.agentflow_agent}",
                f"Model: {node_payload.get('model') or metadata.get('model') or '(default)'}",
                "=== prompt ===",
                prompt_text,
            ]
        )
        + "\n",
    )
    if cli_log_path.exists():
        append_file_to_log(stage_log_path, cli_log_path, "=== agentflow cli output ===")
    if stdout_path and stdout_path.exists():
        append_file_to_log(stage_log_path, stdout_path, "=== agentflow node stdout ===")
    if stderr_path and stderr_path.exists() and stderr_path.stat().st_size > 0:
        append_file_to_log(stage_log_path, stderr_path, "=== agentflow node stderr ===")
    session_files = [prompt_path]
    if trace_path and trace_path.exists():
        session_files.append(trace_path)
    if events_path.exists():
        session_files.append(events_path)
    if last_message_path.exists():
        session_files.append(last_message_path)
    stage_artifacts = [
        StageArtifact("report_output", Path(item["absolute_path"]), display_name=Path(item["absolute_path"]).name)
        for item in existing_report_outputs
    ]
    output_path = Path(existing_report_outputs[0]["absolute_path"]) if existing_report_outputs else None
    return StageExecutionResult(
        stage_name=stage_name,
        status=status,
        message=message,
        return_code=return_code,
        log_path=stage_log_path,
        artifacts=stage_artifacts,
        session_files=session_files,
        output_path=output_path,
        metadata={
            **metadata,
            "graph_node_id": stage_name,
            "graph_node_status": node_status or None,
            "graph_report_output_paths": [str(item["path"]) for item in report_outputs],
        },
    )


def _read_agentflow_run_record(run_dir: Path | None) -> dict[str, Any] | None:
    if run_dir is None:
        return None
    return read_json_file(run_dir / "run.json")


def _read_agentflow_node_status(run_record: dict[str, Any] | None, stage_name: str) -> str:
    if not isinstance(run_record, dict):
        return ""
    nodes = run_record.get("nodes")
    if not isinstance(nodes, dict):
        return ""
    node = nodes.get(stage_name)
    if not isinstance(node, dict):
        return ""
    return str(node.get("status") or "").strip().lower()


def _build_graph_manifest(
    *,
    context: StageContext,
    stage_results: list[StageExecutionResult],
    report_outputs: list[dict[str, Any]],
    pipeline_payload: dict[str, Any],
    pipeline_path: Path,
    run_dir: Path | None,
    process_result,
) -> dict[str, Any]:
    artifact_report_map = {
        result.stage_name: [
            {
                "output_id": str(item.get("output_id") or ""),
                "title": str(item.get("title") or ""),
                "relative_path": str(item.get("path") or ""),
                "format": str(item.get("format") or "markdown"),
                "required": bool(item.get("required", True)),
                "exists": Path(item["absolute_path"]).exists() and Path(item["absolute_path"]).stat().st_size > 0,
            }
            for item in report_outputs
            if str(item.get("node_id") or "") == result.stage_name
        ]
        for result in stage_results
    }
    return {
        "kind": "custom_graph",
        "generated_at": utc_now_z(),
        "task_id": context.task_id,
        "attempt_id": context.attempt_id,
        "pipeline_path": str(pipeline_path),
        "run_dir": str(run_dir) if run_dir else None,
        "pipeline": {
            "name": str(pipeline_payload.get("name") or ""),
            "working_dir": str(pipeline_payload.get("working_dir") or context.repo_root),
            "nodes": [
                {
                    "id": str(node.get("id") or ""),
                    "depends_on": [
                        str(item).strip()
                        for item in (node.get("depends_on") if isinstance(node.get("depends_on"), list) else [])
                        if str(item).strip()
                    ],
                    "agent": str(node.get("agent") or ""),
                    "model": node.get("model"),
                    "tools": str(node.get("tools") or ""),
                    "target": node.get("target") if isinstance(node.get("target"), dict) else None,
                    "success_criteria": node.get("success_criteria") if isinstance(node.get("success_criteria"), list) else [],
                    "prompt": str(node.get("prompt") or ""),
                }
                for node in (pipeline_payload.get("nodes") if isinstance(pipeline_payload.get("nodes"), list) else [])
                if isinstance(node, dict)
            ],
        },
        "process": {
            "return_code": process_result.return_code,
            "cancelled": process_result.cancelled,
            "timed_out": process_result.timed_out,
            "duration_seconds": process_result.duration_seconds,
        },
        "nodes": {
            result.stage_name: {
                "status": result.status,
                "message": result.message,
                "return_code": result.return_code,
                "log_path": str(result.log_path),
                "session_files": [str(path) for path in result.session_files],
                "reports": artifact_report_map.get(result.stage_name, []),
            }
            for result in stage_results
        },
        "reports": [
            {
                "output_id": str(item.get("output_id") or ""),
                "node_id": str(item.get("node_id") or ""),
                "title": str(item.get("title") or ""),
                "relative_path": str(item.get("path") or ""),
                "format": str(item.get("format") or "markdown"),
                "required": bool(item.get("required", True)),
                "exists": Path(item["absolute_path"]).exists() and Path(item["absolute_path"]).stat().st_size > 0,
            }
            for item in report_outputs
        ],
    }


def _summarize_overall_status(stage_results: list[StageExecutionResult]) -> tuple[str, str]:
    statuses = [result.status for result in stage_results]
    if any(status == "cancelled" for status in statuses):
        return "cancelled", "graph execution cancelled"
    if any(status == "timed_out" for status in statuses):
        return "timed_out", "graph execution timed out"
    if statuses and all(status == "succeeded" for status in statuses):
        return "succeeded", "task completed"
    if any(status == "succeeded" for status in statuses):
        return "partial_success", next((result.message for result in stage_results if result.status != "succeeded"), "graph execution partially succeeded")
    return "failed", next((result.message for result in stage_results if result.status != "succeeded"), "graph execution failed")


def _build_failed_graph_result(
    context: StageContext,
    *,
    stage_names: list[str],
    message: str,
    extra_log_path: Path | None = None,
) -> GraphExecutionResult:
    results: list[StageExecutionResult] = []
    for stage_name in stage_names or ["graph"]:
        log_path = context.logs_dir / f"{stage_name}.codex.log"
        write_text_file(
            log_path,
            "\n".join(
                [
                    f"=== {stage_name} ===",
                    f"Generated at (UTC): {utc_now_z()}",
                    f"Repo root: {context.repo_root}",
                    message,
                    "",
                ]
            ),
        )
        if extra_log_path is not None and extra_log_path.exists():
            append_file_to_log(log_path, extra_log_path, "=== graph preparation log ===")
        results.append(
            StageExecutionResult(
                stage_name=stage_name,
                status="failed",
                message=message,
                return_code=None,
                log_path=log_path,
                artifacts=[],
                session_files=[],
                metadata={"executor_mode": "agentflow_cli", "graph_failure": True},
            )
        )
    return GraphExecutionResult(stage_results=results, overall_status="failed", overall_message=message)
