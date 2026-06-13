from __future__ import annotations

import json
import os
import selectors
import signal
import shutil
import subprocess
import time
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from app.core.config import ExecutionConfig, get_config, resolve_agentflow_root

SUPPORTED_EXECUTOR_MODES = ("mock", "codex_cli", "opencode_cli", "agentflow_cli")


def _safe_copy2(src: str | os.PathLike[str], dst: str | os.PathLike[str], *, follow_symlinks: bool = True) -> str:
    if os.fspath(src) == os.fspath(dst):
        return "reused"
    if os.path.realpath(os.fspath(src)) == os.path.realpath(os.fspath(dst)):
        return "reused"
    shutil.copy2(src, dst, follow_symlinks=follow_symlinks)
    return "copied"


@dataclass(frozen=True)
class StageArtifact:
    artifact_kind: str
    file_path: Path
    display_name: str | None = None


@dataclass(frozen=True)
class StageExecutionResult:
    stage_name: str
    status: str
    message: str
    return_code: int | None
    log_path: Path
    artifacts: list[StageArtifact] = field(default_factory=list)
    session_files: list[Path] = field(default_factory=list)
    output_path: Path | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LoggedCommandResult:
    return_code: int | None
    cancelled: bool
    timed_out: bool
    duration_seconds: float


@dataclass(frozen=True)
class StageHooks:
    heartbeat: Callable[[], None]
    is_cancel_requested: Callable[[], bool]
    graph_prepared: Callable[[dict[str, Any]], None] | None = None
    graph_progress: Callable[[dict[str, Any]], None] | None = None


@dataclass(frozen=True)
class StageContext:
    task_id: str
    attempt_id: str
    workspace_id: str
    stage_name: str
    input_kind: str
    pipeline_mode: str
    project_path: str | None
    report_path: str | None
    repo_root: Path
    attempt_root: Path
    runtime_root: Path
    logs_dir: Path
    artifacts_dir: Path
    scratch_dir: Path
    effective_config: dict[str, Any]
    provider_runtime: Any | None = None

    def stage_session_dir(self) -> Path:
        return self.runtime_root / self.stage_name

    def stage_session_file(self, filename: str) -> Path:
        return self.stage_session_dir() / filename

    def stage_log_path(self) -> Path:
        return self.logs_dir / f"{self.stage_name}.codex.log"

    def stage_artifact_path(self, filename: str) -> Path:
        return self.artifacts_dir / filename

    def repo_runtime_root(self) -> Path:
        return self.repo_root / ".audit" / "secflow-app-ipc-audit" / "tasks" / self.task_id / "attempts" / self.attempt_id

    def repo_stage_runtime_dir(self) -> Path:
        return self.repo_runtime_root() / self.stage_name


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def normalize_attempt_relative_path(raw_path: str) -> PurePosixPath:
    normalized = PurePosixPath(str(raw_path or "").strip())
    if not normalized.parts or normalized.is_absolute() or ".." in normalized.parts:
        raise ValueError(f"invalid relative path: {raw_path}")
    return normalized


def resolve_attempt_relative_path(attempt_root: Path, relative_path: str) -> Path:
    normalized = normalize_attempt_relative_path(relative_path)
    candidate = (attempt_root.resolve() / normalized.as_posix()).resolve()
    try:
        candidate.relative_to(attempt_root.resolve())
    except ValueError as exc:
        raise ValueError(f"path escapes attempt root: {relative_path}") from exc
    return candidate


def write_text_file(path: Path, content: str) -> Path:
    ensure_parent(path)
    path.write_text(content, encoding="utf-8")
    return path


def write_json_file(path: Path, payload: dict[str, Any]) -> Path:
    ensure_parent(path)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def copy_file(source: Path, target: Path) -> Path:
    ensure_parent(target)
    _safe_copy2(source, target)
    return target


def normalize_project(project_path: str) -> str:
    return project_path.strip().strip("/")


def project_label(project_path: str) -> str:
    return normalize_project(project_path).replace("/", ".")


def resolve_stage_work_dir(context: StageContext) -> Path:
    repo_root = context.repo_root.resolve()
    project_path = normalize_project(context.project_path or "")
    if not project_path:
        return repo_root
    candidate = (repo_root / project_path).resolve()
    try:
        candidate.relative_to(repo_root)
    except ValueError:
        return repo_root
    if not candidate.is_dir():
        return repo_root
    return candidate


def resolve_executor_mode(effective_config: dict[str, Any]) -> str:
    candidate = str(
        effective_config.get("executor_mode")
        or effective_config.get("execution_mode")
        or get_config().execution.mode
    ).strip()
    if candidate not in SUPPORTED_EXECUTOR_MODES:
        return str(get_config().execution.mode)
    return candidate


def resolve_executor_model(effective_config: dict[str, Any]) -> str | None:
    candidate = str(effective_config.get("model") or "").strip()
    return candidate or None


def resolve_stage_executor_model(context: StageContext) -> str | None:
    runtime = context.provider_runtime
    runtime_model = str(getattr(runtime, "executor_model", "") or "").strip() if runtime is not None else ""
    if runtime_model:
        return runtime_model
    runtime_model = str(getattr(runtime, "effective_model", "") or "").strip() if runtime is not None else ""
    if runtime_model:
        return runtime_model
    return resolve_executor_model(context.effective_config)


def resolve_task_timeout_seconds(effective_config: dict[str, Any] | None) -> int:
    cfg_timeout = int(get_config().execution.task_timeout_seconds)
    if not isinstance(effective_config, dict):
        return cfg_timeout
    try:
        timeout_seconds = int(effective_config.get("timeout_seconds"))
    except (TypeError, ValueError):
        return cfg_timeout
    return timeout_seconds if timeout_seconds > 0 else cfg_timeout


def load_declared_report_outputs(effective_config: dict[str, Any]) -> list[dict[str, Any]]:
    outputs = effective_config.get("report_outputs")
    if not isinstance(outputs, list):
        return []
    normalized_outputs: list[dict[str, Any]] = []
    for item in outputs:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "").strip()
        node_id = str(item.get("node_id") or "").strip()
        output_id = str(item.get("output_id") or "").strip()
        title = str(item.get("title") or output_id or node_id).strip()
        if not path or not node_id or not output_id:
            continue
        normalized_outputs.append(
            {
                "output_id": output_id,
                "node_id": node_id,
                "title": title or output_id,
                "path": path,
                "format": str(item.get("format") or "markdown"),
                "required": bool(item.get("required", True)),
                "order": int(item.get("order") or 0),
            }
        )
    return normalized_outputs


def resolve_report_outputs_for_attempt(attempt_root: Path, effective_config: dict[str, Any]) -> list[dict[str, Any]]:
    resolved_outputs: list[dict[str, Any]] = []
    for item in load_declared_report_outputs(effective_config):
        relative_path = normalize_attempt_relative_path(str(item["path"])).as_posix()
        absolute_path = resolve_attempt_relative_path(attempt_root, relative_path)
        resolved_outputs.append(
            {
                **item,
                "path": relative_path,
                "absolute_path": absolute_path,
            }
        )
    return resolved_outputs


def resolve_stage_primary_report_output_path(
    context: StageContext,
    stage_name: str,
    *,
    default_path: Path,
) -> Path:
    matches = [
        item
        for item in resolve_report_outputs_for_attempt(context.attempt_root, context.effective_config)
        if str(item.get("node_id") or "").strip() == stage_name
    ]
    if not matches:
        return default_path
    matches.sort(key=lambda item: (int(item.get("order") or 0), str(item.get("output_id") or "")))
    return Path(matches[0]["absolute_path"])


def build_codex_exec_command(
    prompt: str,
    *,
    repo_root: Path,
    sandbox_mode: str,
    approval_policy: str,
    network_access: bool,
    model: str | None = None,
    add_dirs: list[Path] | None = None,
    json_output: bool = False,
    output_last_message_path: Path | None = None,
) -> list[str]:
    cfg = get_config().execution
    cmd = [cfg.codex_bin, "-a", approval_policy, "-s", sandbox_mode]
    if sandbox_mode == "workspace-write" and network_access:
        cmd += ["-c", "sandbox_workspace_write.network_access=true"]
    cmd += ["exec"]
    if model:
        cmd += ["-m", model]
    if cfg.codex_skip_git_repo_check:
        cmd.append("--skip-git-repo-check")
    for add_dir in add_dirs or []:
        cmd += ["--add-dir", str(add_dir)]
    if json_output:
        cmd.append("--json")
    if output_last_message_path is not None:
        ensure_parent(output_last_message_path)
        cmd += ["-o", str(output_last_message_path)]
    cmd += ["-C", str(repo_root), prompt]
    return cmd


def build_opencode_exec_command(
    prompt: str,
    *,
    repo_root: Path,
    model: str | None = None,
    json_output: bool = True,
    session_id: str | None = None,
) -> list[str]:
    cfg = get_config().execution
    cmd = [cfg.opencode_bin, "run", "--dir", str(repo_root), "--dangerously-skip-permissions"]
    if session_id:
        cmd += ["--session", session_id]
    if json_output:
        cmd += ["--format", "json"]
    if model:
        cmd += ["-m", model]
    cmd.append(prompt)
    return cmd


def build_agentflow_exec_command(
    pipeline_path: Path,
    *,
    runs_dir: Path,
) -> list[str]:
    cfg = get_config().execution
    return [
        cfg.agentflow_python_bin,
        "-m",
        "agentflow.cli",
        "run",
        str(pipeline_path),
        "--output",
        "json-summary",
        "--preflight",
        "never",
        "--runs-dir",
        str(runs_dir),
    ]


def build_agentflow_node(
    *,
    node_id: str,
    prompt: str,
    repo_root: Path,
    work_dir: Path | None = None,
    attempt_root: Path,
    model: str | None = None,
    sandbox_mode: str | None = None,
    network_access: bool = False,
    depends_on: list[str] | None = None,
    success_criteria: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    cfg = get_config().execution
    agent_name = cfg.agentflow_agent
    executable = cfg.codex_bin if agent_name == "codex" else cfg.opencode_bin
    extra_args: list[str] = []
    node_env: dict[str, str] = {}
    if agent_name == "codex":
        extra_args += ["--add-dir", str(attempt_root)]
        if sandbox_mode:
            node_env["AGENTFLOW_CODEX_SANDBOX_MODE"] = sandbox_mode
            if sandbox_mode == "workspace-write" and network_access:
                extra_args += ["-c", "sandbox_workspace_write.network_access=true"]
    node: dict[str, Any] = {
        "id": node_id,
        "agent": agent_name,
        "prompt": prompt,
        "model": model,
        "tools": "read_write",
        "target": {
            "kind": "local",
            "cwd": str(work_dir or repo_root),
        },
        "timeout_seconds": int(cfg.agentflow_node_timeout_seconds),
        "executable": executable,
        "extra_args": extra_args,
        "env": node_env,
        "success_criteria": success_criteria or [],
    }
    if depends_on:
        node["depends_on"] = depends_on
    return node


def build_process_env(context: StageContext) -> dict[str, str]:
    process_env, _, _ = build_process_env_and_summary(context)
    return process_env


def build_process_env_and_summary(context: StageContext) -> tuple[dict[str, str], str, dict[str, Any]]:
    from app.services.provider_runtime import get_provider_runtime_service

    runtime_service = get_provider_runtime_service()
    materialized = runtime_service.materialize_runtime(context.runtime_root, context.provider_runtime)
    process_env = runtime_service.build_process_env(context.provider_runtime, materialized)
    runtime = context.provider_runtime
    provider_keys = runtime.provider_keys if runtime is not None else []
    metadata = {
        "provider_keys": provider_keys,
        "mapped_env_keys": materialized.mapped_env_keys,
        "mapped_file_paths": materialized.mapped_file_paths,
        "effective_model": runtime.effective_model if runtime is not None else None,
        "executor_model": getattr(runtime, "executor_model", None) if runtime is not None else None,
    }
    summary = "\n".join(
        [
            f"Provider keys: {provider_keys if provider_keys else '[]'}",
            f"Mapped env keys: {materialized.mapped_env_keys if materialized.mapped_env_keys else '[]'}",
            f"Mapped file paths: {materialized.mapped_file_paths if materialized.mapped_file_paths else '[]'}",
            f"Effective model: {runtime.effective_model if runtime is not None and runtime.effective_model else '(default)'}",
            f"Executor model: {getattr(runtime, 'executor_model', None) or '(default)'}",
            f"HOME: {materialized.home_dir}",
            f"XDG_CONFIG_HOME: {materialized.xdg_config_home}",
            f"XDG_DATA_HOME: {materialized.xdg_data_home}",
            f"XDG_CACHE_HOME: {materialized.xdg_cache_home}",
            f"XDG_STATE_HOME: {materialized.xdg_state_home}",
        ]
    )
    return process_env, summary, metadata


def build_opencode_process_env(context: StageContext) -> dict[str, str]:
    return build_process_env(context)


def build_agentflow_process_env_and_summary(context: StageContext) -> tuple[dict[str, str], str, dict[str, Any]]:
    cfg = get_config().execution
    process_env, provider_summary, provider_metadata = build_process_env_and_summary(context)
    resolved_root = resolve_agentflow_root(cfg)
    effective_root = str(resolved_root or cfg.agentflow_root).strip()
    current_pythonpath = str(process_env.get("PYTHONPATH") or "").strip()
    merged_pythonpath = current_pythonpath
    if effective_root:
        merged_pythonpath = effective_root if not current_pythonpath else f"{effective_root}:{current_pythonpath}"
        process_env["PYTHONPATH"] = merged_pythonpath
    metadata = {
        "agentflow_root": effective_root,
        "agentflow_configured_root": cfg.agentflow_root,
        "agentflow_root_resolved": resolved_root is not None,
        "agentflow_python_bin": cfg.agentflow_python_bin,
        "agentflow_agent": cfg.agentflow_agent,
        **provider_metadata,
    }
    summary = "\n".join(
        [
            provider_summary,
            f"AgentFlow configured root: {cfg.agentflow_root}",
            f"AgentFlow resolved root: {effective_root or '(not found)'}",
            f"AgentFlow python: {cfg.agentflow_python_bin}",
            f"AgentFlow agent: {cfg.agentflow_agent}",
            f"PYTHONPATH: {process_env.get('PYTHONPATH', '')}",
        ]
    )
    return process_env, summary, metadata


def read_json_file(path: Path) -> Any | None:
    if not path.exists() or not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def opencode_env_summary(env: dict[str, str]) -> str:
    keys = ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME")
    return "\n".join(f"{key}: {env.get(key, '')}" for key in keys)


def provider_runtime_summary(context: StageContext) -> str:
    _, summary, _ = build_process_env_and_summary(context)
    return summary


def extract_opencode_session_id(events_path: Path) -> str | None:
    if not events_path.exists():
        return None
    for raw_line in events_path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        session_id = _extract_session_id(item)
        if session_id:
            return session_id
    return None


def opencode_last_event_is_error(events_path: Path) -> bool:
    last_event: dict[str, Any] | None = None
    if not events_path.exists():
        return False
    for raw_line in events_path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            last_event = item
    return _is_opencode_error_event(last_event)


def write_last_message_from_jsonl(events_path: Path, output_path: Path) -> Path | None:
    if not events_path.exists():
        return None
    last_message: str | None = None
    fallback_message: str | None = None
    for raw_line in events_path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        message = _extract_event_text(item)
        if message:
            event_type = str(item.get("type") or item.get("event") or "").strip().lower()
            if any(token in event_type for token in ("assistant", "message", "response", "content", "text", "delta")):
                last_message = message
            elif fallback_message is None or not last_message:
                fallback_message = message
    if not last_message:
        last_message = fallback_message
    if not last_message:
        return None
    return write_text_file(output_path, last_message.rstrip() + "\n")


def write_last_message_from_agentflow_result(result_path: Path, output_path: Path) -> Path | None:
    final_message: str | None = None
    if result_path.exists():
        try:
            payload = json.loads(result_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            final_message = str(payload.get("final_response") or payload.get("output") or "").strip() or None
    if not final_message:
        return None
    return write_text_file(output_path, final_message.rstrip() + "\n")


def discover_single_run_dir(runs_dir: Path) -> Path | None:
    if not runs_dir.exists():
        return None
    run_dirs = [path for path in sorted(runs_dir.iterdir()) if path.is_dir()]
    if len(run_dirs) != 1:
        return None
    return run_dirs[0]


def append_file_to_log(log_path: Path, source_path: Path, header: str) -> None:
    if not source_path.exists():
        return
    content = source_path.read_bytes()
    _ensure_trailing_newline(log_path)
    with log_path.open("ab") as handle:
        handle.write((header + "\n").encode("utf-8"))
        handle.write(content)
        if not content.endswith(b"\n"):
            handle.write(b"\n")


def command_line_string(cmd: list[str]) -> str:
    def quote(value: str) -> str:
        if not value or any(ch.isspace() or ch in "\"'\\$`" for ch in value):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'
        return value

    return " ".join(quote(part) for part in cmd)


def run_logged_command(
    cmd: list[str],
    *,
    cwd: Path,
    log_path: Path,
    log_header: str,
    hooks: StageHooks,
    timeout_seconds: int,
    mirror_output_paths: list[Path] | None = None,
    append: bool = False,
    process_env: dict[str, str] | None = None,
    progress_tick: Callable[[], None] | None = None,
) -> LoggedCommandResult:
    cfg: ExecutionConfig = get_config().execution
    heartbeat_interval = max(float(cfg.heartbeat_interval_seconds), 1.0)
    poll_interval = max(float(cfg.cancel_check_interval_seconds), 0.2)
    ensure_parent(log_path)
    if append and log_path.exists():
        _ensure_trailing_newline(log_path)
        with log_path.open("ab") as handle:
            handle.write(log_header.encode("utf-8"))
    else:
        log_path.write_text(log_header, encoding="utf-8")
    mirror_output_paths = mirror_output_paths or []
    mirror_handles = []
    for path in mirror_output_paths:
        ensure_parent(path)
        if append and path.exists():
            _ensure_trailing_newline(path)
        else:
            path.write_bytes(b"")
        mirror_handles.append(path.open("ab"))

    process = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=process_env,
        start_new_session=True,
    )
    selector = selectors.DefaultSelector()
    if process.stdout is not None:
        selector.register(process.stdout, selectors.EVENT_READ)

    cancelled = False
    timed_out = False
    termination_requested = False
    started = time.monotonic()
    last_heartbeat = 0.0
    last_progress_tick = 0.0

    with log_path.open("ab") as handle:
        try:
            while True:
                now = time.monotonic()
                if now - last_heartbeat >= heartbeat_interval:
                    hooks.heartbeat()
                    last_heartbeat = now
                if progress_tick is not None and now - last_progress_tick >= poll_interval:
                    try:
                        progress_tick()
                    except Exception:
                        pass
                    last_progress_tick = now
                if hooks.is_cancel_requested():
                    cancelled = True
                    termination_requested = True
                    _terminate_process(process)
                    break
                if timeout_seconds > 0 and now - started >= timeout_seconds:
                    timed_out = True
                    termination_requested = True
                    _terminate_process(process)
                    break

                events = selector.select(timeout=poll_interval)
                for key, _ in events:
                    chunk = _read_chunk(key.fd)
                    if chunk:
                        handle.write(chunk)
                        handle.flush()
                        for mirror in mirror_handles:
                            mirror.write(chunk)
                            mirror.flush()
                    else:
                        _safe_unregister(selector, key.fileobj)

                if process.poll() is not None and not events:
                    break
        except Exception:
            termination_requested = True
            _terminate_process(process)
            raise
        finally:
            _drain_process_output(process, handle, mirror_handles, nonblocking=termination_requested)
            _close_selector(selector)
            for mirror in mirror_handles:
                mirror.close()

    return_code = process.poll() if termination_requested else process.wait()
    return LoggedCommandResult(
        return_code=return_code,
        cancelled=cancelled,
        timed_out=timed_out,
        duration_seconds=round(time.monotonic() - started, 3),
    )


def _read_chunk(fd: int) -> bytes:
    try:
        return os.read(fd, 4096)
    except OSError:
        return b""


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    process_ids = _collect_process_tree_ids(process.pid)
    if not process_ids and process.poll() is not None:
        return
    group_ids = _collect_process_group_ids(process_ids)
    _signal_process_groups(group_ids, signal.SIGTERM)
    _signal_processes(process_ids, signal.SIGTERM)
    if process.poll() is not None:
        return
    grace_seconds = max(float(get_config().execution.process_terminate_grace_seconds), 0.5)
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        process_ids = _collect_process_tree_ids(process.pid) | process_ids
        group_ids = _collect_process_group_ids(process_ids) | group_ids
        _signal_process_groups(group_ids, signal.SIGKILL)
        _signal_processes(process_ids, signal.SIGKILL)
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=0.2)


def _collect_process_tree_ids(root_pid: int) -> set[int]:
    process_ids: set[int] = set()
    pending = [root_pid]
    while pending:
        current_pid = pending.pop()
        if current_pid in process_ids:
            continue
        if not Path(f"/proc/{current_pid}").exists():
            continue
        process_ids.add(current_pid)
        for child_pid in _child_process_ids(current_pid):
            if child_pid not in process_ids:
                pending.append(child_pid)
    return process_ids


def _child_process_ids(parent_pid: int) -> list[int]:
    task_children = Path(f"/proc/{parent_pid}/task/{parent_pid}/children")
    try:
        return [int(value) for value in task_children.read_text(encoding="utf-8").split() if value.strip()]
    except (OSError, ValueError):
        pass
    children: list[int] = []
    for proc_dir in Path("/proc").iterdir():
        if not proc_dir.name.isdigit():
            continue
        status_path = proc_dir / "status"
        try:
            for line in status_path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("PPid:") and int(line.split()[1]) == parent_pid:
                    children.append(int(proc_dir.name))
                    break
        except (OSError, ValueError, IndexError):
            continue
    return children


def _collect_process_group_ids(process_ids: set[int]) -> set[int]:
    group_ids: set[int] = set()
    for pid in process_ids:
        try:
            group_ids.add(os.getpgid(pid))
        except ProcessLookupError:
            continue
    return group_ids


def _signal_process_groups(group_ids: set[int], sig: signal.Signals) -> None:
    for group_id in sorted(group_ids):
        try:
            os.killpg(group_id, sig)
        except ProcessLookupError:
            continue
        except PermissionError:
            continue


def _signal_processes(process_ids: set[int], sig: signal.Signals) -> None:
    for pid in sorted(process_ids, reverse=True):
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            continue
        except PermissionError:
            continue


def _drain_process_output(
    process: subprocess.Popen[bytes],
    handle,
    mirror_handles: list,
    *,
    nonblocking: bool = False,
) -> None:
    stdout = process.stdout
    if stdout is None:
        return
    fd = stdout.fileno()
    if nonblocking:
        os.set_blocking(fd, False)
    max_chunks = 256 if nonblocking else None
    chunks_read = 0
    try:
        while True:
            if max_chunks is not None and chunks_read >= max_chunks:
                break
            chunk = _read_chunk(fd)
            if not chunk:
                break
            chunks_read += 1
            handle.write(chunk)
            for mirror in mirror_handles:
                mirror.write(chunk)
    finally:
        if nonblocking:
            with suppress(OSError):
                os.set_blocking(fd, True)
    handle.flush()
    for mirror in mirror_handles:
        mirror.flush()
    with suppress(OSError):
        stdout.close()


def _safe_unregister(selector: selectors.BaseSelector, fileobj: object) -> None:
    try:
        selector.unregister(fileobj)
    except Exception:
        pass


def _close_selector(selector: selectors.BaseSelector) -> None:
    try:
        selector.close()
    except Exception:
        pass


def _ensure_trailing_newline(path: Path) -> None:
    if not path.exists() or path.stat().st_size == 0:
        return
    with path.open("rb") as handle:
        handle.seek(-1, os.SEEK_END)
        if handle.read(1) == b"\n":
            return
    with path.open("ab") as handle:
        handle.write(b"\n")


def _extract_session_id(item: Any, *, depth: int = 0) -> str | None:
    if depth > 5:
        return None
    if isinstance(item, list):
        for value in item:
            if session_id := _extract_session_id(value, depth=depth + 1):
                return session_id
        return None
    if not isinstance(item, dict):
        return None
    for key in ("sessionID", "sessionId", "session_id"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for key in ("part", "payload", "data", "response", "item"):
        if key not in item:
            continue
        if session_id := _extract_session_id(item[key], depth=depth + 1):
            return session_id
    return None


def _is_opencode_error_event(item: dict[str, Any] | None) -> bool:
    if not item:
        return False
    markers = (
        str(item.get("type") or "").strip().lower(),
        str(item.get("event") or "").strip().lower(),
        str(item.get("level") or "").strip().lower(),
        str(item.get("status") or "").strip().lower(),
    )
    if any(marker in {"error", "failed", "fatal", "exception"} for marker in markers):
        return True
    return bool(item.get("error"))


def _extract_event_text(item: Any, *, depth: int = 0) -> str | None:
    if depth > 5:
        return None
    if isinstance(item, str):
        stripped = item.strip()
        return stripped or None
    if isinstance(item, list):
        parts = [part for value in item if (part := _extract_event_text(value, depth=depth + 1))]
        if parts:
            return "\n".join(parts)
        return None
    if not isinstance(item, dict):
        return None
    for key in ("text", "message", "content", "delta", "output_text", "value"):
        if key not in item:
            continue
        if message := _extract_event_text(item[key], depth=depth + 1):
            return message
    for key in ("part", "payload", "data", "response", "item"):
        if key not in item:
            continue
        if message := _extract_event_text(item[key], depth=depth + 1):
            return message
    return None
