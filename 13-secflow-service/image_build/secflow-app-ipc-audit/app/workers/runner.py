from __future__ import annotations

import json
import os
import selectors
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from app.core.config import ExecutionConfig, get_config

SUPPORTED_EXECUTOR_MODES = ("mock", "codex_cli", "opencode_cli")


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
    shutil.copy2(source, target)
    return target


def normalize_project(project_path: str) -> str:
    return project_path.strip().strip("/")


def project_label(project_path: str) -> str:
    return normalize_project(project_path).replace("/", ".")


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
    )
    selector = selectors.DefaultSelector()
    if process.stdout is not None:
        selector.register(process.stdout, selectors.EVENT_READ)

    cancelled = False
    timed_out = False
    started = time.monotonic()
    last_heartbeat = 0.0

    with log_path.open("ab") as handle:
        try:
            while True:
                now = time.monotonic()
                if now - last_heartbeat >= heartbeat_interval:
                    hooks.heartbeat()
                    last_heartbeat = now
                if hooks.is_cancel_requested():
                    cancelled = True
                    _terminate_process(process)
                    break
                if timeout_seconds > 0 and now - started >= timeout_seconds:
                    timed_out = True
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
        finally:
            _drain_process_output(process, handle, mirror_handles)
            _close_selector(selector)
            for mirror in mirror_handles:
                mirror.close()

    return LoggedCommandResult(
        return_code=process.wait(),
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
    if process.poll() is not None:
        return
    process.terminate()
    grace_seconds = max(float(get_config().execution.process_terminate_grace_seconds), 0.5)
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _drain_process_output(process: subprocess.Popen[bytes], handle, mirror_handles: list) -> None:
    stdout = process.stdout
    if stdout is None:
        return
    while True:
        chunk = _read_chunk(stdout.fileno())
        if not chunk:
            break
        handle.write(chunk)
        for mirror in mirror_handles:
            mirror.write(chunk)
    handle.flush()
    for mirror in mirror_handles:
        mirror.flush()
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
