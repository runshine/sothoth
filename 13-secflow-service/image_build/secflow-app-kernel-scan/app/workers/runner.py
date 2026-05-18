from __future__ import annotations

import json
import os
import selectors
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from app.core.config import ExecutionConfig, get_config


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
    stage_name: str
    pipeline_mode: str
    kernel_dir: str
    attempt_root: Path
    logs_dir: Path
    artifacts_dir: Path
    effective_config: dict[str, Any]

    def stage_log_path(self) -> Path:
        return self.logs_dir / f"{self.stage_name}.log"

    def stage_artifact_path(self, filename: str) -> Path:
        return self.artifacts_dir / filename


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_text_file(path: Path, content: str) -> Path:
    ensure_parent(path)
    path.write_text(content, encoding="utf-8")
    return path


def write_json_file(path: Path, payload: Any) -> Path:
    ensure_parent(path)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def build_claude_command(prompt: str, *, model: str | None = None) -> list[str]:
    cfg = get_config().execution
    cmd = [cfg.claude_bin, "--dangerously-skip-permissions"]
    effective_model = model or cfg.claude_model
    cmd.extend(["--model", effective_model, "-p", prompt])
    return cmd


def _claude_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    if extra:
        env.update({key: value for key, value in extra.items() if value is not None})
    return env


def run_logged_command(
    cmd: list[str],
    *,
    cwd: Path | str,
    log_path: Path,
    log_header: str,
    hooks: StageHooks,
    timeout_seconds: int,
    append: bool = False,
    env_overrides: dict[str, str] | None = None,
) -> LoggedCommandResult:
    cfg: ExecutionConfig = get_config().execution
    heartbeat_interval = max(float(cfg.heartbeat_interval_seconds), 1.0)
    poll_interval = max(float(cfg.cancel_check_interval_seconds), 0.2)
    ensure_parent(log_path)

    if append and log_path.exists():
        with log_path.open("ab") as handle:
            handle.write(log_header.encode("utf-8"))
    else:
        log_path.write_text(log_header, encoding="utf-8")

    process = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=_claude_env(env_overrides),
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
                    else:
                        _safe_unregister(selector, key.fileobj)

                if process.poll() is not None and not events:
                    break
        finally:
            _drain_process_output(process, handle)
            _close_selector(selector)

    return LoggedCommandResult(
        return_code=process.wait(),
        cancelled=cancelled,
        timed_out=timed_out,
        duration_seconds=round(time.monotonic() - started, 3),
    )


def run_claude_prompt(
    prompt: str,
    *,
    model: str | None = None,
    cwd: Path | str | None = None,
    timeout: int | None = None,
) -> tuple[str, bool]:
    cmd = build_claude_command(prompt, model=model)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(cwd) if cwd else None,
            timeout=timeout,
            env=_claude_env(),
        )
    except subprocess.TimeoutExpired:
        return "", False
    except FileNotFoundError:
        return "claude CLI not found", False
    if proc.returncode != 0:
        return proc.stdout or proc.stderr, False
    return proc.stdout, True


def parse_json_response(response: str) -> dict | None:
    text = response.strip()
    start = text.find("{")
    end = text.rfind("}") + 1
    if start == -1 or end == 0:
        return None
    try:
        return json.loads(text[start:end])
    except json.JSONDecodeError:
        return None


def _read_chunk(fd: int) -> bytes:
    try:
        return os.read(fd, 4096)
    except OSError:
        return b""


def _terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    grace = max(float(get_config().execution.process_terminate_grace_seconds), 0.5)
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _drain_process_output(process: subprocess.Popen, handle) -> None:
    stdout = process.stdout
    if stdout is None:
        return
    while True:
        chunk = _read_chunk(stdout.fileno())
        if not chunk:
            break
        handle.write(chunk)
    handle.flush()
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
