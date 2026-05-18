from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from app.core.config import get_config
from app.core.time_utils import utc_now_z
from app.services.adb_service import AdbCommandResult
from app.workers.runner import (
    StageArtifact,
    StageContext,
    StageExecutionResult,
    StageHooks,
    run_logged_command,
)

SCRIPT_PATH = Path(__file__).resolve().parent.parent.parent / "ask_claude_poc.py"
BASHRC_SOURCE = "source ~/.bashrc"
ANDROID_TOOLS_PATH = "/opt/android-tools"
ANDROID_NDK_BIN_PATH = "/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"
ENV_MARKER = "__SECFLOW_KERNEL_SCAN_ENV__"


def run_poc_stage(
    context: StageContext,
    hooks: StageHooks,
    *,
    report_dir: Path | None = None,
) -> StageExecutionResult:
    cfg = get_config()
    exec_cfg = cfg.execution
    poc_root = Path(cfg.workspace_root) / "poc" / context.task_id
    poc_root.mkdir(parents=True, exist_ok=True)
    log_path = poc_root / "poc.log"
    vullist_path = poc_root / "vullist"
    output_dir = poc_root / "vul_results"
    results_json = poc_root / "poc_results.json"
    kernel_dir = context.kernel_dir

    configured_report_dir = context.effective_config.get("report_dir")
    if report_dir is None and configured_report_dir:
        report_dir = Path(str(configured_report_dir))
    if report_dir is None:
        report_dir = Path(cfg.workspace_root) / "audit" / context.task_id

    effective_report_dir, report_error = _prepare_report_dir(report_dir, poc_root, log_path)
    if report_error:
        log_path.write_text(f"{report_error}: {report_dir}\n", encoding="utf-8")
        return StageExecutionResult(
            stage_name="poc",
            status="failed",
            message=f"{report_error}: {report_dir}",
            return_code=None,
            log_path=log_path,
        )

    threads = context.effective_config.get("poc_threads") or exec_cfg.poc_threads
    model = exec_cfg.poc_model or exec_cfg.claude_model

    header = "\n".join([
        "=== poc verification ===",
        f"Started at (UTC): {utc_now_z()}",
        f"Report path: {report_dir}",
        f"Effective report dir: {effective_report_dir}",
        f"Kernel dir: {kernel_dir}",
        "ADB server socket: from ~/.bashrc",
        f"POC workspace: {poc_root}",
        f"Threads (hint): {threads}",
        f"Model: {model}",
        "",
        "",
    ])
    log_path.write_text(header, encoding="utf-8")

    bashrc_devices_result, bashrc_error, adb_serial, adb_server_socket, sourced_env = _check_adb_devices_after_source_bashrc(
        poc_root,
        hooks,
    )
    _append_adb_log(log_path, [bashrc_devices_result])
    if bashrc_error:
        return StageExecutionResult(
            stage_name="poc",
            status="failed",
            message=bashrc_error,
            return_code=bashrc_devices_result.return_code,
            log_path=log_path,
            metadata={
                "adb_server_socket": adb_server_socket or "",
                "adb_serial": adb_serial or "",
            },
        )

    cmd = [
        sys.executable, "-u", str(SCRIPT_PATH),
        "--report-dir", str(effective_report_dir),
        "--kernel-dir", str(kernel_dir),
        "--device-ip", adb_serial,
        "--vullist", str(vullist_path),
        "--output-dir", str(output_dir),
        "--results-json", str(results_json),
        "--model", model,
    ]
    env_overrides = {
        **sourced_env,
        "ADB_SERVER_SOCKET": adb_server_socket,
        "ANDROID_SERIAL": adb_serial,
    }
    display_cmd = cmd

    script_header = "\n".join([
        "",
        "=== poc script ===",
        "Command: " + " ".join([
            "env",
            f"ADB_SERVER_SOCKET={adb_server_socket}",
            f"ANDROID_SERIAL={adb_serial}",
            *display_cmd,
        ]),
        f"ADB_SERVER_SOCKET: {adb_server_socket}",
        f"ANDROID_SERIAL: {adb_serial}",
        f"PATH: {env_overrides.get('PATH', '')}",
        "",
        "",
    ]
    )

    result = run_logged_command(
        cmd,
        cwd=poc_root,
        log_path=log_path,
        log_header=script_header,
        hooks=hooks,
        timeout_seconds=exec_cfg.task_timeout_seconds,
        append=True,
        env_overrides=env_overrides,
    )

    if result.cancelled:
        return StageExecutionResult(
            stage_name="poc",
            status="cancelled",
            message="poc stage cancelled",
            return_code=result.return_code,
            log_path=log_path,
        )

    if result.timed_out:
        return StageExecutionResult(
            stage_name="poc",
            status="failed",
            message=f"poc stage timed out after {exec_cfg.task_timeout_seconds}s",
            return_code=result.return_code,
            log_path=log_path,
        )

    if result.return_code != 0:
        return StageExecutionResult(
            stage_name="poc",
            status="failed",
            message=f"poc script exited with code {result.return_code}",
            return_code=result.return_code,
            log_path=log_path,
        )

    total = 0
    confirmed = 0
    if results_json.exists():
        try:
            data = json.loads(results_json.read_text(encoding="utf-8"))
            entries = data.get("results", [])
            total = len(entries)
            confirmed = sum(1 for r in entries if r.get("isvul") == "yes")
        except (json.JSONDecodeError, OSError):
            pass

    return StageExecutionResult(
        stage_name="poc",
        status="succeeded",
        message=f"poc completed, {confirmed}/{total} confirmed",
        return_code=result.return_code,
        log_path=log_path,
        artifacts=[StageArtifact("poc_results", results_json, display_name="poc_results.json")],
        output_path=results_json,
        metadata={
            "total_vuls": total,
            "confirmed": confirmed,
            "duration_seconds": result.duration_seconds,
            "report_dir": str(effective_report_dir),
            "kernel_dir": str(kernel_dir),
            "adb_server_socket": adb_server_socket or "",
            "adb_serial": adb_serial,
        },
    )


def _prepare_report_dir(report_path: Path, poc_root: Path, log_path: Path) -> tuple[Path | None, str | None]:
    if report_path.is_dir():
        return report_path, None

    if not report_path.exists():
        return None, "report path not found"

    if not report_path.is_file():
        return None, "report path is neither a directory nor a file"

    if report_path.suffix.lower() != ".md":
        return None, "report file must be a Markdown .md file"

    input_dir = poc_root / "input_reports"
    input_dir.mkdir(parents=True, exist_ok=True)
    target = input_dir / report_path.name
    try:
        if report_path.resolve() != target.resolve():
            shutil.copy2(report_path, target)
    except OSError as exc:
        log_path.write_text(f"failed to prepare report file {report_path}: {exc}\n", encoding="utf-8")
        return None, "failed to prepare report file"
    return input_dir, None


def _append_adb_log(log_path: Path, commands: list) -> None:
    for result in commands:
        output = result.output or ""
        text = "\n".join([
            "",
            "=== adb ===",
            f"Command: {' '.join(result.command)}",
            output.rstrip(),
            f"Exit code: {result.return_code}",
            "",
        ])
        _append_log(log_path, text + "\n")


def _check_adb_devices_after_source_bashrc(
    cwd: Path,
    hooks: StageHooks,
) -> tuple[AdbCommandResult, str | None, str | None, str | None, dict[str, str]]:
    display_command = [BASHRC_SOURCE, "&&", "adb", "devices"]
    sourced_env, source_output, source_error = _load_env_after_source_bashrc(cwd, hooks)
    if source_error:
        return (
            AdbCommandResult(return_code=None, output=source_output, command=display_command),
            source_error,
            None,
            None,
            sourced_env,
        )

    hooks.heartbeat()
    if hooks.is_cancel_requested():
        return (
            AdbCommandResult(return_code=None, output="", command=display_command),
            "poc stage cancelled during adb devices check",
            None,
            None,
            sourced_env,
        )

    adb_server_socket = sourced_env.get("ADB_SERVER_SOCKET", "")
    if not adb_server_socket:
        output = _format_env_probe_output(source_output, sourced_env)
        return (
            AdbCommandResult(return_code=None, output=output, command=display_command),
            "ADB_SERVER_SOCKET is not set after sourcing ~/.bashrc",
            None,
            "",
            sourced_env,
        )

    try:
        proc = subprocess.run(
            ["adb", "devices"],
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            env=sourced_env,
        )
        return_code = proc.returncode
        output = _format_env_probe_output(source_output, sourced_env) + (proc.stdout or "")
    except FileNotFoundError:
        return_code = None
        output = _format_env_probe_output(source_output, sourced_env)
        output += f"adb executable not found in PATH after sourcing ~/.bashrc: {sourced_env.get('PATH', '')}"
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        output = _format_env_probe_output(source_output, sourced_env) + output
        output = output + ("\n" if output else "") + "adb devices check timed out after sourcing ~/.bashrc"
        command_result = AdbCommandResult(return_code=None, output=output, command=display_command)
        hooks.heartbeat()
        return command_result, "adb devices check timed out after sourcing ~/.bashrc", None, adb_server_socket, sourced_env
    finally:
        hooks.heartbeat()

    command_result = AdbCommandResult(
        return_code=return_code,
        output=output,
        command=display_command,
    )
    if return_code is None:
        return command_result, "adb executable not found after sourcing ~/.bashrc", None, adb_server_socket, sourced_env
    if return_code != 0:
        return command_result, f"adb devices failed after sourcing ~/.bashrc with code {return_code}", None, adb_server_socket, sourced_env
    adb_serial = _select_adb_device_serial(output)
    if not adb_serial:
        return command_result, "no online adb device found after sourcing ~/.bashrc", None, adb_server_socket, sourced_env
    return command_result, None, adb_serial, adb_server_socket, sourced_env


def _load_env_after_source_bashrc(cwd: Path, hooks: StageHooks) -> tuple[dict[str, str], str, str | None]:
    base_env = os.environ.copy()
    base_env.pop("ADB_SERVER_SOCKET", None)
    base_env.pop("ANDROID_SERIAL", None)
    command = ["bash", "-lc", f"{BASHRC_SOURCE}; printf '\\n{ENV_MARKER}\\n'; env -0"]

    hooks.heartbeat()
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            env=base_env,
        )
    except FileNotFoundError:
        return {}, "bash executable not found in PATH", "bash executable not found in PATH"
    except subprocess.TimeoutExpired as exc:
        output = _decode_bytes(exc.stdout)
        return {}, output, "source ~/.bashrc timed out"
    finally:
        hooks.heartbeat()

    raw_output = proc.stdout or b""
    marker = f"\n{ENV_MARKER}\n".encode("utf-8")
    source_bytes, separator, env_bytes = raw_output.partition(marker)
    source_output = _decode_bytes(source_bytes)
    if not separator:
        return {}, _decode_bytes(raw_output), "failed to capture environment after sourcing ~/.bashrc"

    sourced_env = _parse_env_bytes(env_bytes)
    _ensure_android_paths(sourced_env)
    if proc.returncode != 0 and not sourced_env:
        return sourced_env, source_output, f"source ~/.bashrc failed with code {proc.returncode}"
    return sourced_env, source_output, None


def _parse_env_bytes(payload: bytes) -> dict[str, str]:
    env: dict[str, str] = {}
    for item in payload.split(b"\0"):
        if not item or b"=" not in item:
            continue
        key, value = item.split(b"=", 1)
        env[key.decode("utf-8", errors="replace")] = value.decode("utf-8", errors="replace")
    return env


def _ensure_android_paths(env: dict[str, str]) -> None:
    parts = [part for part in env.get("PATH", "").split(":") if part]
    for required in reversed([ANDROID_TOOLS_PATH, ANDROID_NDK_BIN_PATH]):
        if required not in parts:
            parts.insert(0, required)
    env["PATH"] = ":".join(parts)


def _format_env_probe_output(source_output: str, env: dict[str, str]) -> str:
    lines = []
    if source_output.strip():
        lines.extend(["=== source ~/.bashrc output ===", source_output.rstrip()])
    lines.extend([
        f"ADB_SERVER_SOCKET={env.get('ADB_SERVER_SOCKET', '')}",
        f"PATH={env.get('PATH', '')}",
    ])
    return "\n".join(lines) + "\n"


def _decode_bytes(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.decode("utf-8", errors="replace")


def _select_adb_device_serial(output: str) -> str:
    for raw in output.splitlines():
        line = raw.strip()
        if not line or line.startswith("List of devices") or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            return parts[0]
    return ""


def _append_log(log_path: Path, text: str) -> None:
    with log_path.open("ab") as handle:
        handle.write(text.encode("utf-8"))
