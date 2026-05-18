from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ADB_SERVER_DEFAULT_PORT = 15037
ADB_CONNECT_TIMEOUT_SECONDS = 30
ADB_STATE_TIMEOUT_SECONDS = 15
ADB_PROPS_TIMEOUT_SECONDS = 15
ADB_SHELL_TIMEOUT_SECONDS = 15
ADB_BASHRC_BEGIN = "# >>> secflow-kernel-scan adb server >>>"
ADB_BASHRC_END = "# <<< secflow-kernel-scan adb server <<<"


@dataclass(frozen=True)
class AdbCommandResult:
    return_code: int | None
    output: str
    command: list[str]


@dataclass(frozen=True)
class AdbDeviceInfo:
    requested_ip: str
    adb_server_socket: str
    target: str
    serial: str
    sn: str
    state: str
    connected: bool
    message: str
    model: str = ""
    product: str = ""
    device: str = ""
    android_version: str = ""
    sdk: str = ""
    commands: list[AdbCommandResult] = field(default_factory=list)


def normalize_adb_server_socket(adb_server_ip: str) -> str:
    value = adb_server_ip.strip()
    if value.startswith("tcp:"):
        value = value.removeprefix("tcp:")
    host, port = _split_host_port(value)
    return f"tcp:{host}:{port or ADB_SERVER_DEFAULT_PORT}"


def normalize_adb_target(device_ip: str) -> str:
    return normalize_adb_server_socket(device_ip)


def set_adb_server_socket_env(adb_server_socket: str) -> str:
    os.environ["ADB_SERVER_SOCKET"] = adb_server_socket
    return adb_server_socket


def persist_adb_server_socket_to_bashrc(adb_server_socket: str, *, bashrc_path: Path | None = None) -> Path:
    path = bashrc_path or (Path.home() / ".bashrc")
    path.parent.mkdir(parents=True, exist_ok=True)
    old_text = path.read_text(encoding="utf-8") if path.exists() else ""
    block = "\n".join([
        ADB_BASHRC_BEGIN,
        f"export ADB_SERVER_SOCKET={_shell_single_quote(adb_server_socket)}",
        ADB_BASHRC_END,
    ])
    new_text = _replace_marked_block(old_text, block)
    path.write_text(new_text, encoding="utf-8")
    return path


def connect_adb_device(
    device_ip: str,
    *,
    cwd: Path | str | None = None,
    heartbeat: Callable[[], None] | None = None,
) -> AdbDeviceInfo:
    adb_server_socket = normalize_adb_server_socket(device_ip)
    set_adb_server_socket_env(adb_server_socket)
    command_results: list[AdbCommandResult] = []

    devices_result = run_adb_command(
        ["devices"],
        cwd=cwd,
        timeout_seconds=ADB_CONNECT_TIMEOUT_SECONDS,
        heartbeat=heartbeat,
        adb_server_socket=adb_server_socket,
    )
    command_results.append(devices_result)
    if devices_result.return_code != 0:
        return AdbDeviceInfo(
            requested_ip=device_ip,
            adb_server_socket=adb_server_socket,
            target="",
            serial="",
            sn="",
            state="unknown",
            connected=False,
            message=f"adb server unavailable at {adb_server_socket}",
            commands=command_results,
        )

    target, listed_state = _select_adb_device(devices_result.output)
    if not target:
        return AdbDeviceInfo(
            requested_ip=device_ip,
            adb_server_socket=adb_server_socket,
            target="",
            serial="",
            sn="",
            state="unknown",
            connected=False,
            message=f"no adb device found via {adb_server_socket}",
            commands=command_results,
        )

    state_result = run_adb_command(
        ["-s", target, "get-state"],
        cwd=cwd,
        timeout_seconds=ADB_STATE_TIMEOUT_SECONDS,
        heartbeat=heartbeat,
        adb_server_socket=adb_server_socket,
    )
    command_results.append(state_result)
    state = _last_nonempty_line(state_result.output) or listed_state or "unknown"
    if state_result.return_code != 0 or state != "device":
        return AdbDeviceInfo(
            requested_ip=device_ip,
            adb_server_socket=adb_server_socket,
            target=target,
            serial=target,
            sn="",
            state=state,
            connected=False,
            message=f"adb device is not ready for {target}: {state}",
            commands=command_results,
        )

    props = _read_device_props(target, cwd=cwd, heartbeat=heartbeat, adb_server_socket=adb_server_socket)
    command_results.extend(props.pop("commands"))

    return AdbDeviceInfo(
        requested_ip=device_ip,
        adb_server_socket=adb_server_socket,
        target=target,
        serial=target,
        sn=str(props.pop("sn") or target),
        state=state,
        connected=True,
        message=f"adb connected via {adb_server_socket} to {target}",
        commands=command_results,
        **props,
    )


def run_adb_devices(
    device_ip: str,
    *,
    cwd: Path | str | None = None,
    heartbeat: Callable[[], None] | None = None,
) -> AdbCommandResult:
    adb_server_socket = normalize_adb_server_socket(device_ip)
    set_adb_server_socket_env(adb_server_socket)
    devices_result = run_adb_command(
        ["devices"],
        cwd=cwd,
        timeout_seconds=ADB_CONNECT_TIMEOUT_SECONDS,
        heartbeat=heartbeat,
        adb_server_socket=adb_server_socket,
    )
    if _can_run_adb_shell(devices_result, cwd=cwd, heartbeat=heartbeat, adb_server_socket=adb_server_socket):
        persist_adb_server_socket_to_bashrc(adb_server_socket)
    return devices_result


def run_adb_command(
    args: list[str],
    *,
    cwd: Path | str | None = None,
    timeout_seconds: int,
    heartbeat: Callable[[], None] | None = None,
    adb_server_socket: str | None = None,
) -> AdbCommandResult:
    cmd = ["adb", *args]
    display_cmd = cmd
    env = None
    if adb_server_socket:
        env = os.environ.copy()
        env["ADB_SERVER_SOCKET"] = adb_server_socket
        display_cmd = [f"ADB_SERVER_SOCKET={adb_server_socket}", *cmd]
    if heartbeat is not None:
        heartbeat()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd is not None else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            env=env,
        )
        return AdbCommandResult(return_code=proc.returncode, output=proc.stdout or "", command=display_cmd)
    except FileNotFoundError:
        return AdbCommandResult(return_code=None, output="adb executable not found in PATH", command=display_cmd)
    except subprocess.TimeoutExpired as exc:
        output = _coerce_output(exc.stdout)
        message = f"adb command timed out after {timeout_seconds}s"
        return AdbCommandResult(
            return_code=None,
            output=output + ("\n" if output else "") + message,
            command=display_cmd,
        )
    finally:
        if heartbeat is not None:
            heartbeat()


def _read_device_props(
    target: str,
    *,
    cwd: Path | str | None,
    heartbeat: Callable[[], None] | None,
    adb_server_socket: str,
) -> dict[str, object]:
    prop_map = {
        "sn": "ro.serialno",
        "model": "ro.product.model",
        "product": "ro.product.name",
        "device": "ro.product.device",
        "android_version": "ro.build.version.release",
        "sdk": "ro.build.version.sdk",
    }
    values: dict[str, object] = {key: "" for key in prop_map}
    commands: list[AdbCommandResult] = []
    for key, prop in prop_map.items():
        result = run_adb_command(
            ["-s", target, "shell", "getprop", prop],
            cwd=cwd,
            timeout_seconds=ADB_PROPS_TIMEOUT_SECONDS,
            heartbeat=heartbeat,
            adb_server_socket=adb_server_socket,
        )
        commands.append(result)
        if result.return_code == 0:
            values[key] = _last_nonempty_line(result.output)
    values["commands"] = commands
    return values


def _split_host_port(value: str) -> tuple[str, int | None]:
    if ":" not in value:
        return value, None
    host, port_text = value.rsplit(":", 1)
    if port_text.isdigit():
        return host, int(port_text)
    return value, None


def _can_run_adb_shell(
    devices_result: AdbCommandResult,
    *,
    cwd: Path | str | None,
    heartbeat: Callable[[], None] | None,
    adb_server_socket: str,
) -> bool:
    if devices_result.return_code != 0:
        return False
    target, state = _select_adb_device(devices_result.output)
    if not target or state != "device":
        return False
    shell_result = run_adb_command(
        ["-s", target, "shell", "true"],
        cwd=cwd,
        timeout_seconds=ADB_SHELL_TIMEOUT_SECONDS,
        heartbeat=heartbeat,
        adb_server_socket=adb_server_socket,
    )
    return shell_result.return_code == 0


def _replace_marked_block(text: str, block: str) -> str:
    start = text.find(ADB_BASHRC_BEGIN)
    end = text.find(ADB_BASHRC_END, start + len(ADB_BASHRC_BEGIN)) if start != -1 else -1
    if start != -1 and end != -1:
        end += len(ADB_BASHRC_END)
        text = (text[:start] + text[end:]).strip()
    if text.strip():
        return block + "\n\n" + text.strip() + "\n"
    return block + "\n"


def _shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _select_adb_device(output: str) -> tuple[str, str]:
    fallback: tuple[str, str] = ("", "")
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices") or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        if state == "device":
            return serial, state
        if not fallback[0]:
            fallback = (serial, state)
    return fallback


def _last_nonempty_line(output: str) -> str:
    for line in reversed(output.splitlines()):
        value = line.strip()
        if value:
            return value
    return ""


def _coerce_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
