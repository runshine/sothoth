"""`poc` CLI invocation helpers (subprocess mechanics only).

The in-memory task store + threading from the old single-process model is gone
(Celery + MySQL own task state now). What stays here, isolated, is:
- `build_poc_cmd`: unpack task fields into `poc` CLI argv (`-e/-r/-b/-o` + options).
- `default_output_dir`: the `<entry>_<bindir>_<ts>` naming convention.
- `run_poc_cli`: subprocess.Popen the `poc` CLI in its own session, stream stdout
  to a log file, kill the whole process group on timeout/abort, collect artifacts.

`run_poc_cli` is called by `task_service._execute_task` (the Celery worker side).
"""
from __future__ import annotations

import os
import re
import shlex
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Optional


def _now_stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def _slug(x: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", x).strip("_") or "poc"


def default_output_dir(entry: str, bindir: str, base: Path) -> str:
    """`<entry>_<bindir-basename>_<ts>` under `base` (mirrors the `poc` CLI's -o default)."""
    bname = Path(bindir).name if bindir else "bindir"
    name = f"{_slug(entry)}_{_slug(bname)}_{time.strftime('%Y%m%d_%H%M%S')}"
    return str(base / name)


def build_poc_cmd(
    *,
    poc_bin: str,
    entry_function: str,
    vuln_report_path: str,
    binary_dir: str,
    output_dir: str,
    model: Optional[str] = None,
    effort: Optional[str] = None,
    session_name: Optional[str] = None,
    session_id: Optional[str] = None,
    session_dir: Optional[str] = None,
) -> list[str]:
    """Build the `poc` CLI argv from task fields."""
    # NOTE: the `poc` CLI has no --timeout flag (it rejects unknown args → exit 2).
    # The timeout is enforced by run_poc_cli's process-group timer, not the CLI.
    cmd = [poc_bin, "-e", entry_function, "-r", vuln_report_path,
           "-b", binary_dir, "-o", output_dir]
    if model:
        cmd += ["--model", model]
    if effort:
        cmd += ["--effort", effort]
    if session_name:
        cmd += ["--session-name", session_name]
    if session_id:
        cmd += ["--session-id", session_id]
    if session_dir:
        cmd += ["--session-dir", session_dir]
    return cmd


def _kill_pg(proc: subprocess.Popen, killed: dict) -> None:
    """Kill the whole process group (poc + claude + gdb + tmux children)."""
    if proc.poll() is not None:
        return
    killed["flag"] = True
    try:
        pgid = os.getpgid(proc.pid)
    except OSError:
        pgid = proc.pid
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            return
        except OSError:
            return
        if sig == signal.SIGTERM:
            time.sleep(0.5)


def run_poc_cli(
    *,
    cmd: list[str],
    work_dir: Path,
    log_path: str,
    output_dir: str,
    timeout: int,
    on_popen: Optional[Callable[[subprocess.Popen], None]] = None,
    should_abort: Optional[Callable[[], bool]] = None,
) -> dict:
    """Run the `poc` CLI, stream stdout to `log_path`, kill the group on timeout/abort.

    - `on_popen(proc)`: called right after Popen so the caller can record the pgid
      (for Celery revoke killpg) and register a kill handle.
    - `should_abort()`: polled each output line; if True, killpg + stop (ownership lost).

    Returns {returncode, artifacts, status, error, timed_out}.
    """
    killed = {"flag": False}
    work_dir.mkdir(parents=True, exist_ok=True)
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    try:
        with open(log_path, "w", encoding="utf-8") as logfh:
            logfh.write(f"# cmd {shlex.join(cmd)}\n# cwd {work_dir}\n\n")
            logfh.flush()
            # start_new_session=True → poc is a session leader; killpg(poc.pid)
            # reaches poc + claude + gdb + tmux children that stayed in its group.
            proc = subprocess.Popen(
                cmd, cwd=str(work_dir), stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1,
                start_new_session=True,
            )
            if on_popen:
                on_popen(proc)
            timer = threading.Timer(timeout, lambda: _kill_pg(proc, killed))
            timer.daemon = True
            timer.start()
            assert proc.stdout is not None
            for line in proc.stdout:
                logfh.write(line)
                logfh.flush()
                if should_abort and should_abort():
                    _kill_pg(proc, killed)
                    break
            proc.wait()
            timer.cancel()
            rc = proc.returncode
        art_dir = Path(output_dir) / "output"  # the `poc` prompt saves under {输出目录}/output
        artifacts = sorted(p.name for p in art_dir.iterdir()) if art_dir.is_dir() else []
    except Exception as exc:  # noqa: BLE001
        return {"returncode": None, "artifacts": [], "status": "failed",
                "error": f"{type(exc).__name__}: {exc}", "timed_out": False}

    if killed["flag"]:
        status = "timeout"
        error = f"timeout after {timeout}s"
    elif rc == 0:
        status = "succeeded"
        error = None
    else:
        status = "failed"
        error = f"poc exit code {rc}"
    return {"returncode": rc, "artifacts": artifacts, "status": status,
            "error": error, "timed_out": killed["flag"]}
