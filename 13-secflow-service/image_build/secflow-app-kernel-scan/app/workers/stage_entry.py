from __future__ import annotations

import json
import sys
from pathlib import Path

from app.core.config import get_config
from app.core.time_utils import utc_now_z
from app.workers.runner import (
    StageArtifact,
    StageContext,
    StageExecutionResult,
    StageHooks,
    run_logged_command,
)

SCRIPT_PATH = Path(__file__).resolve().parent.parent.parent / "ask_claude_entry.py"


def run_entry_stage(context: StageContext, hooks: StageHooks) -> StageExecutionResult:
    cfg = get_config()
    exec_cfg = cfg.execution
    entry_root = Path(cfg.workspace_root) / "entry" / context.task_id
    entry_root.mkdir(parents=True, exist_ok=True)
    log_path = entry_root / "entry.log"
    output_dir = entry_root
    results_path = entry_root / "entry_scan_results.json"
    kernel_dir = Path(context.kernel_dir)

    if not kernel_dir.is_dir():
        log_path.write_text(f"kernel dir not found: {kernel_dir}\n", encoding="utf-8")
        return StageExecutionResult(
            stage_name="entry",
            status="failed",
            message=f"kernel directory not found: {kernel_dir}",
            return_code=None,
            log_path=log_path,
        )

    threads = context.effective_config.get("entry_threads") or exec_cfg.entry_threads
    model = exec_cfg.entry_model or exec_cfg.claude_model

    cmd = [
        sys.executable, "-u", str(SCRIPT_PATH),
        "--kernel-dir", str(kernel_dir),
        "--output-dir", str(output_dir),
        "--threads", str(threads),
        "--model", model,
    ]

    header = "\n".join([
        "=== entry scan ===",
        f"Started at (UTC): {utc_now_z()}",
        f"Kernel dir: {kernel_dir}",
        f"Output dir: {output_dir}",
        f"Threads: {threads}",
        f"Model: {model}",
        f"Command: {' '.join(cmd)}",
        "",
        "",
    ])

    result = run_logged_command(
        cmd,
        cwd=output_dir,
        log_path=log_path,
        log_header=header,
        hooks=hooks,
        timeout_seconds=exec_cfg.task_timeout_seconds,
    )

    if result.cancelled:
        return StageExecutionResult(
            stage_name="entry",
            status="cancelled",
            message="entry stage cancelled",
            return_code=result.return_code,
            log_path=log_path,
        )

    if result.timed_out:
        return StageExecutionResult(
            stage_name="entry",
            status="failed",
            message=f"entry stage timed out after {exec_cfg.task_timeout_seconds}s",
            return_code=result.return_code,
            log_path=log_path,
        )

    if result.return_code != 0:
        return StageExecutionResult(
            stage_name="entry",
            status="failed",
            message=f"entry script exited with code {result.return_code}",
            return_code=result.return_code,
            log_path=log_path,
        )

    entries_found = 0
    if results_path.exists():
        try:
            data = json.loads(results_path.read_text(encoding="utf-8"))
            entries_found = len(data.get("entries", []))
        except (json.JSONDecodeError, OSError):
            pass
    else:
        results_path.write_text('{"entries": []}\n', encoding="utf-8")

    return StageExecutionResult(
        stage_name="entry",
        status="succeeded",
        message=f"entry scan completed, {entries_found} entries",
        return_code=result.return_code,
        log_path=log_path,
        artifacts=[StageArtifact("entry_results", results_path, display_name="entry_scan_results.json")],
        output_path=results_path,
        metadata={"entries_found": entries_found, "duration_seconds": result.duration_seconds},
    )
