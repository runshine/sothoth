from __future__ import annotations

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

SCRIPT_PATH = Path(__file__).resolve().parent.parent.parent / "ask_claude_kernaudit_v2.py"


def _write_entrylist(entries: list[dict], path: Path) -> int:
    lines: list[str] = []
    for e in entries:
        func = (e.get("func") or "").strip()
        method = (e.get("method") or "").strip()
        if not func:
            continue
        lines.append(f"{func} {method}".rstrip())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return len(lines)


def run_audit_stage(
    context: StageContext,
    hooks: StageHooks,
    *,
    entry_results: list[dict] | None = None,
    entrylist_path: Path | None = None,
) -> StageExecutionResult:
    cfg = get_config()
    exec_cfg = cfg.execution
    audit_root = Path(cfg.workspace_root) / "audit" / context.task_id
    audit_root.mkdir(parents=True, exist_ok=True)
    report_dir = audit_root
    log_path = audit_root / "audit.log"

    if entrylist_path is not None:
        if not entrylist_path.is_file():
            log_path.write_text(f"entrylist file not found: {entrylist_path}\n", encoding="utf-8")
            return StageExecutionResult(
                stage_name="audit",
                status="failed",
                message=f"entrylist file not found: {entrylist_path}",
                return_code=None,
                log_path=log_path,
            )
        effective_entrylist = entrylist_path
        try:
            entry_count = sum(
                1
                for line in entrylist_path.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip()
            )
        except OSError as exc:
            log_path.write_text(f"failed to read entrylist: {exc}\n", encoding="utf-8")
            return StageExecutionResult(
                stage_name="audit",
                status="failed",
                message=f"failed to read entrylist: {exc}",
                return_code=None,
                log_path=log_path,
            )
    else:
        if not entry_results:
            log_path.write_text("no entrylist path and no entry results provided for audit stage\n", encoding="utf-8")
            return StageExecutionResult(
                stage_name="audit",
                status="failed",
                message="no entry results available for audit",
                return_code=None,
                log_path=log_path,
            )
        materialized = audit_root / "entrylist"
        entry_count = _write_entrylist(entry_results, materialized)
        effective_entrylist = materialized

    if entry_count == 0:
        log_path.write_text("entrylist is empty\n", encoding="utf-8")
        return StageExecutionResult(
            stage_name="audit",
            status="failed",
            message="entrylist is empty",
            return_code=None,
            log_path=log_path,
        )

    threads = context.effective_config.get("audit_threads") or exec_cfg.audit_threads
    model = exec_cfg.audit_model or exec_cfg.claude_model
    kernel_dir = context.kernel_dir

    cmd = [
        sys.executable, "-u", str(SCRIPT_PATH),
        "--devlist", str(effective_entrylist),
        "--kernel-dir", str(kernel_dir),
        "--report-dir", str(report_dir),
        "--threads", str(threads),
        "--model", model,
    ]

    header = "\n".join([
        "=== kernel audit ===",
        f"Started at (UTC): {utc_now_z()}",
        f"Kernel dir: {kernel_dir}",
        f"Report dir: {report_dir}",
        f"Entrylist: {effective_entrylist} ({entry_count} entries)"
        + (" [from frontend]" if entrylist_path is not None else " [materialized from entry stage]"),
        f"Threads: {threads}",
        f"Model: {model}",
        f"Command: {' '.join(cmd)}",
        "",
        "",
    ])

    result = run_logged_command(
        cmd,
        cwd=report_dir,
        log_path=log_path,
        log_header=header,
        hooks=hooks,
        timeout_seconds=exec_cfg.task_timeout_seconds,
    )

    if result.cancelled:
        return StageExecutionResult(
            stage_name="audit",
            status="cancelled",
            message="audit stage cancelled",
            return_code=result.return_code,
            log_path=log_path,
        )

    if result.timed_out:
        return StageExecutionResult(
            stage_name="audit",
            status="failed",
            message=f"audit stage timed out after {exec_cfg.task_timeout_seconds}s",
            return_code=result.return_code,
            log_path=log_path,
        )

    if result.return_code != 0:
        return StageExecutionResult(
            stage_name="audit",
            status="failed",
            message=f"audit script exited with code {result.return_code}",
            return_code=result.return_code,
            log_path=log_path,
        )

    report_count = len(list(report_dir.glob("*.md")))
    artifacts = [StageArtifact("audit_entrylist", effective_entrylist, display_name="entrylist")]

    return StageExecutionResult(
        stage_name="audit",
        status="succeeded",
        message=f"audit completed, {report_count} report files",
        return_code=result.return_code,
        log_path=log_path,
        artifacts=artifacts,
        metadata={
            "entries_input": entry_count,
            "reports_produced": report_count,
            "duration_seconds": result.duration_seconds,
        },
    )
