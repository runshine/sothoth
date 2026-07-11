from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from app.config import get_service_yaml
from app.models import DiagnosticExecutionRecord


async def run_command(session_id: int, message_id: int | None, command_text: str) -> DiagnosticExecutionRecord:
    cfg = get_service_yaml().app
    started_at = datetime.now(timezone.utc)
    process = await asyncio.create_subprocess_shell(
        command_text,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    status = "completed"
    exit_code = 0
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(),
            timeout=cfg.kubectl_timeout_seconds,
        )
        exit_code = int(process.returncode or 0)
        status = "completed" if exit_code == 0 else "failed"
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        stdout_bytes, stderr_bytes = b"", b"command timed out"
        exit_code = 124
        status = "timeout"

    max_bytes = cfg.max_command_output_bytes
    stdout = stdout_bytes[:max_bytes].decode("utf-8", errors="replace")
    stderr = stderr_bytes[:max_bytes].decode("utf-8", errors="replace")
    return DiagnosticExecutionRecord(
        id=0,
        session_id=session_id,
        message_id=message_id,
        command_text=command_text,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        status=status,
        started_at=started_at,
        finished_at=datetime.now(timezone.utc),
    )
