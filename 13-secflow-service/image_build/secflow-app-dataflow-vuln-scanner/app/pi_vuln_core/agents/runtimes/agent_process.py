from __future__ import annotations

import asyncio
import contextlib
import os
import signal
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from app.pi_vuln_core.agents.runtime_trace import command_display


def _process_group_id(proc: asyncio.subprocess.Process) -> int | None:
    try:
        return os.getpgid(proc.pid)
    except ProcessLookupError:
        return None
    except Exception:
        return None


def _process_group_exists(pgid: int | None) -> bool:
    if pgid is None:
        return False
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return False
    return True


@dataclass
class AgentProcessHandle:
    proc: asyncio.subprocess.Process
    label: str
    logger: Callable[..., Any]
    pgid: int | None

    @classmethod
    async def spawn(
        cls,
        *,
        cmd_args: list[str],
        working_dir: str | None,
        env: dict[str, str] | None,
        is_windows: bool,
        logger: Callable[..., Any],
        label: str,
        with_stdin: bool = True,
    ) -> "AgentProcessHandle":
        stdin = asyncio.subprocess.PIPE if with_stdin else None
        if is_windows:
            proc = await asyncio.create_subprocess_shell(
                command_display(cmd_args),
                stdin=stdin,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=working_dir,
                env=env,
            )
            return cls(proc=proc, label=label, logger=logger, pgid=None)
        proc = await asyncio.create_subprocess_exec(
            *cmd_args,
            stdin=stdin,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=working_dir,
            env=env,
            start_new_session=True,
        )
        return cls(proc=proc, label=label, logger=logger, pgid=_process_group_id(proc))

    async def terminate_tree(
        self,
        *,
        reason: str,
        grace_seconds: float = 5.0,
        force_if_group_still_exists: bool = True,
    ) -> None:
        if self.proc.returncode is not None:
            if force_if_group_still_exists and _process_group_exists(self.pgid):
                self.logger(
                    "runtime_process_group_cleanup_after_exit",
                    label=self.label,
                    pid=self.proc.pid,
                    pgid=self.pgid,
                    reason=reason,
                )
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(self.pgid, signal.SIGKILL)
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self.proc.wait(), timeout=1.0)
            return

        if self.pgid is not None:
            self.logger(
                "runtime_process_group_terminating",
                label=self.label,
                pid=self.proc.pid,
                pgid=self.pgid,
                reason=reason,
            )
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.pgid, signal.SIGTERM)
        else:
            with contextlib.suppress(ProcessLookupError):
                self.proc.terminate()

        try:
            await asyncio.wait_for(self.proc.wait(), timeout=grace_seconds)
        except Exception:
            if self.pgid is not None:
                self.logger(
                    "runtime_process_group_force_kill",
                    label=self.label,
                    pid=self.proc.pid,
                    pgid=self.pgid,
                    reason=reason,
                )
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(self.pgid, signal.SIGKILL)
            else:
                with contextlib.suppress(Exception):
                    self.proc.kill()
            with contextlib.suppress(Exception):
                await self.proc.wait()


async def run_cancel_monitor(
    cancel_event: asyncio.Event,
    on_abort: Callable[[], Awaitable[None]] | None,
    handle: AgentProcessHandle,
    *,
    reason: str,
) -> None:
    await cancel_event.wait()
    if on_abort is not None:
        with contextlib.suppress(Exception):
            await on_abort()
    await handle.terminate_tree(reason=reason)
