from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import pytest

from app.pi_vuln_core.agents.base import BaseAgentRuntime
from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.runner import build_runtime_framework_config, run_framework_config


class InterruptingRuntime(BaseAgentRuntime):
    async def initialize(self) -> None:
        self._initialized = True

    async def create_session(self) -> str:
        session_id = f"interrupt_{len(self._sessions) + 1}"
        self._sessions[session_id] = {"turns": 0}
        return session_id

    async def send_message(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
        working_dir: Optional[str] = None,
    ) -> AgentResponse:
        raise asyncio.CancelledError("simulated SIGINT")

    async def multi_turn_execute(
        self,
        system_prompt: str,
        user_prompt: str,
        working_dir: str,
        max_turns: int = 30,
        session_id: Optional[str] = None,
    ) -> AgentResponse:
        return await self.send_message(
            message=user_prompt,
            system_prompt=system_prompt,
            session_id=session_id,
            working_dir=working_dir,
        )

    async def close_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    async def shutdown(self) -> None:
        self._sessions.clear()
        self._initialized = False


@pytest.mark.asyncio
async def test_interrupted_run_records_standard_abnormal_exit(
    monkeypatch: pytest.MonkeyPatch,
    framework_config_payload: dict,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", InterruptingRuntime)

    input_task = tmp_path / "input-task.md"
    input_task.write_text("# Test Task\n\nTrigger interrupt.\n", encoding="utf-8")
    workspace_root = tmp_path / "workspace"

    config = build_runtime_framework_config(
        framework_config_payload,
        workspace_root=str(workspace_root),
        execution_id="interrupt-run-001",
        input_task_file=str(input_task),
        input_task_id="task-003",
        output_dir=str(tmp_path / "output"),
        summary_file=str(tmp_path / "output" / "execution_summary.json"),
        runtime_mode="local_test",
    )

    with pytest.raises(asyncio.CancelledError):
        await run_framework_config(config)

    composite_abnormal = workspace_root / "pipeline_interrupt-run-001" / "_meta" / "abnormal_exit.json"
    atomic_abnormal = (
        workspace_root
        / "pipeline_interrupt-run-001"
        / "stage_01_scan"
        / "vuln_scan_initial_001"
        / "_meta"
        / "abnormal_exit.json"
    )

    assert composite_abnormal.exists()
    assert atomic_abnormal.exists()

    composite_payload = json.loads(composite_abnormal.read_text(encoding="utf-8"))
    atomic_payload = json.loads(atomic_abnormal.read_text(encoding="utf-8"))

    assert composite_payload["type"] == "abnormal_exit"
    assert atomic_payload["type"] == "abnormal_exit"
    assert "SIGINT / KeyboardInterrupt" in composite_payload["error"]
    assert "SIGINT / KeyboardInterrupt" in atomic_payload["error"]
    assert composite_payload["context"]["exception_type"] == "CancelledError"
    assert atomic_payload["context"]["exception_type"] == "CancelledError"
    assert atomic_payload["context"]["workflow_id"] == config.workflows.atomic[0].id
    assert atomic_payload["context"]["task_id"] == "initial_001"
