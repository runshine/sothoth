from __future__ import annotations

from unittest.mock import patch

import pytest

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.agents.runtimes.agent_process import AgentProcessHandle


@pytest.mark.asyncio
async def test_agent_registry_can_use_mock_runtime_and_reuse_session(patch_mock_agent_runtime):
    registry = AgentRuntimeRegistry()
    registry.register_from_config(
        [
            {
                "id": "mock-worker",
                "name": "Mock Worker",
                "type": "claude_code",
                "reset_context": False,
                "runtime_config": {},
            }
        ]
    )
    await registry.initialize_all()
    agent = registry.get("mock-worker")

    session_id = await agent.create_session()
    first = await agent.send_message("worker step", session_id=session_id, working_dir="/tmp")
    second = await agent.send_message("reflect", session_id=session_id, working_dir="/tmp")

    assert first.success and second.success
    assert first.conversation_id == second.conversation_id == session_id
    assert second.turn_count == 2

    await registry.shutdown_all()


@pytest.mark.asyncio
async def test_agent_process_handle_force_cleans_group_after_exit() -> None:
    events: list[tuple[int, int]] = []

    class FakeProc:
        pid = 123
        returncode = 0

        async def wait(self):
            return 0

    with patch(
        "app.pi_vuln_core.agents.runtimes.agent_process._process_group_exists",
        return_value=True,
    ):
        with patch(
            "app.pi_vuln_core.agents.runtimes.agent_process.os.killpg",
            side_effect=lambda pgid, sig: events.append((pgid, sig)),
        ):
            handle = AgentProcessHandle(
                proc=FakeProc(),
                label="test",
                logger=lambda *args, **kwargs: None,
                pgid=456,
            )
            await handle.terminate_tree(reason="cleanup")

    assert events
