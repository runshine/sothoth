from __future__ import annotations

import pytest

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry


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
