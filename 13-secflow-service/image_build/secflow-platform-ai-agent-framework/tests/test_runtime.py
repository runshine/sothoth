from __future__ import annotations

from app.models.config_models import FrameworkConfig
from app.runtime.registry import RuntimeManager


def test_runtime_healthcheck(framework_config):
    runtime_manager = RuntimeManager(framework_config)
    assert runtime_manager.healthcheck("codex-worker")["installed"] is True
    assert runtime_manager.healthcheck("claude-global-reviewer")["installed"] is True


def test_pipe_and_pty_sessions_can_reuse_context(framework_config_payload):
    payload = framework_config_payload
    for instance in payload["agent_instances"]:
        if instance["id"] in {"claude-global-reviewer", "opencode-result-reviewer"}:
            instance["reset_context"] = False
            instance["runtime_overrides"] = {"session_mode": "pipe" if instance["id"] == "claude-global-reviewer" else "pty", "env": {}}
    config = FrameworkConfig.model_validate(payload)
    runtime_manager = RuntimeManager(config)
    pipe_prompt = 'SECFLOW_PHASE: reflection SECFLOW_CONTEXT_JSON_BEGIN {"task_title":"pipe-session"} SECFLOW_CONTEXT_JSON_END'
    pty_prompt = 'SECFLOW_PHASE: reflection SECFLOW_CONTEXT_JSON_BEGIN {"task_title":"pty-session"} SECFLOW_CONTEXT_JSON_END'

    pipe_response_1 = runtime_manager.run_prompt(
        agent_instance_id="claude-global-reviewer",
        prompt=pipe_prompt,
        task_scope="runtime-pipe",
    )
    pipe_response_2 = runtime_manager.run_prompt(
        agent_instance_id="claude-global-reviewer",
        prompt=pipe_prompt,
        task_scope="runtime-pipe",
    )
    pty_response_1 = runtime_manager.run_prompt(
        agent_instance_id="opencode-result-reviewer",
        prompt=pty_prompt,
        task_scope="runtime-pty",
    )
    pty_response_2 = runtime_manager.run_prompt(
        agent_instance_id="opencode-result-reviewer",
        prompt=pty_prompt,
        task_scope="runtime-pty",
    )

    assert pipe_response_1.success and pipe_response_2.success
    assert pty_response_1.success and pty_response_2.success
    assert "pipe-session" in pipe_response_2.output
    assert "pty-session" in pty_response_2.output
    assert len(runtime_manager._session_cache) == 2
    runtime_manager.close_all()
