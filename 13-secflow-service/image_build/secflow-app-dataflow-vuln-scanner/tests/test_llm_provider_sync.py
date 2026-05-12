import pytest

from app.services.llm_provider_sync import (
    _local_pi_injected_models_json,
    _validated_models_json_provider_count,
    build_models_json,
)


def test_build_models_json_preserves_context_window_and_max_tokens():
    payload = build_models_json(
        [
            {
                "enabled": True,
                "provider_key": "local_ccr",
                "provider_type": "anthropic",
                "api_base": "http://llm.local",
                "api_key": "secret",
                "model": "claude-sonnet",
                "model_context_window": 163804,
                "max_tokens": 16384,
                "extra_config": {},
            }
        ]
    )

    provider = payload["providers"]["local_ccr"]
    model = provider["models"][0]

    assert provider["api"] == "anthropic-messages"
    assert model["id"] == "claude-sonnet"
    assert model["contextWindow"] == 163804
    assert model["maxTokens"] == 16384


def test_build_models_json_uses_extra_config_fallbacks():
    payload = build_models_json(
        [
            {
                "enabled": True,
                "provider_key": "openai_ccr",
                "provider_type": "openai-compatible",
                "api_base": "http://llm.local/v1",
                "api_key": "secret",
                "model": "glm-5",
                "extra_config": {
                    "contextLength": 65536,
                    "maxTokens": 4096,
                },
            }
        ]
    )

    model = payload["providers"]["openai_ccr"]["models"][0]

    assert model["contextWindow"] == 65536
    assert model["maxTokens"] == 4096


def test_local_pi_models_json_file_binding_overrides_generated_payload():
    injected = '{"providers":{"my_llm":{"baseUrl":"http://llm.local/v1","models":[{"id":"glm-5"}]}}}'

    content = _local_pi_injected_models_json(
        [
            {
                "enabled": True,
                "provider_key": "local_pi",
                "file_bindings": [
                    {
                        "enabled": True,
                        "name": "models.json",
                        "path": "/root/.pi/agent/models.json",
                        "content": injected,
                    }
                ],
            },
            {
                "enabled": True,
                "provider_key": "generated_should_not_win",
                "provider_type": "openai-compatible",
                "api_base": "http://generated.local/v1",
                "api_key": "secret",
                "model": "generated-model",
                "extra_config": {},
            },
        ]
    )

    assert content == injected
    assert _validated_models_json_provider_count(content) == 1


def test_local_pi_models_json_file_binding_must_be_valid_json():
    with pytest.raises(ValueError):
        _validated_models_json_provider_count('{"providers":{"my_llm":{"models":[{"id":"glm-5"},]}}}')
