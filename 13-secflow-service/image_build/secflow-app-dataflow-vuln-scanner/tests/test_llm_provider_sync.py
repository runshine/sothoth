from app.services.llm_provider_sync import build_models_json


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
