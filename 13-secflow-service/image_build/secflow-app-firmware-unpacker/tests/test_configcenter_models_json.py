import json

from app.services.configcenter import build_models_json_from_provider, extract_models_json_config


def test_provider_without_models_json_binding_generates_pi_models_json():
    extracted = extract_models_json_config(
        {
            "provider_key": "local_ccr",
            "provider_type": "anthropic",
            "api_base": "http://llm.local",
            "api_key": "secret",
            "model": "claude-sonnet",
            "model_context_window": 163804,
            "max_tokens": 16384,
            "file_bindings": [],
        }
    )

    model = extracted["models_json"]["providers"]["local_ccr"]["models"][0]

    assert extracted["default_model"] == "local_ccr/claude-sonnet"
    assert model["contextWindow"] == 163804
    assert model["maxTokens"] == 16384


def test_explicit_models_json_binding_is_completed_with_provider_limits():
    extracted = extract_models_json_config(
        {
            "provider_key": "local_ccr",
            "provider_type": "openai-compatible",
            "api_base": "http://llm.local/v1",
            "api_key": "secret",
            "model": "glm-5",
            "contextLength": 65536,
            "maxTokens": 4096,
            "file_bindings": [
                {
                    "enabled": True,
                    "name": "models.json",
                    "content": json.dumps(
                        {
                            "providers": {
                                "local_ccr": {
                                    "baseUrl": "http://llm.local/v1",
                                    "api": "openai-completions",
                                    "apiKey": "secret",
                                    "models": ["glm-5"],
                                }
                            }
                        }
                    ),
                }
            ],
        }
    )

    model = extracted["models_json"]["providers"]["local_ccr"]["models"][0]

    assert model["id"] == "glm-5"
    assert model["contextWindow"] == 65536
    assert model["maxTokens"] == 4096


def test_top_level_models_binding_is_normalized_to_provider_block():
    extracted = extract_models_json_config(
        {
            "provider_key": "local_ccr",
            "provider_type": "openai-compatible",
            "api_base": "http://llm.local/v1",
            "api_key": "secret",
            "model": "glm-5",
            "model_context_window": 32768,
            "max_tokens": 2048,
            "file_bindings": [
                {
                    "enabled": True,
                    "path": "models.json",
                    "content": json.dumps({"models": ["glm-5"]}),
                }
            ],
        }
    )

    provider = extracted["models_json"]["providers"]["local_ccr"]
    model = provider["models"][0]

    assert provider["baseUrl"] == "http://llm.local/v1"
    assert model["id"] == "glm-5"
    assert model["contextWindow"] == 32768
    assert model["maxTokens"] == 2048


def test_build_models_json_from_provider_maps_anthropic_api():
    payload = build_models_json_from_provider(
        {
            "provider_key": "anthropic_main",
            "provider_type": "anthropic",
            "api_base": "https://api.anthropic.com",
            "api_key": "secret",
            "model": "claude-sonnet",
        }
    )

    assert payload["providers"]["anthropic_main"]["api"] == "anthropic-messages"
