from types import SimpleNamespace

from app.api.code_server import (
    get_server_llm_provider_keys,
    matches_llm_filters,
    normalize_llm_provider_keys,
)


def _server(llm_provider_key=None, llm_provider_keys=None):
    return SimpleNamespace(
        llm_provider_key=llm_provider_key,
        llm_provider_keys=llm_provider_keys if llm_provider_keys is not None else [],
    )


def test_normalize_llm_provider_keys_dedup_and_keep_order():
    assert normalize_llm_provider_keys("provider-b", ["provider-a", "provider-b", "provider-a", ""]) == [
        "provider-a",
        "provider-b",
    ]
    assert normalize_llm_provider_keys(None, None) == []


def test_get_server_llm_provider_keys_fallback_to_single_key():
    assert get_server_llm_provider_keys(_server(llm_provider_keys=["provider-a"], llm_provider_key="provider-z")) == [
        "provider-a"
    ]
    assert get_server_llm_provider_keys(_server(llm_provider_keys=[], llm_provider_key="provider-z")) == ["provider-z"]
    assert get_server_llm_provider_keys(_server(llm_provider_keys=[], llm_provider_key=None)) == []


def test_matches_llm_filters_by_binding_and_provider_keys():
    bound_server = _server(llm_provider_keys=["provider-a", "provider-b"])
    unbound_server = _server(llm_provider_keys=[])

    assert matches_llm_filters(bound_server, "bound", set())
    assert not matches_llm_filters(unbound_server, "bound", set())
    assert matches_llm_filters(unbound_server, "unbound", set())
    assert not matches_llm_filters(bound_server, "unbound", set())
    assert matches_llm_filters(bound_server, "all", {"provider-b"})
    assert not matches_llm_filters(bound_server, "all", {"provider-x"})
