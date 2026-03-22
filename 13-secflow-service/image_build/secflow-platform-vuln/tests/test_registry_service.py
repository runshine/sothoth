import pytest

from app.services.registry import RegistryService


class DummyResponse:
    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


class DummyClient:
    def __init__(self, responses, recorder):
        self._responses = responses
        self._recorder = recorder

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, json=None):
        self._recorder.append(("POST", url, json))
        return self._responses.pop(0)

    async def delete(self, url):
        self._recorder.append(("DELETE", url, None))
        return self._responses.pop(0)


@pytest.mark.asyncio
async def test_registry_heartbeat_reregisters_on_404(monkeypatch):
    calls = []
    responses = [
        DummyResponse(404, "not found"),
        DummyResponse(200, "registered"),
    ]

    def fake_client(*args, **kwargs):
        return DummyClient(responses, calls)

    monkeypatch.setattr("app.services.registry.httpx.AsyncClient", fake_client)

    service = RegistryService()
    await service.heartbeat()

    assert calls[0][0] == "POST"
    assert "/api/menu/heartbeat/" in calls[0][1]
    assert calls[1][0] == "POST"
    assert calls[1][1].endswith("/api/menu/register")


@pytest.mark.asyncio
async def test_registry_unregister_accepts_404(monkeypatch):
    calls = []

    def fake_client(*args, **kwargs):
        return DummyClient([DummyResponse(404, "not found")], calls)

    monkeypatch.setattr("app.services.registry.httpx.AsyncClient", fake_client)

    service = RegistryService()
    await service.unregister()

    assert calls[0][0] == "DELETE"
    assert "/api/menu/unregister/" in calls[0][1]
