from app.services.k8s import K8SService


class _FakeResponse:
    status_code = 200

    @staticmethod
    def json():
        return {"ok": True}


class _FakeClient:
    def __init__(self):
        self.last_kwargs = None

    def request(self, **kwargs):
        self.last_kwargs = kwargs
        return _FakeResponse()


def test_request_injects_machine_token_header():
    svc = K8SService()
    fake_client = _FakeClient()
    svc.client = fake_client
    svc.config.auth_service.service_machine_token = "token-123"

    svc._request("GET", "/health")

    assert fake_client.last_kwargs is not None
    assert fake_client.last_kwargs["headers"]["Authorization"] == "Bearer token-123"


def test_request_keeps_custom_headers_with_machine_token():
    svc = K8SService()
    fake_client = _FakeClient()
    svc.client = fake_client
    svc.config.auth_service.service_machine_token = "token-123"

    svc._request("GET", "/health", headers={"X-Trace": "abc"})

    assert fake_client.last_kwargs is not None
    assert fake_client.last_kwargs["headers"]["X-Trace"] == "abc"
    assert fake_client.last_kwargs["headers"]["Authorization"] == "Bearer token-123"


def test_create_service_uses_service_create_request_schema(monkeypatch):
    svc = K8SService()
    captured = {}

    class _Resp:
        status_code = 201

        @staticmethod
        def json():
            return {"cluster_ip": "10.0.0.10"}

    def _fake_request(method, path, project_id=None, **kwargs):
        captured["method"] = method
        captured["path"] = path
        captured["project_id"] = project_id
        captured["json"] = kwargs.get("json", {})
        return _Resp()

    monkeypatch.setattr(svc, "_request", _fake_request)

    cluster_ip = svc.create_service("secflow-p1", "svc-test", "cs-1")

    assert cluster_ip == "10.0.0.10"
    assert captured["method"] == "POST"
    assert captured["path"] == "/services"
    assert captured["project_id"] == "p1"
    assert captured["json"]["name"] == "svc-test"
    assert isinstance(captured["json"].get("ports"), list)
    assert "manifest" not in captured["json"]
