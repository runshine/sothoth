from types import SimpleNamespace

from app.model import CodeServerStatus
from app.services.task_manager import TaskManager


class FakeQuery:
    def __init__(self, obj):
        self.obj = obj

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self.obj


class FakeDB:
    def __init__(self, code_server):
        self.code_server = code_server
        self.commit_calls = 0

    def query(self, model):
        return FakeQuery(self.code_server)

    def commit(self):
        self.commit_calls += 1


class FakeK8s:
    def __init__(self):
        self.created_configmap = None
        self.deleted_configmap = None
        self.deployment_call = None
        self.ingress_call = None

    def check_pvc_exists(self, namespace, pvc_name):
        return True

    def create_pvc(self, namespace, pvc_name, storage_size):
        return True

    def create_configmap(self, namespace, name, data, labels=None):
        self.created_configmap = {
            "namespace": namespace,
            "name": name,
            "data": data,
            "labels": labels or {},
        }
        return True

    def delete_configmap(self, namespace, name):
        self.deleted_configmap = {"namespace": namespace, "name": name}
        return True

    def create_deployment(self, **kwargs):
        self.deployment_call = kwargs
        return True, {"PASSWORD": "pwd", "SUDO_PASSWORD": "pwd"}

    def create_service(self, namespace, name, code_server_id):
        return "10.0.0.1"

    def create_ingress(self, namespace, name, host, service_name):
        self.ingress_call = {
            "namespace": namespace,
            "name": name,
            "host": host,
            "service_name": service_name,
        }
        return "example.test"

    def get_pod_by_deployment(self, namespace, deployment_name):
        return {"name": "pod-1"}

    def delete_ingress(self, namespace, name):
        return True

    def delete_service(self, namespace, name):
        return True

    def delete_deployment(self, namespace, name):
        return True

    def delete_pvc(self, namespace, pvc_name):
        return True


class FakeConfigCenter:
    def __init__(self, payload):
        self.payload = payload
        self.last_key = None
        self.requested_keys = []

    def get_llm_provider(self, provider_key):
        self.last_key = provider_key
        self.requested_keys.append(provider_key)
        if isinstance(self.payload, dict) and provider_key in self.payload:
            return self.payload[provider_key]
        return self.payload


def _make_code_server(llm_configmap_name=None):
    return SimpleNamespace(
        id="cs-1",
        project_id="p1",
        name="audit-env",
        namespace="secflow-p1",
        status=CodeServerStatus.PENDING.value,
        source_pvcs=[{"pvc_name": "src-pvc", "mount_path": "/config/workspace"}],
        output_pvcs=[],
        deployment_name=None,
        service_name=None,
        ingress_name=None,
        pod_name=None,
        access_url=None,
        code_server_env={},
        custom_env={},
        llm_provider_key=None,
        llm_provider_keys=[],
        llm_provider_snapshot={},
        llm_provider_snapshots=[],
        llm_provider_mapped_env_keys=[],
        llm_file_bindings=[],
        llm_configmap_name=llm_configmap_name,
        deleted_at=None,
    )


def test_create_without_llm_provider(monkeypatch):
    code_server = _make_code_server()
    db = FakeDB(code_server)
    fake_k8s = FakeK8s()

    monkeypatch.setattr("app.services.task_manager.get_k8s_service", lambda: fake_k8s)
    monkeypatch.setattr("app.services.task_manager.get_configcenter_client", lambda: FakeConfigCenter({}))

    manager = TaskManager()
    task = SimpleNamespace(
        project_id="p1",
        params={
            "code_server_id": "cs-1",
            "namespace": "secflow-p1",
            "name": "audit-env",
            "env": {"USER_ONLY": "v1"},
            "code_server_env": {},
            "image": "",
            "llm_provider_key": "",
            "llm_provider_keys": [],
        },
    )

    result = manager._handle_create_task(task, db)

    assert "创建成功" in result
    assert code_server.status == CodeServerStatus.RUNNING.value
    assert code_server.llm_provider_key is None
    assert code_server.llm_provider_keys == []
    assert fake_k8s.created_configmap is None
    assert fake_k8s.deployment_call["extra_env"] is None
    assert fake_k8s.deployment_call["llm_configmap_name"] is None
    assert fake_k8s.deployment_call["custom_env"]["PROJECT_ID"] == "p1"
    assert fake_k8s.deployment_call["custom_env"]["USER_ONLY"] == "v1"

    manager.executor.shutdown(wait=False)


def test_create_with_llm_provider_env_override(monkeypatch):
    code_server = _make_code_server()
    db = FakeDB(code_server)
    fake_k8s = FakeK8s()
    fake_cc = FakeConfigCenter(
        {
            "provider_key": "openai-prod",
            "display_name": "OpenAI Prod",
            "provider_type": "openai-compatible",
            "model": "gpt-4o",
            "api_base": "https://api.example.com",
            "env_bindings": {
                "COMMON": "from-provider",
                "PROVIDER_ONLY": "p-only",
            },
            "file_bindings": [],
        }
    )

    monkeypatch.setattr("app.services.task_manager.get_k8s_service", lambda: fake_k8s)
    monkeypatch.setattr("app.services.task_manager.get_configcenter_client", lambda: fake_cc)

    manager = TaskManager()
    task = SimpleNamespace(
        project_id="p1",
        params={
            "code_server_id": "cs-1",
            "namespace": "secflow-p1",
            "name": "audit-env",
            "env": {"COMMON": "from-user", "USER_ONLY": "u-only"},
            "code_server_env": {},
            "image": "",
            "llm_provider_key": "openai-prod",
            "llm_provider_keys": ["openai-prod"],
        },
    )

    manager._handle_create_task(task, db)

    assert fake_cc.last_key == "openai-prod"
    assert fake_cc.requested_keys == ["openai-prod"]
    assert code_server.llm_provider_key == "openai-prod"
    assert code_server.llm_provider_keys == ["openai-prod"]
    assert code_server.llm_provider_snapshot["provider_key"] == "openai-prod"
    assert "COMMON" in code_server.llm_provider_mapped_env_keys
    assert fake_k8s.deployment_call["custom_env"]["COMMON"] == "from-provider"
    assert fake_k8s.deployment_call["extra_env"]["COMMON"] == "from-user"
    assert fake_k8s.deployment_call["extra_env"]["USER_ONLY"] == "u-only"

    manager.executor.shutdown(wait=False)


def test_create_with_llm_file_bindings_and_delete_cleanup(monkeypatch):
    code_server = _make_code_server(llm_configmap_name="code-server-llm-cs-1")
    db = FakeDB(code_server)
    fake_k8s = FakeK8s()
    fake_cc = FakeConfigCenter(
        {
            "provider_key": "anthropic-prod",
            "display_name": "Anthropic",
            "provider_type": "anthropic",
            "model": "claude-3-7-sonnet",
            "api_base": "https://api.example.com",
            "env_bindings": {"ANTHROPIC_MODEL": "claude-3-7-sonnet"},
            "file_bindings": [
                {
                    "name": "llm.yaml",
                    "path": "/etc/llm/llm.yaml",
                    "content": "model: claude-3-7-sonnet",
                    "format": "yaml",
                    "enabled": True,
                },
                {
                    "name": "disabled.txt",
                    "path": "/tmp/disabled.txt",
                    "content": "no",
                    "format": "txt",
                    "enabled": False,
                },
            ],
        }
    )

    monkeypatch.setattr("app.services.task_manager.get_k8s_service", lambda: fake_k8s)
    monkeypatch.setattr("app.services.task_manager.get_configcenter_client", lambda: fake_cc)

    manager = TaskManager()
    create_task = SimpleNamespace(
        project_id="p1",
        params={
            "code_server_id": "cs-1",
            "namespace": "secflow-p1",
            "name": "audit-env",
            "env": {},
            "code_server_env": {},
            "image": "",
            "llm_provider_key": "anthropic-prod",
            "llm_provider_keys": ["anthropic-prod"],
        },
    )
    manager._handle_create_task(create_task, db)

    assert fake_k8s.created_configmap is not None
    assert fake_k8s.created_configmap["name"].startswith("code-server-llm-")
    assert fake_k8s.created_configmap["data"] == {"file-1": "model: claude-3-7-sonnet"}
    assert code_server.llm_configmap_name == fake_k8s.created_configmap["name"]
    assert len(code_server.llm_file_bindings) == 1
    assert fake_k8s.deployment_call["extra_file_mounts"] == [{"path": "/etc/llm/llm.yaml", "sub_path": "file-1"}]

    delete_task = SimpleNamespace(
        params={
            "code_server_id": "cs-1",
            "delete_output_pvcs": False,
        }
    )
    manager._handle_delete_task(delete_task, db)

    assert fake_k8s.deleted_configmap is not None
    assert fake_k8s.deleted_configmap["name"] == fake_k8s.created_configmap["name"]

    manager.executor.shutdown(wait=False)


def test_create_with_multiple_llm_providers_merge_rules(monkeypatch):
    code_server = _make_code_server()
    db = FakeDB(code_server)
    fake_k8s = FakeK8s()
    fake_cc = FakeConfigCenter(
        {
            "provider-a": {
                "provider_key": "provider-a",
                "display_name": "Provider A",
                "provider_type": "openai-compatible",
                "model": "a-model",
                "api_base": "https://a.example.com",
                "env_bindings": {
                    "COMMON": "A",
                    "A_ONLY": "A-ONLY",
                },
                "file_bindings": [
                    {"name": "a.cfg", "path": "/etc/llm/agent.yaml", "content": "from: A", "enabled": True},
                    {"name": "skip-a", "path": "/tmp/a.txt", "content": "skip", "enabled": False},
                ],
            },
            "provider-b": {
                "provider_key": "provider-b",
                "display_name": "Provider B",
                "provider_type": "anthropic",
                "model": "b-model",
                "api_base": "https://b.example.com",
                "env_bindings": {
                    "COMMON": "B",
                    "B_ONLY": "B-ONLY",
                },
                "file_bindings": [
                    {"name": "b.cfg", "path": "/etc/llm/agent.yaml", "content": "from: B", "enabled": True},
                    {"name": "b2.cfg", "path": "/etc/llm/extra.json", "content": "{\"from\": \"B\"}", "enabled": True},
                ],
            },
        }
    )
    monkeypatch.setattr("app.services.task_manager.get_k8s_service", lambda: fake_k8s)
    monkeypatch.setattr("app.services.task_manager.get_configcenter_client", lambda: fake_cc)

    manager = TaskManager()
    task = SimpleNamespace(
        project_id="p1",
        params={
            "code_server_id": "cs-1",
            "namespace": "secflow-p1",
            "name": "audit-env",
            "env": {"COMMON": "from-user", "USER_ONLY": "u-only"},
            "code_server_env": {},
            "image": "",
            "llm_provider_keys": ["provider-a", "provider-b"],
        },
    )

    manager._handle_create_task(task, db)

    assert fake_cc.requested_keys == ["provider-a", "provider-b"]
    assert code_server.llm_provider_keys == ["provider-a", "provider-b"]
    assert code_server.llm_provider_key == "provider-b"
    assert code_server.llm_provider_snapshot["provider_key"] == "provider-b"
    assert [item["provider_key"] for item in code_server.llm_provider_snapshots] == ["provider-a", "provider-b"]
    assert code_server.llm_provider_mapped_env_keys == ["A_ONLY", "B_ONLY", "COMMON"]
    assert [item["path"] for item in code_server.llm_file_bindings] == ["/etc/llm/agent.yaml", "/etc/llm/extra.json"]
    assert fake_k8s.deployment_call["custom_env"]["COMMON"] == "B"
    assert fake_k8s.deployment_call["extra_env"]["COMMON"] == "from-user"
    assert fake_k8s.deployment_call["extra_env"]["USER_ONLY"] == "u-only"
    assert fake_k8s.created_configmap["data"] == {
        "file-1": "from: B",
        "file-2": "{\"from\": \"B\"}",
    }
    assert fake_k8s.deployment_call["extra_file_mounts"] == [
        {"path": "/etc/llm/agent.yaml", "sub_path": "file-1"},
        {"path": "/etc/llm/extra.json", "sub_path": "file-2"},
    ]

    manager.executor.shutdown(wait=False)


def test_create_with_llm_file_overrides_applied(monkeypatch):
    code_server = _make_code_server()
    db = FakeDB(code_server)
    fake_k8s = FakeK8s()
    fake_cc = FakeConfigCenter(
        {
            "provider-a": {
                "provider_key": "provider-a",
                "display_name": "Provider A",
                "provider_type": "openai-compatible",
                "model": "a-model",
                "api_base": "https://a.example.com",
                "env_bindings": {},
                "file_bindings": [
                    {"name": "a.cfg", "path": "/etc/llm/agent.yaml", "content": "from: A", "enabled": True},
                    {"name": "b.cfg", "path": "/etc/llm/extra.json", "content": "{\"from\": \"A\"}", "enabled": True},
                ],
            }
        }
    )
    monkeypatch.setattr("app.services.task_manager.get_k8s_service", lambda: fake_k8s)
    monkeypatch.setattr("app.services.task_manager.get_configcenter_client", lambda: fake_cc)

    manager = TaskManager()
    task = SimpleNamespace(
        project_id="p1",
        params={
            "code_server_id": "cs-1",
            "namespace": "secflow-p1",
            "name": "audit-env",
            "env": {},
            "code_server_env": {},
            "image": "",
            "llm_provider_keys": ["provider-a"],
            "llm_file_overrides": [
                {"path": "/etc/llm/agent.yaml", "content": "from: user-override"},
                {"path": "/etc/llm/not-exists.yaml", "content": "ignored"},
            ],
        },
    )

    manager._handle_create_task(task, db)

    assert fake_k8s.created_configmap["data"] == {
        "file-1": "from: user-override",
        "file-2": "{\"from\": \"A\"}",
    }
    assert [item["content"] for item in code_server.llm_file_bindings] == ["from: user-override", "{\"from\": \"A\"}"]

    manager.executor.shutdown(wait=False)


def test_create_passes_unified_env(monkeypatch):
    code_server = _make_code_server()
    db = FakeDB(code_server)
    fake_k8s = FakeK8s()

    monkeypatch.setattr("app.services.task_manager.get_k8s_service", lambda: fake_k8s)
    monkeypatch.setattr("app.services.task_manager.get_configcenter_client", lambda: FakeConfigCenter({}))

    manager = TaskManager()
    task = SimpleNamespace(
        project_id="p1",
        params={
            "code_server_id": "cs-1",
            "namespace": "secflow-p1",
            "name": "audit-env",
            "env": {"A": "1", "B": "2"},
            "code_server_env": {},
            "image": "",
            "llm_provider_keys": [],
        },
    )

    manager._handle_create_task(task, db)

    assert fake_k8s.deployment_call["preset_env"] == {}
    assert fake_k8s.deployment_call["custom_env"]["A"] == "1"
    assert fake_k8s.deployment_call["custom_env"]["B"] == "2"

    manager.executor.shutdown(wait=False)


def test_create_sanitizes_k8s_resource_names(monkeypatch):
    code_server = _make_code_server()
    db = FakeDB(code_server)
    fake_k8s = FakeK8s()

    monkeypatch.setattr("app.services.task_manager.get_k8s_service", lambda: fake_k8s)
    monkeypatch.setattr("app.services.task_manager.get_configcenter_client", lambda: FakeConfigCenter({}))

    manager = TaskManager()
    task = SimpleNamespace(
        project_id="p1",
        params={
            "code_server_id": "cs-ABC12345",
            "namespace": "secflow-p1",
            "name": "NE",
            "env": {},
            "code_server_env": {},
            "image": "",
            "llm_provider_keys": [],
        },
    )

    manager._handle_create_task(task, db)

    assert code_server.deployment_name == "code-server-ne-csabc1"
    assert code_server.service_name == "code-server-ne-csabc1"
    assert code_server.ingress_name == "code-server-ne-csabc1"
    assert fake_k8s.deployment_call["name"] == "code-server-ne-csabc1"

    manager.executor.shutdown(wait=False)


def test_create_uses_random_ingress_host(monkeypatch):
    code_server = _make_code_server()
    db = FakeDB(code_server)
    fake_k8s = FakeK8s()

    monkeypatch.setattr("app.services.task_manager.get_k8s_service", lambda: fake_k8s)
    monkeypatch.setattr("app.services.task_manager.get_configcenter_client", lambda: FakeConfigCenter({}))
    monkeypatch.setattr("app.services.task_manager.generate_id", lambda: "abcdef1234567890")

    manager = TaskManager()
    task = SimpleNamespace(
        project_id="p1",
        params={
            "code_server_id": "cs-ABC12345",
            "namespace": "secflow-p1",
            "name": "NE",
            "env": {},
            "code_server_env": {},
            "image": "",
            "llm_provider_keys": [],
        },
    )

    manager._handle_create_task(task, db)

    assert fake_k8s.ingress_call is not None
    assert fake_k8s.ingress_call["host"] == "cs-abcdef12-p1.code-server.sothothv2.com"

    manager.executor.shutdown(wait=False)
