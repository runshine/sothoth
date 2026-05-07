from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent
if str(FRAMEWORK_ROOT) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK_ROOT))

from app.config import reset_config
from app.models.database import init_database, reset_database_state
from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import FrameworkConfig
from tests.mock_agent_runtime import MockAgentRuntime


@pytest.fixture()
def framework_root() -> Path:
    return FRAMEWORK_ROOT


@pytest.fixture()
def framework_config_payload(framework_root: Path) -> dict:
    return json.loads((framework_root / "config.json").read_text(encoding="utf-8"))


@pytest.fixture()
def framework_config(framework_config_payload: dict) -> FrameworkConfig:
    return FrameworkConfig.model_validate(framework_config_payload)


@pytest.fixture()
def patch_mock_agent_runtime(monkeypatch: pytest.MonkeyPatch):
    original = dict(AgentRuntimeRegistry.RUNTIME_MAP)
    for runtime_name in ("claude_code", "codex", "opencode", "pi_agent"):
        monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, runtime_name, MockAgentRuntime)
    yield
    AgentRuntimeRegistry.RUNTIME_MAP.clear()
    AgentRuntimeRegistry.RUNTIME_MAP.update(original)


@pytest.fixture()
def service_config_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    config_path = tmp_path / "config.yaml"
    config_payload = {
        "app": {"host": "127.0.0.1", "port": 18080, "debug": False},
        "database": {"url": f"sqlite:///{tmp_path / 'service.db'}", "table_prefix": "test_dataflow_"},
        "auth_service": {"enabled": False},
        "project_service": {"enabled": False},
        "fileserver_service": {
            "enabled": False,
            "data_mount_path": str(tmp_path / "data"),
            "project_files_dirname": "files",
            "dataflow_subproject_name": "DATAFLOW_VULN_SCANNER",
        },
        "registry": {"enabled": False},
        "service": {"workspace_base_dir": str(tmp_path / "workspace")},
        "scheduler": {
            "enabled": False,
            "pod_id": "test-pod",
            "host_name": "test-host",
            "worker_capacity": 2,
            "poll_interval_seconds": 1,
            "heartbeat_interval_seconds": 1,
            "worker_timeout_seconds": 2,
            "lease_duration_seconds": 5,
            "cleanup_interval_seconds": 1,
        },
    }
    config_path.write_text(yaml.safe_dump(config_payload, allow_unicode=True), encoding="utf-8")
    monkeypatch.setenv("CONFIG_PATH", str(config_path))
    monkeypatch.setenv("SECFLOW_DATAFLOW_CLI_IN_PROCESS", "1")
    reset_config()
    reset_database_state()
    from app.services import auth, execution_service, fileserver_client, project, scheduler, workflow_service

    auth._auth_service = None
    execution_service._execution_service = None
    fileserver_client._fileserver_client = None
    project._project_service = None
    scheduler._scheduler_service = None
    workflow_service._workflow_service = None
    init_database()
    yield config_path
    reset_config()
    reset_database_state()
    auth._auth_service = None
    execution_service._execution_service = None
    fileserver_client._fileserver_client = None
    project._project_service = None
    scheduler._scheduler_service = None
    workflow_service._workflow_service = None
