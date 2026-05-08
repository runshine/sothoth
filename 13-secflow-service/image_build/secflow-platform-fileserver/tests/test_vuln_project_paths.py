import io
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.api import files as files_api  # noqa: E402
from app.api.files import router  # noqa: E402
from app.config import (  # noqa: E402
    AppConfig,
    AuthServiceConfig,
    Config,
    DatabaseConfig,
    LoggingConfig,
    ProjectServiceConfig,
    RegistryConfig,
    StorageConfig,
    _config,
)
from app.exception import setup_exception_handlers  # noqa: E402
from app.model import Base, get_db  # noqa: E402


def build_test_app():
    app = FastAPI()
    setup_exception_handlers(app)
    app.include_router(router)
    return app


def test_vuln_project_path_workflow(tmp_path, monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    config = Config(
        database=DatabaseConfig(host="localhost", port=3306, username="u", password="p", name="db"),
        auth_service=AuthServiceConfig(host="localhost", port=8080, service_machine_token="token"),
        project_service=ProjectServiceConfig(host="localhost", port=8081),
        registry=RegistryConfig(
            menu_service_url="http://menu",
            service_id="secflow-platform-fileserver",
            service_name="SecFlow Fileserver",
            description="test",
            api_prefix="/api/fileserver",
            port=80,
        ),
        storage=StorageConfig(root_dir=str(tmp_path / "data"), temp_dir=str(tmp_path / "tmp")),
        app=AppConfig(),
        logging=LoggingConfig(),
    )
    monkeypatch.setattr("app.config._config", config)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    async def override_get_current_user():
        return files_api.TokenUser(id=1, username="tester", role=["admin"])

    async def override_project_access(project_id: str, authorization: str | None):
        return {"id": project_id, "name": "demo"}

    app = build_test_app()
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[files_api.get_current_user] = override_get_current_user
    monkeypatch.setattr(files_api, "verify_project_access", override_project_access)

    with TestClient(app) as client:
        headers = {"Authorization": "Bearer fake-token"}
        children_resp = client.get(
            "/api/fileserver/vuln/project-path/children",
            params={"project_id": "demo-project", "path": "/__vuln_cases__/case-001"},
            headers=headers,
        )
        assert children_resp.status_code == 200
        assert children_resp.json()["root_path"] == "/__vuln_cases__/case-001"
        assert children_resp.json()["special_subproject_name"] == "__vuln_cases__"

        mkdir_resp = client.post(
            "/api/fileserver/vuln/project-path/directories",
            json={"project_id": "demo-project", "path": "/__vuln_cases__/case-001/evidence/logs"},
            headers=headers,
        )
        assert mkdir_resp.status_code == 200
        assert mkdir_resp.json()["path"] == "/__vuln_cases__/case-001/evidence/logs"

        upload_resp = client.post(
            "/api/fileserver/vuln/project-path/files/upload",
            data={"project_id": "demo-project", "path": "/__vuln_cases__/case-001/evidence/logs/report.txt"},
            files={"file": ("report.txt", io.BytesIO(b"hello vuln"), "text/plain")},
            headers=headers,
        )
        assert upload_resp.status_code == 200
        uploaded = upload_resp.json()
        assert uploaded["path"] == "/__vuln_cases__/case-001/evidence/logs/report.txt"

        list_resp = client.get(
            "/api/fileserver/vuln/project-path/children",
            params={"project_id": "demo-project", "path": "/__vuln_cases__/case-001/evidence/logs"},
            headers=headers,
        )
        assert list_resp.status_code == 200
        assert list_resp.json()["files"][0]["filename"] == "report.txt"

        explorer_resp = client.get(
            "/api/fileserver/explorer/root",
            params={"project_id": "demo-project"},
            headers=headers,
        )
        assert explorer_resp.status_code == 200
        assert any(item["name"] == "__vuln_cases__" for item in explorer_resp.json()["items"])

        delete_file_resp = client.delete(
            "/api/fileserver/vuln/project-path/object",
            params={"project_id": "demo-project", "path": "/__vuln_cases__/case-001/evidence/logs/report.txt"},
            headers=headers,
        )
        assert delete_file_resp.status_code == 200
        assert delete_file_resp.json()["entry_type"] == "file"

        invalid_resp = client.get(
            "/api/fileserver/vuln/project-path/children",
            params={"project_id": "demo-project", "path": "/outside/case-001"},
            headers=headers,
        )
        assert invalid_resp.status_code == 400
