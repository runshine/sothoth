import io
import sys
import time
import zipfile
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
)
from app.exception import setup_exception_handlers  # noqa: E402
from app.model import Base, get_db  # noqa: E402


def build_test_app():
    app = FastAPI()
    setup_exception_handlers(app)
    app.include_router(router)
    return app


def build_client(tmp_path, monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)
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
        db = testing_session_local()
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
    monkeypatch.setattr(files_api, "verify_project_access_by_token", override_project_access)
    return TestClient(app)


def _wait_task_done(client: TestClient, task_id: str, headers: dict) -> dict:
    for _ in range(40):
        response = client.get(f"/api/fileserver/tasks/{task_id}", headers=headers)
        assert response.status_code == 200
        payload = response.json()
        if payload["status"] in {"succeeded", "failed"}:
            return payload
        time.sleep(0.05)
    raise AssertionError("task timeout")


def test_project_filesystem_archive_task(tmp_path, monkeypatch):
    with build_client(tmp_path, monkeypatch) as client:
        headers = {"Authorization": "Bearer fake-token"}
        assert client.post(
            "/api/fileserver/project-filesystem/directories",
            json={"project_id": "demo-project", "path": "/docs"},
            headers=headers,
        ).status_code == 200
        assert client.post(
            "/api/fileserver/project-filesystem/files/upload",
            data={"project_id": "demo-project", "path": "/docs"},
            files={"file": ("a.txt", io.BytesIO(b"hello"), "text/plain")},
            headers=headers,
        ).status_code == 200

        submit = client.post(
            "/api/fileserver/project-filesystem/archive-tasks",
            json={"project_id": "demo-project", "items": ["/docs"]},
            headers=headers,
        )
        assert submit.status_code == 200
        task_id = submit.json()["task_id"]
        done = _wait_task_done(client, task_id, headers)
        assert done["status"] == "succeeded"
        assert done["task_type"] == "archive_download"

        dl = client.get(f"/api/fileserver/archive-tasks/{task_id}/download", headers=headers)
        assert dl.status_code == 200
        archive_file = tmp_path / "archive.zip"
        archive_file.write_bytes(dl.content)
        with zipfile.ZipFile(archive_file, "r") as zf:
            names = set(zf.namelist())
            assert "docs/a.txt" in names


def test_vuln_project_path_archive_task(tmp_path, monkeypatch):
    with build_client(tmp_path, monkeypatch) as client:
        headers = {"Authorization": "Bearer fake-token"}
        assert client.post(
            "/api/fileserver/vuln/project-path/files/upload",
            data={"project_id": "demo-project", "path": "/__vuln_cases__/case-1/evidence/raw.txt"},
            files={"file": ("raw.txt", io.BytesIO(b"raw"), "text/plain")},
            headers=headers,
        ).status_code == 200

        submit = client.post(
            "/api/fileserver/vuln/project-path/archive-tasks",
            json={"project_id": "demo-project", "items": ["/__vuln_cases__/case-1"]},
            headers=headers,
        )
        assert submit.status_code == 200
        task_id = submit.json()["task_id"]
        done = _wait_task_done(client, task_id, headers)
        assert done["status"] == "succeeded"

        dl = client.get(f"/api/fileserver/archive-tasks/{task_id}/download", headers=headers)
        assert dl.status_code == 200
        archive_file = tmp_path / "archive-vuln.zip"
        archive_file.write_bytes(dl.content)
        with zipfile.ZipFile(archive_file, "r") as zf:
            names = set(zf.namelist())
            assert "__vuln_cases__/case-1/evidence/raw.txt" in names
