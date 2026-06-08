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
    monkeypatch.setattr(files_api, "get_db_session", testing_session_local)

    return TestClient(app)


def test_project_filesystem_upload_conflict_and_overwrite(tmp_path, monkeypatch):
    with build_client(tmp_path, monkeypatch) as client:
        headers = {"Authorization": "Bearer fake-token"}

        create_dir = client.post(
            "/api/fileserver/project-filesystem/directories",
            json={"project_id": "demo-project", "path": "/docs"},
            headers=headers,
        )
        assert create_dir.status_code == 200

        first_upload = client.post(
            "/api/fileserver/project-filesystem/files/upload",
            data={"project_id": "demo-project", "path": "/docs"},
            files={"file": ("report.txt", io.BytesIO(b"version-one"), "text/plain")},
            headers=headers,
        )
        assert first_upload.status_code == 200
        assert first_upload.json()["path"] == "/docs/report.txt"

        conflict_upload = client.post(
            "/api/fileserver/project-filesystem/files/upload",
            data={"project_id": "demo-project", "path": "/docs"},
            files={"file": ("report.txt", io.BytesIO(b"version-two"), "text/plain")},
            headers=headers,
        )
        assert conflict_upload.status_code == 409

        overwrite_upload = client.post(
            "/api/fileserver/project-filesystem/files/upload",
            data={"project_id": "demo-project", "path": "/docs", "overwrite": "true"},
            files={"file": ("report.txt", io.BytesIO(b"version-two"), "text/plain")},
            headers=headers,
        )
        assert overwrite_upload.status_code == 200
        assert overwrite_upload.json()["path"] == "/docs/report.txt"
        assert overwrite_upload.json()["size"] == len(b"version-two")

        preview_resp = client.get(
            "/api/fileserver/project-filesystem/preview",
            params={"project_id": "demo-project", "path": "/docs/report.txt"},
            headers=headers,
        )
        assert preview_resp.status_code == 200
        assert preview_resp.content == b"version-two"


def test_project_filesystem_upload_accepts_project_absolute_path(tmp_path, monkeypatch):
    with build_client(tmp_path, monkeypatch) as client:
        headers = {"Authorization": "Bearer fake-token"}
        project_root = tmp_path / "data" / "files" / "demo-project"
        absolute_dir = project_root / "app" / "secflow-app-binary-security" / "task-1" / "run" / "upload-tmp"

        current = project_root
        for part in absolute_dir.relative_to(project_root).parts:
            current = current / part
            create_dir = client.post(
                "/api/fileserver/project-filesystem/directories",
                json={"project_id": "demo-project", "path": str(current)},
                headers=headers,
            )
            assert create_dir.status_code in (200, 409)

        upload_resp = client.post(
            "/api/fileserver/project-filesystem/files/upload",
            data={"project_id": "demo-project", "path": str(absolute_dir)},
            files={"file": ("source.zip", io.BytesIO(b"zip"), "application/zip")},
            headers=headers,
        )
        assert upload_resp.status_code == 200
        assert upload_resp.json()["path"] == "/app/secflow-app-binary-security/task-1/run/upload-tmp/source.zip"
        assert (absolute_dir / "source.zip").read_bytes() == b"zip"


def test_project_filesystem_rejects_other_project_absolute_path(tmp_path, monkeypatch):
    with build_client(tmp_path, monkeypatch) as client:
        headers = {"Authorization": "Bearer fake-token"}
        other_project_dir = tmp_path / "data" / "files" / "other-project" / "app"

        create_dir = client.post(
            "/api/fileserver/project-filesystem/directories",
            json={"project_id": "demo-project", "path": str(other_project_dir)},
            headers=headers,
        )
        assert create_dir.status_code == 400


def test_project_filesystem_upload_rejects_directory_overwrite(tmp_path, monkeypatch):
    with build_client(tmp_path, monkeypatch) as client:
        headers = {"Authorization": "Bearer fake-token"}

        create_parent_dir = client.post(
            "/api/fileserver/project-filesystem/directories",
            json={"project_id": "demo-project", "path": "/docs"},
            headers=headers,
        )
        assert create_parent_dir.status_code == 200

        create_dir = client.post(
            "/api/fileserver/project-filesystem/directories",
            json={"project_id": "demo-project", "path": "/docs/report.txt"},
            headers=headers,
        )
        assert create_dir.status_code == 200

        upload_resp = client.post(
            "/api/fileserver/project-filesystem/files/upload",
            data={"project_id": "demo-project", "path": "/docs", "overwrite": "true"},
            files={"file": ("report.txt", io.BytesIO(b"payload"), "text/plain")},
            headers=headers,
        )
        assert upload_resp.status_code == 409
        assert "目录" in str(upload_resp.json())
