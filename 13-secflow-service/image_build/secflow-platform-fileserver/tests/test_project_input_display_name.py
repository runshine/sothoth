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
from app.config import AppConfig, AuthServiceConfig, Config, DatabaseConfig, LoggingConfig, ProjectServiceConfig, RegistryConfig, StorageConfig  # noqa: E402
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
    monkeypatch.setattr(files_api, "get_db_session", testing_session_local)
    return TestClient(app)


def _wait_upload_done(client: TestClient, upload_id: str, headers: dict) -> dict:
    for _ in range(60):
        response = client.get(f"/api/fileserver/project-input/uploads/{upload_id}", headers=headers)
        assert response.status_code == 200
        payload = response.json()
        if payload["status"] in {"succeeded", "partial_failed", "failed"}:
            return payload
        time.sleep(0.05)
    raise AssertionError("upload timeout")


def _zip_bytes() -> io.BytesIO:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("demo.txt", "hello")
    buffer.seek(0)
    return buffer


def _raw_bytes() -> io.BytesIO:
    return io.BytesIO(b"raw-input-data")


def test_update_project_input_upload_display_name(tmp_path, monkeypatch):
    with build_client(tmp_path, monkeypatch) as client:
        headers = {"Authorization": "Bearer fake-token"}
        response = client.post(
            "/api/fileserver/project-input/uploads",
            headers=headers,
            data={"project_id": "demo-project", "input_type": "software", "keep_original": "false"},
            files={"files": ("demo.zip", _zip_bytes(), "application/zip")},
        )
        assert response.status_code == 200
        upload_id = response.json()["upload_id"]
        _wait_upload_done(client, upload_id, headers)

        renamed = client.post(
            f"/api/fileserver/project-input/uploads/{upload_id}/display-name",
            headers=headers,
            json={"project_id": "demo-project", "display_name": "测试上传记录"},
        )
        assert renamed.status_code == 200
        payload = renamed.json()
        assert payload["display_name"] == "测试上传记录"

        detail = client.get(f"/api/fileserver/project-input/uploads/{upload_id}", headers=headers)
        assert detail.status_code == 200
        assert detail.json()["display_name"] == "测试上传记录"

        listing = client.get("/api/fileserver/project-input/uploads?project_id=demo-project", headers=headers)
        assert listing.status_code == 200
        assert listing.json()["items"][0]["display_name"] == "测试上传记录"


def test_update_project_input_upload_display_name_rejects_blank(tmp_path, monkeypatch):
    with build_client(tmp_path, monkeypatch) as client:
        headers = {"Authorization": "Bearer fake-token"}
        response = client.post(
            "/api/fileserver/project-input/uploads",
            headers=headers,
            data={"project_id": "demo-project", "input_type": "software", "keep_original": "false"},
            files={"files": ("demo.zip", _zip_bytes(), "application/zip")},
        )
        assert response.status_code == 200
        upload_id = response.json()["upload_id"]

        renamed = client.post(
            f"/api/fileserver/project-input/uploads/{upload_id}/display-name",
            headers=headers,
            json={"project_id": "demo-project", "display_name": "   "},
        )
        assert renamed.status_code == 400
        payload = renamed.json()
        assert "上传记录名称不能为空" in str(payload.get("detail") or payload.get("message") or payload)


def test_project_input_upload_allows_raw_file_when_keep_original_enabled(tmp_path, monkeypatch):
    with build_client(tmp_path, monkeypatch) as client:
        headers = {"Authorization": "Bearer fake-token"}
        response = client.post(
            "/api/fileserver/project-input/uploads",
            headers=headers,
            data={"project_id": "demo-project", "input_type": "software", "keep_original": "true"},
            files={"files": ("demo.bin", _raw_bytes(), "application/octet-stream")},
        )
        assert response.status_code == 200
        upload_id = response.json()["upload_id"]
        detail = _wait_upload_done(client, upload_id, headers)
        assert detail["status"] == "succeeded"

        upload_detail = client.get(f"/api/fileserver/project-input/uploads/{upload_id}", headers=headers)
        assert upload_detail.status_code == 200
        payload = upload_detail.json()
        assert payload["keep_original"] is True
        assert payload["stored_file_count"] == 1
