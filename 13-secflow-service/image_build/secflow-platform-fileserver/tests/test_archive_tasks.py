import io
import sys
import tarfile
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
    monkeypatch.setattr(files_api, "get_db_session", testing_session_local)
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


def _wait_upload_done(client: TestClient, upload_id: str, headers: dict) -> dict:
    for _ in range(60):
        response = client.get(f"/api/fileserver/project-input/uploads/{upload_id}", headers=headers)
        assert response.status_code == 200
        payload = response.json()
        if payload["status"] in {"succeeded", "partial_failed", "failed"}:
            return payload
        time.sleep(0.05)
    raise AssertionError("upload timeout")


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


def test_project_input_upload_extract_and_stats(tmp_path, monkeypatch):
    with build_client(tmp_path, monkeypatch) as client:
        headers = {"Authorization": "Bearer fake-token"}
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("src/main.c", b"int main(void){return 0;}")
            zf.writestr("../escape.txt", b"blocked")
        archive_buffer.seek(0)

        create = client.post(
            "/api/fileserver/project-input/uploads",
            data={"project_id": "demo-project", "input_type": "code", "keep_original": "false"},
            files=[("files", ("source.zip", archive_buffer, "application/zip"))],
            headers=headers,
        )
        assert create.status_code == 200
        payload = create.json()
        upload_id = payload["upload_id"]

        done = _wait_upload_done(client, upload_id, headers)
        assert done["status"] == "partial_failed"
        assert done["stored_file_count"] == 1
        assert done["latest_batch"]["submitted_file_count"] == 1
        assert "skip invalid path" in (done["last_error"] or "")

        list_resp = client.get(
            "/api/fileserver/project-input/uploads",
            params={"project_id": "demo-project", "input_type": "code"},
            headers=headers,
        )
        assert list_resp.status_code == 200
        assert list_resp.json()["total"] == 1

        stats_resp = client.get(
            "/api/fileserver/project-input/uploads/stats",
            params={"project_id": "demo-project", "input_type": "code"},
            headers=headers,
        )
        assert stats_resp.status_code == 200
        stats = stats_resp.json()
        assert stats["total_uploads"] == 1
        assert stats["partial_failed_uploads"] == 1
        assert stats["stored_file_count"] == 1

        fs_resp = client.get(
            "/api/fileserver/project-filesystem/children",
            params={"project_id": "demo-project", "path": f"/user_input/code/{upload_id}/src"},
            headers=headers,
        )
        assert fs_resp.status_code == 200
        assert fs_resp.json()["files"][0]["path"] == f"/user_input/code/{upload_id}/src/main.c"


def test_project_input_upload_keep_original_and_delete(tmp_path, monkeypatch):
    with build_client(tmp_path, monkeypatch) as client:
        headers = {"Authorization": "Bearer fake-token"}
        tar_path = tmp_path / "demo.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tf:
            data = b"payload"
            info = tarfile.TarInfo(name="docs/readme.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        with tar_path.open("rb") as fp:
            create = client.post(
                "/api/fileserver/project-input/uploads",
                data={"project_id": "demo-project", "input_type": "document", "keep_original": "true"},
                files=[("files", ("demo.tar.gz", fp, "application/gzip"))],
                headers=headers,
            )
        assert create.status_code == 200
        upload_id = create.json()["upload_id"]

        done = _wait_upload_done(client, upload_id, headers)
        assert done["status"] == "succeeded"
        assert done["stored_file_count"] == 1
        assert done["keep_original"] is True

        fs_resp = client.get(
            "/api/fileserver/project-filesystem/children",
            params={"project_id": "demo-project", "path": f"/user_input/document/{upload_id}"},
            headers=headers,
        )
        assert fs_resp.status_code == 200
        assert fs_resp.json()["files"][0]["name"] == "demo.tar.gz"

        delete_resp = client.request(
            "DELETE",
            "/api/fileserver/project-input/uploads",
            json={"project_id": "demo-project", "input_type": "document", "upload_ids": [upload_id]},
            headers=headers,
        )
        assert delete_resp.status_code == 200
        assert delete_resp.json()["deleted_ids"] == [upload_id]


def test_project_input_upload_overview_and_pagination(tmp_path, monkeypatch):
    with build_client(tmp_path, monkeypatch) as client:
        headers = {"Authorization": "Bearer fake-token"}
        for input_type, filename in [("code", "a.zip"), ("document", "b.zip"), ("software", "c.zip"), ("other", "d.zip")]:
            archive_buffer = io.BytesIO()
            with zipfile.ZipFile(archive_buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(f"{input_type}/readme.txt", f"{input_type}".encode("utf-8"))
            archive_buffer.seek(0)
            resp = client.post(
                "/api/fileserver/project-input/uploads",
                data={"project_id": "demo-project", "input_type": input_type, "keep_original": "false"},
                files=[("files", (filename, archive_buffer, "application/zip"))],
                headers=headers,
            )
            assert resp.status_code == 200
            _wait_upload_done(client, resp.json()["upload_id"], headers)

        overview = client.get(
            "/api/fileserver/project-input/uploads/overview",
            params={"project_id": "demo-project"},
            headers=headers,
        )
        assert overview.status_code == 200
        overview_payload = overview.json()
        assert overview_payload["project_id"] == "demo-project"
        assert len(overview_payload["categories"]) == 4
        assert {item["input_type"] for item in overview_payload["categories"]} == {"code", "document", "software", "other"}

        page1 = client.get(
            "/api/fileserver/project-input/uploads",
            params={"project_id": "demo-project", "page": 1, "page_size": 2},
            headers=headers,
        )
        assert page1.status_code == 200
        assert page1.json()["page"] == 1
        assert page1.json()["page_size"] == 2
        assert page1.json()["total"] == 4
        assert len(page1.json()["items"]) == 2
