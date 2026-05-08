import json
import os
import sys
import time
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
from app.exception import ForbiddenError, setup_exception_handlers  # noqa: E402
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

    async def override_project_access(project_id: str, authorization: str | None):
        return {"id": project_id, "name": "demo"}

    async def override_project_access_by_token(project_id: str, token: str):
        if token != "ok-token":
            raise ForbiddenError("invalid")
        return {"id": project_id, "name": "demo"}

    app = build_test_app()
    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr(files_api, "verify_project_access", override_project_access)
    monkeypatch.setattr(files_api, "verify_project_access_by_token", override_project_access_by_token)
    return TestClient(app), config


def test_ws_watch_line_delta_and_delete_event(tmp_path, monkeypatch):
    client, config = build_client(tmp_path, monkeypatch)
    project_id = "demo-project"
    target_file = Path(config.storage.root_dir) / "files" / project_id / "logs" / "runtime.log"
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_text("line-1\n", encoding="utf-8")

    with client.websocket_connect(
        f"/api/fileserver/ws/watch?project_id={project_id}&path=/logs/runtime.log&path_mode=project_filesystem&read_mode=line&start_from=head&token=ok-token"
    ) as ws:
        snap = ws.receive_json()
        assert snap["type"] == "snapshot"
        assert snap["path"] == "/logs/runtime.log"
        assert snap["read_mode"] == "line"

        with target_file.open("a", encoding="utf-8") as fh:
            fh.write("line-2\n")

        got_delta = False
        for _ in range(10):
            msg = ws.receive_json()
            if msg["type"] == "delta" and msg["read_mode"] == "line":
                assert "line-2" in msg["lines"]
                got_delta = True
                break
        assert got_delta

        os.remove(target_file)
        got_deleted = False
        for _ in range(10):
            msg = ws.receive_json()
            if msg["type"] == "file_event" and msg["event"] == "deleted":
                got_deleted = True
                break
        assert got_deleted


def test_ws_watch_rejects_bad_token(tmp_path, monkeypatch):
    client, _ = build_client(tmp_path, monkeypatch)
    with client.websocket_connect(
        "/api/fileserver/ws/watch?project_id=demo-project&path=/logs/runtime.log&path_mode=project_filesystem&read_mode=line&token=bad-token"
    ) as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert "invalid" in json.dumps(msg, ensure_ascii=False)
