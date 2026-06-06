from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app.config import _config
from app.main import app
from app.model import Base, get_db, get_engine


@pytest.fixture(autouse=True)
def reset_config_and_db(monkeypatch):
    global _config
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    monkeypatch.setenv("CONFIG_PATH", "")
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    from app import config as config_module
    from app import model as model_module
    from app.service import auth as auth_module
    from app.service import project as project_module
    from app.service import litellm as litellm_module
    from app.service import schedule_manager as schedule_module
    from app.service import registry as registry_module
    from app import main as main_module

    config_module._config = None
    model_module._engine = None
    model_module._SessionFactory = None
    auth_module._auth_service = None
    project_module._project_service = None
    litellm_module._virtual_key_manager = None
    schedule_module._schedule_manager = None
    schedule_module._scheduler_runtime = None
    registry_module._registry_service = None

    cfg = config_module.load_config()
    cfg.database.url = f"sqlite:///{db_path}"
    cfg.auth_service.service_machine_token = "machine-token"
    cfg.registry.enabled = False
    cfg.scheduler.enabled = False
    monkeypatch.setattr(main_module, "verify_auth_service_or_exit", lambda: None)
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    os.remove(db_path)


@pytest.fixture
def db_session():
    from app.model import get_db_session

    session = get_db_session()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    def override_get_db():
        from app.model import get_db_session

        db = get_db_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
