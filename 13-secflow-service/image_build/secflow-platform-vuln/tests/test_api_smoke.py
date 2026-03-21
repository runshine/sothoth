import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["SECFLOW_VULN_SKIP_STARTUP"] = "1"

from app.main import app  # noqa: E402
from app.api.dependencies import get_current_subject  # noqa: E402
from app.api import cases as cases_api  # noqa: E402
from app.models.database import Base, get_db  # noqa: E402


@pytest.fixture()
def client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    async def override_subject():
        return (
            {
                "id": 1,
                "username": "tester",
                "token_type": "human",
                "role": ["admin"],
            },
            "fake-token",
        )

    async def override_project_access(project_id: str, token: str):
        return {"id": project_id, "status": "active", "name": "demo-project"}

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_subject] = override_subject
    original_ensure_project_access = cases_api.ensure_project_access
    cases_api.ensure_project_access = override_project_access

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
    cases_api.ensure_project_access = original_ensure_project_access


def test_health(client: TestClient):
    response = client.get("/api/vuln/health")
    assert response.status_code == 200
    assert response.json()["service"] == "secflow-platform-vuln"


def test_register_service_and_list(client: TestClient):
    payload = {
        "service_id": "svc-analyzer-01",
        "service_name": "Analyzer",
        "service_type": "analyzer",
        "endpoint": "http://analyzer",
        "healthcheck_url": "http://analyzer/health",
        "callback_mode": "push",
        "auth_mode": "machine_token",
        "version": "1.0.0",
        "meta": {},
        "capabilities": [
            {
                "capability_code": "analysis-default",
                "action_type": "analysis",
                "priority": 100,
                "timeout_seconds": 300,
                "concurrency_limit": 2,
                "input_schema_meta": {},
                "output_schema_meta": {},
                "meta": {},
            }
        ],
    }
    response = client.post("/api/vuln/services/register", json=payload)
    assert response.status_code == 200
    listed = client.get("/api/vuln/services")
    assert listed.status_code == 200
    assert listed.json()["total"] == 1


def test_create_case_and_timeline(client: TestClient):
    payload = {
        "project_id": "demo-project",
        "title": "Demo vuln case",
        "summary": "summary",
        "severity": "high",
        "confidence": 80,
        "source_meta": {"source_service": "manual"},
        "target_meta": {"asset_type": "web", "asset_locator": "/login"},
        "display_meta": {"preferred_render_type": "generic"},
        "created_by_type": "human",
        "created_by": "tester",
    }
    response = client.post("/api/vuln/cases", json=payload)
    assert response.status_code == 200
    case_id = response.json()["id"]

    detail = client.get(f"/api/vuln/cases/{case_id}")
    assert detail.status_code == 200
    assert detail.json()["current_stage"] == "normalize"

    timeline = client.get(f"/api/vuln/cases/{case_id}/timeline")
    assert timeline.status_code == 200
    assert timeline.json()["total"] >= 2


def test_mock_dispatch_and_callback(client: TestClient):
    case_resp = client.post(
        "/api/vuln/cases",
        json={
            "project_id": "demo-project",
            "title": "Callback case",
            "summary": "summary",
            "severity": "medium",
            "confidence": 60,
            "source_meta": {},
            "target_meta": {},
            "display_meta": {},
            "created_by_type": "human",
            "created_by": "tester",
        },
    )
    case_id = case_resp.json()["id"]

    action_resp = client.post(f"/api/vuln/actions/mock-dispatch/{case_id}")
    assert action_resp.status_code == 200
    action_id = action_resp.json()["action_id"]

    callback_resp = client.post(
        f"/api/vuln/actions/{action_id}/callback",
        json={
            "source_service_id": "svc-analyzer-01",
            "result_type": "analysis",
            "status": "succeeded",
            "summary": "analysis completed",
            "confidence": 70,
            "suggested_stage": "verify",
            "suggested_decision": "suspected",
            "result_meta": {"ok": True},
            "raw_payload": {"trace": "demo"},
            "artifact_refs": [],
        },
    )
    assert callback_resp.status_code == 200

    detail = client.get(f"/api/vuln/cases/{case_id}")
    assert detail.status_code == 200
    assert detail.json()["decision_status"] == "suspected"
    assert detail.json()["current_stage"] == "verify"
