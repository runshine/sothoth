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
from app.api import actions as actions_api  # noqa: E402
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
    original_actions_project_access = actions_api.ensure_project_access
    cases_api.ensure_project_access = override_project_access
    actions_api.ensure_project_access = override_project_access

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
    cases_api.ensure_project_access = original_ensure_project_access
    actions_api.ensure_project_access = original_actions_project_access


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

    detail = client.get("/api/vuln/services/svc-analyzer-01")
    assert detail.status_code == 200
    assert detail.json()["service_id"] == "svc-analyzer-01"

    heartbeat = client.post("/api/vuln/services/heartbeat/svc-analyzer-01")
    assert heartbeat.status_code == 200

    unregister = client.delete("/api/vuln/services/unregister/svc-analyzer-01")
    assert unregister.status_code == 200

    listed_after = client.get("/api/vuln/services")
    assert listed_after.status_code == 200
    assert listed_after.json()["total"] == 0


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

    control_resp = client.post(
        f"/api/vuln/actions/{action_id}/control",
        json={"operation": "retry"},
    )
    assert control_resp.status_code == 200
    assert control_resp.json()["action"]["execution_status"] == "queued"

    cancel_resp = client.post(
        f"/api/vuln/actions/{action_id}/control",
        json={"operation": "cancel"},
    )
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["action"]["execution_status"] == "cancelled"


def test_dashboard_manual_task_and_decision_flow(client: TestClient):
    service_resp = client.post(
        "/api/vuln/services/register",
        json={
            "service_id": "svc-validator-01",
            "service_name": "Validator",
            "service_type": "validator",
            "endpoint": "http://validator",
            "healthcheck_url": "http://validator/health",
            "callback_mode": "push",
            "auth_mode": "machine_token",
            "version": "1.0.0",
            "meta": {},
            "capabilities": [
                {
                    "capability_code": "validation-default",
                    "action_type": "validation",
                    "priority": 100,
                    "timeout_seconds": 300,
                    "concurrency_limit": 2,
                    "input_schema_meta": {},
                    "output_schema_meta": {},
                    "meta": {},
                }
            ],
        },
    )
    assert service_resp.status_code == 200

    case_resp = client.post(
        "/api/vuln/cases",
        json={
            "project_id": "demo-project",
            "title": "Ops case",
            "summary": "ops summary",
            "severity": "high",
            "confidence": 90,
            "source_meta": {"source_service": "manual"},
            "target_meta": {"asset_type": "service", "asset_locator": "svc://demo"},
            "display_meta": {},
            "created_by_type": "human",
            "created_by": "tester",
        },
    )
    assert case_resp.status_code == 200
    case_id = case_resp.json()["id"]

    dispatch_resp = client.post(
        f"/api/vuln/cases/{case_id}/actions/dispatch",
        json={"action_type": "validation"},
    )
    assert dispatch_resp.status_code == 200
    assert dispatch_resp.json()["count"] == 1

    queue_resp = client.get(
        "/api/vuln/actions/ops/queue",
        params={"project_id": "demo-project", "execution_status": "queued"},
    )
    assert queue_resp.status_code == 200
    assert queue_resp.json()["total"] >= 1

    recommend_resp = client.get(f"/api/vuln/cases/{case_id}/recommended-actions")
    assert recommend_resp.status_code == 200
    assert recommend_resp.json()["total"] >= 1

    auto_resp = client.post(f"/api/vuln/cases/{case_id}/orchestrate/auto")
    assert auto_resp.status_code == 200

    task_resp = client.post(
        f"/api/vuln/cases/{case_id}/manual-tasks",
        json={
            "task_type": "manual_review",
            "title": "Review this case",
            "summary": "Need analyst confirmation",
            "assignee": "alice",
            "context": {"origin": "smoke-test"},
        },
    )
    assert task_resp.status_code == 200
    assert task_resp.json()["task"]["status"] == "open"
    task_id = task_resp.json()["task"]["id"]

    task_status_resp = client.post(
        f"/api/vuln/cases/{case_id}/manual-tasks/{task_id}/status",
        json={"status": "completed"},
    )
    assert task_status_resp.status_code == 200
    assert task_status_resp.json()["task"]["status"] == "completed"

    decision_resp = client.post(
        f"/api/vuln/cases/{case_id}/decisions",
        json={
            "decision_status": "confirmed",
            "summary": "Human analyst confirmed",
        },
    )
    assert decision_resp.status_code == 200
    assert decision_resp.json()["case"]["decision_status"] == "confirmed"

    stage_resp = client.post(
        f"/api/vuln/cases/{case_id}/stage-transition",
        json={"to_stage": "track", "reason": "manual_promote"},
    )
    assert stage_resp.status_code == 200
    assert stage_resp.json()["case"]["current_stage"] == "track"

    task_list = client.get("/api/vuln/cases/ops/manual-tasks", params={"project_id": "demo-project"})
    assert task_list.status_code == 200
    assert task_list.json()["total"] == 1

    overview = client.get("/api/vuln/cases/ops/dashboard/overview", params={"project_id": "demo-project"})
    assert overview.status_code == 200
    assert overview.json()["metrics"]["total_cases"] == 1
    assert overview.json()["metrics"]["manual_tasks_open"] == 0
    assert overview.json()["severity_counts"]["high"] == 1
    assert len(overview.json()["recent_trend"]) == 7


def test_failed_result_creates_automation_manual_task(client: TestClient):
    case_resp = client.post(
        "/api/vuln/cases",
        json={
            "project_id": "demo-project",
            "title": "Automation follow-up case",
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
            "source_service_id": "svc-validator-01",
            "result_type": "validation",
            "status": "failed",
            "summary": "validation engine crashed",
            "confidence": 20,
            "result_meta": {"phase": "replay"},
            "raw_payload": {},
            "artifact_refs": [],
        },
    )
    assert callback_resp.status_code == 200

    detail = client.get(f"/api/vuln/cases/{case_id}")
    assert detail.status_code == 200
    assert detail.json()["current_status"] == "waiting_manual"
    assert len(detail.json()["manual_tasks"]) == 1
    assert detail.json()["manual_tasks"][0]["task_type"] == "manual_validation"

    timeline = client.get(f"/api/vuln/cases/{case_id}/timeline")
    assert timeline.status_code == 200
    assert any(
        item["payload"].get("event_type") == "automation_rule_applied"
        for item in timeline.json()["items"]
        if item["item_type"] == "event"
    )


def test_low_confidence_success_creates_manual_review_task(client: TestClient):
    case_resp = client.post(
        "/api/vuln/cases",
        json={
            "project_id": "demo-project",
            "title": "Low confidence follow-up case",
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
            "summary": "analysis completed with weak confidence",
            "confidence": 30,
            "result_meta": {"phase": "analysis"},
            "raw_payload": {},
            "artifact_refs": [],
        },
    )
    assert callback_resp.status_code == 200

    detail = client.get(f"/api/vuln/cases/{case_id}")
    assert detail.status_code == 200
    assert detail.json()["current_status"] == "waiting_manual"
    assert len(detail.json()["manual_tasks"]) == 1
    assert detail.json()["manual_tasks"][0]["task_type"] == "manual_review"


def test_recommended_actions_marks_active_service_action_pair(client: TestClient):
    register_resp = client.post(
        "/api/vuln/services/register",
        json={
            "service_id": "svc-ai-01",
            "service_name": "AI Analyzer",
            "service_type": "analyzer",
            "endpoint": "http://ai-analyzer",
            "healthcheck_url": "http://ai-analyzer/health",
            "callback_mode": "push",
            "auth_mode": "machine_token",
            "version": "1.0.0",
            "meta": {},
            "capabilities": [
                {
                    "capability_code": "ai-analysis-default",
                    "action_type": "ai_analysis",
                    "priority": 10,
                    "timeout_seconds": 300,
                    "concurrency_limit": 2,
                    "input_schema_meta": {},
                    "output_schema_meta": {},
                    "meta": {},
                }
            ],
        },
    )
    assert register_resp.status_code == 200

    case_resp = client.post(
        "/api/vuln/cases",
        json={
            "project_id": "demo-project",
            "title": "Recommendation case",
            "summary": "summary",
            "severity": "high",
            "confidence": 80,
            "source_meta": {},
            "target_meta": {},
            "display_meta": {},
            "created_by_type": "human",
            "created_by": "tester",
        },
    )
    case_id = case_resp.json()["id"]

    dispatch_resp = client.post(
        f"/api/vuln/cases/{case_id}/actions/dispatch",
        json={"action_type": "ai_analysis", "service_id": "svc-ai-01"},
    )
    assert dispatch_resp.status_code == 200
    assert dispatch_resp.json()["count"] == 1

    recommended = client.get(f"/api/vuln/cases/{case_id}/recommended-actions")
    assert recommended.status_code == 200
    pairs = [
        item for item in recommended.json()["items"]
        if item["service_id"] == "svc-ai-01" and item["action_type"] == "ai_analysis"
    ]
    assert len(pairs) == 1
    assert pairs[0]["already_active"] is True
