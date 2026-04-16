import os
import re
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
from app.api import public as public_api  # noqa: E402
from app.models.database import Base, get_db  # noqa: E402


def make_suspicion_payload(**overrides):
    payload = {
        "project_id": "demo-project",
        "report_id": "demo-report-001",
        "title": "Demo suspicion",
        "summary": "summary",
        "severity": "medium",
        "cvss_score": 5.0,
        "confidence": 60,
        "state": "suspected",
        "category": "generic_issue",
        "rule_id": "RULE-001",
        "rule_name": "Generic Rule",
        "fingerprint": "fp-demo-001",
        "reporter": {
            "name": "manual-console",
            "version": "1.0.0",
            "type": "human",
        },
        "subject": {
            "type": "service",
            "locator": "svc://demo",
            "name": "demo-service",
        },
        "evidence": {
            "summary": "summary",
            "reproduction_hint": "check manually",
            "references": [],
        },
        "artifacts": [],
        "metadata": {},
    }
    payload.update(overrides)
    return payload


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
    original_public_project_access = public_api.ensure_project_access
    cases_api.ensure_project_access = override_project_access
    actions_api.ensure_project_access = override_project_access
    public_api.ensure_project_access = override_project_access

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
    cases_api.ensure_project_access = original_ensure_project_access
    actions_api.ensure_project_access = original_actions_project_access
    public_api.ensure_project_access = original_public_project_access


def test_health(client: TestClient):
    response = client.get("/api/vuln/health")
    assert response.status_code == 200
    assert response.json()["service"] == "secflow-platform-vuln"


def test_public_intake_catalog_downloads_and_examples(client: TestClient):
    catalog = client.get("/api/vuln/public/intake/catalog")
    assert catalog.status_code == 200
    payload = catalog.json()
    assert payload["version"] == "2.1.0"
    assert len(payload["items"]) == 4

    cli_download = client.get("/api/vuln/public/intake/sdk/cli")
    assert cli_download.status_code == 200
    assert cli_download.headers["content-type"].startswith("application/zip")

    plugin_download = client.get("/api/vuln/public/intake/sdk/plugin")
    assert plugin_download.status_code == 200
    assert plugin_download.headers["content-type"].startswith("application/zip")

    skill_download = client.get("/api/vuln/public/intake/sdk/skill")
    assert skill_download.status_code == 200
    assert skill_download.headers["content-type"].startswith("application/zip")

    openapi_spec = client.get("/api/vuln/public/intake/spec/openapi")
    assert openapi_spec.status_code == 200
    assert openapi_spec.headers["content-type"].startswith("application/json")

    for kind in ("cli", "plugin", "skill", "openapi"):
        example = client.get(f"/api/vuln/public/intake/examples/{kind}")
        assert example.status_code == 200


def test_public_authenticated_submission_creates_case(client: TestClient):
    response = client.post(
        "/api/vuln/public/intake/submissions",
        json=make_suspicion_payload(
            title="Authenticated submission",
            summary="created through public intake",
            severity="high",
            cvss_score=8.1,
            confidence=77,
            reporter={"name": "public-ci", "version": "2.3.0", "type": "cli"},
            subject={"type": "http_endpoint", "locator": "/auth/login", "name": "login"},
            metadata={"source": {"source_service": "public-cli"}, "tool_output": {"trace_id": "anon-001"}},
            artifacts=[
                {
                    "kind": "text",
                    "name": "stdout.txt",
                    "content": "authenticated result",
                    "encoding": "utf-8",
                }
            ],
        ),
    )
    assert response.status_code == 200
    payload = response.json()
    assert re.match(r"^case-\d{8}-\d{6}-[0-9a-f]{10}$", payload["id"])
    assert payload["created_by_type"] == "human"
    assert payload["created_by"] == "tester"
    assert payload["project_id"] == "demo-project"
    assert payload["files_root_path"].startswith("/__vuln_cases__/")

    detail = client.get(f"/api/vuln/cases/{payload['id']}")
    assert detail.status_code == 200
    assert detail.json()["created_by_type"] == "human"
    assert detail.json()["reporter"]["name"] == "public-ci"
    assert detail.json()["subject"]["locator"] == "/auth/login"
    assert detail.json()["cvss_score"] == 8.1
    assert detail.json()["metadata"]["source"]["anonymous_submission"] is False
    assert detail.json()["files_root_path"] == f"/__vuln_cases__/{payload['id']}"
    assert detail.json()["fileserver_root"]["special_subproject_name"] == "__vuln_cases__"


def test_draft_case_creation_returns_fileserver_root(client: TestClient):
    response = client.post(
        "/api/vuln/cases/draft",
        json={
            "project_id": "demo-project",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert re.match(r"^case-\d{8}-\d{6}-[0-9a-f]{10}$", payload["id"])
    assert payload["project_id"] == "demo-project"
    assert payload["current_status"] == "intake_created"
    assert payload["files_root_path"] == f"/__vuln_cases__/{payload['id']}"
    assert payload["fileserver_root"]["root_name"] == payload["id"]
    assert payload["reporter"]["name"] == "tester"
    assert payload["subject"]["locator"] == "draft://demo-project"


def test_public_submission_and_private_routes_require_auth(client: TestClient):
    public_response = client.get("/api/vuln/public/intake/catalog")
    assert public_response.status_code == 200

    override = app.dependency_overrides.pop(get_current_subject)
    try:
        submission_response = client.post(
            "/api/vuln/public/intake/submissions",
            json=make_suspicion_payload(),
        )
        assert submission_response.status_code == 401
        private_response = client.get("/api/vuln/cases")
        assert private_response.status_code == 401
    finally:
        app.dependency_overrides[get_current_subject] = override


def test_suspicion_submission_requires_reporter_and_subject(client: TestClient):
    response = client.post(
        "/api/vuln/public/intake/submissions",
        json={
            "project_id": "demo-project",
            "title": "invalid submission",
        },
    )
    assert response.status_code == 422


def test_artifacts_and_metadata_round_trip(client: TestClient):
    response = client.post(
        "/api/vuln/cases",
        json=make_suspicion_payload(
            title="Artifact round trip case",
            reporter={"name": "artifact-tester", "version": "1.1.0", "type": "human"},
            subject={"type": "repo", "locator": "repo://demo/service", "name": "service"},
            artifacts=[
                {
                    "kind": "directory",
                    "name": "workspace",
                    "children": [
                        {
                            "kind": "file",
                            "name": "report.txt",
                            "path": "workspace/report.txt",
                            "content": "hello",
                            "encoding": "utf-8",
                        }
                    ],
                },
                {
                    "kind": "binary",
                    "name": "sample.bin",
                    "encoding": "base64",
                    "content": "AAEC",
                },
            ],
            metadata={
                "source": {"source_service": "artifact-suite"},
                "custom": {"note": "round-trip"},
            },
        ),
    )
    assert response.status_code == 200
    detail = client.get(f"/api/vuln/cases/{response.json()['id']}")
    assert detail.status_code == 200
    assert detail.json()["artifacts"][0]["children"][0]["path"] == "workspace/report.txt"
    assert detail.json()["artifacts"][1]["encoding"] == "base64"
    assert detail.json()["metadata"]["custom"]["note"] == "round-trip"


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
        "meta": {
            "module_role": "validator",
            "bind_stage": "validation",
        },
        "capabilities": [
            {
                "capability_code": "analysis-default",
                "action_type": "analysis",
                "priority": 100,
                "timeout_seconds": 300,
                "concurrency_limit": 2,
                "input_schema_meta": {},
                "output_schema_meta": {},
                "meta": {
                    "bind_stage": "triage",
                },
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
    assert detail.json()["meta"]["module_role"] == "validator"
    assert detail.json()["healthcheck_url"] == "http://analyzer/health"
    assert detail.json()["callback_mode"] == "push"
    assert detail.json()["capabilities"][0]["meta"]["bind_stage"] == "triage"

    heartbeat = client.post("/api/vuln/services/heartbeat/svc-analyzer-01")
    assert heartbeat.status_code == 200

    unregister = client.delete("/api/vuln/services/unregister/svc-analyzer-01")
    assert unregister.status_code == 200

    listed_after = client.get("/api/vuln/services")
    assert listed_after.status_code == 200
    assert listed_after.json()["total"] == 0


def test_create_case_and_timeline(client: TestClient):
    payload = make_suspicion_payload(
        title="Demo suspicion case",
        severity="high",
        cvss_score=7.5,
        confidence=80,
        reporter={"name": "manual-reviewer", "version": "1.0.0", "type": "human"},
        subject={"type": "http_endpoint", "locator": "/login", "name": "login"},
        metadata={"source": {"source_service": "manual"}},
    )
    response = client.post("/api/vuln/cases", json=payload)
    assert response.status_code == 200
    case_id = response.json()["id"]

    detail = client.get(f"/api/vuln/cases/{case_id}")
    assert detail.status_code == 200
    assert detail.json()["current_stage"] == "receive"
    assert detail.json()["reporter"]["name"] == "manual-reviewer"
    assert detail.json()["subject"]["locator"] == "/login"
    assert detail.json()["cvss_score"] == 7.5

    timeline = client.get(f"/api/vuln/cases/{case_id}/timeline")
    assert timeline.status_code == 200
    assert timeline.json()["total"] >= 2


def test_update_case_intake_partial_fields(client: TestClient):
    create_resp = client.post(
        "/api/vuln/cases",
        json=make_suspicion_payload(
            title="Before update",
            summary="before summary",
            reporter={"name": "before-reporter", "version": "1.0.0", "type": "human"},
            subject={"type": "service", "locator": "svc://before", "name": "before"},
            metadata={"source": {"source_service": "before-service"}},
        ),
    )
    assert create_resp.status_code == 200
    case_id = create_resp.json()["id"]
    old_root = create_resp.json()["files_root_path"]

    update_resp = client.patch(
        f"/api/vuln/cases/{case_id}",
        json={
            "title": "After update",
            "reporter": {"name": "after-reporter", "version": "2.0.0", "type": "api"},
            "subject": {"type": "http_endpoint", "locator": "/after", "name": "after-api"},
            "metadata": {"source": {"source_service": "after-service"}, "custom": {"tag": "updated"}},
            "artifacts": [{"kind": "text", "name": "note.txt", "content": "updated"}],
        },
    )
    assert update_resp.status_code == 200
    payload = update_resp.json()
    assert payload["title"] == "After update"
    assert payload["summary"] == "before summary"
    assert payload["reporter"]["name"] == "after-reporter"
    assert payload["subject"]["locator"] == "/after"
    assert payload["metadata"]["source"]["source_service"] == "after-service"
    assert payload["artifacts"][0]["name"] == "note.txt"
    assert payload["files_root_path"] == old_root

    timeline = client.get(f"/api/vuln/cases/{case_id}/timeline")
    assert timeline.status_code == 200
    assert any(
        item["payload"].get("event_type") == "case_intake_updated"
        for item in timeline.json()["items"]
        if item["item_type"] == "event"
    )


def test_update_case_intake_validation_error(client: TestClient):
    create_resp = client.post(
        "/api/vuln/cases",
        json=make_suspicion_payload(title="Needs valid title"),
    )
    assert create_resp.status_code == 200
    case_id = create_resp.json()["id"]

    update_resp = client.patch(
        f"/api/vuln/cases/{case_id}",
        json={"title": ""},
    )
    assert update_resp.status_code == 400


def test_delete_case_removes_suspicion(client: TestClient):
    create_resp = client.post(
        "/api/vuln/cases",
        json=make_suspicion_payload(
            title="Delete me",
            reporter={"name": "deleter", "version": "1.0.0", "type": "human"},
            subject={"type": "service", "locator": "svc://delete-me", "name": "delete-me"},
        ),
    )
    assert create_resp.status_code == 200
    case_id = create_resp.json()["id"]

    delete_resp = client.delete(f"/api/vuln/cases/{case_id}")
    assert delete_resp.status_code == 200
    assert delete_resp.json()["deleted_case_id"] == case_id

    detail_resp = client.get(f"/api/vuln/cases/{case_id}")
    assert detail_resp.status_code == 404


def test_mock_dispatch_and_callback(client: TestClient):
    case_resp = client.post(
        "/api/vuln/cases",
        json=make_suspicion_payload(title="Callback case"),
    )
    case_id = case_resp.json()["id"]
    transition_resp = client.post(
        f"/api/vuln/cases/{case_id}/stage-transition",
        json={"to_stage": "triage", "reason": "manual_enter_triage"},
    )
    assert transition_resp.status_code == 200

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
            "suggested_stage": "validation",
            "suggested_decision": "issue",
            "result_meta": {"ok": True},
            "raw_payload": {"trace": "demo"},
            "artifact_refs": [],
        },
    )
    assert callback_resp.status_code == 200

    detail = client.get(f"/api/vuln/cases/{case_id}")
    assert detail.status_code == 200
    assert detail.json()["decision_status"] == "issue"
    assert detail.json()["current_stage"] == "triage"
    assert detail.json()["current_status"] == "awaiting_manual_gate"

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
        },
    )
    assert service_resp.status_code == 200

    case_resp = client.post(
        "/api/vuln/cases",
        json=make_suspicion_payload(
            title="Ops case",
            summary="ops summary",
            severity="high",
            confidence=90,
            reporter={"name": "ops-console", "version": "1.0.0", "type": "human"},
            subject={"type": "service", "locator": "svc://demo", "name": "demo"},
            metadata={"source": {"source_service": "manual"}},
        ),
    )
    assert case_resp.status_code == 200
    case_id = case_resp.json()["id"]
    transition_to_triage = client.post(
        f"/api/vuln/cases/{case_id}/stage-transition",
        json={"to_stage": "triage", "reason": "manual_enter_triage"},
    )
    assert transition_to_triage.status_code == 200

    dispatch_resp = client.post(
        f"/api/vuln/cases/{case_id}/actions/dispatch",
        json={"action_type": "analysis"},
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
            "decision_status": "issue",
            "summary": "Human analyst confirmed",
        },
    )
    assert decision_resp.status_code == 200
    assert decision_resp.json()["case"]["decision_status"] == "issue"

    gate_resp = client.post(
        f"/api/vuln/cases/{case_id}/triage/gate",
        json={"triage_gate": "approved_to_validation", "summary": "manual gate approved"},
    )
    assert gate_resp.status_code == 200

    stage_resp = client.post(
        f"/api/vuln/cases/{case_id}/stage-transition",
        json={"to_stage": "validation", "reason": "manual_promote"},
    )
    assert stage_resp.status_code == 200
    assert stage_resp.json()["case"]["current_stage"] == "validation"

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
        json=make_suspicion_payload(title="Automation follow-up case"),
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
    assert detail.json()["current_status"] == "files_collecting"
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
        json=make_suspicion_payload(title="Low confidence follow-up case"),
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
    assert detail.json()["current_status"] == "files_collecting"
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
        json=make_suspicion_payload(
            title="Recommendation case",
            severity="high",
            confidence=80,
        ),
    )
    case_id = case_resp.json()["id"]
    transition_to_triage = client.post(
        f"/api/vuln/cases/{case_id}/stage-transition",
        json={"to_stage": "triage", "reason": "manual_enter_triage"},
    )
    assert transition_to_triage.status_code == 200

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


def test_finish_stage_requires_reason_and_blocks_orchestration(client: TestClient):
    case_resp = client.post(
        "/api/vuln/cases",
        json=make_suspicion_payload(title="Finish lifecycle case"),
    )
    assert case_resp.status_code == 200
    case_id = case_resp.json()["id"]

    transition_to_triage = client.post(
        f"/api/vuln/cases/{case_id}/stage-transition",
        json={"to_stage": "triage", "reason": "manual_enter_triage"},
    )
    assert transition_to_triage.status_code == 200

    missing_summary = client.post(
        f"/api/vuln/cases/{case_id}/finish",
        json={"finished_reason": "manual_terminated", "summary": ""},
    )
    assert missing_summary.status_code == 400

    finish_resp = client.post(
        f"/api/vuln/cases/{case_id}/finish",
        json={"finished_reason": "non_issue", "summary": "manual close in triage"},
    )
    assert finish_resp.status_code == 200
    assert finish_resp.json()["case"]["current_stage"] == "finished"
    assert finish_resp.json()["case"]["current_status"] == "finished"
    assert finish_resp.json()["case"]["finished_reason"] == "non_issue"

    detail_resp = client.get(f"/api/vuln/cases/{case_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["current_stage"] == "finished"
    assert detail_resp.json()["finished_reason"] == "non_issue"

    recommend_resp = client.get(f"/api/vuln/cases/{case_id}/recommended-actions")
    assert recommend_resp.status_code == 200
    assert recommend_resp.json()["total"] == 0

    dispatch_resp = client.post(
        f"/api/vuln/cases/{case_id}/actions/dispatch",
        json={"action_type": "analysis"},
    )
    assert dispatch_resp.status_code == 400

    orchestrate_resp = client.post(f"/api/vuln/cases/{case_id}/orchestrate/auto")
    assert orchestrate_resp.status_code == 400

    illegal_transition = client.post(
        f"/api/vuln/cases/{case_id}/stage-transition",
        json={"to_stage": "validation", "reason": "should_fail"},
    )
    assert illegal_transition.status_code == 400
