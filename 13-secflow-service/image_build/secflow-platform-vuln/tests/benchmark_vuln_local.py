import asyncio
import json
import logging
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["SECFLOW_VULN_SKIP_STARTUP"] = "1"

from app.main import app  # noqa: E402
from app.api.dependencies import get_current_subject  # noqa: E402
from app.api import cases as cases_api  # noqa: E402
from app.api import actions as actions_api  # noqa: E402
from app.models.database import Base, get_db  # noqa: E402


logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


def _build_app_overrides():
    db_file = tempfile.NamedTemporaryFile(prefix="secflow-vuln-bench-", suffix=".db", delete=False)
    db_file.close()
    engine = create_engine(
        f"sqlite:///{db_file.name}",
        connect_args={"check_same_thread": False},
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    async def override_subject():
        return (
            {
                "id": 1,
                "username": "bench",
                "token_type": "human",
                "role": ["admin"],
            },
            "bench-token",
        )

    async def override_project_access(project_id: str, token: str):
        return {"id": project_id, "status": "active", "name": "bench-project"}

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_subject] = override_subject
    original_cases = cases_api.ensure_project_access
    original_actions = actions_api.ensure_project_access
    cases_api.ensure_project_access = override_project_access
    actions_api.ensure_project_access = override_project_access
    return engine, db_file.name, original_cases, original_actions


def _cleanup_app_overrides(engine, db_path: str, original_cases, original_actions):
    app.dependency_overrides.clear()
    cases_api.ensure_project_access = original_cases
    actions_api.ensure_project_access = original_actions
    engine.dispose()
    try:
        os.unlink(db_path)
    except FileNotFoundError:
        pass


async def _benchmark_requests(client: httpx.AsyncClient, name: str, total: int, concurrency: int, request_factory):
    latencies = []
    errors = []
    semaphore = asyncio.Semaphore(concurrency)

    async def runner(index: int):
        async with semaphore:
            started = time.perf_counter()
            try:
                response = await request_factory(index)
                if response.status_code >= 400:
                    errors.append({"index": index, "status_code": response.status_code, "body": response.text})
            except Exception as exc:  # noqa: BLE001
                errors.append({"index": index, "error": str(exc)})
            finally:
                latencies.append((time.perf_counter() - started) * 1000)

    started = time.perf_counter()
    await asyncio.gather(*(runner(index) for index in range(total)))
    elapsed = time.perf_counter() - started
    ordered = sorted(latencies)
    p95_index = max(0, min(len(ordered) - 1, int(len(ordered) * 0.95) - 1))
    return {
        "name": name,
        "total_requests": total,
        "concurrency": concurrency,
        "total_seconds": round(elapsed, 4),
        "throughput_rps": round(total / elapsed, 2) if elapsed else 0,
        "avg_ms": round(statistics.mean(latencies), 2) if latencies else 0,
        "p95_ms": round(ordered[p95_index], 2) if ordered else 0,
        "max_ms": round(max(ordered), 2) if ordered else 0,
        "errors": errors[:10],
        "error_count": len(errors),
    }


async def main():
    engine, db_path, original_cases, original_actions = _build_app_overrides()
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            register_resp = await client.post(
                "/api/vuln/services/register",
                json={
                    "service_id": "svc-bench-01",
                    "service_name": "Bench Analyzer",
                    "service_type": "analyzer",
                    "endpoint": "http://bench-analyzer",
                    "healthcheck_url": "http://bench-analyzer/health",
                    "callback_mode": "push",
                    "auth_mode": "machine_token",
                    "version": "1.0.0",
                    "meta": {},
                    "capabilities": [
                        {
                            "capability_code": "analysis-default",
                            "action_type": "analysis",
                            "priority": 50,
                            "timeout_seconds": 300,
                            "concurrency_limit": 5,
                            "input_schema_meta": {},
                            "output_schema_meta": {},
                            "meta": {},
                        },
                        {
                            "capability_code": "poc-default",
                            "action_type": "poc_generation",
                            "priority": 60,
                            "timeout_seconds": 300,
                            "concurrency_limit": 5,
                            "input_schema_meta": {},
                            "output_schema_meta": {},
                            "meta": {},
                        },
                    ],
                },
            )
            register_resp.raise_for_status()

            health_result = await _benchmark_requests(
                client,
                "health_read",
                total=100,
                concurrency=20,
                request_factory=lambda _: client.get("/api/vuln/health"),
            )

            create_result = await _benchmark_requests(
                client,
                "case_create",
                total=40,
                concurrency=5,
                request_factory=lambda index: client.post(
                    "/api/vuln/cases",
                    json={
                        "project_id": "bench-project",
                        "title": f"bench-case-{index}",
                        "summary": "benchmark",
                        "severity": "medium",
                        "confidence": 50,
                        "source_meta": {"source_service": "bench"},
                        "target_meta": {"asset_type": "web", "asset_locator": f"/bench/{index}"},
                        "display_meta": {},
                        "created_by_type": "human",
                        "created_by": "bench",
                    },
                ),
            )

            list_result = await _benchmark_requests(
                client,
                "case_list",
                total=60,
                concurrency=15,
                request_factory=lambda _: client.get("/api/vuln/cases", params={"project_id": "bench-project"}),
            )

            overview_result = await _benchmark_requests(
                client,
                "dashboard_overview",
                total=60,
                concurrency=15,
                request_factory=lambda _: client.get("/api/vuln/cases/ops/dashboard/overview", params={"project_id": "bench-project"}),
            )

            flow_latencies = []
            flow_errors = []
            started = time.perf_counter()
            for index in range(15):
                create_resp = await client.post(
                    "/api/vuln/cases",
                    json={
                        "project_id": "bench-project",
                        "title": f"flow-case-{index}",
                        "summary": "stateful-flow",
                        "severity": "high",
                        "confidence": 75,
                        "source_meta": {"source_service": "bench"},
                        "target_meta": {"asset_type": "service", "asset_locator": f"svc://flow/{index}"},
                        "display_meta": {},
                        "created_by_type": "human",
                        "created_by": "bench",
                    },
                )
                case_id = create_resp.json()["id"]
                loop_started = time.perf_counter()
                dispatch_resp = await client.post(
                    f"/api/vuln/cases/{case_id}/actions/dispatch",
                    json={"action_type": "analysis", "service_id": "svc-bench-01"},
                )
                if dispatch_resp.status_code != 200 or dispatch_resp.json()["count"] < 1:
                    flow_errors.append({"index": index, "phase": "dispatch", "body": dispatch_resp.text})
                    continue
                action_id = dispatch_resp.json()["items"][0]["id"]
                callback_resp = await client.post(
                    f"/api/vuln/actions/{action_id}/callback",
                    json={
                        "source_service_id": "svc-bench-01",
                        "result_type": "analysis",
                        "status": "succeeded",
                        "summary": "analysis completed",
                        "confidence": 70,
                        "suggested_stage": "verify",
                        "suggested_decision": "suspected",
                        "result_meta": {"ok": True},
                        "raw_payload": {},
                        "artifact_refs": [],
                    },
                )
                if callback_resp.status_code != 200:
                    flow_errors.append({"index": index, "phase": "callback", "body": callback_resp.text})
                    continue
                detail_resp = await client.get(f"/api/vuln/cases/{case_id}")
                if detail_resp.status_code != 200:
                    flow_errors.append({"index": index, "phase": "detail", "body": detail_resp.text})
                    continue
                flow_latencies.append((time.perf_counter() - loop_started) * 1000)
            flow_elapsed = time.perf_counter() - started
            flow_sorted = sorted(flow_latencies)
            p95_index = max(0, min(len(flow_sorted) - 1, int(len(flow_sorted) * 0.95) - 1))
            flow_result = {
                "name": "stateful_case_flow",
                "total_requests": len(flow_latencies),
                "concurrency": 1,
                "total_seconds": round(flow_elapsed, 4),
                "throughput_rps": round(len(flow_latencies) / flow_elapsed, 2) if flow_elapsed else 0,
                "avg_ms": round(statistics.mean(flow_latencies), 2) if flow_latencies else 0,
                "p95_ms": round(flow_sorted[p95_index], 2) if flow_sorted else 0,
                "max_ms": round(max(flow_sorted), 2) if flow_sorted else 0,
                "errors": flow_errors[:10],
                "error_count": len(flow_errors),
            }

            results = {
                "environment": {
                    "mode": "local_asgi_benchmark",
                    "database": "sqlite_file",
                    "cases_seeded": 40,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
                "benchmarks": [
                    health_result,
                    create_result,
                    list_result,
                    overview_result,
                    flow_result,
                ],
            }
            print(json.dumps(results, indent=2, ensure_ascii=False))
    finally:
        _cleanup_app_overrides(engine, db_path, original_cases, original_actions)


if __name__ == "__main__":
    asyncio.run(main())
