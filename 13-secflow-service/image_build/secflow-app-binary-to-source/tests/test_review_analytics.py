from __future__ import annotations

import json
import unittest
from types import SimpleNamespace
from unittest import mock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import tasks as tasks_api
from app.schemas import AdvancedBatch, AdvancedFile, AdvancedRun, TaskItemAdvancedResponse, TokenUser
from app.service import task_service


PROJECT_ID = "2abc83006a7ca7a4"
TASK_ID = "ad38c8d3115f4967"
ITEM_ID = "6a0e2f5132a447b2"


def _review_file(name: str, attempt_no: int, payload: dict) -> AdvancedFile:
    return AdvancedFile(
        name=name,
        path=f"/tmp/b2s/run-1/batch_001/{name}",
        kind="review",
        size=128,
        content=json.dumps(payload, ensure_ascii=False, indent=2),
        batch_no=1,
        attempt_no=attempt_no,
    )


def _source_snapshot(name: str, attempt_no: int) -> AdvancedFile:
    return AdvancedFile(
        name=name,
        path=f"/tmp/b2s/run-1/batch_001/{name}",
        kind="batch_source",
        size=200,
        content="""
int sub_880(const char *serial) { return serial ? 0 : 1; }
int sub_E74(void) { return 0; }
""".strip(),
        batch_no=1,
        attempt_no=attempt_no,
    )


def _advanced_response() -> TaskItemAdvancedResponse:
    attempt_1 = _review_file(
        "batch_001_attempt_01.verdict.json",
        1,
        {
            "verdict": "FAIL",
            "issues": [
                "sub_880: serial length validation logic INVERTED - original rejects if len <= 0x1F",
                "sub_880: return value incorrect - original returns v18^1u=0 for accepted",
                "sub_880: validation check 'hex_len == 0' appears in output but not in disassembly",
            ],
            "summary": "Logic inversion in serial length validation and incorrect return value",
            "total_functions": 10,
            "verified_functions": 8,
        },
    )
    attempt_2 = _review_file(
        "batch_001_attempt_02.verdict.json",
        2,
        {
            "verdict": "PASS",
            "issues": [],
            "summary": "All 10 functions decompiled correctly",
            "total_functions": 10,
            "verified_functions": 10,
        },
    )
    return TaskItemAdvancedResponse(
        task_id=TASK_ID,
        item_id=ITEM_ID,
        sequence_no=1,
        mode="deep",
        mode_label="深度模式",
        output_dir="/tmp/b2s/output",
        work_dir="/tmp/b2s/output/.re_work_latest",
        runs=[
            AdvancedRun(
                name="run-1",
                path="/tmp/b2s/output/.re_work_latest/runs/run-1",
                batches=[
                    AdvancedBatch(
                        name="batch_001",
                        batch_no=1,
                        source=_source_snapshot("batch_001_attempt_02.c", 2),
                        reviews=[attempt_1, attempt_2],
                        review_snapshots=[_source_snapshot("batch_001_attempt_01.c", 1), _source_snapshot("batch_001_attempt_02.c", 2)],
                    )
                ],
            )
        ],
    )


class ReviewAnalyticsParserTests(unittest.TestCase):
    def test_parse_review_file_reads_verdict_issues_and_function_counts(self) -> None:
        file = _review_file(
            "batch_001_attempt_01.verdict.json",
            1,
            {
                "verdict": "FAIL",
                "issues": ["sub_880: return value incorrect", ""],
                "total_functions": 10,
                "verified_functions": 8,
            },
        )

        parsed = task_service._parse_review_file(file)

        self.assertEqual(parsed["attempt_no"], 1)
        self.assertEqual(parsed["verdict"], "FAIL")
        self.assertEqual(parsed["issues"], ["sub_880: return value incorrect"])
        self.assertEqual(parsed["total"], 10)
        self.assertEqual(parsed["verified"], 8)
        self.assertEqual(parsed["score"], 64)

    def test_parse_review_file_falls_back_to_attempt_number_from_filename(self) -> None:
        file = _review_file("batch_001_attempt_02.verdict.json", 0, {"verdict": "PASS", "total_functions": 10, "verified_functions": 10})
        file.attempt_no = None

        parsed = task_service._parse_review_file(file)

        self.assertEqual(parsed["attempt_no"], 2)
        self.assertEqual(parsed["verdict"], "PASS")
        self.assertEqual(parsed["total"], 10)
        self.assertEqual(parsed["verified"], 10)
        self.assertEqual(parsed["score"], 100)

    def test_build_review_analytics_from_real_verdicts_populates_frontend_contract(self) -> None:
        item = SimpleNamespace(task_id=TASK_ID, id=ITEM_ID)
        with mock.patch.object(task_service, "build_task_item_advanced", return_value=_advanced_response()):
            response = task_service.build_task_item_review_analytics(item)

        self.assertEqual(response.meta.schema_version, "review_analytics.v2")
        self.assertEqual(response.meta.source, "validator_verdict")
        self.assertEqual(response.summary.final_verdict, "PASS")
        self.assertEqual(response.summary.final_verdict_label, "通过")
        self.assertEqual(response.summary.issue_total, 3)
        self.assertEqual(response.summary.issue_resolved, 3)
        self.assertEqual(response.summary.issue_remaining, 0)
        self.assertEqual(response.summary.issue_closure_rate, 1.0)
        self.assertEqual(response.summary.residual_risk, "low")

        self.assertEqual(len(response.attempts), 2)
        self.assertEqual(response.attempts[0].verdict, "FAIL")
        self.assertEqual(response.attempts[0].total_functions, 10)
        self.assertEqual(response.attempts[0].verified_functions, 8)
        self.assertEqual(response.attempts[0].blocking_issues, 3)
        self.assertEqual(response.attempts[0].issues_discovered, 3)
        self.assertEqual(response.attempts[0].issues_open_after_attempt, 3)
        self.assertEqual(response.attempts[1].verdict, "PASS")
        self.assertEqual(response.attempts[1].total_functions, 10)
        self.assertEqual(response.attempts[1].verified_functions, 10)
        self.assertEqual(response.attempts[1].blocking_issues, 0)
        self.assertEqual(response.attempts[1].issues_resolved, 3)
        self.assertEqual(response.attempts[1].issues_open_after_attempt, 0)

        issue_labels = {issue.label for issue in response.issues}
        self.assertIn("Length Logic", issue_labels)
        self.assertIn("Return Code", issue_labels)
        self.assertIn("Extra Check", issue_labels)
        self.assertTrue(all(issue.status == "resolved" for issue in response.issues))
        self.assertTrue(all(issue.resolved_attempt == 2 for issue in response.issues))

        self.assertGreaterEqual(len(response.dimensions), 3)
        self.assertEqual({dimension.key for dimension in response.dimensions}, {"logic_accuracy", "data_structure_accuracy", "readability"})
        for dimension in response.dimensions:
            self.assertEqual([point.attempt_no for point in dimension.points], [1, 2])
            self.assertTrue(dimension.label)
            self.assertIsInstance(dimension.score, int)
            self.assertIsInstance(dimension.components, dict)

        self.assertIsNotNone(response.trend)
        self.assertEqual(len(response.trend.series), 3)
        self.assertGreaterEqual(len(response.radar), 2)
        self.assertGreaterEqual(len(response.function_matrix), 1)


class ReviewAnalyticsApiTests(unittest.TestCase):
    def test_review_analytics_endpoint_returns_parsed_verdict_data(self) -> None:
        app = FastAPI()
        app.include_router(tasks_api.router)

        fake_task = SimpleNamespace(id=TASK_ID, project_id=PROJECT_ID, status="completed")
        fake_item = SimpleNamespace(id=ITEM_ID, task_id=TASK_ID, project_id=PROJECT_ID)

        async def fake_context(project_id: str, authorization: str | None = None) -> TokenUser:
            self.assertEqual(project_id, PROJECT_ID)
            return TokenUser(user_id="1", username="tester", role=["admin"], platform_role="super_admin")

        def fake_db():
            yield object()

        app.dependency_overrides[tasks_api.get_current_context] = fake_context
        app.dependency_overrides[tasks_api.get_db] = fake_db

        with (
            mock.patch.object(tasks_api, "get_task_or_404", return_value=fake_task),
            mock.patch.object(tasks_api, "sync_task", new=mock.AsyncMock()),
            mock.patch.object(tasks_api, "get_task_item_or_404", return_value=fake_item),
            mock.patch.object(task_service, "build_task_item_advanced", return_value=_advanced_response()),
        ):
            client = TestClient(app)
            resp = client.get(
                f"/api/app/binary-to-source/projects/{PROJECT_ID}/tasks/{TASK_ID}/items/{ITEM_ID}/review-analytics",
                headers={"Authorization": "Bearer test-token"},
            )

        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["summary"]["final_verdict"], "PASS")
        self.assertEqual(payload["summary"]["issue_total"], 3)
        self.assertEqual(payload["attempts"][0]["verdict"], "FAIL")
        self.assertEqual(payload["attempts"][0]["total_functions"], 10)
        self.assertEqual(payload["attempts"][0]["verified_functions"], 8)
        self.assertEqual(payload["attempts"][0]["blocking_issues"], 3)
        self.assertEqual(payload["attempts"][1]["verdict"], "PASS")
        self.assertEqual(payload["attempts"][1]["total_functions"], 10)
        self.assertEqual(payload["attempts"][1]["verified_functions"], 10)
        self.assertEqual(len(payload["dimensions"]), 3)
        self.assertEqual(len(payload["trend"]["series"]), 3)
        self.assertGreaterEqual(len(payload["radar"]), 2)
        self.assertGreaterEqual(len(payload["function_matrix"]), 1)


if __name__ == "__main__":
    unittest.main()
