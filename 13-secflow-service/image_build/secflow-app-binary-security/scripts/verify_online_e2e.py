#!/usr/bin/env python3
"""Read-only online E2E verification for binary-security."""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any


DEFAULT_BASE_URL = "https://secflow.ai.icsl.huawei.com"
DEFAULT_PROJECT_ID = "44f9029d00650a10"
DEFAULT_PROJECT_NAME = "NE8K固件泄漏逆向（正式项目-勿删）"


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str
    payload: Any | None = None


@dataclass
class VerificationReport:
    base_url: str
    project_id: str
    project_name: str
    task_id: str | None = None
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(item.ok for item in self.checks)

    def add(self, name: str, ok: bool, detail: str, payload: Any | None = None) -> None:
        self.checks.append(CheckResult(name=name, ok=ok, detail=detail, payload=payload))

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "base_url": self.base_url,
            "project_id": self.project_id,
            "project_name": self.project_name,
            "task_id": self.task_id,
            "checks": [
                {
                    "name": item.name,
                    "ok": item.ok,
                    "detail": item.detail,
                    "payload": item.payload,
                }
                for item in self.checks
            ],
        }


class HttpClient:
    def __init__(self, base_url: str, token: str | None = None, *, insecure: bool = False):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.insecure = insecure

    def request(self, method: str, path: str, data: dict[str, Any] | None = None) -> tuple[int, Any]:
        url = f"{self.base_url}{path}"
        raw = None if data is None else json.dumps(data).encode("utf-8")
        req = urllib.request.Request(url, data=raw, method=method.upper())
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        context = ssl._create_unverified_context() if self.insecure else None
        try:
            with urllib.request.urlopen(req, timeout=30, context=context) as resp:
                body = resp.read().decode("utf-8")
                return resp.status, json.loads(body) if body else None
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(body) if body else None
            except json.JSONDecodeError:
                payload = {"raw": body}
            return exc.code, payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify binary-security online APIs against a real project.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--project-id", default=DEFAULT_PROJECT_ID)
    parser.add_argument("--project-name", default=DEFAULT_PROJECT_NAME)
    parser.add_argument("--task-id")
    parser.add_argument("--stage-name", default="dataflow_analysis")
    parser.add_argument("--dump-json", action="store_true")
    parser.add_argument("--insecure", action="store_true")
    return parser.parse_args()


def first_task_id(tasks_payload: dict[str, Any]) -> str | None:
    items = list(tasks_payload.get("items") or [])
    if not items:
        return None
    ranked = sorted(
        items,
        key=lambda item: (
            0 if str(item.get("status") or "").lower() == "running" else 1,
            str(item.get("updated_at") or ""),
        ),
        reverse=False,
    )
    return str(ranked[0].get("id") or "")


def expect(condition: bool, message: str) -> tuple[bool, str]:
    return condition, message


def main() -> int:
    args = parse_args()
    anon = HttpClient(args.base_url, insecure=args.insecure)
    report = VerificationReport(
        base_url=args.base_url,
        project_id=args.project_id,
        project_name=args.project_name,
    )

    status, login_payload = anon.request(
        "POST",
        "/api/auth/login",
        {"username": args.username, "password": args.password},
    )
    token = str((login_payload or {}).get("access_token") or "")
    ok, detail = expect(status == 200 and bool(token), f"status={status}")
    report.add("login", ok, detail)
    if not ok:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        return 1

    client = HttpClient(args.base_url, token=token, insecure=args.insecure)

    status, projects_payload = client.request("GET", "/api/project")
    projects = list((projects_payload or {}).get("projects") or [])
    project = next((item for item in projects if str(item.get("id")) == args.project_id), None)
    ok, detail = expect(status == 200 and project is not None, f"status={status}, found={project is not None}")
    report.add("project_lookup", ok, detail, payload={"project_name": project.get("name") if project else None})

    status, config_payload = client.request("GET", "/api/app/binary-security/config")
    config = (config_payload or {}).get("config") or {}
    has_pipeline_mode = "pipeline_mode" in config
    ok = status == 200 and has_pipeline_mode
    detail = f"status={status}, pipeline_mode_present={has_pipeline_mode}"
    report.add(
        "project_config_pipeline_mode",
        ok,
        detail,
        payload={"config_keys": sorted(config.keys())},
    )

    status, tasks_payload = client.request("GET", f"/api/app/binary-security/projects/{args.project_id}/tasks")
    items = list((tasks_payload or {}).get("items") or [])
    selected_task_id = args.task_id or first_task_id(tasks_payload or {})
    report.task_id = selected_task_id
    ok, detail = expect(status == 200 and bool(items) and bool(selected_task_id), f"status={status}, total={len(items)}")
    report.add("task_list", ok, detail, payload={"task_count": len(items), "selected_task_id": selected_task_id})
    if not selected_task_id:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        return 1

    status, detail_payload = client.request(
        "GET",
        f"/api/app/binary-security/projects/{args.project_id}/tasks/{selected_task_id}",
    )
    current_stage = str((detail_payload or {}).get("current_stage") or "")
    stage_summaries = list((detail_payload or {}).get("stage_summaries") or [])
    has_manual_state = isinstance((detail_payload or {}).get("manual_operation_state"), dict)
    ok = status == 200 and bool(stage_summaries) and has_manual_state
    report.add(
        "task_detail",
        ok,
        f"status={status}, stage_count={len(stage_summaries)}, manual_state={has_manual_state}",
        payload={
            "task_status": (detail_payload or {}).get("status"),
            "current_stage": current_stage,
            "task_type": (detail_payload or {}).get("task_type"),
        },
    )

    observability_path = f"/api/app/binary-security/projects/{args.project_id}/tasks/{selected_task_id}/orchestration-observability"
    status, observability_payload = client.request("GET", observability_path)
    state_events = (observability_payload or {}).get("state_events") or {}
    has_recent_events = isinstance(state_events.get("recent"), list)
    ok = status == 200 and isinstance(state_events, dict) and has_recent_events
    report.add(
        "orchestration_observability",
        ok,
        f"status={status}, recent_present={has_recent_events}",
        payload={"status_counts": state_events.get("status_counts")},
    )

    stage_name = args.stage_name or current_stage or "dataflow_analysis"
    query = urllib.parse.urlencode({"stage_name": stage_name, "page": 1, "per_page": 5})
    status, stage_items_payload = client.request(
        "GET",
        f"/api/app/binary-security/projects/{args.project_id}/tasks/{selected_task_id}/stage-items?{query}",
    )
    records = list((stage_items_payload or {}).get("items") or [])
    ok = status == 200 and isinstance((stage_items_payload or {}).get("items"), list)
    report.add(
        "stage_items",
        ok,
        f"status={status}, item_count={len(records)}",
        payload={
            "stage_name": stage_name,
            "response_keys": sorted((stage_items_payload or {}).keys()) if isinstance(stage_items_payload, dict) else [],
        },
    )

    if args.dump_json or not report.ok:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        for check in report.checks:
            marker = "PASS" if check.ok else "FAIL"
            print(f"[{marker}] {check.name}: {check.detail}")
        print(f"Selected task: {report.task_id}")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
