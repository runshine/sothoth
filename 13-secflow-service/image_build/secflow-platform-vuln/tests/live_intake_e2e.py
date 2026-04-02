#!/usr/bin/env python3
"""Live E2E test for authenticated vuln intake + fileserver nested/binary uploads.

Usage:
  python tests/live_intake_e2e.py \
    --base-url http://127.0.0.1:3000 \
    --username admin \
    --password 'Huawei12#$' \
    --project-id abbbb
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import random
import string
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def random_suffix(n: int = 6) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def extract_token(payload: dict[str, Any]) -> str | None:
    candidates = [
        payload.get("access_token"),
        payload.get("token"),
        payload.get("data", {}).get("access_token") if isinstance(payload.get("data"), dict) else None,
        payload.get("data", {}).get("token") if isinstance(payload.get("data"), dict) else None,
    ]
    for value in candidates:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def assert_ok(resp: requests.Response, context: str) -> dict[str, Any]:
    if resp.ok:
        if resp.headers.get("content-type", "").startswith("application/json"):
            return resp.json()
        return {}
    detail = f"{context} failed: HTTP {resp.status_code}"
    try:
        body = resp.json()
    except Exception:
        body = {"raw": resp.text[:800]}
    raise RuntimeError(f"{detail}, body={body}")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


@dataclass
class CaseRun:
    mode: str
    index: int
    case_id: str
    files_root_path: str | None
    intake_http_code: int
    file_ops: list[dict[str, Any]]
    tree_snapshot: dict[str, Any] | None


def build_simple_payload(project_id: str, i: int) -> dict[str, Any]:
    suffix = f"s{i}-{random_suffix()}"
    return {
        "project_id": project_id,
        "report_id": f"live-simple-{suffix}",
        "title": f"Live simple suspicion {suffix}",
        "summary": "Quick intake without artifacts (live e2e)",
        "severity": "medium",
        "cvss_score": 5.8,
        "confidence": 70,
        "state": "suspected",
        "category": "generic_issue",
        "rule_id": f"LIVE-SIMPLE-{i:03d}",
        "rule_name": "Live Simple Rule",
        "fingerprint": f"live-simple-fp-{suffix}",
        "reported_at": utc_now_iso(),
        "reporter": {
            "name": "live-e2e-runner",
            "version": "1.0.0",
            "type": "cli",
            "vendor": "secflow",
        },
        "subject": {
            "type": "http_endpoint",
            "locator": f"https://demo.example/api/simple/{suffix}",
            "name": "simple endpoint",
        },
        "evidence": {
            "summary": "Simple live report without files",
            "reproduction_hint": "N/A",
            "references": [],
        },
        "metadata": {
            "source": {"source_service": "live-e2e", "source_kind": "script"},
            "runtime": {"scenario": "simple"},
        },
    }


def build_with_files_payload(project_id: str, i: int, nested_binary: bool) -> dict[str, Any]:
    suffix = f"f{i}-{random_suffix()}"
    binary_content = base64.b64encode(f"binary-seed-{suffix}".encode("utf-8")).decode("ascii")
    artifacts: list[dict[str, Any]] = [
        {
            "kind": "json",
            "name": "scanner-output.json",
            "media_type": "application/json",
            "encoding": "utf-8",
            "content": json.dumps({"finding_id": f"live-normal-{suffix}", "severity": "high"}),
        },
        {
            "kind": "text",
            "name": "request.txt",
            "path": "evidence/http/request.txt",
            "encoding": "utf-8",
            "content": "GET /api/login HTTP/1.1\nHost: demo.example\n",
        },
    ]
    if nested_binary:
        artifacts.append(
            {
                "kind": "tree",
                "name": "evidence",
                "children": [
                    {
                        "kind": "directory",
                        "name": "http",
                        "path": "evidence/http",
                        "children": [
                            {
                                "kind": "binary",
                                "name": "capture.bin",
                                "path": "evidence/http/raw/capture.bin",
                                "media_type": "application/octet-stream",
                                "encoding": "base64",
                                "content": binary_content,
                            },
                            {
                                "kind": "json",
                                "name": "response.json",
                                "path": "evidence/http/parsed/response.json",
                                "encoding": "utf-8",
                                "content": json.dumps({"status": 200, "token_like": True}),
                            },
                        ],
                    }
                ],
            }
        )
    else:
        artifacts.append(
            {
                "kind": "binary",
                "name": "payload.bin",
                "path": "evidence/payload.bin",
                "media_type": "application/octet-stream",
                "encoding": "base64",
                "content": binary_content,
            }
        )

    return {
        "project_id": project_id,
        "report_id": f"live-file-{suffix}",
        "title": f"Live normal suspicion with artifacts {suffix}",
        "summary": "Report with text/json/binary and nested tree",
        "severity": "high",
        "cvss_score": 8.1,
        "confidence": 86,
        "state": "suspected",
        "category": "http_security_issue",
        "rule_id": f"LIVE-NORMAL-{i:03d}",
        "rule_name": "Live Normal Rule",
        "fingerprint": f"live-normal-fp-{suffix}",
        "reported_at": utc_now_iso(),
        "reporter": {
            "name": "live-e2e-runner",
            "version": "1.1.0",
            "type": "cli",
            "vendor": "secflow",
        },
        "subject": {
            "type": "http_endpoint",
            "locator": f"https://demo.example/api/login/{suffix}",
            "name": "login endpoint",
        },
        "evidence": {
            "summary": "Observed suspicious auth flow and captured traces",
            "reproduction_hint": "Replay request and compare responses",
            "references": [],
        },
        "artifacts": artifacts,
        "metadata": {
            "source": {"source_service": "live-e2e", "source_kind": "script"},
            "runtime": {"scenario": "with-files", "nested_binary": nested_binary},
        },
    }


def login_get_human_token(session: requests.Session, base_url: str, username: str, password: str) -> str:
    resp = session.post(
        f"{base_url}/api/auth/login",
        json={"username": username, "password": password},
        timeout=20,
    )
    payload = assert_ok(resp, "login")
    token = extract_token(payload)
    if not token:
        raise RuntimeError(f"login ok but token not found: {payload}")
    return token


def get_project_token(session: requests.Session, base_url: str, human_token: str, project_id: str) -> str:
    headers = {"Authorization": f"Bearer {human_token}"}
    resp = session.get(
        f"{base_url}/api/auth/machine-tokens/projects/{project_id}",
        headers=headers,
        timeout=20,
    )
    if resp.status_code == 404:
        refresh = session.post(
            f"{base_url}/api/auth/machine-tokens/projects/{project_id}/refresh",
            headers=headers,
            timeout=20,
        )
        _ = assert_ok(refresh, "refresh project machine token")
        resp = session.get(
            f"{base_url}/api/auth/machine-tokens/projects/{project_id}",
            headers=headers,
            timeout=20,
        )
    payload = assert_ok(resp, "get project machine token")
    token = payload.get("token")
    if not isinstance(token, str) or not token.strip():
        raise RuntimeError(f"project token missing/empty: {payload}")
    return token.strip()


def resolve_project_id(session: requests.Session, base_url: str, human_token: str, project_input: str) -> tuple[str, str]:
    headers = {"Authorization": f"Bearer {human_token}"}
    resp = session.get(f"{base_url}/api/project", headers=headers, timeout=20)
    payload = assert_ok(resp, "list projects")
    projects = payload.get("projects", []) if isinstance(payload, dict) else []
    if not isinstance(projects, list):
        raise RuntimeError(f"unexpected project list payload: {payload}")

    target = project_input.strip()
    by_id = None
    by_name = None
    for item in projects:
        if not isinstance(item, dict):
            continue
        pid = str(item.get("id", "")).strip()
        pname = str(item.get("name", "")).strip()
        if pid == target:
            by_id = (pid, pname or pid)
            break
        if pname == target:
            by_name = (pid, pname or pid)
    if by_id:
        return by_id
    if by_name:
        return by_name
    raise RuntimeError(f"project '{project_input}' not found in /api/project list")


def submit_case(session: requests.Session, base_url: str, project_token: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    headers = {"Authorization": f"Bearer {project_token}", "Content-Type": "application/json"}
    resp = session.post(
        f"{base_url}/api/vuln/public/intake/submissions",
        headers=headers,
        data=json.dumps(payload),
        timeout=30,
    )
    return resp.status_code, assert_ok(resp, "submit intake")


def upload_file_to_case_root(
    session: requests.Session,
    base_url: str,
    project_token: str,
    project_id: str,
    path: str,
    local_file: Path,
    content_type: str,
) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {project_token}"}
    with local_file.open("rb") as fp:
        resp = session.post(
            f"{base_url}/api/fileserver/vuln/project-path/files/upload",
            headers=headers,
            data={"project_id": project_id, "path": path},
            files={"file": (local_file.name, fp, content_type)},
            timeout=30,
        )
    return assert_ok(resp, f"upload file {path}")


def mkdirs_case_root(
    session: requests.Session,
    base_url: str,
    project_token: str,
    project_id: str,
    paths: list[str],
) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {project_token}", "Content-Type": "application/json"}
    resp = session.post(
        f"{base_url}/api/fileserver/vuln/project-path/mkdirs",
        headers=headers,
        data=json.dumps({"project_id": project_id, "paths": paths}),
        timeout=20,
    )
    return assert_ok(resp, "mkdirs")


def get_case_detail(session: requests.Session, base_url: str, project_token: str, case_id: str) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {project_token}"}
    resp = session.get(f"{base_url}/api/vuln/cases/{case_id}", headers=headers, timeout=20)
    return assert_ok(resp, "get case detail")


def get_children(
    session: requests.Session,
    base_url: str,
    project_token: str,
    project_id: str,
    path: str,
) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {project_token}"}
    resp = session.get(
        f"{base_url}/api/fileserver/vuln/project-path/children",
        headers=headers,
        params={"project_id": project_id, "path": path},
        timeout=20,
    )
    return assert_ok(resp, f"children {path}")


def collect_tree_recursive(
    session: requests.Session,
    base_url: str,
    project_token: str,
    project_id: str,
    root_path: str,
) -> dict[str, Any]:
    visited: set[str] = set()

    def walk(path: str) -> dict[str, Any]:
        if path in visited:
            return {"path": path, "cycle": True}
        visited.add(path)
        node = get_children(session, base_url, project_token, project_id, path)
        children = []
        for directory in node.get("directories", []):
            dpath = directory.get("path")
            if isinstance(dpath, str) and dpath:
                children.append(walk(dpath))
        return {
            "path": node.get("current_path"),
            "directories": node.get("directories", []),
            "files": node.get("files", []),
            "children": children,
        }

    return walk(root_path)


def create_local_test_files(base_dir: Path, case_id: str) -> tuple[Path, Path]:
    case_dir = base_dir / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    text_file = case_dir / "evidence.json"
    payload = {
        "case_id": case_id,
        "timestamp": utc_now_iso(),
        "note": "text evidence from live e2e",
    }
    write_json(text_file, payload)

    binary_file = case_dir / "capture.bin"
    binary_blob = os.urandom(16384)  # 16KB
    binary_file.write_bytes(binary_blob)
    return text_file, binary_file


def run_negative_path_test(
    session: requests.Session,
    base_url: str,
    project_token: str,
    project_id: str,
) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {project_token}"}
    resp = session.get(
        f"{base_url}/api/fileserver/vuln/project-path/children",
        headers=headers,
        params={"project_id": project_id, "path": "/__vuln_cases__/../outside"},
        timeout=20,
    )
    ok = resp.status_code >= 400
    return {
        "status_code": resp.status_code,
        "expected_rejected": True,
        "rejected": ok,
        "body": resp.text[:500],
    }


def run_invalid_token_test(session: requests.Session, base_url: str, project_id: str) -> dict[str, Any]:
    headers = {"Authorization": "Bearer invalid-token", "Content-Type": "application/json"}
    payload = build_simple_payload(project_id, 999)
    resp = session.post(
        f"{base_url}/api/vuln/public/intake/submissions",
        headers=headers,
        data=json.dumps(payload),
        timeout=20,
    )
    return {
        "status_code": resp.status_code,
        "expected_rejected": True,
        "rejected": resp.status_code >= 400,
        "body": resp.text[:500],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Live vuln intake/fileserver E2E runner")
    parser.add_argument("--base-url", default="http://127.0.0.1:3000")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="Huawei12#$")
    parser.add_argument("--project-id", default="abbbb")
    parser.add_argument("--simple-count", type=int, default=5)
    parser.add_argument("--with-files-count", type=int, default=5)
    parser.add_argument("--nested-min-count", type=int, default=2)
    parser.add_argument("--output-dir", default="")
    args = parser.parse_args()

    if args.output_dir.strip():
        out_dir = Path(args.output_dir)
    else:
        out_dir = Path(__file__).resolve().parent / "live_outputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    run_tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = out_dir / f"intake_e2e_{run_tag}"
    run_dir.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    session.verify = False

    print(f"[INFO] base_url={args.base_url}")
    print("[INFO] login...")
    human_token = login_get_human_token(session, args.base_url, args.username, args.password)
    print("[INFO] login ok")

    resolved_project_id, resolved_project_name = resolve_project_id(session, args.base_url, human_token, args.project_id)
    print(f"[INFO] project resolved: input={args.project_id} -> id={resolved_project_id}, name={resolved_project_name}")

    print(f"[INFO] fetch project token: {resolved_project_id}")
    project_token = get_project_token(session, args.base_url, human_token, resolved_project_id)
    print("[INFO] project token ready")

    runs: list[CaseRun] = []
    seen_case_ids: set[str] = set()

    for i in range(1, args.simple_count + 1):
        payload = build_simple_payload(resolved_project_id, i)
        write_json(run_dir / f"payload_simple_{i:02d}.json", payload)
        code, result = submit_case(session, args.base_url, project_token, payload)
        case_id = str(result.get("id"))
        if not case_id:
            raise RuntimeError(f"simple submission missing id: {result}")
        seen_case_ids.add(case_id)
        runs.append(
            CaseRun(
                mode="simple",
                index=i,
                case_id=case_id,
                files_root_path=result.get("files_root_path"),
                intake_http_code=code,
                file_ops=[],
                tree_snapshot=None,
            )
        )
        print(f"[OK] simple #{i} -> {case_id}")

    for i in range(1, args.with_files_count + 1):
        nested_binary = i <= args.nested_min_count
        payload = build_with_files_payload(resolved_project_id, i, nested_binary=nested_binary)
        write_json(run_dir / f"payload_with_files_{i:02d}.json", payload)
        code, result = submit_case(session, args.base_url, project_token, payload)
        case_id = str(result.get("id"))
        if not case_id:
            raise RuntimeError(f"with-files submission missing id: {result}")
        files_root_path = result.get("files_root_path")
        if not isinstance(files_root_path, str) or not files_root_path.startswith("/__vuln_cases__/"):
            raise RuntimeError(f"invalid files_root_path: {result}")
        seen_case_ids.add(case_id)

        text_file, binary_file = create_local_test_files(run_dir / "local_files", case_id)
        base_upload_paths = [
            f"{files_root_path}/evidence/http/raw",
            f"{files_root_path}/evidence/http/parsed",
            f"{files_root_path}/evidence/bin",
        ]
        mkdirs_resp = mkdirs_case_root(session, args.base_url, project_token, resolved_project_id, base_upload_paths)
        text_upload = upload_file_to_case_root(
            session,
            args.base_url,
            project_token,
            resolved_project_id,
            f"{files_root_path}/evidence/http/parsed/evidence.json",
            text_file,
            "application/json",
        )
        binary_upload = upload_file_to_case_root(
            session,
            args.base_url,
            project_token,
            resolved_project_id,
            f"{files_root_path}/evidence/bin/capture.bin",
            binary_file,
            "application/octet-stream",
        )

        detail = get_case_detail(session, args.base_url, project_token, case_id)
        if detail.get("id") != case_id:
            raise RuntimeError(f"case detail id mismatch: expected={case_id}, got={detail.get('id')}")
        if detail.get("files_root_path") != files_root_path:
            raise RuntimeError("case detail files_root_path mismatch")
        if not isinstance(detail.get("fileserver_root"), dict):
            raise RuntimeError("case detail missing fileserver_root")

        tree = collect_tree_recursive(
            session,
            args.base_url,
            project_token,
            resolved_project_id,
            files_root_path,
        )

        runs.append(
            CaseRun(
                mode="with_files_nested_binary" if nested_binary else "with_files",
                index=i,
                case_id=case_id,
                files_root_path=files_root_path,
                intake_http_code=code,
                file_ops=[
                    {"mkdirs": mkdirs_resp},
                    {"upload_text": text_upload},
                    {"upload_binary": binary_upload},
                ],
                tree_snapshot=tree,
            )
        )
        print(f"[OK] with-files #{i} -> {case_id}")

    negative_path = run_negative_path_test(session, args.base_url, project_token, resolved_project_id)
    invalid_token = run_invalid_token_test(session, args.base_url, resolved_project_id)

    summary = {
        "run_tag": run_tag,
        "base_url": args.base_url,
        "project_input": args.project_id,
        "project_id": resolved_project_id,
        "project_name": resolved_project_name,
        "counts": {
            "simple": args.simple_count,
            "with_files": args.with_files_count,
            "nested_binary_min_required": args.nested_min_count,
            "total_expected": args.simple_count + args.with_files_count,
            "total_submitted": len(runs),
            "unique_case_ids": len(seen_case_ids),
        },
        "security_negative_tests": {
            "path_traversal": negative_path,
            "invalid_token": invalid_token,
        },
        "runs": [
            {
                "mode": run.mode,
                "index": run.index,
                "case_id": run.case_id,
                "files_root_path": run.files_root_path,
                "intake_http_code": run.intake_http_code,
                "file_ops": run.file_ops,
                "tree_snapshot": run.tree_snapshot,
            }
            for run in runs
        ],
    }
    write_json(run_dir / "summary.json", summary)

    # Lightweight assertions for pass/fail exit code
    expected_total = args.simple_count + args.with_files_count
    if len(runs) != expected_total:
        raise RuntimeError(f"submitted {len(runs)} != expected {expected_total}")
    if len(seen_case_ids) != expected_total:
        raise RuntimeError("case ids are not unique")
    nested_count = len([r for r in runs if r.mode == "with_files_nested_binary"])
    if nested_count < args.nested_min_count:
        raise RuntimeError(f"nested+binary count {nested_count} < required {args.nested_min_count}")
    if not negative_path.get("rejected"):
        raise RuntimeError("path traversal negative test not rejected")
    if not invalid_token.get("rejected"):
        raise RuntimeError("invalid token negative test not rejected")

    print(f"[DONE] summary: {run_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise
