#!/usr/bin/env python3
"""Standalone self-evolution runner for dataflow-vuln-scanner.

This CLI intentionally avoids the FastAPI/DB/worker stack. It is a small
debugging harness that replays existing normal scanner tasks with candidate
agent memory packages and optionally promotes the best package for production
scans.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TERMINAL_DATAFLOW_STATUSES = {"completed", "succeeded", "failed", "cancelled", "interrupted", "error"}
SUCCESS_DATAFLOW_STATUSES = {"completed", "succeeded"}
DEFAULT_EVOLVE_AGENTS = ("pi-worker", "pi-advisor")
ALLOWED_EVOLVE_AGENTS = set(DEFAULT_EVOLVE_AGENTS)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _trimmed(value: Any) -> str:
    return str(value or "").strip()


def _safe_component(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in str(value or "")).strip("-.")
    return cleaned or "item"


def _json_dump(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _split_values(values: list[str] | None) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        for item in str(value or "").split(","):
            item = item.strip()
            if item and item not in seen:
                result.append(item)
                seen.add(item)
    return result


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for raw in values:
        value = str(raw or "").strip()
        if value and value not in seen:
            result.append(value)
            seen.add(value)
    return result


def _read_id_file(path: str | None) -> list[str]:
    if not path:
        return []
    file_path = Path(path)
    if not file_path.is_file():
        raise SystemExit(f"❌ id 文件不存在: {file_path}")
    result: list[str] = []
    seen: set[str] = set()
    if file_path.suffix.lower() == ".csv":
        with file_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            for row in reader:
                for cell in row:
                    value = cell.strip()
                    if value and value not in seen:
                        result.append(value)
                        seen.add(value)
    else:
        for line in file_path.read_text(encoding="utf-8").splitlines():
            value = line.strip()
            if value and not value.startswith("#") and value not in seen:
                result.append(value)
                seen.add(value)
    return result


def _case_source_task(case: dict[str, Any]) -> dict[str, Any]:
    source_task = case.get("source_task")
    if isinstance(source_task, dict) and source_task:
        return source_task
    source = case.get("source")
    if isinstance(source, dict) and source:
        return source
    metadata = case.get("metadata")
    if isinstance(metadata, dict):
        source = metadata.get("source")
        if isinstance(source, dict):
            return source
    return {}


def _normalize_agents(raw: str | None) -> list[str]:
    values = [item.strip() for item in (raw or ",".join(DEFAULT_EVOLVE_AGENTS)).split(",") if item.strip()]
    if not values:
        raise SystemExit("❌ --evolve-agents 不能为空")
    result: list[str] = []
    seen: set[str] = set()
    for agent_id in values:
        if agent_id not in ALLOWED_EVOLVE_AGENTS:
            raise SystemExit(f"❌ 不支持的 agent: {agent_id}; 可选: {', '.join(DEFAULT_EVOLVE_AGENTS)}")
        if agent_id not in seen:
            result.append(agent_id)
            seen.add(agent_id)
    return result


def _auth_header(token: str | None, token_file: str | None) -> str | None:
    value = token or os.environ.get("AUTHORIZATION") or os.environ.get("SECFLOW_AUTHORIZATION")
    if not value and token_file:
        value = Path(token_file).read_text(encoding="utf-8").strip()
    if not value:
        return None
    return value if value.lower().startswith("bearer ") else f"Bearer {value}"


class HttpJsonClient:
    def __init__(self, *, timeout: int, authorization: str | None) -> None:
        self.timeout = timeout
        self.authorization = authorization

    def request(self, method: str, url: str, *, payload: dict[str, Any] | None = None, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if params:
            query = urllib.parse.urlencode({k: v for k, v in params.items() if v not in (None, "", [], {})})
            url = f"{url}?{query}" if query else url
        data = None
        headers = {"Accept": "application/json"}
        if self.authorization:
            headers["Authorization"] = self.authorization
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{method} {url} failed: HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"{method} {url} failed: {exc}") from exc
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"{method} {url} returned non-json response: {raw[:200]}") from exc
        return parsed if isinstance(parsed, dict) else {"items": parsed}


class DataflowClient:
    def __init__(self, *, base_url: str, api_prefix: str, http: HttpJsonClient) -> None:
        self.api_base = f"{base_url.rstrip('/')}{api_prefix}"
        self.http = http

    def get_task(self, task_id: str) -> dict[str, Any]:
        return self.http.request("GET", f"{self.api_base}/tasks/{task_id}")

    def get_replay_ready(self, task_id: str) -> dict[str, Any]:
        return self.http.request("GET", f"{self.api_base}/tasks/{task_id}/replay-ready")

    def create_evolution_task(self, source_task_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.http.request("POST", f"{self.api_base}/tasks/{source_task_id}/create-evolution", payload=payload)


class VulnClient:
    def __init__(self, *, base_url: str, api_prefix: str, http: HttpJsonClient) -> None:
        self.api_base = f"{base_url.rstrip('/')}{api_prefix}"
        self.http = http

    def get_case(self, case_id: str) -> dict[str, Any]:
        return self.http.request("GET", f"{self.api_base}/cases/{case_id}")

    def list_cases(self, **params: Any) -> list[dict[str, Any]]:
        payload = self.http.request("GET", f"{self.api_base}/cases", params=params)
        return list(payload.get("items") or [])


@dataclass
class SourceSpec:
    source_task_id: str
    selected_result_ids: list[str] = field(default_factory=list)
    expected_result_count: int = 0
    source_execution_id: str | None = None
    source_title: str | None = None
    replay_ready: dict[str, Any] = field(default_factory=dict)


@dataclass
class RoundResult:
    round_no: int
    candidate_roots: dict[str, str]
    derived_tasks: list[dict[str, Any]]
    metrics: dict[str, Any]
    meta_evaluation: dict[str, Any]
    score: int
    passed: bool


class EvolutionCliRunner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.authorization = _auth_header(args.token, args.token_file)
        self.http = HttpJsonClient(timeout=args.http_timeout, authorization=self.authorization)
        self.dataflow = DataflowClient(base_url=args.dataflow_base_url, api_prefix=args.dataflow_api_prefix, http=self.http)
        self.vuln = VulnClient(base_url=args.vuln_base_url, api_prefix=args.vuln_api_prefix, http=self.http)
        self.agents = _normalize_agents(args.evolve_agents)
        self.experiment_id = args.experiment_id or f"evo-cli-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        self.project_root = (Path(args.workspace_root).expanduser().resolve() / _safe_component(args.project_id)).resolve()
        self.agent_state_root = self.project_root / "app" / args.dataflow_subproject_name / "agent-state"
        self.experiment_root = self.agent_state_root / "evolution-cli" / _safe_component(self.experiment_id)
        self.report_path = self.experiment_root / "experiment-report.json"
        self.round_results: list[RoundResult] = []

    def run(self) -> int:
        if self.args.show_memory_mode:
            self.show_memory_mode()
            return 0
        if self.args.disable_memory_mode:
            self.disable_memory_mode()
            return 0

        selected_results = _dedupe(_split_values(self.args.selected_result) + _read_id_file(self.args.selected_results_file))
        source_tasks = _dedupe(_split_values(self.args.source_task) + _read_id_file(self.args.source_tasks_file))
        if not selected_results and not source_tasks:
            raise SystemExit("❌ 必须提供 --selected-result/--selected-results-file 或 --source-task/--source-tasks-file")
        if not self.args.direction:
            raise SystemExit("❌ 必须提供 --direction")

        sources = self.resolve_sources(selected_results=selected_results, source_tasks=source_tasks)
        self.experiment_root.mkdir(parents=True, exist_ok=True)
        _json_dump(self.experiment_root / "sources.json", [source.__dict__ for source in sources])
        self.write_experiment_summary(status="running", sources=sources)

        print("═" * 72)
        print("  Dataflow Vulnerability Scanner Self-Evolution CLI")
        print("═" * 72)
        print(f"  Project:        {self.args.project_id}")
        print(f"  Experiment:     {self.experiment_id}")
        print(f"  Direction:      {self.args.direction}")
        print(f"  Agents:         {', '.join(self.agents)}")
        print(f"  Sources:        {len(sources)}")
        print(f"  Workspace:      {self.experiment_root}")
        print(f"  Dry run:        {'yes' if self.args.dry_run else 'no'}")
        print("═" * 72)

        previous_roots: dict[str, str] | None = None
        best: RoundResult | None = None
        for round_no in range(1, self.args.max_rounds + 1):
            print(f"\n▶ Round {round_no}/{self.args.max_rounds}")
            candidate_roots = self.prepare_candidate_roots(round_no, previous_roots, sources)
            derived_tasks = self.launch_replay_round(round_no, candidate_roots, sources)
            metrics = self.compute_metrics(sources, derived_tasks)
            score = self.score_metrics(metrics)
            meta = self.meta_evaluate(round_no, metrics, score, candidate_roots)
            result = RoundResult(
                round_no=round_no,
                candidate_roots=candidate_roots,
                derived_tasks=derived_tasks,
                metrics=metrics,
                meta_evaluation=meta,
                score=score,
                passed=bool(meta.get("passed")),
            )
            self.round_results.append(result)
            self.write_round_report(result)
            previous_roots = candidate_roots
            if best is None or result.score > best.score:
                best = result
            print(f"  score={score} decision={meta.get('decision')} reported={metrics.get('reported_result_count')} expected={metrics.get('expected_result_count')}")
            self.write_experiment_summary(status="running", sources=sources)
            if round_no >= self.args.min_rounds and result.passed:
                print("  meta evaluator passed; stopping.")
                break

        if best is None:
            raise SystemExit("❌ 没有产生任何轮次结果")
        self.write_experiment_summary(status="succeeded", sources=sources, best_round=best.round_no)
        if self.args.promote:
            self.promote(best)
        print(f"\n✅ Done. Report: {self.report_path}")
        return 0

    def resolve_sources(self, *, selected_results: list[str], source_tasks: list[str]) -> list[SourceSpec]:
        grouped: dict[str, SourceSpec] = {}
        for task_id in source_tasks:
            if task_id not in grouped:
                grouped[task_id] = SourceSpec(source_task_id=task_id)
        for result_id in selected_results:
            case = self.vuln.get_case(result_id)
            source_task = _case_source_task(case)
            service_name = _trimmed(source_task.get("service_name") or source_task.get("service_id"))
            if service_name and service_name != "secflow-app-dataflow-vuln-scanner":
                raise RuntimeError(f"result {result_id} is not from dataflow-vuln-scanner: {service_name}")
            source_task_id = _trimmed(source_task.get("task_id"))
            if not source_task_id:
                raise RuntimeError(f"result {result_id} has no source_task.task_id")
            item = grouped.setdefault(source_task_id, SourceSpec(source_task_id=source_task_id))
            item.selected_result_ids.append(result_id)
            item.source_execution_id = _trimmed(source_task.get("execution_id")) or item.source_execution_id
            item.source_title = _trimmed(source_task.get("run_name")) or item.source_title

        sources: list[SourceSpec] = []
        for source in grouped.values():
            if self.args.skip_source_validation:
                source.replay_ready = {
                    "task_id": source.source_task_id,
                    "project_id": self.args.project_id,
                    "task_purpose": "normal",
                    "replay_ready": True,
                    "reason": "skipped by run_evolution.py",
                    "agent_state_dirs": {},
                }
            else:
                replay_ready = self.dataflow.get_replay_ready(source.source_task_id)
                if not replay_ready.get("replay_ready"):
                    raise RuntimeError(f"source task is not replay-ready: {source.source_task_id}: {replay_ready.get('reason')}")
                task_purpose = _trimmed(replay_ready.get("task_purpose")).lower()
                if task_purpose != "normal":
                    raise RuntimeError(f"source task is not normal: {source.source_task_id}: {task_purpose}")
                source.replay_ready = replay_ready
            if self.args.auto_expand_source_results and self.args.project_id:
                cases = self.vuln.list_cases(
                    project_id=self.args.project_id,
                    source_service_name="secflow-app-dataflow-vuln-scanner",
                    source_task_id=source.source_task_id,
                )
                source.expected_result_count = len(cases)
            elif source.selected_result_ids:
                source.expected_result_count = len(source.selected_result_ids)
            else:
                if self.args.skip_source_validation:
                    source.expected_result_count = self.args.expected_result_count
                else:
                    detail = self.dataflow.get_task(source.source_task_id)
                    latest_run = detail.get("latest_run") if isinstance(detail.get("latest_run"), dict) else {}
                    source.expected_result_count = _as_int(latest_run.get("result_count"), self.args.expected_result_count)
            sources.append(source)
        return sources

    def prepare_candidate_roots(
        self,
        round_no: int,
        previous_roots: dict[str, str] | None,
        sources: list[SourceSpec],
    ) -> dict[str, str]:
        roots: dict[str, str] = {}
        round_root = self.experiment_root / "rounds" / f"round-{round_no}"
        source_state_dirs = self._first_source_agent_state_dirs(sources)
        for agent_id in self.agents:
            root = round_root / agent_id
            memory_dir = root / "memory"
            memory_dir.mkdir(parents=True, exist_ok=True)
            previous_root = Path(previous_roots[agent_id]) if previous_roots and agent_id in previous_roots else None
            if previous_root and (previous_root / "memory").is_dir():
                shutil.copytree(previous_root / "memory", memory_dir, dirs_exist_ok=True)
            elif self.args.seed_from_source_memory:
                source_root = Path(_trimmed((source_state_dirs.get(agent_id) or {}).get("root_dir")))
                if (source_root / "memory").is_dir():
                    shutil.copytree(source_root / "memory", memory_dir, dirs_exist_ok=True)
            roots[agent_id] = str(root)
        self.write_candidate_memory(round_no, roots, sources)
        return roots

    def _first_source_agent_state_dirs(self, sources: list[SourceSpec]) -> dict[str, dict[str, Any]]:
        for source in sources:
            dirs = source.replay_ready.get("agent_state_dirs")
            if isinstance(dirs, dict):
                return {str(key): value for key, value in dirs.items() if isinstance(value, dict)}
        return {}

    def write_candidate_memory(self, round_no: int, roots: dict[str, str], sources: list[SourceSpec]) -> None:
        extra = ""
        if self.args.memory_note:
            note_path = Path(self.args.memory_note)
            if not note_path.is_file():
                raise SystemExit(f"❌ --memory-note 文件不存在: {note_path}")
            extra = "\n\n## Extra Memory Note\n\n" + note_path.read_text(encoding="utf-8").strip() + "\n"
        previous = self.round_results[-1].meta_evaluation if self.round_results else {}
        selected = {source.source_task_id: source.selected_result_ids for source in sources}
        for agent_id, root in roots.items():
            advisor_guardrails = ""
            if agent_id == "pi-advisor":
                advisor_guardrails = """
## Advisor Guardrails

- Do not make candidate output look better by relaxing scanner review standards.
- Do not mark real vulnerabilities as false_positive without concrete evidence.
- Do not let global review pass early by reducing coverage depth.
"""
            content = f"""# Evolution Candidate Round {round_no}

## Direction

{self.args.direction}

## Replay Context

- project_id: `{self.args.project_id}`
- experiment_id: `{self.experiment_id}`
- agent_id: `{agent_id}`
- selected_results_by_source: `{json.dumps(selected, ensure_ascii=False)}`

## Previous Meta Evaluation

```json
{json.dumps(previous, ensure_ascii=False, indent=2)}
```

## Memory Policy

- This file is memory-only. Do not assume prompts, code, or skills changed.
- Prefer precise filtering over broad suppression.
- Preserve high-value findings unless the evolution direction explicitly says they should be suppressed.
{advisor_guardrails}
{extra}
"""
            Path(root, "memory", f"evolution-candidate-round-{round_no}.md").write_text(content, encoding="utf-8")

    def launch_replay_round(self, round_no: int, candidate_roots: dict[str, str], sources: list[SourceSpec]) -> list[dict[str, Any]]:
        payloads = [
            (source, self.build_replay_payload(round_no, source, candidate_roots))
            for source in sources
        ]
        for source, payload in payloads:
            _json_dump(self.experiment_root / "rounds" / f"round-{round_no}" / "replay-payloads" / f"{source.source_task_id}.json", payload)
        if self.args.dry_run:
            return [
                {
                    "source_task_id": source.source_task_id,
                    "status": "dry_run",
                    "result_count": source.expected_result_count,
                    "payload_path": str(self.experiment_root / "rounds" / f"round-{round_no}" / "replay-payloads" / f"{source.source_task_id}.json"),
                }
                for source, _ in payloads
            ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.max_concurrent_source_tasks) as pool:
            futures = [pool.submit(self.create_and_wait_replay, source, payload) for source, payload in payloads]
            return [future.result() for future in concurrent.futures.as_completed(futures)]

    def build_replay_payload(self, round_no: int, source: SourceSpec, candidate_roots: dict[str, str]) -> dict[str, Any]:
        return {
            "title": f"{self.experiment_id} / round {round_no} / {source.source_task_id}",
            "profile_id": self.args.profile_id,
            "model": self.args.model,
            "provider": self.args.provider,
            "review_profile": self.args.review_profile,
            "agent_run_timeout_seconds": self.args.agent_run_timeout_seconds,
            "agent_state_roots": {
                agent_id: {
                    "root_dir": {
                        "source": "project_filesystem",
                        "path": self.project_visible_path(Path(root)),
                    }
                }
                for agent_id, root in candidate_roots.items()
            },
            "scan_options": {},
            "evolution_task_id": self.experiment_id,
            "evolution_round": round_no,
            "evolution_source_task_id": source.source_task_id,
            "evolution_source_execution_id": source.source_execution_id,
            "auto_report_vulnerabilities": bool(self.args.auto_report_vulnerabilities),
        }

    def create_and_wait_replay(self, source: SourceSpec, payload: dict[str, Any]) -> dict[str, Any]:
        created = self.dataflow.create_evolution_task(source.source_task_id, _drop_empty(payload))
        derived_task_id = _trimmed(created.get("task_id"))
        result = {
            "source_task_id": source.source_task_id,
            "source_execution_id": source.source_execution_id,
            "derived_task_id": derived_task_id,
            "status": created.get("status"),
        }
        if not derived_task_id:
            return result
        deadline = time.monotonic() + self.args.derived_timeout_seconds
        while True:
            if time.monotonic() > deadline:
                raise RuntimeError(f"derived task timed out: {derived_task_id}")
            time.sleep(self.args.poll_interval_seconds)
            detail = self.dataflow.get_task(derived_task_id)
            status = _trimmed(detail.get("status")).lower()
            result["status"] = status or detail.get("status")
            result["latest_execution_id"] = detail.get("latest_execution_id")
            latest_run = detail.get("latest_run") if isinstance(detail.get("latest_run"), dict) else detail.get("run")
            if isinstance(latest_run, dict):
                result["latest_run"] = latest_run
                result["result_count"] = latest_run.get("result_count")
            if status in TERMINAL_DATAFLOW_STATUSES:
                break
        if _trimmed(result.get("status")).lower() not in SUCCESS_DATAFLOW_STATUSES:
            raise RuntimeError(f"derived task failed: {derived_task_id}: {result.get('status')}")
        return result

    def compute_metrics(self, sources: list[SourceSpec], derived_tasks: list[dict[str, Any]]) -> dict[str, Any]:
        expected_by_source = {source.source_task_id: source.expected_result_count for source in sources}
        actual_by_source: dict[str, int] = {}
        success_count = 0
        for task in derived_tasks:
            source_id = _trimmed(task.get("source_task_id"))
            status = _trimmed(task.get("status")).lower()
            if status in SUCCESS_DATAFLOW_STATUSES or status == "dry_run":
                success_count += 1
            count = _as_int(task.get("result_count"), -1)
            if count < 0:
                latest_run = task.get("latest_run") if isinstance(task.get("latest_run"), dict) else {}
                count = _as_int(latest_run.get("result_count"), 0)
            if source_id:
                actual_by_source[source_id] = actual_by_source.get(source_id, 0) + max(0, count)
        expected = sum(expected_by_source.values())
        reported = sum(actual_by_source.values())
        false_negative = sum(max(expected_by_source.get(source, 0) - actual_by_source.get(source, 0), 0) for source in expected_by_source)
        false_positive = sum(max(actual_by_source.get(source, 0) - expected_by_source.get(source, 0), 0) for source in actual_by_source)
        total = max(len(derived_tasks), 1)
        return {
            "expected_result_count": expected,
            "reported_result_count": reported,
            "false_negative_count": false_negative,
            "false_positive_count": false_positive,
            "false_negative_rate": false_negative / expected if expected else 0.0,
            "false_positive_rate": false_positive / max(reported, 1) if reported else 0.0,
            "run_success_rate": success_count / total,
            "expected_by_source": expected_by_source,
            "actual_by_source": actual_by_source,
        }

    def score_metrics(self, metrics: dict[str, Any]) -> int:
        fn_rate = float(metrics.get("false_negative_rate") or 0.0)
        fp_rate = float(metrics.get("false_positive_rate") or 0.0)
        success_rate = float(metrics.get("run_success_rate") or 0.0)
        return int(1000 * success_rate - 500 * fn_rate - 300 * fp_rate)

    def meta_evaluate(self, round_no: int, metrics: dict[str, Any], score: int, candidate_roots: dict[str, str]) -> dict[str, Any]:
        advisor_evolved = "pi-advisor" in candidate_roots
        risks: list[str] = []
        if metrics.get("false_negative_count"):
            risks.append("candidate may be suppressing non-target or high-value results")
        if advisor_evolved and metrics.get("reported_result_count") == 0:
            risks.append("advisor memory may be relaxing review or stopping coverage too early")
        passed = (
            score >= self.args.pass_score_threshold
            and float(metrics.get("false_negative_rate") or 0.0) <= self.args.max_false_negative_rate
            and float(metrics.get("false_positive_rate") or 0.0) <= self.args.max_false_positive_rate
            and not (advisor_evolved and metrics.get("reported_result_count") == 0)
        )
        return {
            "evaluator": "run_evolution.py fixed meta evaluator",
            "isolated_from_candidate_agent_memory": True,
            "round_no": round_no,
            "direction": self.args.direction,
            "score": score,
            "decision": "pass" if passed else "continue",
            "passed": passed,
            "advisor_memory_evolved": advisor_evolved,
            "guardrails": [
                "promotion is based on this fixed evaluator and rule metrics",
                "candidate advisor memory is not loaded by the evaluator",
                "do not reward relaxed scanner review standards",
            ],
            "risks": risks,
            "metrics": metrics,
        }

    def write_round_report(self, result: RoundResult) -> None:
        round_root = self.experiment_root / "rounds" / f"round-{result.round_no}"
        _json_dump(round_root / "round-report.json", {
            "round_no": result.round_no,
            "candidate_roots": result.candidate_roots,
            "derived_tasks": result.derived_tasks,
            "metrics": result.metrics,
            "score": result.score,
            "meta_evaluation": result.meta_evaluation,
        })
        for agent_id, root in result.candidate_roots.items():
            Path(root, "memory", f"evolution-round-{result.round_no}-meta.md").write_text(
                "# Evolution Round Meta Evaluation\n\n"
                f"```json\n{json.dumps(result.meta_evaluation, ensure_ascii=False, indent=2)}\n```\n",
                encoding="utf-8",
            )

    def write_experiment_summary(self, *, status: str, sources: list[SourceSpec], best_round: int | None = None) -> None:
        _json_dump(self.report_path, {
            "experiment_id": self.experiment_id,
            "project_id": self.args.project_id,
            "direction": self.args.direction,
            "status": status,
            "created_or_updated_at": _now_iso(),
            "agents": self.agents,
            "source_tasks": [source.__dict__ for source in sources],
            "rounds": [
                {
                    "round_no": item.round_no,
                    "score": item.score,
                    "passed": item.passed,
                    "candidate_roots": item.candidate_roots,
                    "metrics": item.metrics,
                    "meta_evaluation": item.meta_evaluation,
                    "derived_tasks": item.derived_tasks,
                }
                for item in self.round_results
            ],
            "best_round": best_round,
        })

    def promote(self, best: RoundResult) -> None:
        promoted_root = self.agent_state_root / "promoted-evolution-cli" / _safe_component(self.experiment_id) / f"round-{best.round_no}"
        promoted_roots: dict[str, str] = {}
        for agent_id, candidate_root in best.candidate_roots.items():
            destination = promoted_root / agent_id
            if destination.exists():
                shutil.rmtree(destination)
            destination.mkdir(parents=True, exist_ok=True)
            source_memory = Path(candidate_root) / "memory"
            if source_memory.is_dir():
                shutil.copytree(source_memory, destination / "memory", dirs_exist_ok=True)
            else:
                (destination / "memory").mkdir(parents=True, exist_ok=True)
            promoted_roots[agent_id] = str(destination)
        payload = {
            "project_id": self.args.project_id,
            "mode": "evolution",
            "enabled_agents": list(promoted_roots.keys()),
            "promoted_task_id": f"cli:{self.experiment_id}",
            "promoted_round": best.round_no,
            "agent_state_roots": promoted_roots,
            "updated_at": _now_iso(),
        }
        self.memory_mode_path.parent.mkdir(parents=True, exist_ok=True)
        _json_dump(self.memory_mode_path, payload)
        print(f"  promoted memory-mode: {self.memory_mode_path}")

    def disable_memory_mode(self) -> None:
        payload = {
            "project_id": self.args.project_id,
            "mode": "shared",
            "enabled_agents": [],
            "agent_state_roots": {},
            "updated_at": _now_iso(),
        }
        self.memory_mode_path.parent.mkdir(parents=True, exist_ok=True)
        _json_dump(self.memory_mode_path, payload)
        print(f"✅ memory-mode disabled: {self.memory_mode_path}")

    def show_memory_mode(self) -> None:
        if not self.memory_mode_path.is_file():
            print(f"memory-mode file not found: {self.memory_mode_path}")
            return
        print(self.memory_mode_path.read_text(encoding="utf-8"))

    @property
    def memory_mode_path(self) -> Path:
        return self.agent_state_root / "evolution-memory-mode.json"

    def project_visible_path(self, absolute_path: Path) -> str:
        resolved = absolute_path.resolve()
        try:
            relative = resolved.relative_to(self.project_root)
        except ValueError as exc:
            raise RuntimeError(f"path escapes project root: {absolute_path}") from exc
        return "/" + relative.as_posix()


def _drop_empty(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if value not in (None, "", [], {})}


def _as_int(value: Any, fallback: int) -> int:
    try:
        if value is None:
            return fallback
        return int(value)
    except Exception:
        return fallback


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="数据流漏洞挖掘自进化调试启动器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 用勾选的漏洞结果反查原始 normal 任务，进化 worker + advisor memory
  python3 run_evolution.py \\
    --project-id default \\
    --direction "降低命令注入误报，不要牺牲真实高危漏洞" \\
    --selected-result case-1 --selected-result case-2 \\
    --token "$TOKEN" \\
    --max-rounds 3

  # 不经过漏洞平台，直接指定一个或多个原始 normal task 调试
  python3 run_evolution.py \\
    --project-id default \\
    --direction "不要上报 web 模块里的路径遍历类结果" \\
    --source-task tt-source-1,tt-source-2 \\
    --expected-result-count 4 \\
    --dry-run

  # 只进化 pi-worker，跑完后把最佳 memory 晋级为项目 evolution memory
  python3 run_evolution.py \\
    --project-id default \\
    --direction "降低误报率" \\
    --source-task tt-source-1 \\
    --evolve-agents pi-worker \\
    --promote

  # 关闭生产扫描的 evolution memory 开关，恢复 shared memory
  python3 run_evolution.py --project-id default --disable-memory-mode
""",
    )
    parser.add_argument("--project-id", required=True, help="项目 id；用于定位 /data/files/<project_id> 以及 REST 创建 replay 任务")
    parser.add_argument("--direction", default="", help="进化方向；会写入 candidate memory 和 meta evaluator 报告")
    parser.add_argument("--selected-result", action="append", help="勾选的漏洞结果 id；可重复，也可逗号分隔")
    parser.add_argument("--selected-results-file", help="漏洞结果 id 文件；每行一个 id，或 CSV")
    parser.add_argument("--source-task", action="append", help="原始 dataflow normal task id；可重复，也可逗号分隔；用于绕过漏洞平台直接调试")
    parser.add_argument("--source-tasks-file", help="原始 normal task id 文件；每行一个 id，或 CSV")
    parser.add_argument("--auto-expand-source-results", action="store_true", help="通过漏洞平台把同一 source task 的所有结果都计入 baseline expected count")
    parser.add_argument("--expected-result-count", type=int, default=0, help="直接用 --source-task 且无法读取 latest_run.result_count 时使用的 baseline 结果数")
    parser.add_argument("--skip-source-validation", action="store_true", help="跳过 replay-ready/get_task 预检；主要用于 --source-task + --dry-run 调试 payload")

    parser.add_argument("--dataflow-base-url", default="http://secflow-app-dataflow-vuln-scanner", help="dataflow-vuln-scanner 服务 base URL")
    parser.add_argument("--dataflow-api-prefix", default="/api/dataflow-vuln-scanner", help="dataflow-vuln-scanner API 前缀")
    parser.add_argument("--vuln-base-url", default="http://secflow-platform-vuln", help="漏洞平台 base URL；使用 --selected-result 时需要")
    parser.add_argument("--vuln-api-prefix", default="/api/vuln", help="漏洞平台 API 前缀")
    parser.add_argument("--token", default=None, help="访问服务的 Authorization token；可带或不带 Bearer 前缀")
    parser.add_argument("--token-file", default=None, help="从文件读取 Authorization token")
    parser.add_argument("--http-timeout", type=int, default=60, help="单次 REST 请求超时秒数")

    parser.add_argument("--workspace-root", default="/data/files", help="项目文件根目录；最终项目根为 <workspace-root>/<project-id>")
    parser.add_argument("--dataflow-subproject-name", default="DATAFLOW_VULN_SCANNER", help="dataflow scanner 文件子项目名")
    parser.add_argument("--experiment-id", default=None, help="实验 id；默认自动生成 evo-cli-<timestamp>-<suffix>")
    parser.add_argument("--evolve-agents", default="pi-worker,pi-advisor", help="要进化的 agent，逗号分隔；支持 pi-worker、pi-advisor")
    parser.add_argument("--max-rounds", type=int, default=3, help="最大进化轮数")
    parser.add_argument("--min-rounds", type=int, default=1, help="最小进化轮数；达到后 meta evaluator 通过才会提前停止")
    parser.add_argument("--max-concurrent-source-tasks", type=int, default=4, help="每轮并发 replay 的 source task 数")
    parser.add_argument("--poll-interval-seconds", type=int, default=5, help="轮询 derived replay task 状态的间隔秒数")
    parser.add_argument("--derived-timeout-seconds", type=int, default=7200, help="单个 derived replay task 的最大等待秒数")

    parser.add_argument("--profile-id", default=None, help="覆盖 replay 使用的 dataflow scan profile id；默认沿用源任务")
    parser.add_argument("--model", default=None, help="覆盖 replay 使用的模型，如 icsl/zai-org/GLM-5；默认沿用源任务")
    parser.add_argument("--provider", default=None, help="可选 provider；通常 model 已带 provider 时不需要")
    parser.add_argument("--review-profile", default=None, help="覆盖 replay 使用的 review profile，如 fast/balanced/audit")
    parser.add_argument("--agent-run-timeout-seconds", type=int, default=None, help="覆盖 replay 单次 agent 运行超时")
    parser.add_argument("--auto-report-vulnerabilities", action="store_true", help="让 replay 自动写入漏洞池；默认关闭，避免污染正式结果")

    parser.add_argument("--seed-from-source-memory", action=argparse.BooleanOptionalAction, default=True, help="第一轮是否复制源任务 agent memory 作为 seed")
    parser.add_argument("--memory-note", default=None, help="额外追加到每轮 candidate memory 的 markdown 文件")
    parser.add_argument("--pass-score-threshold", type=int, default=800, help="meta evaluator 通过所需最低规则分")
    parser.add_argument("--max-false-negative-rate", type=float, default=0.05, help="meta evaluator 允许的最大漏报率")
    parser.add_argument("--max-false-positive-rate", type=float, default=0.20, help="meta evaluator 允许的最大误报率")

    parser.add_argument("--dry-run", action="store_true", help="只生成 candidate memory 和 replay payload，不实际创建 replay 任务")
    parser.add_argument("--promote", action="store_true", help="运行结束后把最佳 round 的 memory 晋级到 promoted-evolution-cli 并写入 memory-mode")
    parser.add_argument("--disable-memory-mode", action="store_true", help="写入 shared memory-mode 并退出，用于恢复普通 shared memory")
    parser.add_argument("--show-memory-mode", action="store_true", help="打印当前项目 evolution-memory-mode.json 并退出")
    return parser


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.max_rounds < 1:
        parser.error("--max-rounds 必须 >= 1")
    if args.min_rounds < 1:
        parser.error("--min-rounds 必须 >= 1")
    if args.min_rounds > args.max_rounds:
        parser.error("--min-rounds 不能大于 --max-rounds")
    if args.max_concurrent_source_tasks < 1:
        parser.error("--max-concurrent-source-tasks 必须 >= 1")
    if args.poll_interval_seconds < 1:
        parser.error("--poll-interval-seconds 必须 >= 1")
    if args.derived_timeout_seconds < 1:
        parser.error("--derived-timeout-seconds 必须 >= 1")
    if args.expected_result_count < 0:
        parser.error("--expected-result-count 必须 >= 0")
    if args.dry_run and args.promote:
        parser.error("--dry-run 不能和 --promote 同时使用")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(args, parser)
    try:
        return EvolutionCliRunner(args).run()
    except KeyboardInterrupt:
        print("\n⚠️ interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
