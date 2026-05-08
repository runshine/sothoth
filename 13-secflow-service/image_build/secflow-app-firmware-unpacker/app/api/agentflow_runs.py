"""AgentFlow run control endpoints exposed through firmware-unpacker REST."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import ValidationError

from app.api.dependencies import get_current_subject
from app.config import get_config

_repo_root = Path(__file__).resolve().parents[2]
_local_agentflow = _repo_root / "agentflow"
if _local_agentflow.exists() and str(_local_agentflow) not in sys.path:
    sys.path.insert(0, str(_local_agentflow))

from agentflow.defaults import bundled_template_path
from agentflow.loader import load_pipeline_from_data, load_pipeline_from_path, load_pipeline_from_text
from agentflow.orchestrator import Orchestrator
from agentflow.specs import RunStatus
from agentflow.store import RunStore


router = APIRouter(tags=["AgentFlow Runs"])

_TERMINAL_RUN_STATUSES = {"completed", "failed", "cancelled"}
_runtime_lock = threading.Lock()
_runtime_key: tuple[str, int] | None = None
_runtime_store: RunStore | None = None
_runtime_orchestrator: Orchestrator | None = None


def _api_pipeline_path_enabled() -> bool:
    return os.getenv("AGENTFLOW_API_ALLOW_PIPELINE_PATH", "").strip().lower() in {"1", "true", "yes", "on"}


def _require_json_request(request: Request) -> None:
    content_type = request.headers.get("content-type", "")
    if "application/json" not in content_type.lower():
        raise HTTPException(status_code=415, detail="application/json content type required")


@lru_cache(maxsize=1)
def _load_default_web_example() -> str:
    example_path = bundled_template_path("pipeline")
    project_root = _local_agentflow if _local_agentflow.exists() else _repo_root
    pythonpath = str(project_root)
    existing_pythonpath = os.environ.get("PYTHONPATH")
    if existing_pythonpath:
        pythonpath = f"{project_root}{os.pathsep}{existing_pythonpath}"

    result = subprocess.run(
        [sys.executable, str(example_path)],
        capture_output=True,
        text=True,
        cwd=str(project_root),
        env={**os.environ, "PYTHONPATH": pythonpath},
    )
    if result.returncode != 0:
        raise RuntimeError(f"default pipeline example failed:\n{result.stderr.strip()}")
    return result.stdout.strip()


def _parse_pipeline_payload(payload: dict[str, Any], *, allow_pipeline_path: bool = True):
    try:
        if not isinstance(payload, dict):
            raise ValueError("request body must be a JSON object")

        pipeline_path = payload.get("pipeline_path")
        if isinstance(pipeline_path, str) and pipeline_path.strip():
            if not allow_pipeline_path:
                raise HTTPException(status_code=403, detail="pipeline_path is disabled for the web API by default")
            return load_pipeline_from_path(pipeline_path)

        base_dir = payload.get("base_dir")
        if base_dir is not None and not isinstance(base_dir, (str, os.PathLike)):
            raise ValueError("base_dir must be a string path")
        if "pipeline_text" in payload:
            pipeline_text = payload["pipeline_text"]
            if not isinstance(pipeline_text, str):
                raise ValueError("pipeline_text must be a string")
            return load_pipeline_from_text(pipeline_text, base_dir=base_dir)

        pipeline_data = payload["pipeline"] if "pipeline" in payload else dict(payload)
        if isinstance(pipeline_data, dict):
            pipeline_data = dict(pipeline_data)
            pipeline_data.pop("base_dir", None)
            pipeline_data.pop("pipeline_path", None)
        return load_pipeline_from_data(pipeline_data, base_dir=base_dir)
    except HTTPException:
        raise
    except (ValueError, ValidationError, KeyError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _runtime() -> tuple[RunStore, Orchestrator]:
    global _runtime_key, _runtime_orchestrator, _runtime_store

    config = get_config().agentflow
    key = (str(config.runs_dir), int(config.max_concurrent_runs))
    with _runtime_lock:
        if _runtime_key != key or _runtime_store is None or _runtime_orchestrator is None:
            _runtime_store = RunStore(config.runs_dir)
            _runtime_orchestrator = Orchestrator(
                store=_runtime_store,
                max_concurrent_runs=config.max_concurrent_runs,
            )
            _runtime_key = key
        return _runtime_store, _runtime_orchestrator


def _task_run_store_paths(run_id: str | None = None) -> list[Path]:
    from app.model import UnpackTask, get_db_session

    db = get_db_session()
    try:
        query = db.query(UnpackTask).filter(UnpackTask.agentflow_run_id.isnot(None), UnpackTask.run_path.isnot(None))
        if run_id:
            query = query.filter(UnpackTask.agentflow_run_id == run_id)
        paths: list[Path] = []
        for task in query.all():
            if not task.run_path:
                continue
            paths.append(Path(str(task.run_path)) / "agentflow" / "runs")
        return paths
    finally:
        db.close()


def _stores_for_lookup(run_id: str | None = None) -> list[RunStore]:
    stores = [_runtime()[0]]
    seen = {str(stores[0].base_dir)}
    try:
        task_paths = _task_run_store_paths(run_id)
    except Exception:
        task_paths = []
    for path in task_paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        stores.append(RunStore(path))
    return stores


def _find_store_for_run(run_id: str) -> RunStore:
    for store in _stores_for_lookup(run_id):
        try:
            store.get_run(run_id)
            return store
        except KeyError:
            continue
    raise HTTPException(status_code=404, detail="run not found")


def _run_payload(store: RunStore, run_id: str) -> dict[str, Any]:
    return store.get_run(run_id).model_dump(mode="json")


def _all_run_payloads() -> list[dict[str, Any]]:
    runs_by_id: dict[str, Any] = {}
    for store in _stores_for_lookup():
        for run in store.list_runs():
            runs_by_id[run.id] = run
    runs = sorted(runs_by_id.values(), key=lambda run: run.created_at, reverse=True)
    return [run.model_dump(mode="json") for run in runs]


async def _default_example() -> JSONResponse:
    return JSONResponse({"example": _load_default_web_example(), "base_dir": os.getcwd()})


async def _validate_run(request: Request) -> JSONResponse:
    _require_json_request(request)
    payload = await request.json()
    pipeline = _parse_pipeline_payload(payload, allow_pipeline_path=_api_pipeline_path_enabled())
    return JSONResponse({"ok": True, "pipeline": pipeline.model_dump(mode="json")})


async def _create_run(request: Request) -> JSONResponse:
    _require_json_request(request)
    payload = await request.json()
    pipeline = _parse_pipeline_payload(payload, allow_pipeline_path=_api_pipeline_path_enabled())
    _, orchestrator = _runtime()
    run = await orchestrator.submit(pipeline)
    return JSONResponse(run.model_dump(mode="json"))


async def _list_runs() -> JSONResponse:
    return JSONResponse(_all_run_payloads())


async def _get_run(run_id: str) -> JSONResponse:
    store = _find_store_for_run(run_id)
    return JSONResponse(_run_payload(store, run_id))


async def _cancel_run(run_id: str) -> JSONResponse:
    store, orchestrator = _runtime()
    try:
        run = await orchestrator.cancel(run_id)
        return JSONResponse(run.model_dump(mode="json"))
    except KeyError:
        pass

    store = _find_store_for_run(run_id)
    record = store.get_run(run_id)
    await store.request_cancel(run_id)
    if record.status in {RunStatus.RUNNING, RunStatus.PENDING, RunStatus.QUEUED}:
        record.status = RunStatus.CANCELLING
        await store.persist_run(run_id)
    return JSONResponse(record.model_dump(mode="json"))


async def _rerun(run_id: str) -> JSONResponse:
    store = _find_store_for_run(run_id)
    _, orchestrator = _runtime()
    run = await orchestrator.submit(store.get_run(run_id).pipeline)
    return JSONResponse(run.model_dump(mode="json"))


async def _get_events(run_id: str) -> JSONResponse:
    store = _find_store_for_run(run_id)
    return JSONResponse([event.model_dump(mode="json") for event in store.get_events(run_id)])


async def _get_artifact(run_id: str, node_id: str, name: str) -> PlainTextResponse:
    store = _find_store_for_run(run_id)
    try:
        content = store.read_artifact_text(run_id, node_id, name)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="artifact not found") from exc
    return PlainTextResponse(content)


async def _get_scratchboard(run_id: str) -> PlainTextResponse:
    from agentflow.scratchboard import SCRATCHBOARD_FILENAME

    store = _find_store_for_run(run_id)
    try:
        path = store.run_dir(run_id) / SCRATCHBOARD_FILENAME
        if not path.exists():
            return PlainTextResponse("")
        return PlainTextResponse(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=404, detail="scratchboard not found") from exc


async def _stream_run(run_id: str):
    store = _find_store_for_run(run_id)

    async def event_stream():
        emitted = 0
        while True:
            events = store.get_events(run_id)
            for event in events[emitted:]:
                yield f"data: {event.model_dump_json()}\n\n"
            emitted = len(events)
            run = store.get_run(run_id)
            if run.status.value in _TERMINAL_RUN_STATUSES:
                break
            await asyncio.sleep(0.5)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


async def _health() -> JSONResponse:
    runs = _all_run_payloads()
    return JSONResponse(
        {
            "ok": True,
            "runs": {
                "total": len(runs),
                "queued": sum(run.get("status") == "queued" for run in runs),
                "running": sum(run.get("status") in {"running", "cancelling"} for run in runs),
            },
        }
    )


def _agentflow_dependency(subject_and_token: tuple[dict, str] = Depends(get_current_subject)) -> tuple[dict, str]:
    return subject_and_token


for prefix in ("/api/app/firmware-unpacker/api", "/api/app/firmware-unpacker/agentflow"):
    deps = [Depends(_agentflow_dependency)]
    router.add_api_route(f"{prefix}/examples/default", _default_example, methods=["GET"], dependencies=deps)
    router.add_api_route(f"{prefix}/runs/validate", _validate_run, methods=["POST"], dependencies=deps)
    router.add_api_route(f"{prefix}/runs", _create_run, methods=["POST"], dependencies=deps)
    router.add_api_route(f"{prefix}/runs", _list_runs, methods=["GET"], dependencies=deps)
    router.add_api_route(f"{prefix}/runs/{{run_id}}", _get_run, methods=["GET"], dependencies=deps)
    router.add_api_route(f"{prefix}/runs/{{run_id}}/cancel", _cancel_run, methods=["POST"], dependencies=deps)
    router.add_api_route(f"{prefix}/runs/{{run_id}}/rerun", _rerun, methods=["POST"], dependencies=deps)
    router.add_api_route(f"{prefix}/runs/{{run_id}}/events", _get_events, methods=["GET"], dependencies=deps)
    router.add_api_route(
        f"{prefix}/runs/{{run_id}}/artifacts/{{node_id}}/{{name}}",
        _get_artifact,
        methods=["GET"],
        dependencies=deps,
    )
    router.add_api_route(f"{prefix}/runs/{{run_id}}/scratchboard", _get_scratchboard, methods=["GET"], dependencies=deps)
    router.add_api_route(f"{prefix}/runs/{{run_id}}/stream", _stream_run, methods=["GET"], dependencies=deps)
    router.add_api_route(f"{prefix}/health", _health, methods=["GET"], dependencies=deps)
