"""Public anonymous intake and SDK endpoints."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from sqlalchemy.orm import Session

from app.models.database import get_db
from app.schemas import PublicIntakeSubmissionRequest
from app.services.lifecycle_engine import create_case_with_runtime


router = APIRouter(prefix="/api/vuln/public", tags=["public"])

ASSETS_ROOT = Path(__file__).resolve().parents[1] / "public_assets" / "intake-sdk"
SDK_DIRS = {
    "cli": ASSETS_ROOT / "cli",
    "plugin": ASSETS_ROOT / "plugin",
    "skill": ASSETS_ROOT / "skill",
    "openapi": ASSETS_ROOT / "openapi",
}
SDK_FILENAMES = {
    "cli": "secflow-vuln-cli-sdk.zip",
    "plugin": "secflow-vuln-plugin-sdk.zip",
    "skill": "secflow-vuln-skill-sdk.zip",
}
EXAMPLE_FILES = {
    "cli": SDK_DIRS["cli"] / "example-command.json",
    "plugin": SDK_DIRS["plugin"] / "example-payload.json",
    "skill": SDK_DIRS["skill"] / "example-skill-call.json",
    "openapi": SDK_DIRS["openapi"] / "anonymous-intake-openapi.json",
}


def _iter_files(base_dir: Path) -> list[Path]:
    if not base_dir.exists():
        raise HTTPException(status_code=404, detail=f"asset directory missing: {base_dir.name}")
    return sorted(path for path in base_dir.rglob("*") if path.is_file())


def _build_zip_bytes(base_dir: Path) -> bytes:
    file_buffer = io.BytesIO()
    with ZipFile(file_buffer, "w", compression=ZIP_DEFLATED) as archive:
        for file_path in _iter_files(base_dir):
            archive.write(file_path, arcname=file_path.relative_to(base_dir))
    return file_buffer.getvalue()


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _catalog_payload(request: Request) -> dict:
    cli_zip = _build_zip_bytes(SDK_DIRS["cli"])
    plugin_zip = _build_zip_bytes(SDK_DIRS["plugin"])
    skill_zip = _build_zip_bytes(SDK_DIRS["skill"])
    openapi_path = SDK_DIRS["openapi"] / "anonymous-intake-openapi.json"

    return {
        "version": "1.0.0",
        "anonymous_submission_endpoint": str(request.url_for("submit_anonymous_submission")),
        "items": [
            {
                "kind": "cli",
                "title": "CLI 命令行上报",
                "description": "适合 Shell、CI/CD、批处理脚本和运维自动化场景。",
                "anonymous_access": True,
                "download_url": str(request.url_for("download_cli_sdk")),
                "example_url": str(request.url_for("get_public_example", kind="cli")),
                "filename": SDK_FILENAMES["cli"],
                "sha256": _sha256_bytes(cli_zip),
                "channels": ["terminal", "ci", "script"],
            },
            {
                "kind": "plugin",
                "title": "插件开发上报",
                "description": "适合扫描器插件、分析器插件和其他微服务直接集成。",
                "anonymous_access": True,
                "download_url": str(request.url_for("download_plugin_sdk")),
                "example_url": str(request.url_for("get_public_example", kind="plugin")),
                "filename": SDK_FILENAMES["plugin"],
                "sha256": _sha256_bytes(plugin_zip),
                "channels": ["plugin", "service", "integration"],
            },
            {
                "kind": "skill",
                "title": "AI Agent Skill 上报",
                "description": "同时提供 Markdown Skill 包与 JSON/OpenAPI 模板，适合 AI Agent 与 Skill 调用。",
                "anonymous_access": True,
                "download_url": str(request.url_for("download_skill_sdk")),
                "example_url": str(request.url_for("get_public_example", kind="skill")),
                "filename": SDK_FILENAMES["skill"],
                "sha256": _sha256_bytes(skill_zip),
                "channels": ["agent", "skill", "llm"],
            },
            {
                "kind": "openapi",
                "title": "JSON/OpenAPI 结构化接入",
                "description": "适合程序化调用、API 生成器与接口联调。",
                "anonymous_access": True,
                "download_url": str(request.url_for("get_public_openapi_spec")),
                "example_url": str(request.url_for("get_public_example", kind="openapi")),
                "filename": openapi_path.name,
                "sha256": _sha256_file(openapi_path),
                "channels": ["api", "openapi", "schema"],
            },
        ],
    }


def _read_json_file(path: Path) -> dict:
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"example missing: {path.name}")
    return json.loads(path.read_text(encoding="utf-8"))


@router.get("/intake/catalog", name="get_public_intake_catalog")
async def get_public_intake_catalog(request: Request):
    return _catalog_payload(request)


@router.get("/intake/sdk/cli", name="download_cli_sdk")
async def download_cli_sdk():
    archive = _build_zip_bytes(SDK_DIRS["cli"])
    return StreamingResponse(
        io.BytesIO(archive),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{SDK_FILENAMES["cli"]}"'},
    )


@router.get("/intake/sdk/plugin", name="download_plugin_sdk")
async def download_plugin_sdk():
    archive = _build_zip_bytes(SDK_DIRS["plugin"])
    return StreamingResponse(
        io.BytesIO(archive),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{SDK_FILENAMES["plugin"]}"'},
    )


@router.get("/intake/sdk/skill", name="download_skill_sdk")
async def download_skill_sdk():
    archive = _build_zip_bytes(SDK_DIRS["skill"])
    return StreamingResponse(
        io.BytesIO(archive),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{SDK_FILENAMES["skill"]}"'},
    )


@router.get("/intake/spec/openapi", name="get_public_openapi_spec")
async def get_public_openapi_spec():
    path = SDK_DIRS["openapi"] / "anonymous-intake-openapi.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="OpenAPI spec not found")
    return FileResponse(path, media_type="application/json", filename=path.name)


@router.get("/intake/examples/{kind}", name="get_public_example")
async def get_public_example(kind: str):
    example_path = EXAMPLE_FILES.get(kind)
    if example_path is None:
        raise HTTPException(status_code=404, detail=f"unsupported example kind: {kind}")
    return JSONResponse(_read_json_file(example_path))


@router.post("/intake/submissions", name="submit_anonymous_submission")
async def submit_anonymous_submission(request: PublicIntakeSubmissionRequest, db: Session = Depends(get_db)):
    item = create_case_with_runtime(db, request.to_case_create_request())
    return {
        "id": item.id,
        "project_id": item.project_id,
        "title": item.title,
        "current_stage": item.current_stage,
        "current_status": item.current_status,
        "decision_status": item.decision_status,
        "created_by_type": item.created_by_type,
        "created_by": item.created_by,
    }
