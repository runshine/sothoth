"""Public authenticated intake and SDK endpoints."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from sqlalchemy.orm import Session

from app.api.config import DEFAULT_VULN_ENGINE_CONFIG
from app.api.dependencies import ensure_project_access, get_current_subject, get_optional_subject
from app.models.database import get_db
from app.models.database import EngineProjectConfig
from app.schemas import PublicIntakeSubmissionRequest
from app.services.lifecycle_engine import build_case_fileserver_root
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
    "openapi": SDK_DIRS["openapi"] / "authenticated-intake-openapi.json",
}


def _deep_merge(base: dict, override: dict) -> dict:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _normalize_project_config(config_value: object) -> dict:
    if not isinstance(config_value, dict):
        return json.loads(json.dumps(DEFAULT_VULN_ENGINE_CONFIG, ensure_ascii=False))
    return _deep_merge(DEFAULT_VULN_ENGINE_CONFIG, config_value)


def _intake_requires_project_token_auth(db: Session, project_id: str) -> bool:
    record = db.query(EngineProjectConfig).filter(EngineProjectConfig.project_id == project_id).first()
    raw_config = {}
    if record and record.config_json:
        try:
            raw_config = json.loads(record.config_json)
        except json.JSONDecodeError:
            raw_config = {}
    config = _normalize_project_config(raw_config)
    return bool((config.get("receive") or {}).get("intake_require_project_token_auth"))


def _assert_project_token_subject(subject: dict, project_id: str) -> None:
    if str(subject.get("token_type") or "").strip().lower() != "machine":
        raise HTTPException(status_code=403, detail="当前项目要求使用项目 Token 上报")
    if str(subject.get("token_scope") or "").strip().lower() != "project":
        raise HTTPException(status_code=403, detail="当前项目要求使用项目级 Token 上报")
    if str(subject.get("project_id") or "").strip() != str(project_id or "").strip():
        raise HTTPException(status_code=403, detail="项目 Token 未绑定当前项目")


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
    openapi_path = SDK_DIRS["openapi"] / "authenticated-intake-openapi.json"

    return {
        "version": "2.1.0",
        "authenticated_submission_endpoint": str(request.url_for("submit_authenticated_submission")),
        "items": [
            {
                "kind": "cli",
                "title": "CLI 命令行上报",
                "description": "适合 Shell、CI/CD、批处理脚本和运维自动化场景。",
                "anonymous_access": False,
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
                "anonymous_access": False,
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
                "anonymous_access": False,
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
                "anonymous_access": False,
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
    path = SDK_DIRS["openapi"] / "authenticated-intake-openapi.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="OpenAPI spec not found")
    return FileResponse(path, media_type="application/json", filename=path.name)


@router.get("/intake/examples/{kind}", name="get_public_example")
async def get_public_example(kind: str):
    example_path = EXAMPLE_FILES.get(kind)
    if example_path is None:
        raise HTTPException(status_code=404, detail=f"unsupported example kind: {kind}")
    return JSONResponse(_read_json_file(example_path))


@router.post("/intake/submissions", name="submit_authenticated_submission")
async def submit_authenticated_submission(
    request: PublicIntakeSubmissionRequest,
    user_and_token: tuple[dict, str] | None = Depends(get_optional_subject),
    db: Session = Depends(get_db),
):
    requires_project_token_auth = _intake_requires_project_token_auth(db, request.project_id)
    subject: dict | None = None
    token: str | None = None
    creator = request.reporter.name
    created_by = creator
    created_by_type = "service" if getattr(request.reporter, "type", None) == "service" else "human"

    if requires_project_token_auth:
        if user_and_token is None:
            raise HTTPException(status_code=401, detail="当前项目要求使用项目 Token 认证后才能上报")
        subject, token = user_and_token
        _assert_project_token_subject(subject, request.project_id)
        await ensure_project_access(request.project_id, token)
        creator = subject.get("username") or str(subject.get("id")) or request.reporter.name
        if getattr(request.reporter, "type", None) == "service":
            created_by_type = "service"
            created_by = request.reporter.name
        else:
            created_by_type = "human"
            created_by = creator
    elif user_and_token is not None:
        subject, token = user_and_token
        await ensure_project_access(request.project_id, token)
        creator = subject.get("username") or str(subject.get("id")) or request.reporter.name
        if getattr(request.reporter, "type", None) == "service":
            created_by_type = "service"
            created_by = request.reporter.name
        else:
            created_by_type = "human"
            created_by = creator

    item = create_case_with_runtime(
        db,
        request.to_case_create_request(
            created_by_type=created_by_type,
            created_by=created_by,
            anonymous_submission=not requires_project_token_auth and user_and_token is None,
        ),
    )
    source_meta = json.loads(item.source_meta_json or "{}")
    duplicate = bool(request.report_id and str(source_meta.get("report_id") or "").strip() == str(request.report_id or "").strip())
    return {
        "id": item.id,
        "global_vuln_id": item.global_vuln_id or source_meta.get("global_vuln_id"),
        "project_id": item.project_id,
        "duplicate": duplicate,
        "files_root_path": build_case_fileserver_root(item.id)["root_path"],
        "fileserver_root": build_case_fileserver_root(item.id),
        "title": item.title,
        "current_stage": item.current_stage,
        "current_status": item.current_status,
        "decision_status": item.decision_status,
        "created_by_type": item.created_by_type,
        "created_by": item.created_by,
    }
