from __future__ import annotations

from fastapi import APIRouter, Query
from fastapi.responses import FileResponse

from app.schemas import ArtifactContentResponse
from app.services.artifact_service import get_artifact_service

router = APIRouter()


@router.get("/artifacts/{artifact_id}/content", response_model=ArtifactContentResponse)
def get_artifact_content(
    artifact_id: str,
    max_bytes: int = Query(default=512000, ge=1, le=8 * 1024 * 1024),
) -> ArtifactContentResponse:
    return get_artifact_service().get_artifact_content(artifact_id, max_bytes=max_bytes)


@router.get("/artifacts/{artifact_id}/download")
def download_artifact(artifact_id: str) -> FileResponse:
    artifact, path = get_artifact_service().resolve_artifact(artifact_id)
    return FileResponse(path, media_type=artifact["content_type"], filename=artifact["display_name"])

