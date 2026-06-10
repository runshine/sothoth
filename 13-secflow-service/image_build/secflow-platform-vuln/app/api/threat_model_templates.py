"""Threat model template endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.cases import _case_payload, _get_accessible_case
from app.api.dependencies import ensure_project_access, get_current_subject
from app.models.database import get_db
from app.schemas import ThreatModelTemplateRenderRequest
from app.services.threat_model_templates import list_templates, render_template

router = APIRouter(prefix="/api/vuln/threat-model-templates", tags=["threat-model-templates"])


@router.get("")
async def get_threat_model_templates(project_id: str | None = Query(None), user_and_token: tuple[dict, str] = Depends(get_current_subject)):
    _, token = user_and_token
    if project_id:
        await ensure_project_access(project_id, token)
    templates = list_templates(project_id)
    return {"items": templates, "total": len(templates)}


@router.post("/{template_id}/render")
async def render_threat_model_template(
    template_id: str,
    request: ThreatModelTemplateRenderRequest,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    _, token = user_and_token
    item = await _get_accessible_case(request.case_id, token, db)
    try:
        return render_template(template_id, _case_payload(item), request.variables)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="template not found") from exc
