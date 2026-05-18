from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status

from app.core.auth import Subject, get_current_subject
from app.schemas import SuccessResponse, TaskTemplateCreateRequest, TaskTemplateResponse, TaskTemplateUpdateRequest
from app.services.template_service import get_template_service

router = APIRouter()


@router.get("/templates", response_model=list[TaskTemplateResponse])
def list_templates(workspace_id: str | None = Query(default=None)) -> list[TaskTemplateResponse]:
    return get_template_service().list_templates(workspace_id=workspace_id)


@router.get("/templates/{template_id}", response_model=TaskTemplateResponse)
def get_template(template_id: str) -> TaskTemplateResponse:
    return get_template_service().get_template(template_id)


@router.post("/templates", response_model=TaskTemplateResponse, status_code=status.HTTP_201_CREATED)
def create_template(
    payload: TaskTemplateCreateRequest,
    subject: Subject = Depends(get_current_subject),
) -> TaskTemplateResponse:
    return get_template_service().create_template(payload, subject)


@router.put("/templates/{template_id}", response_model=TaskTemplateResponse)
def update_template(
    template_id: str,
    payload: TaskTemplateUpdateRequest,
    subject: Subject = Depends(get_current_subject),
) -> TaskTemplateResponse:
    return get_template_service().update_template(template_id, payload, subject)


@router.delete("/templates/{template_id}", response_model=SuccessResponse)
def delete_template(template_id: str) -> SuccessResponse:
    get_template_service().delete_template(template_id)
    return SuccessResponse(success=True, message="template deleted")
