"""Prompt template endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.model import get_db
from app.schemas import (
    MessageResponse,
    PromptTemplateCloneRequest,
    PromptTemplateCreateRequest,
    PromptTemplateListResponse,
    PromptTemplateResponse,
    PromptTemplateUpdateRequest,
)
from app.service.prompt_service import get_prompt_service

router = APIRouter(prefix="/prompts")


@router.get("", response_model=PromptTemplateListResponse)
def list_prompts(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=200),
    category: Optional[str] = Query(None),
    keyword: Optional[str] = Query(None),
    is_enabled: Optional[bool] = Query(None),
    user_and_token=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _user, _token = user_and_token
    return get_prompt_service().list_prompts(
        db,
        page=page,
        per_page=per_page,
        category=category,
        keyword=keyword,
        is_enabled=is_enabled,
    )


@router.post("", response_model=PromptTemplateResponse)
def create_prompt(
    payload: PromptTemplateCreateRequest,
    user_and_token=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user, _token = user_and_token
    username = str(user.get("username") or user.get("user", {}).get("username") or "system")
    return get_prompt_service().create_prompt(db, payload, username)


@router.get("/{prompt_id}", response_model=PromptTemplateResponse)
def get_prompt(
    prompt_id: str,
    user_and_token=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _user, _token = user_and_token
    return get_prompt_service().get_prompt(db, prompt_id)


@router.put("/{prompt_id}", response_model=PromptTemplateResponse)
def update_prompt(
    prompt_id: str,
    payload: PromptTemplateUpdateRequest,
    user_and_token=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user, _token = user_and_token
    username = str(user.get("username") or user.get("user", {}).get("username") or "system")
    return get_prompt_service().update_prompt(db, prompt_id, payload, username)


@router.delete("/{prompt_id}", response_model=MessageResponse)
def delete_prompt(
    prompt_id: str,
    user_and_token=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _user, _token = user_and_token
    get_prompt_service().delete_prompt(db, prompt_id)
    return MessageResponse(message="deleted")


@router.post("/{prompt_id}/clone", response_model=PromptTemplateResponse)
def clone_prompt(
    prompt_id: str,
    payload: PromptTemplateCloneRequest,
    user_and_token=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user, _token = user_and_token
    username = str(user.get("username") or user.get("user", {}).get("username") or "system")
    return get_prompt_service().clone_prompt(db, prompt_id, payload, username)

