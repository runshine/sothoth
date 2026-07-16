"""Prompt template management: CRUD for reusable poc prompt templates.

Templates stored in DB table secflow_app_poc_prompt_templates.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models import AppPocPromptTemplate
from app.time_utils import isoformat_local

logger = logging.getLogger("poc.prompt_service")


def _row_to_dict(row: AppPocPromptTemplate) -> dict:
    return {
        "id": row.id,
        "prompt_id": row.prompt_id,
        "name": row.name,
        "category": row.category,
        "description": row.description,
        "content": row.content,
        "variables": row.variables_json or [],
        "version": row.version,
        "is_default": row.is_default,
        "is_enabled": row.is_enabled,
        "created_by": row.created_by,
        "updated_by": row.updated_by,
        "created_at": isoformat_local(row.created_at),
        "updated_at": isoformat_local(row.updated_at),
    }


def list_templates(db: Session, *, category: Optional[str] = None,
                   page: int = 1, per_page: int = 100) -> dict:
    q = db.query(AppPocPromptTemplate).filter(AppPocPromptTemplate.is_deleted.is_(False))
    if category:
        q = q.filter(AppPocPromptTemplate.category == category)
    total = q.count()
    rows = q.order_by(AppPocPromptTemplate.id.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return {"items": [_row_to_dict(r) for r in rows], "total": total}


def get_template(db: Session, prompt_id: str) -> dict:
    row = db.query(AppPocPromptTemplate).filter_by(
        prompt_id=prompt_id, is_deleted=False
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Prompt template not found: {prompt_id}")
    return _row_to_dict(row)


def create_template(db: Session, *, prompt_id: str, name: str, content: str,
                    category: str = "general", description: Optional[str] = None,
                    variables: Optional[List[str]] = None,
                    is_default: bool = False, is_enabled: bool = True,
                    created_by: Optional[str] = None) -> dict:
    existing = db.query(AppPocPromptTemplate).filter_by(prompt_id=prompt_id).first()
    if existing and not existing.is_deleted:
        raise HTTPException(status_code=409, detail=f"Prompt ID already exists: {prompt_id}")
    row = AppPocPromptTemplate(
        prompt_id=prompt_id, name=name, category=category, description=description,
        content=content, variables_json=variables or [],
        is_default=is_default, is_enabled=is_enabled, created_by=created_by,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    logger.info("created prompt template: %s", prompt_id)
    return _row_to_dict(row)


def update_template(db: Session, prompt_id: str, updates: dict) -> dict:
    row = db.query(AppPocPromptTemplate).filter_by(
        prompt_id=prompt_id, is_deleted=False
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Prompt template not found: {prompt_id}")
    for key, val in updates.items():
        if val is None:
            continue
        if key == "name":
            row.name = val
        elif key == "category":
            row.category = val
        elif key == "description":
            row.description = val
        elif key == "content":
            row.content = val
            row.version = int(row.version or 1) + 1
        elif key == "variables":
            row.variables_json = val
        elif key == "is_default":
            row.is_default = val
        elif key == "is_enabled":
            row.is_enabled = val
    db.commit()
    db.refresh(row)
    return _row_to_dict(row)


def delete_template(db: Session, prompt_id: str) -> dict:
    row = db.query(AppPocPromptTemplate).filter_by(
        prompt_id=prompt_id, is_deleted=False
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Prompt template not found: {prompt_id}")
    row.is_deleted = True
    db.commit()
    return {"status": "ok", "prompt_id": prompt_id, "message": "deleted"}
