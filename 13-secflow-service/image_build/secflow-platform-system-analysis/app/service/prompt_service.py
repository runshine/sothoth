"""Prompt template service."""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy.orm import Session

from app.exception import NotFoundError
from app.model import SystemAnalysisPrompt
from app.schemas import (
    PromptTemplateCloneRequest,
    PromptTemplateCreateRequest,
    PromptTemplateListItem,
    PromptTemplateListResponse,
    PromptTemplateResponse,
    PromptTemplateUpdateRequest,
)


class PromptService:
    def list_prompts(
        self,
        db: Session,
        *,
        page: int = 1,
        per_page: int = 20,
        category: Optional[str] = None,
        keyword: Optional[str] = None,
        is_enabled: Optional[bool] = None,
    ) -> PromptTemplateListResponse:
        query = db.query(SystemAnalysisPrompt).filter(SystemAnalysisPrompt.is_deleted.is_(False))
        if category:
            query = query.filter(SystemAnalysisPrompt.category == category)
        if keyword:
            like = f"%{keyword}%"
            query = query.filter(
                (SystemAnalysisPrompt.name.like(like)) | (SystemAnalysisPrompt.description.like(like))
            )
        if is_enabled is not None:
            query = query.filter(SystemAnalysisPrompt.is_enabled.is_(is_enabled))

        total = query.count()
        rows = (
            query.order_by(SystemAnalysisPrompt.updated_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )
        items = [
            PromptTemplateListItem(
                prompt_id=row.prompt_id,
                name=row.name,
                category=row.category,
                description=row.description,
                version=row.version,
                is_default=bool(row.is_default),
                is_enabled=bool(row.is_enabled),
                updated_at=row.updated_at,
            )
            for row in rows
        ]
        return PromptTemplateListResponse(items=items, page=page, per_page=per_page, total=total)

    def get_prompt(self, db: Session, prompt_id: str) -> PromptTemplateResponse:
        row = (
            db.query(SystemAnalysisPrompt)
            .filter(SystemAnalysisPrompt.prompt_id == prompt_id, SystemAnalysisPrompt.is_deleted.is_(False))
            .first()
        )
        if not row:
            raise NotFoundError("Prompt模板", prompt_id)
        return self._to_response(row)

    def create_prompt(self, db: Session, payload: PromptTemplateCreateRequest, username: str) -> PromptTemplateResponse:
        if payload.is_default:
            self._unset_default(db)
        row = SystemAnalysisPrompt(
            prompt_id=f"tpl_{uuid.uuid4().hex[:12]}",
            name=payload.name,
            category=payload.category,
            description=payload.description,
            content=payload.content,
            variables_json=payload.variables_json,
            version=1,
            is_default=payload.is_default,
            is_enabled=payload.is_enabled,
            created_by=username,
            updated_by=username,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return self._to_response(row)

    def update_prompt(self, db: Session, prompt_id: str, payload: PromptTemplateUpdateRequest, username: str) -> PromptTemplateResponse:
        row = (
            db.query(SystemAnalysisPrompt)
            .filter(SystemAnalysisPrompt.prompt_id == prompt_id, SystemAnalysisPrompt.is_deleted.is_(False))
            .first()
        )
        if not row:
            raise NotFoundError("Prompt模板", prompt_id)

        data = payload.model_dump(exclude_unset=True)
        if data.get("is_default") is True:
            self._unset_default(db)
        for key, value in data.items():
            setattr(row, key, value)
        row.version = int(row.version or 1) + 1
        row.updated_by = username

        db.add(row)
        db.commit()
        db.refresh(row)
        return self._to_response(row)

    def delete_prompt(self, db: Session, prompt_id: str) -> None:
        row = (
            db.query(SystemAnalysisPrompt)
            .filter(SystemAnalysisPrompt.prompt_id == prompt_id, SystemAnalysisPrompt.is_deleted.is_(False))
            .first()
        )
        if not row:
            raise NotFoundError("Prompt模板", prompt_id)
        row.is_deleted = True
        row.is_default = False
        db.add(row)
        db.commit()

    def clone_prompt(self, db: Session, prompt_id: str, payload: PromptTemplateCloneRequest, username: str) -> PromptTemplateResponse:
        row = (
            db.query(SystemAnalysisPrompt)
            .filter(SystemAnalysisPrompt.prompt_id == prompt_id, SystemAnalysisPrompt.is_deleted.is_(False))
            .first()
        )
        if not row:
            raise NotFoundError("Prompt模板", prompt_id)

        clone = SystemAnalysisPrompt(
            prompt_id=f"tpl_{uuid.uuid4().hex[:12]}",
            name=payload.name,
            category=row.category,
            description=row.description,
            content=row.content,
            variables_json=row.variables_json,
            version=1,
            is_default=False,
            is_enabled=row.is_enabled,
            created_by=username,
            updated_by=username,
        )
        db.add(clone)
        db.commit()
        db.refresh(clone)
        return self._to_response(clone)

    def _unset_default(self, db: Session):
        rows = db.query(SystemAnalysisPrompt).filter(
            SystemAnalysisPrompt.is_default.is_(True),
            SystemAnalysisPrompt.is_deleted.is_(False),
        )
        for row in rows:
            row.is_default = False
            db.add(row)

    @staticmethod
    def _to_response(row: SystemAnalysisPrompt) -> PromptTemplateResponse:
        return PromptTemplateResponse(
            prompt_id=row.prompt_id,
            name=row.name,
            category=row.category,
            description=row.description,
            content=row.content,
            variables_json=row.variables_json or [],
            version=row.version,
            is_default=bool(row.is_default),
            is_enabled=bool(row.is_enabled),
            created_by=row.created_by,
            updated_by=row.updated_by,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )


_prompt_service: Optional[PromptService] = None


def get_prompt_service() -> PromptService:
    global _prompt_service
    if _prompt_service is None:
        _prompt_service = PromptService()
    return _prompt_service

