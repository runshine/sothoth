import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.models import TemplateTag, get_db
from app.schemas import TemplateTagItem, TemplateTagListResponse, TemplateTagResponse
from app.services.template_tags import ensure_tag

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/template-tags", tags=["Template Tags"])


@router.get("", response_model=TemplateTagListResponse)
async def list_template_tags(
    category: Optional[str] = Query(None),
    enabled: Optional[bool] = Query(True),
    keyword: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(TemplateTag)
    if category:
        query = query.filter(TemplateTag.category == category)
    if enabled is not None:
        query = query.filter(TemplateTag.enabled == enabled)
    if keyword:
        pattern = f"%{keyword.strip()}%"
        query = query.filter(
            (TemplateTag.tag_key.like(pattern)) |
            (TemplateTag.tag_label.like(pattern))
        )
    items = query.order_by(TemplateTag.sort_order.asc(), TemplateTag.tag_label.asc()).all()
    return TemplateTagListResponse(total=len(items), items=items)


@router.post("", response_model=TemplateTagResponse, status_code=status.HTTP_201_CREATED)
async def create_template_tag(
    payload: TemplateTagItem,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user_id = str(current_user.get("id", ""))
    tag = ensure_tag(
        db,
        tag_key=payload.tag_key,
        tag_label=payload.tag_label,
        category=payload.category,
        description=payload.description,
        color=payload.color or "slate",
        is_system=payload.is_system,
        created_by=user_id,
    )
    db.commit()
    db.refresh(tag)
    logger.info("Created template tag %s by user %s", tag.tag_key, user_id)
    return tag
