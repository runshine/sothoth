import re
from typing import Iterable, List, Optional

from sqlalchemy.orm import Session

from app.api.dependencies import generate_id
from app.exception import ValidationError
from app.models import TemplateTag, TemplateTagBinding

TAG_KEY_PATTERN = re.compile(r"^[a-z0-9-]+$")


def normalize_tag_key(value: str) -> str:
    key = (value or "").strip().lower()
    if not key:
        raise ValidationError("tag_key cannot be empty")
    if not TAG_KEY_PATTERN.match(key):
        raise ValidationError("tag_key only allows lowercase letters, numbers, and hyphen")
    return key


def dedupe_preserve_order(values: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    ordered: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def ensure_tag(
    db: Session,
    *,
    tag_key: str,
    created_by: str,
    tag_label: Optional[str] = None,
    category: str = "capability",
    color: str = "slate",
    description: Optional[str] = None,
    is_system: bool = False,
) -> TemplateTag:
    normalized_key = normalize_tag_key(tag_key)
    tag = db.query(TemplateTag).filter(TemplateTag.tag_key == normalized_key).first()
    if tag:
        return tag

    label = (tag_label or normalized_key).strip() or normalized_key
    tag = TemplateTag(
        id=generate_id(normalized_key),
        tag_key=normalized_key,
        tag_label=label,
        category=category,
        description=description,
        color=color,
        is_system=is_system,
        enabled=True,
        created_by=created_by,
    )
    db.add(tag)
    db.flush()
    return tag


def sync_template_tags(
    db: Session,
    *,
    template_type: str,
    template_id: str,
    tags: Optional[list],
    created_by: str,
) -> None:
    if tags is None:
        return

    normalized_items = []
    for item in tags:
        if isinstance(item, str):
            normalized_items.append({"tag_key": item})
        elif isinstance(item, dict):
            normalized_items.append(item)
        elif hasattr(item, "model_dump"):
            normalized_items.append(item.model_dump())
        elif hasattr(item, "dict"):
            normalized_items.append(item.dict())
        else:
            raise ValidationError("invalid tag payload")

    normalized_keys = dedupe_preserve_order(
        normalize_tag_key(str(item.get("tag_key") or item.get("key") or ""))
        for item in normalized_items
    )

    desired_tags: List[TemplateTag] = []
    for item in normalized_items:
        tag_key = normalize_tag_key(str(item.get("tag_key") or item.get("key") or ""))
        if tag_key not in normalized_keys:
            continue
        tag = ensure_tag(
            db,
            tag_key=tag_key,
            created_by=created_by,
            tag_label=item.get("tag_label") or item.get("label"),
            category=item.get("category") or "capability",
            color=item.get("color") or "slate",
            description=item.get("description"),
            is_system=bool(item.get("is_system", False)),
        )
        if all(existing.id != tag.id for existing in desired_tags):
            desired_tags.append(tag)

    existing_bindings = db.query(TemplateTagBinding).filter(
        TemplateTagBinding.template_type == template_type,
        TemplateTagBinding.template_id == template_id,
    ).all()
    existing_by_tag_id = {binding.tag_id: binding for binding in existing_bindings}
    desired_tag_ids = {tag.id for tag in desired_tags}

    for binding in existing_bindings:
        if binding.tag_id not in desired_tag_ids:
            db.delete(binding)

    for tag in desired_tags:
        if tag.id in existing_by_tag_id:
            continue
        db.add(TemplateTagBinding(
            id=generate_id(f"{template_type}-{template_id}-{tag.tag_key}"),
            template_type=template_type,
            template_id=template_id,
            tag_id=tag.id,
            source="manual",
            created_by=created_by,
        ))


def get_template_tags(db: Session, *, template_type: str, template_ids: List[str]) -> dict[str, list[TemplateTag]]:
    if not template_ids:
        return {}
    bindings = db.query(TemplateTagBinding).join(TemplateTag, TemplateTag.id == TemplateTagBinding.tag_id).filter(
        TemplateTagBinding.template_type == template_type,
        TemplateTagBinding.template_id.in_(template_ids),
        TemplateTag.enabled == True,  # noqa: E712
    ).order_by(TemplateTag.sort_order.asc(), TemplateTag.tag_label.asc()).all()

    grouped: dict[str, list[TemplateTag]] = {}
    for binding in bindings:
        grouped.setdefault(binding.template_id, []).append(binding.tag)
    return grouped


def filter_template_ids_by_tag_keys(
    db: Session,
    *,
    template_type: str,
    tag_keys: List[str],
) -> Optional[List[str]]:
    normalized_keys = dedupe_preserve_order(normalize_tag_key(item) for item in tag_keys if item)
    if not normalized_keys:
        return None

    bindings = db.query(TemplateTagBinding).join(TemplateTag, TemplateTag.id == TemplateTagBinding.tag_id).filter(
        TemplateTagBinding.template_type == template_type,
        TemplateTag.tag_key.in_(normalized_keys),
        TemplateTag.enabled == True,  # noqa: E712
    ).all()
    return dedupe_preserve_order(binding.template_id for binding in bindings)

