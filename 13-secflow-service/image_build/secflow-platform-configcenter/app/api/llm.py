"""LLM provider management APIs."""

import re

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.exception import ConflictError, NotFoundError, ValidationError
from app.model import LlmProvider, get_db
from app.schemas import (
    LlmProviderCreateRequest,
    LlmProviderDetail,
    LlmProviderListResponse,
    LlmProviderServiceListResponse,
    LlmProviderUpdateRequest,
    MessageResponse,
    build_detail_payload,
    build_service_payload,
    build_summary_payload,
)
from app.service.auth import get_current_super_admin, get_machine_client


router = APIRouter(prefix="/api/configcenter", tags=["Config Center"])


def mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    if len(value) <= 8:
        return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"
    return f"{value[:3]}{'*' * (len(value) - 6)}{value[-3:]}"


def normalize_provider_key(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9-_]+", "-", (value or "").strip().lower()).strip("-")
    if not normalized:
        raise ValidationError("provider_key 不能为空，且只能包含小写字母、数字、-、_")
    return normalized


def get_provider_or_404(db: Session, provider_key: str) -> LlmProvider:
    provider = db.query(LlmProvider).filter(LlmProvider.provider_key == provider_key).first()
    if provider is None:
        raise NotFoundError("LLM Provider", provider_key)
    return provider


def ensure_single_default(db: Session, provider: LlmProvider):
    db.query(LlmProvider).filter(LlmProvider.id != provider.id).update({"is_default": False})


def validate_env_bindings(env_bindings: dict):
    for key in env_bindings.keys():
        if not re.match(r"^[A-Z][A-Z0-9_]*$", str(key)):
            raise ValidationError(f"环境变量名不合法: {key}")


def apply_payload(provider: LlmProvider, payload: LlmProviderCreateRequest | LlmProviderUpdateRequest):
    provider.provider_key = normalize_provider_key(payload.provider_key)
    provider.display_name = payload.display_name.strip()
    provider.provider_type = payload.provider_type.strip()
    provider.enabled = payload.enabled
    provider.is_default = payload.is_default
    provider.api_base = payload.api_base.strip()
    provider.model = payload.model.strip()
    provider.api_key = payload.api_key.strip()
    provider.organization = payload.organization.strip() if payload.organization else None
    provider.api_version = payload.api_version.strip() if payload.api_version else None
    provider.timeout_seconds = payload.timeout_seconds
    provider.max_tokens = payload.max_tokens
    provider.temperature = payload.temperature
    provider.env_bindings = payload.env_bindings or {}
    provider.extra_config = payload.extra_config or {}
    provider.description = payload.description.strip() if payload.description else None
    validate_env_bindings(provider.env_bindings)


@router.get("/health")
async def health():
    return {"status": "ok", "service": "secflow-platform-configcenter"}


@router.get("/admin/llm/providers", response_model=LlmProviderListResponse)
async def list_admin_llm_providers(
    current_user: dict = Depends(get_current_super_admin),
    db: Session = Depends(get_db),
):
    items = db.query(LlmProvider).order_by(LlmProvider.is_default.desc(), LlmProvider.display_name.asc()).all()
    default_provider = next((item.provider_key for item in items if item.is_default), None)
    return LlmProviderListResponse(
        total=len(items),
        default_provider_key=default_provider,
        items=[build_summary_payload(item, mask_secret(item.api_key)) for item in items],
    )


@router.get("/admin/llm/providers/{provider_key}", response_model=LlmProviderDetail)
async def get_admin_llm_provider(
    provider_key: str,
    current_user: dict = Depends(get_current_super_admin),
    db: Session = Depends(get_db),
):
    provider = get_provider_or_404(db, normalize_provider_key(provider_key))
    return build_detail_payload(provider)


@router.post("/admin/llm/providers", response_model=LlmProviderDetail)
async def create_llm_provider(
    request: LlmProviderCreateRequest,
    current_user: dict = Depends(get_current_super_admin),
    db: Session = Depends(get_db),
):
    provider_key = normalize_provider_key(request.provider_key)
    existing = db.query(LlmProvider).filter(LlmProvider.provider_key == provider_key).first()
    if existing is not None:
        raise ConflictError(f"LLM Provider 已存在: {provider_key}")

    provider = LlmProvider()
    apply_payload(provider, request)
    db.add(provider)
    db.flush()
    if provider.is_default:
        ensure_single_default(db, provider)
    elif db.query(LlmProvider).filter(LlmProvider.is_default.is_(True)).count() == 0:
        provider.is_default = True
    db.commit()
    db.refresh(provider)
    return build_detail_payload(provider)


@router.put("/admin/llm/providers/{provider_key}", response_model=LlmProviderDetail)
async def update_llm_provider(
    provider_key: str,
    request: LlmProviderUpdateRequest,
    current_user: dict = Depends(get_current_super_admin),
    db: Session = Depends(get_db),
):
    provider = get_provider_or_404(db, normalize_provider_key(provider_key))
    normalized_target_key = normalize_provider_key(request.provider_key)
    existing = db.query(LlmProvider).filter(
        LlmProvider.provider_key == normalized_target_key,
        LlmProvider.id != provider.id,
    ).first()
    if existing is not None:
        raise ConflictError(f"LLM Provider 已存在: {normalized_target_key}")

    was_default = provider.is_default
    apply_payload(provider, request)
    if provider.is_default:
        ensure_single_default(db, provider)
    elif was_default:
        # 保持总有一个默认 provider
        replacement = db.query(LlmProvider).filter(LlmProvider.id != provider.id).order_by(
            LlmProvider.enabled.desc(),
            LlmProvider.updated_at.desc(),
        ).first()
        if replacement is None:
            provider.is_default = True
        else:
            replacement.is_default = True
    db.commit()
    db.refresh(provider)
    return build_detail_payload(provider)


@router.post("/admin/llm/providers/{provider_key}/enable", response_model=MessageResponse)
async def enable_llm_provider(
    provider_key: str,
    current_user: dict = Depends(get_current_super_admin),
    db: Session = Depends(get_db),
):
    provider = get_provider_or_404(db, normalize_provider_key(provider_key))
    provider.enabled = True
    db.commit()
    return MessageResponse(message="Provider 已启用", provider_key=provider.provider_key)


@router.post("/admin/llm/providers/{provider_key}/disable", response_model=MessageResponse)
async def disable_llm_provider(
    provider_key: str,
    current_user: dict = Depends(get_current_super_admin),
    db: Session = Depends(get_db),
):
    provider = get_provider_or_404(db, normalize_provider_key(provider_key))
    if provider.is_default:
        replacement = db.query(LlmProvider).filter(
            LlmProvider.id != provider.id,
            LlmProvider.enabled.is_(True),
        ).order_by(LlmProvider.updated_at.desc()).first()
        if replacement is None:
            raise ValidationError("默认 Provider 不能直接禁用，请先设置其它默认 Provider")
        provider.is_default = False
        replacement.is_default = True
    provider.enabled = False
    db.commit()
    return MessageResponse(message="Provider 已禁用", provider_key=provider.provider_key)


@router.post("/admin/llm/providers/{provider_key}/set-default", response_model=MessageResponse)
async def set_default_llm_provider(
    provider_key: str,
    current_user: dict = Depends(get_current_super_admin),
    db: Session = Depends(get_db),
):
    provider = get_provider_or_404(db, normalize_provider_key(provider_key))
    ensure_single_default(db, provider)
    provider.is_default = True
    provider.enabled = True
    db.commit()
    return MessageResponse(message="默认 Provider 已更新", provider_key=provider.provider_key)


@router.delete("/admin/llm/providers/{provider_key}", response_model=MessageResponse)
async def delete_llm_provider(
    provider_key: str,
    current_user: dict = Depends(get_current_super_admin),
    db: Session = Depends(get_db),
):
    provider = get_provider_or_404(db, normalize_provider_key(provider_key))
    deleted_key = provider.provider_key
    was_default = provider.is_default
    db.delete(provider)
    db.flush()
    if was_default:
        replacement = db.query(LlmProvider).order_by(LlmProvider.enabled.desc(), LlmProvider.updated_at.desc()).first()
        if replacement is not None:
            replacement.is_default = True
    db.commit()
    return MessageResponse(message="Provider 已删除", provider_key=deleted_key)


@router.get("/service/llm/providers", response_model=LlmProviderServiceListResponse)
async def list_service_llm_providers(
    machine_client: dict = Depends(get_machine_client),
    db: Session = Depends(get_db),
):
    items = db.query(LlmProvider).filter(LlmProvider.enabled.is_(True)).order_by(
        LlmProvider.is_default.desc(),
        LlmProvider.display_name.asc(),
    ).all()
    default_provider = next((item.provider_key for item in items if item.is_default), None)
    return LlmProviderServiceListResponse(
        total=len(items),
        default_provider_key=default_provider,
        items=[build_service_payload(item) for item in items],
    )


@router.get("/service/llm/providers/{provider_key}", response_model=LlmProviderDetail)
async def get_service_llm_provider(
    provider_key: str,
    machine_client: dict = Depends(get_machine_client),
    db: Session = Depends(get_db),
):
    provider = get_provider_or_404(db, normalize_provider_key(provider_key))
    if not provider.enabled:
        raise NotFoundError("已启用的 LLM Provider", provider_key)
    return build_detail_payload(provider)
