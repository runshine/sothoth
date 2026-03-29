"""Pydantic schemas for config center."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class LlmProviderBase(BaseModel):
    provider_key: str
    display_name: str
    provider_type: str
    enabled: bool = True
    is_default: bool = False
    api_base: str
    model: str
    api_key: str
    organization: Optional[str] = None
    api_version: Optional[str] = None
    timeout_seconds: int = 60
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    env_bindings: Dict[str, Any] = Field(default_factory=dict)
    extra_config: Dict[str, Any] = Field(default_factory=dict)
    description: Optional[str] = None

    @field_validator("provider_key", "display_name", "provider_type", "api_base", "api_key")
    @classmethod
    def validate_required_str(cls, value: str) -> str:
        value = (value or "").strip()
        if not value:
            raise ValueError("字段不能为空")
        return value

    @field_validator("model")
    @classmethod
    def normalize_model(cls, value: str) -> str:
        return (value or "").strip()

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("timeout_seconds 必须大于 0")
        return value

    @field_validator("temperature")
    @classmethod
    def validate_temperature(cls, value: Optional[float]) -> Optional[float]:
        if value is not None and (value < 0 or value > 2):
            raise ValueError("temperature 需介于 0 到 2 之间")
        return value


class LlmProviderCreateRequest(LlmProviderBase):
    pass


class LlmProviderUpdateRequest(LlmProviderBase):
    pass


class LlmProviderSummary(BaseModel):
    provider_key: str
    display_name: str
    provider_type: str
    enabled: bool
    is_default: bool
    api_base: str
    model: str
    api_key_masked: str
    organization: Optional[str] = None
    api_version: Optional[str] = None
    timeout_seconds: int
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    env_bindings: Dict[str, Any]
    extra_config: Dict[str, Any]
    description: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class LlmProviderDetail(BaseModel):
    provider_key: str
    display_name: str
    provider_type: str
    enabled: bool
    is_default: bool
    api_base: str
    model: str
    api_key: str
    organization: Optional[str] = None
    api_version: Optional[str] = None
    timeout_seconds: int
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    env_bindings: Dict[str, Any]
    extra_config: Dict[str, Any]
    description: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class LlmProviderListResponse(BaseModel):
    total: int
    default_provider_key: Optional[str] = None
    items: List[LlmProviderSummary]


class LlmProviderServiceListItem(BaseModel):
    provider_key: str
    display_name: str
    provider_type: str
    enabled: bool
    is_default: bool
    api_base: str
    model: str
    organization: Optional[str] = None
    api_version: Optional[str] = None
    timeout_seconds: int
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    env_bindings: Dict[str, Any]
    extra_config: Dict[str, Any]
    description: Optional[str] = None


class LlmProviderServiceListResponse(BaseModel):
    total: int
    default_provider_key: Optional[str] = None
    items: List[LlmProviderServiceListItem]


class MessageResponse(BaseModel):
    message: str
    provider_key: Optional[str] = None


def build_summary_payload(item, api_key_masked: str) -> LlmProviderSummary:
    return LlmProviderSummary(
        provider_key=item.provider_key,
        display_name=item.display_name,
        provider_type=item.provider_type,
        enabled=item.enabled,
        is_default=item.is_default,
        api_base=item.api_base,
        model=item.model,
        api_key_masked=api_key_masked,
        organization=item.organization,
        api_version=item.api_version,
        timeout_seconds=item.timeout_seconds,
        max_tokens=item.max_tokens,
        temperature=item.temperature,
        env_bindings=item.env_bindings or {},
        extra_config=item.extra_config or {},
        description=item.description,
        created_at=item.created_at.isoformat() if isinstance(item.created_at, datetime) else None,
        updated_at=item.updated_at.isoformat() if isinstance(item.updated_at, datetime) else None,
    )


def build_detail_payload(item) -> LlmProviderDetail:
    return LlmProviderDetail(
        provider_key=item.provider_key,
        display_name=item.display_name,
        provider_type=item.provider_type,
        enabled=item.enabled,
        is_default=item.is_default,
        api_base=item.api_base,
        model=item.model,
        api_key=item.api_key,
        organization=item.organization,
        api_version=item.api_version,
        timeout_seconds=item.timeout_seconds,
        max_tokens=item.max_tokens,
        temperature=item.temperature,
        env_bindings=item.env_bindings or {},
        extra_config=item.extra_config or {},
        description=item.description,
        created_at=item.created_at.isoformat() if isinstance(item.created_at, datetime) else None,
        updated_at=item.updated_at.isoformat() if isinstance(item.updated_at, datetime) else None,
    )


def build_service_payload(item) -> LlmProviderServiceListItem:
    return LlmProviderServiceListItem(
        provider_key=item.provider_key,
        display_name=item.display_name,
        provider_type=item.provider_type,
        enabled=item.enabled,
        is_default=item.is_default,
        api_base=item.api_base,
        model=item.model,
        organization=item.organization,
        api_version=item.api_version,
        timeout_seconds=item.timeout_seconds,
        max_tokens=item.max_tokens,
        temperature=item.temperature,
        env_bindings=item.env_bindings or {},
        extra_config=item.extra_config or {},
        description=item.description,
    )
