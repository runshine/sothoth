"""LiteLLM client and key management."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import NotFoundError, UpstreamError
from app.model import LiteLLMKeyEvent, LiteLLMVirtualKey
from app.schemas import VirtualKeyCreate
from app.service.http_client import get_shared_async_client


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class LiteLLMClient:
    def __init__(self):
        self.config = get_config().litellm

    def _url(self, path: str) -> str:
        return f"{self.config.api_base.rstrip('/')}/{path.lstrip('/')}"

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.admin_key:
            headers["Authorization"] = f"Bearer {self.config.admin_key}"
        return headers

    async def create_virtual_key(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            client = await get_shared_async_client("litellm", timeout=self.config.timeout_seconds, verify=self.config.verify_tls)
            response = await client.post(self._url(self.config.create_key_path), headers=self._headers(), json=payload)
        except httpx.TimeoutException as exc:
            raise UpstreamError("LiteLLM 创建 key 超时") from exc
        except httpx.RequestError as exc:
            raise UpstreamError(f"LiteLLM 请求失败: {exc}") from exc
        if response.status_code not in (200, 201):
            raise UpstreamError(f"LiteLLM 创建 key 失败: {response.status_code}")
        return response.json()

    async def disable_virtual_key(self, key_id: str) -> dict[str, Any]:
        payload = {"key": key_id}
        try:
            client = await get_shared_async_client("litellm", timeout=self.config.timeout_seconds, verify=self.config.verify_tls)
            response = await client.post(self._url(self.config.disable_key_path), headers=self._headers(), json=payload)
        except httpx.TimeoutException as exc:
            raise UpstreamError("LiteLLM 禁用 key 超时") from exc
        except httpx.RequestError as exc:
            raise UpstreamError(f"LiteLLM 请求失败: {exc}") from exc
        if response.status_code not in (200, 201):
            raise UpstreamError(f"LiteLLM 禁用 key 失败: {response.status_code}")
        return response.json()

    async def list_virtual_keys(self) -> dict[str, Any]:
        try:
            client = await get_shared_async_client("litellm", timeout=self.config.timeout_seconds, verify=self.config.verify_tls)
            response = await client.get(self._url(self.config.list_key_path), headers=self._headers())
        except httpx.TimeoutException as exc:
            raise UpstreamError("LiteLLM 查询 key 超时") from exc
        except httpx.RequestError as exc:
            raise UpstreamError(f"LiteLLM 请求失败: {exc}") from exc
        if response.status_code != 200:
            raise UpstreamError(f"LiteLLM 查询 key 失败: {response.status_code}")
        return response.json()

    async def get_virtual_key(self, key_id: str) -> dict[str, Any]:
        try:
            client = await get_shared_async_client("litellm", timeout=self.config.timeout_seconds, verify=self.config.verify_tls)
            response = await client.get(self._url(self.config.get_key_path), headers=self._headers(), params={"key": key_id})
        except httpx.TimeoutException as exc:
            raise UpstreamError("LiteLLM 查询单个 key 超时") from exc
        except httpx.RequestError as exc:
            raise UpstreamError(f"LiteLLM 请求失败: {exc}") from exc
        if response.status_code != 200:
            raise UpstreamError(f"LiteLLM 查询单个 key 失败: {response.status_code}")
        return response.json()


class VirtualKeyManager:
    def __init__(self):
        self.client = LiteLLMClient()

    def get_key_or_404(self, db: Session, project_id: str, key_id: str) -> LiteLLMVirtualKey:
        key = db.query(LiteLLMVirtualKey).filter(
            LiteLLMVirtualKey.project_id == project_id,
            LiteLLMVirtualKey.id == key_id,
        ).first()
        if key is None:
            raise NotFoundError("VirtualKey", key_id)
        return key

    def _append_event(self, db: Session, virtual_key_id: str, event_type: str, payload: dict[str, Any]) -> None:
        db.add(LiteLLMKeyEvent(virtual_key_id=virtual_key_id, event_type=event_type, payload=payload))

    async def create_key(self, db: Session, project_id: str, payload: VirtualKeyCreate, actor: str) -> tuple[LiteLLMVirtualKey, str | None]:
        request_payload = {
            "models": payload.models,
            "metadata": {"project_id": project_id, **(payload.metadata or {})},
            "duration": payload.duration or get_config().litellm.default_duration,
            "max_budget": payload.budget_config.max_budget,
            "key_alias": payload.alias or payload.name,
        }
        result = await self.client.create_virtual_key(request_payload)
        plain_text_key = result.get("key") or result.get("token") or result.get("api_key")
        litellm_key_id = result.get("key_id") or result.get("id") or plain_text_key
        if not litellm_key_id:
            raise UpstreamError("LiteLLM 返回缺少 key 标识")
        suffix = plain_text_key[-4:] if plain_text_key else None
        key_hash = hashlib.sha256(str(plain_text_key or litellm_key_id).encode("utf-8")).hexdigest()
        record = LiteLLMVirtualKey(
            project_id=project_id,
            name=payload.name,
            alias=payload.alias,
            status="active",
            litellm_key_id=str(litellm_key_id),
            key_suffix=suffix,
            key_hash=key_hash,
            models=list(payload.models or []),
            metadata_json=dict(payload.metadata or {}),
            budget_config=payload.budget_config.model_dump(),
            created_by=actor,
            updated_by=actor,
            last_synced_at=_now(),
        )
        db.add(record)
        db.flush()
        self._append_event(db, record.id, "created", {"litellm_result": result, "plain_text_key_returned": bool(plain_text_key)})
        db.commit()
        db.refresh(record)
        return record, plain_text_key

    async def disable_key(self, db: Session, project_id: str, key_id: str, actor: str) -> LiteLLMVirtualKey:
        record = self.get_key_or_404(db, project_id, key_id)
        if record.litellm_key_id:
            result = await self.client.disable_virtual_key(record.litellm_key_id)
        else:
            result = {"status": "skipped"}
        record.status = "disabled"
        record.updated_by = actor
        record.last_synced_at = _now()
        self._append_event(db, record.id, "disabled", {"litellm_result": result})
        db.commit()
        db.refresh(record)
        return record

    async def sync_key(self, db: Session, project_id: str, key_id: str, actor: str) -> LiteLLMVirtualKey:
        record = self.get_key_or_404(db, project_id, key_id)
        if not record.litellm_key_id:
            raise UpstreamError("当前 key 缺少 LiteLLM key id")
        result = await self.client.get_virtual_key(record.litellm_key_id)
        record.last_synced_at = _now()
        record.updated_by = actor
        if result.get("disabled") is True:
            record.status = "disabled"
        self._append_event(db, record.id, "synced", {"litellm_result": result})
        db.commit()
        db.refresh(record)
        return record

    def list_keys(self, db: Session, project_id: str) -> list[LiteLLMVirtualKey]:
        return db.query(LiteLLMVirtualKey).filter(LiteLLMVirtualKey.project_id == project_id).order_by(
            LiteLLMVirtualKey.created_at.desc()
        ).all()

    def list_events(self, db: Session, project_id: str, key_id: str) -> list[LiteLLMKeyEvent]:
        record = self.get_key_or_404(db, project_id, key_id)
        return db.query(LiteLLMKeyEvent).filter(
            LiteLLMKeyEvent.virtual_key_id == record.id
        ).order_by(LiteLLMKeyEvent.created_at.asc()).all()


_virtual_key_manager: Optional[VirtualKeyManager] = None


def get_virtual_key_manager() -> VirtualKeyManager:
    global _virtual_key_manager
    if _virtual_key_manager is None:
        _virtual_key_manager = VirtualKeyManager()
    return _virtual_key_manager
