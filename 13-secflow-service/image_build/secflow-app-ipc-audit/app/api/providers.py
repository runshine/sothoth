from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from app.schemas import ProviderListResponse, ProviderSummaryResponse
from app.services.provider_client import ProviderClientError, ProviderNotFoundError
from app.services.provider_runtime import get_provider_runtime_service

router = APIRouter()


@router.get("/providers", response_model=ProviderListResponse)
def list_providers() -> ProviderListResponse:
    try:
        payload = get_provider_runtime_service().list_provider_summaries()
    except ProviderClientError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    return ProviderListResponse(
        total=int(payload.get("total") or 0),
        default_provider_key=payload.get("default_provider_key"),
        items=[ProviderSummaryResponse(**item) for item in payload.get("items", [])],
    )


@router.get("/providers/{provider_key}", response_model=ProviderSummaryResponse)
def get_provider(provider_key: str) -> ProviderSummaryResponse:
    try:
        payload = get_provider_runtime_service().get_provider_summary(provider_key)
    except ProviderNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ProviderClientError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    return ProviderSummaryResponse(**payload)
