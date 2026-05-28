from __future__ import annotations

from typing import Mapping

import httpx
from fastapi import APIRouter, HTTPException, Request, Response, status

from app.config import get_config
from app.services.scheduler import get_scheduler_service

router = APIRouter(prefix="/api/dataflow-vuln-scanner-admin-proxy", tags=["Dataflow Vuln Scanner Admin Proxy"])

_FORWARDED_HEADERS = {"authorization", "content-type", "accept"}


def _manager_base_url() -> str:
    cfg = get_config().scheduler
    return f"http://{cfg.manager_service_name}:{cfg.manager_service_port}"


def _build_forward_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {key: value for key, value in headers.items() if key.lower() in _FORWARDED_HEADERS}


async def _forward_to_manager(request: Request, target_path: str) -> Response:
    if get_scheduler_service().role not in {"api", "standalone"}:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    query = request.url.query
    target_url = f"{_manager_base_url()}{target_path}"
    if query:
        target_url = f"{target_url}?{query}"

    body = await request.body()
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            upstream = await client.request(
                method=request.method,
                url=target_url,
                headers=_build_forward_headers(request.headers),
                content=body or None,
            )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"manager proxy request failed: {exc}",
        ) from exc

    media_type = upstream.headers.get("content-type")
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type=media_type,
    )


@router.get("/scheduler/workers")
async def list_scheduler_workers_proxy(request: Request):
    return await _forward_to_manager(request, "/api/dataflow-vuln-scanner/admin/scheduler/workers")


@router.get("/scheduler/workers/{pod_id}")
async def get_scheduler_worker_proxy(pod_id: str, request: Request):
    return await _forward_to_manager(request, f"/api/dataflow-vuln-scanner/admin/scheduler/workers/{pod_id}")


@router.post("/scheduler/workers/{pod_id}/drain")
async def drain_scheduler_worker_proxy(pod_id: str, request: Request):
    return await _forward_to_manager(request, f"/api/dataflow-vuln-scanner/admin/scheduler/workers/{pod_id}/drain")


@router.post("/scheduler/workers/{pod_id}/activate")
async def activate_scheduler_worker_proxy(pod_id: str, request: Request):
    return await _forward_to_manager(request, f"/api/dataflow-vuln-scanner/admin/scheduler/workers/{pod_id}/activate")
