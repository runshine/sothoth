from __future__ import annotations

import os
from typing import Any

import httpx

from app.config import get_config


class DataflowWorkerError(RuntimeError):
    pass


class DataflowWorkerClient:
    def __init__(self, base_url: str | None = None) -> None:
        self._base_url = base_url

    @property
    def base_url(self) -> str:
        cfg = get_config().dataflow_worker
        return (self._base_url or os.environ.get("DATAFLOW_WORKER_URL") or cfg.base_url).rstrip("/")

    @property
    def api_key(self) -> str | None:
        cfg = get_config()
        return (
            os.environ.get("DATAFLOW_WORKER_API_KEY")
            or cfg.dataflow_worker.api_key
            or cfg.auth_service.service_machine_token
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def create_job(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            with httpx.Client(timeout=get_config().dataflow_worker.timeout) as client:
                response = client.post(
                    f"{self.base_url}/api/v1/jobs",
                    headers=self._headers(),
                    json=payload,
                )
        except httpx.TimeoutException as exc:
            raise DataflowWorkerError("dataflow worker create job timed out") from exc
        except httpx.HTTPError as exc:
            raise DataflowWorkerError(f"dataflow worker unreachable: {exc}") from exc
        return _handle_response(response)

    def list_jobs(self) -> list[dict[str, Any]]:
        try:
            with httpx.Client(timeout=get_config().dataflow_worker.timeout) as client:
                response = client.get(f"{self.base_url}/api/v1/jobs", headers=self._headers())
        except httpx.TimeoutException as exc:
            raise DataflowWorkerError("dataflow worker list jobs timed out") from exc
        except httpx.HTTPError as exc:
            raise DataflowWorkerError(f"dataflow worker unreachable: {exc}") from exc
        payload = _handle_response(response)
        jobs = payload.get("jobs") if isinstance(payload, dict) else []
        return jobs if isinstance(jobs, list) else []

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        try:
            with httpx.Client(timeout=get_config().dataflow_worker.timeout) as client:
                response = client.get(f"{self.base_url}/api/v1/jobs/{job_id}", headers=self._headers())
        except httpx.TimeoutException as exc:
            raise DataflowWorkerError("dataflow worker get job timed out") from exc
        except httpx.HTTPError as exc:
            raise DataflowWorkerError(f"dataflow worker unreachable: {exc}") from exc
        if response.status_code == 404:
            return None
        return _handle_response(response)

    def cancel_job(self, job_id: str) -> dict[str, Any]:
        try:
            with httpx.Client(timeout=get_config().dataflow_worker.timeout) as client:
                response = client.post(f"{self.base_url}/api/v1/jobs/{job_id}/cancel", headers=self._headers())
        except httpx.TimeoutException as exc:
            raise DataflowWorkerError("dataflow worker cancel job timed out") from exc
        except httpx.HTTPError as exc:
            raise DataflowWorkerError(f"dataflow worker unreachable: {exc}") from exc
        if response.status_code == 409:
            return {"status": "already_terminal"}
        return _handle_response(response)


def _handle_response(response: httpx.Response) -> dict[str, Any]:
    if 200 <= response.status_code < 300:
        return response.json() if response.content else {}
    body = response.text[:500]
    if response.status_code == 404:
        raise DataflowWorkerError("dataflow worker job not found")
    if response.status_code == 409:
        raise DataflowWorkerError(body or "dataflow worker job conflict")
    if response.status_code in {401, 403, 422}:
        raise DataflowWorkerError(body or "dataflow worker request rejected")
    raise DataflowWorkerError(f"dataflow worker returned {response.status_code}: {body}")


_clients: dict[str, DataflowWorkerClient] = {}
_default_client: DataflowWorkerClient | None = None


def get_dataflow_worker_client(base_url: str | None = None) -> DataflowWorkerClient:
    global _default_client
    if base_url:
        normalized = base_url.rstrip("/")
        if normalized not in _clients:
            _clients[normalized] = DataflowWorkerClient(normalized)
        return _clients[normalized]
    if _default_client is None:
        _default_client = DataflowWorkerClient()
    return _default_client
