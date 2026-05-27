from __future__ import annotations

__all__ = ["build_metrics_response", "observe_http_request", "observe_http_request_inflight"]


def build_metrics_response():
    from app.observability.metrics import build_metrics_response as _build_metrics_response

    return _build_metrics_response()


def observe_http_request(method: str, path: str, status_code: int, duration_seconds: float) -> None:
    from app.observability.metrics import observe_http_request as _observe_http_request

    _observe_http_request(method, path, status_code, duration_seconds)


def observe_http_request_inflight(method: str, path: str, delta: int) -> None:
    from app.observability.metrics import observe_http_request_inflight as _observe_http_request_inflight

    _observe_http_request_inflight(method, path, delta)
