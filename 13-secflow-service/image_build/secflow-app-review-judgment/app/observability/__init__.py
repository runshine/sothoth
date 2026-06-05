from __future__ import annotations

import logging

from prometheus_client import Counter, Gauge, Histogram, generate_latest
from fastapi.responses import Response

logger = logging.getLogger(__name__)

HTTP_REQUEST_TOTAL = Counter(
    "rj_http_request_total",
    "Total HTTP requests",
    ["method", "path", "status_code"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "rj_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "path"],
)

HTTP_REQUEST_INFLIGHT = Gauge(
    "rj_http_request_inflight",
    "Current in-flight HTTP requests",
    ["method", "path"],
)


def observe_http_request(method: str, path: str, status_code: int, duration_seconds: float) -> None:
    try:
        HTTP_REQUEST_TOTAL.labels(method=method, path=str(path), status_code=str(status_code)).inc()
        HTTP_REQUEST_DURATION_SECONDS.labels(method=method, path=str(path)).observe(duration_seconds)
    except Exception:
        pass


def observe_http_request_inflight(method: str, path: str, delta: int) -> None:
    try:
        if delta > 0:
            HTTP_REQUEST_INFLIGHT.labels(method=method, path=str(path)).inc()
        else:
            HTTP_REQUEST_INFLIGHT.labels(method=method, path=str(path)).dec()
    except Exception:
        pass


def build_metrics_response() -> Response:
    body = generate_latest()
    return Response(content=body, media_type="text/plain; charset=utf-8")