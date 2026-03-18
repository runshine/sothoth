"""
Compatibility wrapper for workflow K8S client.

All K8S operations are unified through secflow-platform-k8s.
Use app.services.k8s_service_client as the real implementation.
"""

from typing import Optional

from app.services.k8s_service_client import K8SServiceClient, get_k8s_service_client


class K8SClient(K8SServiceClient):
    """Backward-compatible alias."""


_k8s_client: Optional[K8SClient] = None


def get_k8s_client() -> K8SClient:
    global _k8s_client
    if _k8s_client is None:
        # Reuse the shared singleton from k8s_service_client to avoid duplicate clients.
        _k8s_client = get_k8s_service_client()  # type: ignore[assignment]
    return _k8s_client
