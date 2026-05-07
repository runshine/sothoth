"""Task worker pod resource metrics helpers."""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Optional


logger = logging.getLogger(__name__)


def _cpu_to_millicores(raw: str) -> int:
    value = str(raw or "").strip()
    if not value:
        return 0
    if value.endswith("n"):
        return int(int(value[:-1]) / 1_000_000)
    if value.endswith("u"):
        return int(int(value[:-1]) / 1_000)
    if value.endswith("m"):
        return int(value[:-1] or "0")
    return int(float(value) * 1000)


def _memory_to_mib(raw: str) -> int:
    value = str(raw or "").strip()
    if not value:
        return 0
    units = {
        "Ki": 1 / 1024,
        "Mi": 1,
        "Gi": 1024,
        "Ti": 1024 * 1024,
        "K": 1000 / (1024 * 1024),
        "M": 1000 * 1000 / (1024 * 1024),
        "G": 1000 * 1000 * 1000 / (1024 * 1024),
    }
    for suffix, factor in units.items():
        if value.endswith(suffix):
            return int(float(value[: -len(suffix)] or "0") * factor)
    return int(int(value) / (1024 * 1024))


def _resource_to_millicores(raw: Optional[str]) -> int:
    return _cpu_to_millicores(str(raw or ""))


def _resource_to_mib(raw: Optional[str]) -> int:
    return _memory_to_mib(str(raw or ""))


@lru_cache(maxsize=1)
def _get_clients():
    from kubernetes import client, config

    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()
    return client.CoreV1Api(), client.CustomObjectsApi()


def get_runtime_namespace() -> str:
    return (
        os.environ.get("POD_NAMESPACE")
        or os.environ.get("K8S_NAMESPACE")
        or "secflow-ns"
    )


def get_pod_resource_usage(pod_name: str, namespace: Optional[str] = None) -> Optional[dict]:
    normalized_pod = str(pod_name or "").strip()
    if not normalized_pod:
        return None

    runtime_namespace = str(namespace or get_runtime_namespace()).strip() or "secflow-ns"

    try:
        core_v1, custom_objects = _get_clients()
        pod = core_v1.read_namespaced_pod(name=normalized_pod, namespace=runtime_namespace)
        metrics = custom_objects.get_namespaced_custom_object(
            group="metrics.k8s.io",
            version="v1beta1",
            namespace=runtime_namespace,
            plural="pods",
            name=normalized_pod,
        )
    except Exception as exc:
        logger.warning("failed to load pod metrics for %s/%s: %s", runtime_namespace, normalized_pod, exc)
        return None

    containers: list[dict] = []
    total_cpu_millicores = 0
    total_memory_mib = 0
    total_cpu_limit_millicores = 0
    total_memory_limit_mib = 0

    pod_spec_containers = {
        getattr(container, "name", None): container
        for container in (getattr(getattr(pod, "spec", None), "containers", None) or [])
    }

    for container in metrics.get("containers", []) or []:
        usage = container.get("usage", {}) or {}
        cpu_m = _cpu_to_millicores(str(usage.get("cpu", "")))
        mem_mib = _memory_to_mib(str(usage.get("memory", "")))
        total_cpu_millicores += cpu_m
        total_memory_mib += mem_mib
        pod_spec_container = pod_spec_containers.get(container.get("name"))
        resources = getattr(pod_spec_container, "resources", None)
        limits = getattr(resources, "limits", None) if resources else None
        total_cpu_limit_millicores += _resource_to_millicores((limits or {}).get("cpu"))
        total_memory_limit_mib += _resource_to_mib((limits or {}).get("memory"))
        containers.append(
            {
                "name": container.get("name"),
                "cpu_millicores": cpu_m,
                "memory_mib": mem_mib,
            }
        )

    return {
        "pod_name": normalized_pod,
        "namespace": runtime_namespace,
        "phase": getattr(getattr(pod, "status", None), "phase", None),
        "timestamp": metrics.get("timestamp"),
        "window": metrics.get("window"),
        "cpu_millicores": total_cpu_millicores,
        "memory_mib": total_memory_mib,
        "pod_cpu_limit_millicores": total_cpu_limit_millicores or None,
        "pod_memory_limit_mib": total_memory_limit_mib or None,
        "containers": containers,
    }
