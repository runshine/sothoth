"""PVC file gateway manager (control plane)."""

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx

from fastapi import HTTPException

from app.main import get_config
from app.services.k8s import get_k8s_service

logger = logging.getLogger(__name__)


@dataclass
class FileGatewayConfig:
    enabled: bool = True
    fallback_to_exec: bool = False
    name: str = "secflow-platform-resource-file-gateway"
    worker_name_prefix: str = "secflow-platform-resource-file-gateway-worker"
    worker_app_label: str = "secflow-platform-resource-file-gateway-worker"
    worker_image: str = "ghcr.io/runshine/secflow-platform-resource-file-gateway-worker:latest"
    worker_container_port: int = 8081
    worker_mount_path: str = "/data/pvc"
    worker_idle_ttl_seconds: int = 900
    worker_ready_timeout_seconds: int = 60
    worker_request_timeout_seconds: int = 120
    internal_token: str = ""


class FileGatewayManager:
    """Manage per-PVC worker lifecycle and proxy file operations."""

    def __init__(self, config: FileGatewayConfig):
        self.config = config
        self._worker_access_time: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._worker_locks: Dict[str, threading.Lock] = {}

    @classmethod
    def from_runtime_config(cls) -> "FileGatewayManager":
        runtime = get_config()
        fg = runtime.get("file_gateway", {}) if isinstance(runtime, dict) else {}
        config = FileGatewayConfig(
            enabled=bool(fg.get("enabled", True)),
            fallback_to_exec=bool(fg.get("fallback_to_exec", False)),
            name=str(fg.get("name", "secflow-platform-resource-file-gateway")),
            worker_name_prefix=str(fg.get("worker_name_prefix", "secflow-platform-resource-file-gateway-worker")),
            worker_app_label=str(fg.get("worker_app_label", "secflow-platform-resource-file-gateway-worker")),
            worker_image=str(
                fg.get(
                    "worker_image",
                    "ghcr.io/runshine/secflow-platform-resource-file-gateway-worker:latest",
                )
            ),
            worker_container_port=int(fg.get("worker_container_port", 8081)),
            worker_mount_path=str(fg.get("worker_mount_path", "/data/pvc")),
            worker_idle_ttl_seconds=int(fg.get("worker_idle_ttl_seconds", 900)),
            worker_ready_timeout_seconds=int(fg.get("worker_ready_timeout_seconds", 60)),
            worker_request_timeout_seconds=int(fg.get("worker_request_timeout_seconds", 120)),
            internal_token=str(fg.get("internal_token", "")),
        )
        return cls(config)

    def is_enabled(self) -> bool:
        return self.config.enabled

    def should_fallback(self) -> bool:
        return self.config.fallback_to_exec

    def _hash_worker_suffix(self, project_id: str, pvc_name: str) -> str:
        raw = f"{project_id}:{pvc_name}".encode("utf-8")
        return hashlib.sha1(raw).hexdigest()[:6]

    def _worker_name(self, project_id: str, pvc_name: str) -> str:
        return f"{self.config.worker_name_prefix}-{self._hash_worker_suffix(project_id, pvc_name)}"

    def _service_name(self, worker_name: str) -> str:
        return f"{worker_name}-svc"

    def get_worker_info(self, project_id: str, pvc_name: str) -> Dict[str, Any]:
        worker_name = self._worker_name(project_id, pvc_name)
        service_name = self._service_name(worker_name)
        namespace = get_k8s_service().get_project_namespace(project_id)
        service = get_k8s_service().get_service(project_id, service_name)
        deployment = get_k8s_service().get_deployment(project_id, worker_name)
        deployment_status = (deployment or {}).get("status", {}) if isinstance(deployment, dict) else {}
        return {
            "enabled": bool(self.config.enabled),
            "worker_name": worker_name,
            "service_name": service_name,
            "namespace": namespace,
            "worker_image": self.config.worker_image,
            "service_exists": service is not None,
            "deployment_exists": deployment is not None,
            "replicas": int(deployment_status.get("replicas") or 0),
            "ready_replicas": int(deployment_status.get("readyReplicas") or 0),
            "available_replicas": int(deployment_status.get("availableReplicas") or 0),
        }

    def cleanup_worker(self, project_id: str, pvc_name: str) -> Dict[str, Any]:
        worker_name = self._worker_name(project_id, pvc_name)
        service_name = self._service_name(worker_name)
        k8s = get_k8s_service()
        service_deleted = k8s.delete_service(project_id, service_name)
        deployment_deleted = k8s.delete_deployment(project_id, worker_name)
        with self._lock:
            self._worker_access_time.pop(worker_name, None)
            self._worker_locks.pop(worker_name, None)
        return {
            "worker_name": worker_name,
            "service_name": service_name,
            "service_deleted": bool(service_deleted),
            "deployment_deleted": bool(deployment_deleted),
        }

    def _touch(self, worker_name: str) -> None:
        with self._lock:
            self._worker_access_time[worker_name] = time.time()

    def _get_worker_lock(self, worker_name: str) -> threading.Lock:
        with self._lock:
            lock = self._worker_locks.get(worker_name)
            if lock is None:
                lock = threading.Lock()
                self._worker_locks[worker_name] = lock
            return lock

    def _cleanup_idle_workers(self, project_id: str) -> None:
        now = time.time()
        ttl = self.config.worker_idle_ttl_seconds
        if ttl <= 0:
            return
        k8s = get_k8s_service()
        expired = []
        with self._lock:
            for worker_name, last_seen in self._worker_access_time.items():
                if now - last_seen > ttl:
                    expired.append(worker_name)
        for worker_name in expired:
            service_name = self._service_name(worker_name)
            logger.info("Cleaning idle file gateway worker. project_id=%s worker=%s", project_id, worker_name)
            k8s.delete_service(project_id, service_name)
            k8s.delete_deployment(project_id, worker_name)
            with self._lock:
                self._worker_access_time.pop(worker_name, None)
                self._worker_locks.pop(worker_name, None)

    def ensure_worker(self, project_id: str, pvc_name: str) -> Dict[str, str]:
        if not self.config.enabled:
            raise HTTPException(status_code=503, detail="File gateway is disabled")

        self._cleanup_idle_workers(project_id)

        worker_name = self._worker_name(project_id, pvc_name)
        service_name = self._service_name(worker_name)
        namespace = get_k8s_service().get_project_namespace(project_id)
        worker_lock = self._get_worker_lock(worker_name)
        k8s = get_k8s_service()
        for attempt in range(2):
            with worker_lock:
                labels = {
                    "app": self.config.worker_app_label,
                    "managed-by": self.config.name,
                    "project-id": project_id,
                    "pvc-name": pvc_name,
                    "worker-name": worker_name,
                }

                service = k8s.get_service(project_id, service_name)
                if not service:
                    created_svc = k8s.create_service(
                        project_id=project_id,
                        name=service_name,
                        selector={"worker-name": worker_name},
                        ports=[{"name": "http", "port": self.config.worker_container_port, "target_port": self.config.worker_container_port}],
                        service_type="ClusterIP",
                    )
                    if not created_svc:
                        raise HTTPException(status_code=500, detail=f"Failed to create file gateway service: {service_name}")

                deployment = k8s.get_deployment(project_id, worker_name)
                if not deployment:
                    manifest = {
                        "apiVersion": "apps/v1",
                        "kind": "Deployment",
                        "metadata": {"name": worker_name, "labels": labels},
                        "spec": {
                            "replicas": 1,
                            "selector": {"matchLabels": {"worker-name": worker_name}},
                            "template": {
                                "metadata": {"labels": {**labels, "worker-name": worker_name}},
                                "spec": {
                                    "containers": [
                                        {
                                            "name": "secflow-platform-resource-file-gateway-worker",
                                            "image": self.config.worker_image,
                                            "imagePullPolicy": "Always",
                                            "ports": [{"containerPort": self.config.worker_container_port}],
                                            "env": [
                                                {"name": "APP_PORT", "value": str(self.config.worker_container_port)},
                                                {"name": "PVC_MOUNT_PATH", "value": self.config.worker_mount_path},
                                                {"name": "FILE_GATEWAY_INTERNAL_TOKEN", "value": self.config.internal_token},
                                            ],
                                            "readinessProbe": {
                                                "httpGet": {
                                                    "path": "/health",
                                                    "port": self.config.worker_container_port,
                                                },
                                                "initialDelaySeconds": 1,
                                                "periodSeconds": 2,
                                                "timeoutSeconds": 1,
                                                "failureThreshold": 15,
                                            },
                                            "livenessProbe": {
                                                "httpGet": {
                                                    "path": "/health",
                                                    "port": self.config.worker_container_port,
                                                },
                                                "initialDelaySeconds": 5,
                                                "periodSeconds": 10,
                                                "timeoutSeconds": 2,
                                                "failureThreshold": 3,
                                            },
                                            "volumeMounts": [
                                                {"name": "target-pvc", "mountPath": self.config.worker_mount_path}
                                            ],
                                            "resources": {
                                                "requests": {"cpu": "50m", "memory": "64Mi"},
                                                "limits": {"cpu": "500m", "memory": "512Mi"},
                                            },
                                        }
                                    ],
                                    "volumes": [
                                        {"name": "target-pvc", "persistentVolumeClaim": {"claimName": pvc_name}}
                                    ],
                                },
                            },
                        },
                    }
                    created = k8s.create_deployment(project_id, manifest)
                    if not created:
                        raise HTTPException(status_code=500, detail=f"Failed to create file gateway worker: {worker_name}")

                if not k8s.wait_for_deployment_ready(project_id, worker_name, timeout=self.config.worker_ready_timeout_seconds):
                    raise HTTPException(status_code=504, detail=f"File gateway worker not ready: {worker_name}")

            self._touch(worker_name)
            base_url = f"http://{service_name}.{namespace}.svc.cluster.local:{self.config.worker_container_port}"
            try:
                self._health_check(base_url)
                return {"worker_name": worker_name, "service_name": service_name, "base_url": base_url}
            except HTTPException as error:
                if attempt >= 1:
                    raise
                logger.warning(
                    "File gateway health check failed, recreating worker once. project_id=%s pvc=%s worker=%s error=%s",
                    project_id,
                    pvc_name,
                    worker_name,
                    error.detail if hasattr(error, "detail") else str(error),
                )
                k8s.delete_service(project_id, service_name)
                k8s.delete_deployment(project_id, worker_name)
                with self._lock:
                    self._worker_access_time.pop(worker_name, None)
                time.sleep(1)

        raise HTTPException(status_code=503, detail=f"File gateway worker unavailable: {worker_name}")

    def _request_worker(
        self,
        method: str,
        project_id: str,
        pvc_name: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Any:
        endpoint = self.ensure_worker(project_id, pvc_name)
        headers = {}
        if self.config.internal_token:
            headers["X-Internal-Token"] = self.config.internal_token
        url = f"{endpoint['base_url']}{path}"
        timeout = httpx.Timeout(self.config.worker_request_timeout_seconds)
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.request(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                    params=params,
                    json=json_body,
                    files=files,
                    data=data,
                )
        except Exception as error:
            raise HTTPException(status_code=502, detail=f"File gateway request failed: {error}") from error

        if response.status_code >= 400:
            detail = ""
            try:
                payload = response.json()
                detail = str(payload.get("detail") or payload)
            except Exception:
                detail = response.text.strip()
            raise HTTPException(status_code=response.status_code, detail=detail or "File gateway request failed")
        ctype = response.headers.get("content-type", "")
        if "application/json" in ctype:
            return response.json()
        return response

    def _health_check(self, base_url: str) -> None:
        headers = {}
        if self.config.internal_token:
            headers["X-Internal-Token"] = self.config.internal_token
        deadline = time.time() + max(10, int(self.config.worker_ready_timeout_seconds))
        last_error = None
        try:
            while time.time() < deadline:
                try:
                    with httpx.Client(timeout=httpx.Timeout(5)) as client:
                        response = client.get(f"{base_url}/health", headers=headers)
                    if response.status_code == 200:
                        return
                    last_error = f"health status={response.status_code}"
                except Exception as error:
                    last_error = str(error)
                time.sleep(1)
            if last_error:
                raise HTTPException(status_code=503, detail=f"File gateway worker unavailable: {last_error}")
            raise HTTPException(status_code=503, detail="File gateway worker health check failed")
        except HTTPException:
            raise

    def list_children(self, project_id: str, pvc_name: str, path: str = "/") -> Dict[str, Any]:
        return self._request_worker("GET", project_id, pvc_name, "/fs/children", params={"path": path})

    def read_file(self, project_id: str, pvc_name: str, path: str, max_bytes: int = 1048576) -> Dict[str, Any]:
        return self._request_worker(
            "GET",
            project_id,
            pvc_name,
            "/fs/file",
            params={"path": path, "max_bytes": max_bytes},
        )

    def upload_file_bytes(self, project_id: str, pvc_name: str, path: str, filename: str, content: bytes) -> Dict[str, Any]:
        files = {"file": (filename, content, "application/octet-stream")}
        return self._request_worker("POST", project_id, pvc_name, "/fs/upload", files=files, data={"path": path})

    def upload_file_stream(
        self,
        project_id: str,
        pvc_name: str,
        path: str,
        filename: str,
        file_obj: Any,
        content_type: str = "application/octet-stream",
    ) -> Dict[str, Any]:
        if hasattr(file_obj, "seek"):
            try:
                file_obj.seek(0)
            except Exception:
                pass
        files = {"file": (filename, file_obj, content_type)}
        return self._request_worker("POST", project_id, pvc_name, "/fs/upload", files=files, data={"path": path})

    def create_directory(self, project_id: str, pvc_name: str, path: str, name: str) -> Dict[str, Any]:
        return self._request_worker(
            "POST",
            project_id,
            pvc_name,
            "/fs/directories",
            json_body={"path": path, "name": name},
        )

    def rename_node(self, project_id: str, pvc_name: str, path: str, target_name: str) -> Dict[str, Any]:
        return self._request_worker(
            "POST",
            project_id,
            pvc_name,
            "/fs/rename",
            json_body={"path": path, "target_name": target_name},
        )

    def move_node(self, project_id: str, pvc_name: str, path: str, target_path: str) -> Dict[str, Any]:
        return self._request_worker(
            "POST",
            project_id,
            pvc_name,
            "/fs/move",
            json_body={"path": path, "target_path": target_path},
        )

    def delete_node(self, project_id: str, pvc_name: str, path: str) -> Dict[str, Any]:
        return self._request_worker("DELETE", project_id, pvc_name, "/fs/node", params={"path": path})

    def extract_archive(self, project_id: str, pvc_name: str, path: str, filename: str, content: bytes) -> Dict[str, Any]:
        files = {"file": (filename, content, "application/octet-stream")}
        return self._request_worker("POST", project_id, pvc_name, "/fs/extract", files=files, data={"path": path})

    def extract_archive_stream(
        self,
        project_id: str,
        pvc_name: str,
        path: str,
        filename: str,
        file_obj: Any,
        content_type: str = "application/octet-stream",
    ) -> Dict[str, Any]:
        if hasattr(file_obj, "seek"):
            try:
                file_obj.seek(0)
            except Exception:
                pass
        files = {"file": (filename, file_obj, content_type)}
        return self._request_worker("POST", project_id, pvc_name, "/fs/extract", files=files, data={"path": path})


_file_gateway_manager: Optional[FileGatewayManager] = None


def get_file_gateway_manager() -> FileGatewayManager:
    global _file_gateway_manager
    if _file_gateway_manager is None:
        _file_gateway_manager = FileGatewayManager.from_runtime_config()
    return _file_gateway_manager
