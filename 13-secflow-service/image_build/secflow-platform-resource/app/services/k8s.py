"""Kubernetes operation service (unified via secflow-platform-k8s)."""

import asyncio
import logging
import os
import time
from typing import Optional, Dict, Any, List

import httpx

logger = logging.getLogger(__name__)


class KubernetesService:
    """Kubernetes operation service class."""

    def __init__(
        self,
        connection_mode: str,
        kubeconfig_path: Optional[str] = None,
        storage_class_name: str = "nfs-client",
        pvc_size: int = 10,
        job_timeout: int = 600,
        k8s_service_base_url: Optional[str] = None,
        k8s_service_timeout: int = 30,
        service_machine_token: Optional[str] = None,
    ):
        # Keep old parameters for compatibility, but all operations are routed to platform-k8s.
        self.connection_mode = connection_mode
        self.kubeconfig_path = kubeconfig_path
        self.storage_class_name = storage_class_name
        self.pvc_size = pvc_size
        self.job_timeout = job_timeout
        self.k8s_service_base_url = (
            k8s_service_base_url
            or os.environ.get("K8S_SERVICE_BASE_URL")
            or "http://secflow-platform-k8s:80/api/k8s"
        ).rstrip("/")
        self.timeout = k8s_service_timeout
        self.client = httpx.Client(timeout=self.timeout)
        self.service_machine_token = service_machine_token
        self.last_error: Optional[str] = None

    def get_last_error(self) -> Optional[str]:
        """Return latest k8s operation error message."""
        return self.last_error

    def _request(
        self,
        method: str,
        path: str,
        project_id: Optional[str] = None,
        **kwargs,
    ) -> httpx.Response:
        url = f"{self.k8s_service_base_url}{path}"
        params = dict(kwargs.pop("params", {}) or {})
        headers = dict(kwargs.pop("headers", {}) or {})
        if self.service_machine_token and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {self.service_machine_token}"
        if project_id:
            params["project_id"] = project_id
        return self.client.request(method.upper(), url, params=params, headers=headers, **kwargs)

    def load_config(self):
        """Compatibility method for legacy startup flow."""
        return self.check_connection()

    def check_connection(self) -> bool:
        """Check platform-k8s connection."""
        try:
            resp = self._request("GET", "/health")
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"Failed to connect platform-k8s: {e}")
            return False

    def get_project_namespace(self, project_id: str) -> str:
        """Get project namespace."""
        return f"secflow-{project_id}"

    def ensure_namespace(self, project_id: str) -> bool:
        """Ensure namespace exists."""
        namespace = self.get_project_namespace(project_id)
        try:
            check = self._request("GET", f"/namespaces/{namespace}")
            if check.status_code == 200 and check.json().get("exists", False):
                return True
            create = self._request("POST", f"/namespaces/{namespace}")
            if create.status_code in (200, 201):
                return True
            logger.error(f"Failed to ensure namespace {namespace}: {create.status_code} {create.text}")
            return False
        except Exception as e:
            logger.error(f"Failed to ensure namespace {namespace}: {e}")
            return False

    def get_pvc_name(self, upload_uuid: str) -> str:
        """Generate unique PVC name for each upload."""
        return f"secflow-pvc-{upload_uuid[:12]}"

    def create_pvc(
        self,
        project_id: str,
        pvc_name: str,
        size: Optional[int] = None,
        storage_class: Optional[str] = None,
    ) -> Optional[str]:
        """Create a PVC in the project namespace."""
        self.last_error = None
        namespace = self.get_project_namespace(project_id)
        if not self.ensure_namespace(project_id):
            self.last_error = f"Failed to ensure namespace: {namespace}"
            return None

        try:
            exists = self._request("GET", f"/pvcs/{pvc_name}", project_id=project_id)
            if exists.status_code == 200:
                return pvc_name

            manifest = {
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                "metadata": {
                    "name": pvc_name,
                    "namespace": namespace,
                    "labels": {
                        "app": "secflow-resource",
                        "project": project_id,
                        "pvc_uuid": pvc_name,
                    },
                },
                "spec": {
                    "accessModes": ["ReadWriteOnce"],
                    "storageClassName": storage_class or self.storage_class_name,
                    "resources": {"requests": {"storage": f"{size or self.pvc_size}Gi"}},
                },
            }
            # platform-k8s /pvcs endpoint expects raw manifest body (not wrapped by {"manifest": ...}).
            resp = self._request("POST", "/pvcs", project_id=project_id, json=manifest)
            if resp.status_code in (200, 201):
                return pvc_name
            if resp.status_code == 409:
                return pvc_name
            logger.error(f"Failed to create PVC {pvc_name}: {resp.status_code} {resp.text}")
            self.last_error = f"platform-k8s create pvc failed: HTTP {resp.status_code} {resp.text}"
            return None
        except Exception as e:
            logger.error(f"Failed to create PVC {pvc_name}: {e}")
            self.last_error = f"platform-k8s create pvc exception: {e}"
            return None

    def get_pod(self, project_id: str, pod_name: str) -> Optional[Dict[str, Any]]:
        """Get Pod details."""
        try:
            resp = self._request("GET", f"/pods/{pod_name}", project_id=project_id)
            if resp.status_code != 200:
                return None
            return resp.json()
        except Exception as e:
            logger.error(f"Failed to get Pod {pod_name}: {e}")
            return None

    def create_pod(self, project_id: str, manifest: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create a Pod in the project namespace."""
        try:
            resp = self._request("POST", "/pods", project_id=project_id, json=manifest)
            if resp.status_code in (200, 201):
                return resp.json()
            logger.error(f"Failed to create Pod: {resp.status_code} {resp.text}")
            return None
        except Exception as e:
            logger.error(f"Failed to create Pod: {e}")
            return None

    def delete_pod(self, project_id: str, pod_name: str) -> bool:
        """Delete a Pod in the project namespace."""
        try:
            resp = self._request("DELETE", f"/pods/{pod_name}", project_id=project_id)
            return resp.status_code in (200, 404)
        except Exception as e:
            logger.error(f"Failed to delete Pod {pod_name}: {e}")
            return False

    def wait_for_pod_running(self, project_id: str, pod_name: str, timeout: int = 60) -> bool:
        """Wait for a Pod to become Running."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            pod = self.get_pod(project_id, pod_name)
            if pod and pod.get("status") == "Running":
                return True
            time.sleep(1)
        return False

    def exec_pod_command(
        self,
        project_id: str,
        pod_name: str,
        command: List[str],
        container: Optional[str] = None,
        stdin: Optional[str] = None,
        timeout: int = 30,
        tty: bool = False,
    ) -> Dict[str, Any]:
        """Execute a non-interactive command inside a Pod."""
        try:
            resp = self._request(
                "POST",
                f"/pods/{pod_name}/exec",
                project_id=project_id,
                json={
                    "command": command,
                    "container": container,
                    "stdin": stdin,
                    "timeout": timeout,
                    "tty": tty,
                },
            )
            if resp.status_code != 200:
                raise RuntimeError(f"HTTP {resp.status_code}: {resp.text}")
            return resp.json() or {"stdout": "", "stderr": "", "exit_code": 0}
        except Exception as e:
            logger.error(f"Failed to exec Pod command {command} on {pod_name}: {e}")
            raise

    def wait_for_pvc_bound(self, project_id: str, pvc_name: str, timeout: int = 60) -> bool:
        """Wait for PVC to reach Bound state."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                pvc_resp = self._request("GET", f"/pvcs/{pvc_name}", project_id=project_id)
                if pvc_resp.status_code != 200:
                    time.sleep(1)
                    continue
                pvc = pvc_resp.json()
                phase = pvc.get("status", "Unknown")
                if phase == "Bound":
                    return True
                if phase == "Lost":
                    return False
            except Exception as e:
                logger.debug(f"Waiting for PVC {pvc_name}: {e}")
            time.sleep(1)

        logger.error(f"Timeout waiting for PVC {pvc_name} to be Bound")
        return False

    def get_job_pod_logs(self, project_id: str, job_name: str, tail_lines: int = 200) -> str:
        """Get logs from the Pod associated with a Job."""
        try:
            pods_resp = self._request(
                "GET",
                "/pods",
                project_id=project_id,
                params={"label_selector": f"job-name={job_name}"},
            )
            if pods_resp.status_code != 200:
                return f"Failed to list pods for job {job_name}: {pods_resp.status_code}"

            pods_data = pods_resp.json() or {}
            pods = pods_data.get("items", [])
            if not pods:
                return f"No pods found for job {job_name}"

            pod_name = pods[0].get("name")
            if not pod_name:
                return f"No pod name found for job {job_name}"

            logs_resp = self._request(
                "GET",
                f"/pods/{pod_name}/logs",
                project_id=project_id,
                params={"tail_lines": tail_lines},
            )
            if logs_resp.status_code != 200:
                return f"Failed to get pod logs: {logs_resp.status_code}"
            return (logs_resp.json() or {}).get("logs", "")
        except Exception as e:
            return f"Failed to get pod logs: {str(e)}"

    def delete_pvc(self, project_id: str, pvc_name: str, timeout: int = 60) -> bool:
        """Delete a PVC and wait for it to be fully removed."""
        try:
            exists = self._request("GET", f"/pvcs/{pvc_name}", project_id=project_id)
            if exists.status_code == 404:
                return True

            resp = self._request("DELETE", f"/pvcs/{pvc_name}", project_id=project_id)
            if resp.status_code not in (200, 404):
                logger.error(f"Failed to delete PVC {pvc_name}: {resp.status_code} {resp.text}")
                return False

            start_time = time.time()
            while time.time() - start_time < timeout:
                check = self._request("GET", f"/pvcs/{pvc_name}", project_id=project_id)
                if check.status_code == 404:
                    return True
                time.sleep(0.5)

            logger.error(f"Timeout waiting for PVC {pvc_name} deletion")
            return False
        except Exception as e:
            logger.error(f"Failed to delete PVC {pvc_name}: {e}")
            return False

    def create_upload_extract_job(
        self,
        project_id: str,
        pvc_name: str,
        upload_uuid: str,
        archive_url: str,
        file_format: str = None,
        extract_path: str = "/",
    ) -> Optional[str]:
        """Create a Job to download archive from URL and extract to PVC."""
        namespace = self.get_project_namespace(project_id)
        job_name = f"secflow-upload-{upload_uuid[:12]}"

        if file_format:
            if file_format == "tar.gz":
                ext = ".tar.gz"
            else:
                ext = f".{file_format}"
        else:
            ext = self._get_archive_extension(archive_url)

        extract_cmd = self._build_extract_command(extract_path, ext, archive_url)

        manifest = {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": job_name,
                "namespace": namespace,
                "labels": {
                    "app": "secflow-resource",
                    "project": project_id,
                    "job_type": "upload",
                    "upload_uuid": upload_uuid,
                },
            },
            "spec": {
                "ttlSecondsAfterFinished": 300,
                "backoffLimit": 2,
                "template": {
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": [
                            {
                                "name": "upload-extract",
                                "image": "ghcr.io/runshine/vpn-monitor:latest",
                                "command": ["/bin/sh", "-c", extract_cmd],
                                "volumeMounts": [{"name": "pvc-data", "mountPath": "/mnt"}],
                                "resources": {
                                    "requests": {"memory": "64Mi", "cpu": "100m"},
                                    "limits": {"memory": "256Mi", "cpu": "500m"},
                                },
                            }
                        ],
                        "volumes": [{"name": "pvc-data", "persistentVolumeClaim": {"claimName": pvc_name}}],
                    }
                },
            },
        }

        try:
            resp = self._request("POST", "/jobs", project_id=project_id, json={"manifest": manifest})
            if resp.status_code in (200, 201):
                return job_name
            logger.error(f"Failed to create upload job {job_name}: {resp.status_code} {resp.text}")
            return None
        except Exception as e:
            logger.error(f"Failed to create upload job {job_name}: {e}")
            return None

    async def wait_for_job_completion(
        self,
        project_id: str,
        job_name: str,
        timeout: int = None,
    ) -> tuple[bool, str]:
        """Wait for job completion."""
        timeout = timeout or self.job_timeout
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                resp = self._request("GET", f"/jobs/{job_name}", project_id=project_id)
                if resp.status_code != 200:
                    await asyncio.sleep(2)
                    continue

                job = resp.json() or {}
                if int(job.get("succeeded", 0)) > 0:
                    logs = self.get_job_pod_logs(project_id, job_name, tail_lines=50)
                    logger.info(f"Job {job_name} completed successfully. Logs snippet: {logs[:500]}")
                    return True, f"Job {job_name} completed successfully"

                if int(job.get("failed", 0)) > 0:
                    logs = self.get_job_pod_logs(project_id, job_name, tail_lines=200)
                    logger.error(f"Job {job_name} failed. Logs: {logs}")
                    return False, f"Job {job_name} failed. Logs: {logs}"

                await asyncio.sleep(2)
            except Exception as e:
                logger.debug(f"Waiting for job {job_name}: {e}")
                await asyncio.sleep(2)

        return False, f"Job {job_name} timed out after {timeout}s"

    def delete_job(self, project_id: str, job_name: str, timeout: int = 60) -> bool:
        """Delete a Job and wait for it to be fully removed."""
        try:
            exists = self._request("GET", f"/jobs/{job_name}", project_id=project_id)
            if exists.status_code == 404:
                return True

            resp = self._request("DELETE", f"/jobs/{job_name}", project_id=project_id)
            if resp.status_code not in (200, 404):
                logger.error(f"Failed to delete Job {job_name}: {resp.status_code} {resp.text}")
                return False

            start_time = time.time()
            while time.time() - start_time < timeout:
                check = self._request("GET", f"/jobs/{job_name}", project_id=project_id)
                if check.status_code == 404:
                    return True
                time.sleep(0.5)

            logger.error(f"Timeout waiting for Job {job_name} deletion")
            return False
        except Exception as e:
            logger.error(f"Failed to delete Job {job_name}: {e}")
            return False

    def cleanup_created_resources(
        self,
        created_resources: List[Dict[str, str]],
        timeout: int = 60,
    ) -> bool:
        """Cleanup K8S resources created during task execution."""
        success = True

        for resource in created_resources:
            resource_type = resource.get("type")
            name = resource.get("name")
            namespace = resource.get("namespace")
            project_id = namespace.replace("secflow-", "", 1) if namespace and namespace.startswith("secflow-") else None

            try:
                if resource_type == "pvc" and project_id:
                    if not self.delete_pvc(project_id, name, timeout=timeout):
                        success = False
                elif resource_type == "job" and project_id:
                    if not self.delete_job(project_id, name, timeout=timeout):
                        success = False
            except Exception as e:
                logger.error(f"Failed to cleanup resource {resource_type} {name}: {e}")
                success = False

        return success

    def _get_archive_extension(self, url: str) -> str:
        """Get archive file extension from URL."""
        if url.endswith(".zip"):
            return ".zip"
        if url.endswith(".tar.gz") or url.endswith(".tgz"):
            return ".tar.gz"
        if url.endswith(".tar"):
            return ".tar"
        return ""

    def _build_extract_command(self, extract_path: str, archive_type: str, archive_url: str) -> str:
        """Build shell command for download and extract."""
        target_path = "/mnt"

        if archive_type == ".zip":
            cmd = f"""\
echo "Starting download from {archive_url}" && \\
cd {target_path} && \\
wget -t 3 -T 120 --no-check-certificate -q -O archive.zip '{archive_url}' && \\
echo "Download completed, size:" $(stat -c%s archive.zip) && \\
echo "Extracting archive..." && \\
unzip -o archive.zip && \\
rm -f archive.zip && \\
echo "Extract completed successfully" && \\
ls -la {target_path}/"""
        elif archive_type == ".tar.gz":
            cmd = f"""\
echo "Starting download from {archive_url}" && \\
cd {target_path} && \\
wget -t 3 -T 120 --no-check-certificate -q -O archive.tar.gz '{archive_url}' && \\
echo "Download completed, size:" $(stat -c%s archive.tar.gz) && \\
echo "Extracting archive..." && \\
tar -xzf archive.tar.gz && \\
rm -f archive.tar.gz && \\
echo "Extract completed successfully" && \\
ls -la {target_path}/"""
        elif archive_type == ".tar":
            cmd = f"""\
echo "Starting download from {archive_url}" && \\
cd {target_path} && \\
wget -t 3 -T 120 --no-check-certificate -q -O archive.tar '{archive_url}' && \\
echo "Download completed, size:" $(stat -c%s archive.tar) && \\
echo "Extracting archive..." && \\
tar -xf archive.tar && \\
rm -f archive.tar && \\
echo "Extract completed successfully" && \\
ls -la {target_path}/"""
        else:
            cmd = f"""\
echo "Starting download from {archive_url}" && \\
cd {target_path} && \\
wget -t 3 -T 120 --no-check-certificate -q -O archive '{archive_url}' && \\
echo "Download completed, size:" $(stat -c%s archive) && \\
echo "Download completed successfully" && \\
ls -la {target_path}/"""

        return cmd

    def list_pvcs(self, project_id: str) -> List[Dict[str, Any]]:
        """List PVCs in project namespace."""
        namespace = self.get_project_namespace(project_id)
        try:
            resp = self._request("GET", "/pvcs", project_id=project_id)
            if resp.status_code != 200:
                logger.error(f"Failed to list PVCs in {namespace}: {resp.status_code} {resp.text}")
                return []

            items = (resp.json() or {}).get("items", [])
            result = []
            for pvc in items:
                name = (pvc.get("name") or "").strip()
                if not name:
                    # Ignore malformed records to avoid breaking upper-layer response_model validation.
                    continue
                capacity = self._normalize_capacity(pvc.get("capacity"))
                storage_class = self._normalize_storage_class(pvc.get("storage_class"))
                result.append(
                    {
                        "name": name,
                        "capacity": capacity,
                        "status": pvc.get("status", "Unknown") or "Unknown",
                        "storage_class": storage_class,
                        "namespace": (pvc.get("namespace") or namespace).strip() or namespace,
                    }
                )
            return result
        except Exception as e:
            logger.error(f"Failed to list PVCs in {namespace}: {e}")
            return []

    def list_all_secflow_pvcs(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all PVCs in secflow projects or specific project."""
        if project_id:
            return self.list_pvcs(project_id)

        # For cross-project statistics, use local cached project table and aggregate.
        try:
            from app.models.database import SessionLocal, Project

            db = SessionLocal()
            try:
                project_ids = [p.id for p in db.query(Project.id).all()]
            finally:
                db.close()

            all_pvcs: List[Dict[str, Any]] = []
            for pid in project_ids:
                pvcs = self.list_pvcs(pid)
                for pvc in pvcs:
                    pvc["project_id"] = pid
                    all_pvcs.append(pvc)
            return all_pvcs
        except Exception as e:
            logger.error(f"Failed to list all SecFlow PVCs: {e}")
            return []

    def get_pvc_statistics(self, project_id: Optional[str] = None) -> Dict[str, Any]:
        """Get PVC statistics."""
        all_pvcs = self.list_all_secflow_pvcs(project_id)

        status_counts: Dict[str, int] = {}
        for pvc in all_pvcs:
            status = pvc.get("status", "Unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        total_storage_gi = 0.0
        for pvc in all_pvcs:
            capacity = pvc.get("capacity", "0Gi") or "0Gi"
            try:
                if isinstance(capacity, str) and capacity.endswith("Gi"):
                    total_storage_gi += float(capacity[:-2])
                elif isinstance(capacity, str) and capacity.endswith("Mi"):
                    total_storage_gi += float(capacity[:-2]) / 1024
                elif isinstance(capacity, str) and capacity.endswith("Ti"):
                    total_storage_gi += float(capacity[:-2]) * 1024
            except ValueError:
                continue

        return {
            "total_pvcs": len(all_pvcs),
            "total_storage_gi": round(total_storage_gi, 2),
            "status_counts": status_counts,
            "namespaces_count": len(set(pvc.get("namespace") for pvc in all_pvcs if pvc.get("namespace"))),
        }

    def get_pvc_status(self, project_id: str, pvc_name: str) -> Optional[Dict[str, Any]]:
        """Get PVC status."""
        try:
            resp = self._request("GET", f"/pvcs/{pvc_name}", project_id=project_id)
            if resp.status_code != 200:
                return None
            pvc = resp.json() or {}
            capacity = self._normalize_capacity(pvc.get("capacity"))
            namespace = self.get_project_namespace(project_id)
            return {
                "name": (pvc.get("name") or pvc_name or "").strip(),
                "capacity": capacity,
                "status": pvc.get("status", "Unknown") or "Unknown",
                "storage_class": self._normalize_storage_class(pvc.get("storage_class")),
                "namespace": (pvc.get("namespace") or namespace).strip() or namespace,
            }
        except Exception as e:
            logger.error(f"Failed to get PVC {pvc_name}: {e}")
            return None

    def _normalize_capacity(self, capacity: Any) -> str:
        if isinstance(capacity, dict):
            value = capacity.get("storage")
            if value is None:
                return "0Gi"
            value_str = str(value).strip()
            return value_str or "0Gi"
        if capacity is None:
            return "0Gi"
        value_str = str(capacity).strip()
        return value_str or "0Gi"

    def _normalize_storage_class(self, storage_class: Any) -> str:
        value = "" if storage_class is None else str(storage_class).strip()
        # Hand-created PVCs may have no storageClassName (None/empty); keep response model stable.
        return value or "n/a"

    def check_pvc_in_use(self, project_id: str, pvc_name: str) -> tuple[bool, str]:
        """Check if a PVC is currently in use by any pod/job."""
        try:
            resp = self._request("GET", f"/pvcs/{pvc_name}/usage", project_id=project_id)
            if resp.status_code != 200:
                return True, f"Error checking PVC usage: HTTP {resp.status_code}"
            data = resp.json() or {}
            return bool(data.get("in_use", False)), data.get("message", "")
        except Exception as e:
            logger.error(f"Failed to check PVC usage for {pvc_name}: {e}")
            return True, f"Error checking PVC usage: {str(e)}"


# Global K8S service instance
_k8s_service: Optional[KubernetesService] = None


def get_k8s_service() -> KubernetesService:
    """Get K8S service instance."""
    global _k8s_service
    if _k8s_service is None:
        raise RuntimeError("Kubernetes service not initialized")
    return _k8s_service


def init_k8s_service(config: Dict[str, Any]) -> KubernetesService:
    """Initialize K8S service instance."""
    global _k8s_service

    # Compatible parsing: supports legacy `k8s` and new `k8s_service` blocks.
    k8s_cfg = config.get("k8s", config) if isinstance(config, dict) else {}
    k8s_svc_cfg = config.get("k8s_service", {}) if isinstance(config, dict) else {}
    auth_cfg = config.get("auth_service", {}) if isinstance(config, dict) else {}

    host = k8s_svc_cfg.get("host")
    port = k8s_svc_cfg.get("port")
    base_url = k8s_svc_cfg.get("base_url")
    if not base_url:
        if host and port:
            base_url = f"http://{host}:{port}/api/k8s"
        else:
            base_url = "http://secflow-platform-k8s:80/api/k8s"

    _k8s_service = KubernetesService(
        connection_mode=k8s_cfg.get("connection_mode", "incluster"),
        kubeconfig_path=k8s_cfg.get("kubeconfig_path"),
        storage_class_name=k8s_cfg.get("storage_class_name", "nfs-client"),
        pvc_size=k8s_cfg.get("pvc_size", 10),
        job_timeout=k8s_cfg.get("job_timeout", 600),
        k8s_service_base_url=base_url,
        k8s_service_timeout=k8s_svc_cfg.get("timeout", 30),
        service_machine_token=auth_cfg.get("service_machine_token"),
    )

    if not _k8s_service.check_connection():
        raise ConnectionError(f"Failed to connect to platform-k8s: {base_url}")

    logger.info(f"Kubernetes service initialized successfully via platform-k8s: {base_url}")
    return _k8s_service
