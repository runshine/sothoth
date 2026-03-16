"""Kubernetes operation service."""

import os
import uuid
import asyncio
import time
from typing import Optional, Dict, Any, List
from kubernetes import client, config
from kubernetes.client import CoreV1Api, BatchV1Api, V1ObjectMeta, V1PersistentVolumeClaim, V1Job
import logging

logger = logging.getLogger(__name__)


class KubernetesService:
    """Kubernetes operation service class."""

    def __init__(
        self,
        connection_mode: str,
        kubeconfig_path: Optional[str] = None,
        storage_class_name: str = "nfs-client",
        pvc_size: int = 10,
        job_timeout: int = 600
    ):
        """
        Initialize K8S service.

        Args:
            connection_mode: Connection mode ("incluster" or "kubeconfig")
            kubeconfig_path: kubeconfig file path
            storage_class_name: Storage class name
            pvc_size: PVC size (Gi)
            job_timeout: Job timeout (seconds)
        """
        self.connection_mode = connection_mode
        self.kubeconfig_path = kubeconfig_path
        self.storage_class_name = storage_class_name
        self.pvc_size = pvc_size
        self.job_timeout = job_timeout
        self.core_api: Optional[CoreV1Api] = None
        self.batch_api: Optional[BatchV1Api] = None

    def load_config(self):
        """Load K8S configuration."""
        try:
            if self.connection_mode == "incluster":
                config.load_incluster_config()
            else:
                if self.kubeconfig_path and os.path.exists(self.kubeconfig_path):
                    config.load_kube_config(config_file=self.kubeconfig_path)
                else:
                    raise FileNotFoundError(
                        f"Kubeconfig file not found: {self.kubeconfig_path}"
                    )

            self.core_api = client.CoreV1Api()
            self.batch_api = client.BatchV1Api()
            return True

        except Exception as e:
            logger.error(f"Failed to load Kubernetes config: {e}")
            return False

    def check_connection(self) -> bool:
        """Check K8S connection."""
        if not self.core_api:
            if not self.load_config():
                return False

        try:
            self.core_api.read_cluster_name()
            return True
        except Exception:
            try:
                self.core_api.list_namespace(limit=1)
                return True
            except Exception:
                return False

    def get_project_namespace(self, project_id: str) -> str:
        """Get project namespace (from secflow_project service)."""
        return f"secflow-{project_id}"

    def ensure_namespace(self, project_id: str) -> bool:
        """Ensure namespace exists, create if not."""
        if not self.core_api:
            return False

        namespace = self.get_project_namespace(project_id)
        try:
            try:
                self.core_api.read_namespace(name=namespace)
                return True
            except Exception:
                pass

            body = {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": namespace,
                    "labels": {
                        "app": "secflow-resource",
                        "project": project_id
                    }
                }
            }
            self.core_api.create_namespace(body=body)
            logger.info(f"Namespace {namespace} created")
            return True

        except Exception as e:
            logger.error(f"Failed to ensure namespace {namespace}: {e}")
            return False

    def get_pvc_name(self, upload_uuid: str) -> str:
        """Generate unique PVC name for each upload."""
        # 格式: secflow-pvc-{uuid[:12]}
        return f"secflow-pvc-{upload_uuid[:12]}"

    def create_pvc(
        self,
        project_id: str,
        pvc_name: str,
        size: Optional[int] = None,
        storage_class: Optional[str] = None
    ) -> Optional[str]:
        """
        Create a PVC in the project namespace.

        Args:
            project_id: Project ID
            pvc_name: PVC name
            size: PVC size (Gi), default use config value
            storage_class: Storage class name, default use config value

        Returns:
            str: PVC name, None on failure
        """
        if not self.core_api:
            return None

        namespace = self.get_project_namespace(project_id)

        try:
            # Ensure namespace exists
            self.ensure_namespace(project_id)

            # Check if PVC already exists
            try:
                self.core_api.read_namespaced_persistent_volume_claim(
                    name=pvc_name,
                    namespace=namespace
                )
                logger.info(f"PVC {pvc_name} already exists in namespace {namespace}")
                return pvc_name
            except Exception:
                pass

            # Create PVC
            body = V1PersistentVolumeClaim(
                api_version="v1",
                kind="PersistentVolumeClaim",
                metadata=V1ObjectMeta(
                    name=pvc_name,
                    namespace=namespace,
                    labels={
                        "app": "secflow-resource",
                        "project": project_id,
                        "pvc_uuid": pvc_name
                    }
                ),
                spec={
                    "accessModes": ["ReadWriteOnce"],
                    "storageClassName": storage_class or self.storage_class_name,
                    "resources": {
                        "requests": {
                            "storage": f"{size or self.pvc_size}Gi"
                        }
                    }
                }
            )

            self.core_api.create_namespaced_persistent_volume_claim(
                namespace=namespace,
                body=body
            )
            logger.info(f"PVC {pvc_name} created in namespace {namespace}")
            return pvc_name

        except Exception as e:
            logger.error(f"Failed to create PVC {pvc_name}: {e}")
            return None

    def wait_for_pvc_bound(self, project_id: str, pvc_name: str, timeout: int = 60) -> bool:
        """
        Wait for PVC to reach Bound state.

        Args:
            project_id: Project ID
            pvc_name: PVC name
            timeout: Max time to wait in seconds

        Returns:
            bool: True if PVC is Bound, False if timeout or error
        """
        if not self.core_api:
            return False

        namespace = self.get_project_namespace(project_id)
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                pvc = self.core_api.read_namespaced_persistent_volume_claim(
                    name=pvc_name,
                    namespace=namespace
                )

                if pvc.status.phase == "Bound":
                    logger.info(f"PVC {pvc_name} is now Bound")
                    return True

                if pvc.status.phase == "Lost":
                    logger.error(f"PVC {pvc_name} is Lost")
                    return False

                logger.debug(f"Waiting for PVC {pvc_name}: {pvc.status.phase}")

            except Exception as e:
                logger.debug(f"Waiting for PVC {pvc_name}: {e}")

            time.sleep(1)

        logger.error(f"Timeout waiting for PVC {pvc_name} to be Bound")
        return False

    def get_job_pod_logs(self, project_id: str, job_name: str, tail_lines: int = 200) -> str:
        """
        Get logs from the Pod associated with a Job.

        Args:
            project_id: Project ID
            job_name: Job name
            tail_lines: Number of lines to get from the end of logs

        Returns:
            str: Pod logs
        """
        if not self.core_api:
            return "Core API not initialized"

        namespace = self.get_project_namespace(project_id)

        try:
            # Find pods with the job-name label
            pods = self.core_api.list_namespaced_pod(
                namespace=namespace,
                label_selector=f"job-name={job_name}"
            )

            if not pods.items:
                return f"No pods found for job {job_name}"

            # Get logs from the first pod
            pod_name = pods.items[0].metadata.name
            logs = self.core_api.read_namespaced_pod_log(
                name=pod_name,
                namespace=namespace,
                tail_lines=tail_lines
            )

            return logs

        except Exception as e:
            return f"Failed to get pod logs: {str(e)}"

    def delete_pvc(self, project_id: str, pvc_name: str, timeout: int = 60) -> bool:
        """Delete a PVC and wait for it to be fully removed.

        Args:
            project_id: Project ID
            pvc_name: PVC name
            timeout: Max time to wait for PVC deletion (seconds)

        Returns:
            bool: True if PVC is fully deleted, False otherwise
        """
        if not self.core_api:
            return False

        namespace = self.get_project_namespace(project_id)
        try:
            # First, check if PVC exists
            try:
                self.core_api.read_namespaced_persistent_volume_claim(
                    name=pvc_name,
                    namespace=namespace
                )
            except Exception:
                # PVC doesn't exist, consider it already deleted
                logger.info(f"PVC {pvc_name} does not exist in namespace {namespace}, skipping deletion")
                return True

            # Delete PVC
            self.core_api.delete_namespaced_persistent_volume_claim(
                name=pvc_name,
                namespace=namespace
            )

            # Wait for PVC to be fully deleted
            import time
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    self.core_api.read_namespaced_persistent_volume_claim(
                        name=pvc_name,
                        namespace=namespace
                    )
                    # PVC still exists, wait a bit
                    time.sleep(0.5)
                except Exception:
                    # PVC no longer exists, deletion complete
                    logger.info(f"PVC {pvc_name} fully deleted from namespace {namespace}")
                    return True

            # Timeout reached but PVC still exists
            logger.error(f"Timeout waiting for PVC {pvc_name} deletion in namespace {namespace}")
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
        extract_path: str = "/"
    ) -> Optional[str]:
        """
        Create a Job to download archive from URL and extract to PVC.

        Args:
            project_id: Project ID
            pvc_name: PVC name
            upload_uuid: Upload UUID for job naming
            archive_url: URL to download archive from
            file_format: File format (e.g., "zip", "tar.gz", "tar"), will be auto-detected from URL if not provided
            extract_path: Path to extract in PVC

        Returns:
            str: Job name, None on failure
        """
        if not self.batch_api:
            return None

        namespace = self.get_project_namespace(project_id)
        job_name = f"secflow-upload-{upload_uuid[:12]}"

        # Use provided file_format if available, otherwise detect from URL
        if file_format:
            # Convert format like "zip" to extension ".zip"
            if file_format == "tar.gz":
                ext = ".tar.gz"
            else:
                ext = f".{file_format}"
        else:
            # Fallback to detecting from URL
            ext = self._get_archive_extension(archive_url)

        extract_cmd = self._build_extract_command(extract_path, ext, archive_url)

        job_body = V1Job(
            api_version="batch/v1",
            kind="Job",
            metadata=V1ObjectMeta(
                name=job_name,
                namespace=namespace,
                labels={
                    "app": "secflow-resource",
                    "project": project_id,
                    "job_type": "upload",
                    "upload_uuid": upload_uuid
                }
            ),
            spec={
                "ttlSecondsAfterFinished": 300,
                "backoffLimit": 2,
                "template": {
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": [{
                            "name": "upload-extract",
                            "image": "ghcr.io/runshine/vpn-monitor:latest",
                            "command": ["/bin/sh", "-c", extract_cmd],
                            "volumeMounts": [{
                                "name": "pvc-data",
                                "mountPath": "/mnt"
                            }],
                            "resources": {
                                "requests": {"memory": "64Mi", "cpu": "100m"},
                                "limits": {"memory": "256Mi", "cpu": "500m"}
                            }
                        }],
                        "volumes": [{
                            "name": "pvc-data",
                            "persistentVolumeClaim": {
                                "claimName": pvc_name
                            }
                        }]
                    }
                }
            }
        )

        try:
            self.batch_api.create_namespaced_job(
                namespace=namespace,
                body=job_body
            )
            logger.info(f"Upload job {job_name} created in namespace {namespace} with format {ext}")
            return job_name

        except Exception as e:
            logger.error(f"Failed to create upload job {job_name}: {e}")
            return None

    async def wait_for_job_completion(self, project_id: str, job_name: str, timeout: int = None) -> tuple[bool, str]:
        """
        Wait for job completion.

        Args:
            project_id: Project ID
            job_name: Job name
            timeout: Timeout in seconds

        Returns:
            tuple: (success, message)
        """
        if not self.batch_api:
            return False, "Batch API not initialized"

        namespace = self.get_project_namespace(project_id)
        timeout = timeout or self.job_timeout

        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                job = self.batch_api.read_namespaced_job(
                    name=job_name,
                    namespace=namespace
                )

                # Check job status
                if job.status.succeeded is not None and job.status.succeeded > 0:
                    # Get logs for successful completion
                    logs = self.get_job_pod_logs(project_id, job_name, tail_lines=50)
                    logger.info(f"Job {job_name} completed successfully. Logs snippet: {logs[:500]}")
                    return True, f"Job {job_name} completed successfully"

                if job.status.failed is not None and job.status.failed > 0:
                    # Get logs for failed job
                    logs = self.get_job_pod_logs(project_id, job_name, tail_lines=200)
                    logger.error(f"Job {job_name} failed. Logs: {logs}")
                    return False, f"Job {job_name} failed. Logs: {logs}"

                await asyncio.sleep(2)

            except Exception as e:
                logger.debug(f"Waiting for job {job_name}: {e}")
                await asyncio.sleep(2)

        return False, f"Job {job_name} timed out after {timeout}s"

    def delete_job(self, project_id: str, job_name: str, timeout: int = 60) -> bool:
        """Delete a Job and wait for it to be fully removed.

        Args:
            project_id: Project ID
            job_name: Job name
            timeout: Max time to wait for Job deletion (seconds)

        Returns:
            bool: True if Job is fully deleted, False otherwise
        """
        if not self.batch_api:
            return False

        namespace = self.get_project_namespace(project_id)
        try:
            # Check if Job exists first
            try:
                self.batch_api.read_namespaced_job(name=job_name, namespace=namespace)
            except Exception:
                logger.info(f"Job {job_name} does not exist in namespace {namespace}, skipping deletion")
                return True

            # Delete Job with foreground propagation
            self.batch_api.delete_namespaced_job(
                name=job_name,
                namespace=namespace,
                propagation_policy="Foreground"
            )

            # Wait for Job to be fully deleted
            import time
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    self.batch_api.read_namespaced_job(name=job_name, namespace=namespace)
                    time.sleep(0.5)
                except Exception:
                    logger.info(f"Job {job_name} fully deleted from namespace {namespace}")
                    return True

            logger.error(f"Timeout waiting for Job {job_name} deletion in namespace {namespace}")
            return False

        except Exception as e:
            logger.error(f"Failed to delete Job {job_name}: {e}")
            return False

    def cleanup_created_resources(
        self,
        created_resources: List[Dict[str, str]],
        timeout: int = 60
    ) -> bool:
        """
        Cleanup K8S resources created during task execution.

        Args:
            created_resources: List of [{type, name, namespace}]
            timeout: Max time to wait for each resource deletion (seconds)

        Returns:
            bool: All resources cleaned up successfully
        """
        import time
        success = True

        for resource in created_resources:
            resource_type = resource.get("type")
            name = resource.get("name")
            namespace = resource.get("namespace")

            try:
                if resource_type == "pvc":
                    # Check if PVC exists first
                    try:
                        self.core_api.read_namespaced_persistent_volume_claim(
                            name=name, namespace=namespace
                        )
                    except Exception:
                        logger.info(f"PVC {name} already deleted, skipping")
                        continue

                    # Delete PVC
                    self.core_api.delete_namespaced_persistent_volume_claim(
                        name=name, namespace=namespace
                    )

                    # Wait for PVC to be fully deleted
                    start_time = time.time()
                    deleted = False
                    while time.time() - start_time < timeout:
                        try:
                            self.core_api.read_namespaced_persistent_volume_claim(
                                name=name, namespace=namespace
                            )
                            time.sleep(0.5)
                        except Exception:
                            deleted = True
                            break

                    if deleted:
                        logger.info(f"Cleaned up PVC {name} in namespace {namespace}")
                    else:
                        logger.error(f"Timeout waiting for PVC {name} deletion")
                        success = False

                elif resource_type == "job":
                    # Check if Job exists first
                    try:
                        self.batch_api.read_namespaced_job(name=name, namespace=namespace)
                    except Exception:
                        logger.info(f"Job {name} already deleted, skipping")
                        continue

                    # Delete Job with foreground propagation
                    self.batch_api.delete_namespaced_job(
                        name=name, namespace=namespace,
                        propagation_policy="Foreground"
                    )

                    # Wait for Job to be fully deleted
                    start_time = time.time()
                    deleted = False
                    while time.time() - start_time < timeout:
                        try:
                            self.batch_api.read_namespaced_job(name=name, namespace=namespace)
                            time.sleep(0.5)
                        except Exception:
                            deleted = True
                            break

                    if deleted:
                        logger.info(f"Cleaned up Job {name} in namespace {namespace}")
                    else:
                        logger.error(f"Timeout waiting for Job {name} deletion")
                        success = False

            except Exception as e:
                logger.error(f"Failed to cleanup resource {resource_type} {name}: {e}")
                success = False

        return success

    def _get_archive_extension(self, url: str) -> str:
        """Get archive file extension from URL."""
        if url.endswith(".zip"):
            return ".zip"
        elif url.endswith(".tar.gz") or url.endswith(".tgz"):
            return ".tar.gz"
        elif url.endswith(".tar"):
            return ".tar"
        return ""

    def _build_extract_command(
        self,
        extract_path: str,
        archive_type: str,
        archive_url: str
    ) -> str:
        """Build shell command for download and extract."""
        # PVC 挂载在 /mnt，extract_path 是 "\"/\" 表示根目录
        # 所以实际解压目标路径是 /mnt
        target_path = "/mnt"

        # Download based on archive type with retry and timeout
        if archive_type == ".zip":
            cmd = f"""\
echo "Starting download from {archive_url}" && \
cd {target_path} && \
wget -t 3 -T 120 --no-check-certificate -q -O archive.zip '{archive_url}' && \
echo "Download completed, size:" $(stat -c%s archive.zip) && \
echo "Extracting archive..." && \
unzip -o archive.zip && \
rm -f archive.zip && \
echo "Extract completed successfully" && \
ls -la {target_path}/"""
        elif archive_type == ".tar.gz":
            cmd = f"""\
echo "Starting download from {archive_url}" && \
cd {target_path} && \
wget -t 3 -T 120 --no-check-certificate -q -O archive.tar.gz '{archive_url}' && \
echo "Download completed, size:" $(stat -c%s archive.tar.gz) && \
echo "Extracting archive..." && \
tar -xzf archive.tar.gz && \
rm -f archive.tar.gz && \
echo "Extract completed successfully" && \
ls -la {target_path}/"""
        elif archive_type == ".tar":
            cmd = f"""\
echo "Starting download from {archive_url}" && \
cd {target_path} && \
wget -t 3 -T 120 --no-check-certificate -q -O archive.tar '{archive_url}' && \
echo "Download completed, size:" $(stat -c%s archive.tar) && \
echo "Extracting archive..." && \
tar -xf archive.tar && \
rm -f archive.tar && \
echo "Extract completed successfully" && \
ls -la {target_path}/"""
        else:
            # Default: download without extraction
            cmd = f"""\
echo "Starting download from {archive_url}" && \
cd {target_path} && \
wget -t 3 -T 120 --no-check-certificate -q -O archive '{archive_url}' && \
echo "Download completed, size:" $(stat -c%s archive) && \
echo "Download completed successfully" && \
ls -la {target_path}/"""

        return cmd

    def list_pvcs(self, project_id: str) -> List[Dict[str, Any]]:
        """List PVCs in project namespace."""
        if not self.core_api:
            return []

        namespace = self.get_project_namespace(project_id)
        try:
            pvcs = self.core_api.list_namespaced_persistent_volume_claim(
                namespace=namespace
            )

            result = []
            for pvc in pvcs.items:
                result.append({
                    "name": pvc.metadata.name,
                    "capacity": pvc.status.capacity.get("storage", "0Gi") if pvc.status else "0Gi",
                    "status": pvc.status.phase if pvc.status else "Unknown",
                    "storage_class": pvc.spec.storage_class_name,
                    "namespace": namespace
                })

            return result

        except Exception as e:
            logger.error(f"Failed to list PVCs in {namespace}: {e}")
            return []

    def list_all_secflow_pvcs(self) -> List[Dict[str, Any]]:
        """List all PVCs in all SecFlow namespaces (secflow_*)."""
        if not self.core_api:
            return []

        try:
            # List all namespaces and filter those starting with "secflow_"
            namespaces = self.core_api.list_namespace()
            secflow_namespaces = [
                ns.metadata.name for ns in namespaces.items
                if ns.metadata.name.startswith("secflow_")
            ]

            all_pvcs = []
            for namespace in secflow_namespaces:
                try:
                    pvcs = self.core_api.list_namespaced_persistent_volume_claim(
                        namespace=namespace
                    )
                    for pvc in pvcs.items:
                        all_pvcs.append({
                            "name": pvc.metadata.name,
                            "capacity": pvc.status.capacity.get("storage", "0Gi") if pvc.status else "0Gi",
                            "status": pvc.status.phase if pvc.status else "Unknown",
                            "storage_class": pvc.spec.storage_class_name,
                            "namespace": namespace,
                            "project_id": namespace.replace("secflow_", "", 1)
                        })
                except Exception as e:
                    logger.error(f"Failed to list PVCs in namespace {namespace}: {e}")

            return all_pvcs

        except Exception as e:
            logger.error(f"Failed to list all SecFlow PVCs: {e}")
            return []

    def get_pvc_statistics(self) -> Dict[str, Any]:
        """Get PVC statistics across all SecFlow namespaces."""
        all_pvcs = self.list_all_secflow_pvcs()

        # Count by status
        status_counts = {}
        for pvc in all_pvcs:
            status = pvc.get("status", "Unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        # Calculate total storage
        total_storage_gi = 0
        for pvc in all_pvcs:
            capacity = pvc.get("capacity", "0Gi")
            if capacity.endswith("Gi"):
                try:
                    total_storage_gi += int(capacity.replace("Gi", ""))
                except ValueError:
                    pass
            elif capacity.endswith("Mi"):
                try:
                    total_storage_gi += int(capacity.replace("Mi", "")) / 1024
                except ValueError:
                    pass
            elif capacity.endswith("Ti"):
                try:
                    total_storage_gi += int(capacity.replace("Ti", "")) * 1024
                except ValueError:
                    pass

        return {
            "total_pvcs": len(all_pvcs),
            "total_storage_gi": round(total_storage_gi, 2),
            "status_counts": status_counts,
            "namespaces_count": len(set(pvc.get("namespace") for pvc in all_pvcs))
        }

    def get_pvc_status(self, project_id: str, pvc_name: str) -> Optional[Dict[str, Any]]:
        """Get PVC status."""
        if not self.core_api:
            return None

        namespace = self.get_project_namespace(project_id)
        try:
            pvc = self.core_api.read_namespaced_persistent_volume_claim(
                name=pvc_name,
                namespace=namespace
            )

            return {
                "name": pvc.metadata.name,
                "capacity": pvc.status.capacity.get("storage", "0Gi") if pvc.status else "0Gi",
                "status": pvc.status.phase if pvc.status else "Unknown",
                "storage_class": pvc.spec.storage_class_name,
                "namespace": namespace
            }

        except Exception as e:
            logger.error(f"Failed to get PVC {pvc_name}: {e}")
            return None

    def check_pvc_in_use(self, project_id: str, pvc_name: str) -> tuple[bool, str]:
        """
        Check if a PVC is currently in use by any pod.

        Args:
            project_id: Project ID
            pvc_name: PVC name

        Returns:
            tuple: (in_use, message)
                in_use: True if PVC is being used, False otherwise
                message: Description of the usage status
        """
        if not self.core_api:
            return False, "K8S API not initialized"

        namespace = self.get_project_namespace(project_id)

        try:
            # Check if PVC exists first
            try:
                self.core_api.read_namespaced_persistent_volume_claim(
                    name=pvc_name,
                    namespace=namespace
                )
            except Exception:
                # PVC doesn't exist, consider it not in use
                return False, f"PVC {pvc_name} does not exist"

            # List all pods in the namespace and check if any are using this PVC
            pods = self.core_api.list_namespaced_pod(namespace=namespace)

            for pod in pods.items:
                # Check volumes
                if pod.spec and pod.spec.volumes:
                    for volume in pod.spec.volumes:
                        if volume.persistent_volume_claim and \
                           volume.persistent_volume_claim.claim_name == pvc_name:
                            # Check pod status - only consider running/pending pods
                            pod_phase = pod.status.phase if pod.status else "Unknown"
                            if pod_phase in ["Running", "Pending"]:
                                return True, f"PVC is mounted by running pod {pod.metadata.name}"
                            elif pod_phase == "Succeeded":
                                # Job completed, PVC not really "in use" anymore
                                continue
                            else:
                                return True, f"PVC is mounted by pod {pod.metadata.name} with status {pod_phase}"

            # Check for jobs that might be using this PVC
            if self.batch_api:
                jobs = self.batch_api.list_namespaced_job(namespace=namespace)
                for job in jobs.items:
                    if job.spec and job.spec.template and job.spec.template.spec and job.spec.template.spec.volumes:
                        for volume in job.spec.template.spec.volumes:
                            if volume.persistent_volume_claim and \
                               volume.persistent_volume_claim.claim_name == pvc_name:
                                # Check job status
                                job_status = "Unknown"
                                if job.status.active and job.status.active > 0:
                                    job_status = "Active"
                                elif job.status.succeeded and job.status.succeeded > 0:
                                    job_status = "Succeeded"
                                elif job.status.failed and job.status.failed > 0:
                                    job_status = "Failed"

                                if job_status in ["Active", "Pending"]:
                                    return True, f"PVC is being used by active job {job.metadata.name}"

            return False, "PVC is not in use"

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
    _k8s_service = KubernetesService(
        connection_mode=config.get("connection_mode", "incluster"),
        kubeconfig_path=config.get("kubeconfig_path"),
        storage_class_name=config.get("storage_class_name", "nfs-client"),
        pvc_size=config.get("pvc_size", 10),
        job_timeout=config.get("job_timeout", 600)
    )

    # Verify connection
    if not _k8s_service.load_config():
        raise ConnectionError("Failed to load Kubernetes configuration")

    if not _k8s_service.check_connection():
        raise ConnectionError("Failed to connect to Kubernetes cluster")

    logger.info("Kubernetes service initialized successfully")
    return _k8s_service