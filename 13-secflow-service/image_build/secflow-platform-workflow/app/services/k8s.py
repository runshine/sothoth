"""
K8S client service for workflow management
Supports both kubeconfig and serviceaccount connection modes
"""

import logging
import time
from typing import Optional, Dict, List, Any, Tuple

from kubernetes import client, config
from kubernetes.client.rest import ApiException

from app.config import get_config

logger = logging.getLogger(__name__)


class K8SClient:
    """K8S client for workflow operations"""

    def __init__(self):
        self.k8s_config = get_config().kubernetes
        self.core_api: Optional[client.CoreV1Api] = None
        self.apps_api: Optional[client.AppsV1Api] = None
        self.batch_api: Optional[client.BatchV1Api] = None
        self.networking_api: Optional[client.NetworkingV1Api] = None

    def connect(self) -> bool:
        """
        Connect to K8S cluster

        Returns:
            Whether connection succeeded
        """
        try:
            if self.k8s_config.connection_mode == "incluster":
                # Use ServiceAccount (inside K8S cluster)
                config.load_incluster_config()
                logger.info("Using ServiceAccount to load K8S config")
            else:
                # Use kubeconfig (outside cluster for debugging)
                kubeconfig_path = self.k8s_config.kubeconfig_path or "~/.kube/config"
                config.load_kube_config(config_file=kubeconfig_path)
                logger.info(f"Using kubeconfig to load K8S config: {kubeconfig_path}")

            # Initialize API clients
            self.core_api = client.CoreV1Api()
            self.apps_api = client.AppsV1Api()
            self.batch_api = client.BatchV1Api()
            self.networking_api = client.NetworkingV1Api()

            # Verify connection
            self.core_api.list_namespace(limit=1)
            logger.info("K8S connection verified successfully")
            return True

        except Exception as e:
            logger.error(f"K8S connection failed: {e}")
            return False

    def get_project_namespace(self, project_id: str) -> str:
        """Get project namespace name"""
        return f"secflow-{project_id}"

    def ensure_namespace(self, project_id: str) -> bool:
        """Ensure namespace exists"""
        namespace = self.get_project_namespace(project_id)
        try:
            self.core_api.read_namespace(name=namespace)
            return True
        except ApiException as e:
            if e.status == 404:
                # Namespace doesn't exist
                logger.warning(f"Namespace {namespace} does not exist")
                return False
            raise

    # ============ Deployment Operations ============

    def create_deployment_with_containers(
        self,
        project_id: str,
        name: str,
        containers: List[Dict[str, Any]],
        ports: Optional[List[Dict[str, Any]]] = None,
        volume_mounts: Optional[List[Dict[str, Any]]] = None,
        replicas: int = 1
    ) -> Tuple[bool, Optional[str]]:
        """
        Create a Deployment with multiple containers

        Args:
            project_id: Project ID
            name: Deployment name
            containers: List of container configs with fields like:
                       - name
                       - image
                       - command
                       - args
                       - env_vars
                       - volume_mounts (container level)
                       - container_port
                       - privileged
                       - image_pull_policy
                       - resources
                       - health_check
            ports: Service ports (these become deployment ports too)
            volume_mounts: Global volume mounts for all containers
            replicas: Number of replicas

        Returns:
            Tuple of (success, error_message)
        """
        namespace = self.get_project_namespace(project_id)

        try:
            # Build container definitions
            k8s_containers = []
            volumes = []
            volume_index = 0

            # Track all PVCs to create volumes
            pvc_volumes = {}  # pvc_name -> volume_name

            for idx, container in enumerate(containers):
                container_name = container.get("name", f"container-{idx}")
                image = container.get("image")
                if not image:
                    return False, f"Container {container_name} has no image"

                # Build container volume mounts
                container_mounts = []
                container_volumes = container.get("volume_mounts", [])

                for vm in container_volumes:
                    pvc_name = vm.get("pvc_name")
                    mount_path = vm.get("mount_path")
                    sub_path = vm.get("sub_path")  # Support subdirectory mounting
                    if not pvc_name or not mount_path:
                        continue

                    if pvc_name not in pvc_volumes:
                        volume_name = f"volume-{volume_index}"
                        pvc_volumes[pvc_name] = volume_name
                        volumes.append(
                            client.V1Volume(
                                name=volume_name,
                                persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                                    claim_name=pvc_name
                                )
                            )
                        )
                        volume_index += 1

                    container_mounts.append(
                        client.V1VolumeMount(
                            name=pvc_volumes[pvc_name],
                            mount_path=mount_path,
                            sub_path=sub_path,  # Add sub_path support
                            read_only=vm.get("read_only", False)
                        )
                    )

                # Add global volume mounts if provided
                if volume_mounts:
                    for vm in volume_mounts:
                        pvc_name = vm.get("pvcName")
                        mount_path = vm.get("mountPath")
                        if not pvc_name or not mount_path:
                            continue

                        if pvc_name not in pvc_volumes:
                            volume_name = f"volume-{volume_index}"
                            pvc_volumes[pvc_name] = volume_name
                            volumes.append(
                                client.V1Volume(
                                    name=volume_name,
                                    persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                                        claim_name=pvc_name
                                    )
                                )
                            )
                            volume_index += 1

                        container_mounts.append(
                            client.V1VolumeMount(
                                name=pvc_volumes[pvc_name],
                                mount_path=mount_path,
                                read_only=vm.get("readOnly", False)
                            )
                        )

                # Build environment variables
                env = []
                env_vars = container.get("env_vars", [])
                for e in env_vars:
                    if e.get("name"):
                        env.append(client.V1EnvVar(name=e["name"], value=e.get("value", "")))

                # Build resources
                resource_requirements = None
                resources = container.get("resources")
                if resources:
                    limits = resources.get("limits", {})
                    requests = resources.get("requests", {})
                    resource_requirements = client.V1ResourceRequirements(
                        limits=limits if limits else None,
                        requests=requests if requests else None
                    )

                # Build health check probes
                # For Deployment (App Template): each container can have health check
                # For Job (Task Template): health check is optional (not typically used)
                liveness_probe = None
                readiness_probe = None

                liveness_config = container.get("liveness_probe")
                readiness_config = container.get("readiness_probe")

                if liveness_config or readiness_config:
                    # Build liveness probe
                    if liveness_config:
                        probe_type = liveness_config.get("type", "http")
                        if probe_type == "http":
                            liveness_probe = client.V1Probe(
                                http_get=client.V1HTTPGetAction(
                                    path=liveness_config.get("path", "/health"),
                                    port=liveness_config.get("port", 8080)
                                ),
                                initial_delay_seconds=liveness_config.get("initialDelaySeconds", 10),
                                period_seconds=liveness_config.get("periodSeconds", 10),
                                timeout_seconds=liveness_config.get("timeoutSeconds", 5),
                                failure_threshold=liveness_config.get("failureThreshold", 3),
                                success_threshold=liveness_config.get("successThreshold", 1)
                            )
                        elif probe_type == "tcp":
                            liveness_probe = client.V1Probe(
                                tcp_socket=client.V1TCPSocketAction(
                                    port=liveness_config.get("port", 8080)
                                ),
                                initial_delay_seconds=liveness_config.get("initialDelaySeconds", 10),
                                period_seconds=liveness_config.get("periodSeconds", 10),
                                timeout_seconds=liveness_config.get("timeoutSeconds", 5),
                                failure_threshold=liveness_config.get("failureThreshold", 3),
                                success_threshold=liveness_config.get("successThreshold", 1)
                            )
                        else:  # exec
                            liveness_probe = client.V1Probe(
                                exec_=client.V1ExecAction(
                                    command=liveness_config.get("command", ["echo", "ok"])
                                ),
                                initial_delay_seconds=liveness_config.get("initialDelaySeconds", 10),
                                period_seconds=liveness_config.get("periodSeconds", 10),
                                timeout_seconds=liveness_config.get("timeoutSeconds", 5),
                                failure_threshold=liveness_config.get("failureThreshold", 3),
                                success_threshold=liveness_config.get("successThreshold", 1)
                            )

                    # Build readiness probe
                    if readiness_config:
                        probe_type = readiness_config.get("type", "http")
                        if probe_type == "http":
                            readiness_probe = client.V1Probe(
                                http_get=client.V1HTTPGetAction(
                                    path=readiness_config.get("path", "/health"),
                                    port=readiness_config.get("port", 8080)
                                ),
                                initial_delay_seconds=readiness_config.get("initialDelaySeconds", 10),
                                period_seconds=readiness_config.get("periodSeconds", 10),
                                timeout_seconds=readiness_config.get("timeoutSeconds", 5),
                                failure_threshold=readiness_config.get("failureThreshold", 3),
                                success_threshold=readiness_config.get("successThreshold", 1)
                            )
                        elif probe_type == "tcp":
                            readiness_probe = client.V1Probe(
                                tcp_socket=client.V1TCPSocketAction(
                                    port=readiness_config.get("port", 8080)
                                ),
                                initial_delay_seconds=readiness_config.get("initialDelaySeconds", 10),
                                period_seconds=readiness_config.get("periodSeconds", 10),
                                timeout_seconds=readiness_config.get("timeoutSeconds", 5),
                                failure_threshold=readiness_config.get("failureThreshold", 3),
                                success_threshold=readiness_config.get("successThreshold", 1)
                            )
                        else:  # exec
                            readiness_probe = client.V1Probe(
                                exec_=client.V1ExecAction(
                                    command=readiness_config.get("command", ["echo", "ok"])
                                ),
                                initial_delay_seconds=readiness_config.get("initialDelaySeconds", 10),
                                period_seconds=readiness_config.get("periodSeconds", 10),
                                timeout_seconds=readiness_config.get("timeoutSeconds", 5),
                                failure_threshold=readiness_config.get("failureThreshold", 3),
                                success_threshold=readiness_config.get("successThreshold", 1)
                            )

                # Build container ports from service ports (for first container only)
                container_ports = []
                if idx == 0 and ports:
                    for port in ports:
                        container_ports.append(
                            client.V1ContainerPort(
                                name=port.get("name", f"port-{port.get('containerPort', port.get('port', 8080))}"),
                                container_port=port.get("containerPort", port.get("port", 8080)),
                                protocol=port.get("protocol", "TCP")
                            )
                        )

                # Create container
                k8s_container = client.V1Container(
                    name=container_name,
                    image=image,
                    command=container.get("command"),
                    args=container.get("args"),
                    env=env if env else None,
                    ports=container_ports if container_ports else None,
                    volume_mounts=container_mounts if container_mounts else None,
                    resources=resource_requirements,
                    security_context=client.V1SecurityContext(
                        privileged=container.get("privileged", False)
                    ) if container.get("privileged") else None,
                    image_pull_policy=container.get("image_pull_policy", "IfNotPresent"),
                    liveness_probe=liveness_probe,
                    readiness_probe=readiness_probe
                )
                k8s_containers.append(k8s_container)

            # Create deployment
            deployment = client.V1Deployment(
                api_version="apps/v1",
                kind="Deployment",
                metadata=client.V1ObjectMeta(
                    name=name,
                    namespace=namespace,
                    labels={
                        "app": name,
                        "managed-by": "secflow-workflow"
                    }
                ),
                spec=client.V1DeploymentSpec(
                    replicas=replicas,
                    selector={"matchLabels": {"app": name}},
                    template=client.V1PodTemplateSpec(
                        metadata=client.V1ObjectMeta(labels={"app": name}),
                        spec=client.V1PodSpec(
                            containers=k8s_containers,
                            volumes=volumes if volumes else None
                        )
                    )
                )
            )

            self.apps_api.create_namespaced_deployment(
                namespace=namespace,
                body=deployment
            )
            logger.info(f"Deployment {name} with {len(k8s_containers)} containers created in namespace {namespace}")
            return True, None

        except ApiException as e:
            error_msg = f"Failed to create deployment {name}: {e}"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error creating deployment {name}: {e}"
            logger.error(error_msg)
            return False, error_msg

    def create_deployment(
        self,
        project_id: str,
        name: str,
        containers: List[Dict[str, Any]],
        ports: Optional[List[Dict[str, Any]]] = None,
        volume_mounts: Optional[List[Dict[str, Any]]] = None,
        replicas: int = 1
    ) -> Tuple[bool, Optional[str]]:
        """
        Create a Deployment (wrapper for create_deployment_with_containers)

        Returns:
            Tuple of (success, error_message)
        """
        # Delegate to create_deployment_with_containers
        return self.create_deployment_with_containers(
            project_id=project_id,
            name=name,
            containers=containers,
            ports=ports,
            volume_mounts=volume_mounts,
            replicas=replicas
        )

    def delete_deployment(self, project_id: str, name: str) -> bool:
        """Delete a Deployment"""
        namespace = self.get_project_namespace(project_id)
        try:
            self.apps_api.delete_namespaced_deployment(
                name=name,
                namespace=namespace
            )
            logger.info(f"Deployment {name} deleted from namespace {namespace}")
            return True
        except ApiException as e:
            if e.status == 404:
                logger.info(f"Deployment {name} not found, consider it deleted")
                return True
            logger.error(f"Failed to delete deployment {name}: {e}")
            return False

    def get_deployment_status(self, project_id: str, name: str) -> Optional[Dict[str, Any]]:
        """Get deployment status"""
        namespace = self.get_project_namespace(project_id)
        try:
            deployment = self.apps_api.read_namespaced_deployment(
                name=name,
                namespace=namespace
            )
            return {
                "name": deployment.metadata.name,
                "replicas": deployment.spec.replicas,
                "available_replicas": deployment.status.available_replicas or 0,
                "ready_replicas": deployment.status.ready_replicas or 0,
                "updated_replicas": deployment.status.updated_replicas or 0,
                "status": "Running" if deployment.status.ready_replicas == deployment.spec.replicas else "Pending"
            }
        except ApiException as e:
            if e.status != 404:
                logger.error(f"Failed to get deployment status: {e}")
            return None

    # ============ Service Operations ============

    def create_service(
        self,
        project_id: str,
        name: str,
        selector: Dict[str, str],
        ports: List[Dict[str, Any]],
        service_type: str = "ClusterIP"
    ) -> Tuple[bool, Optional[str]]:
        """
        Create a Service

        Returns:
            Tuple of (success, error_message)
        """
        namespace = self.get_project_namespace(project_id)

        try:
            service_ports = []
            for port in ports:
                service_ports.append(
                    client.V1ServicePort(
                        name=port.get("name", f"port-{port['port']}"),
                        port=port["port"],
                        target_port=port["targetPort"],
                        protocol=port.get("protocol", "TCP")
                    )
                )

            service = client.V1Service(
                api_version="v1",
                kind="Service",
                metadata=client.V1ObjectMeta(
                    name=name,
                    namespace=namespace,
                    labels={"managed-by": "secflow-workflow"}
                ),
                spec=client.V1ServiceSpec(
                    selector=selector,
                    ports=service_ports,
                    type=service_type
                )
            )

            self.core_api.create_namespaced_service(
                namespace=namespace,
                body=service
            )
            logger.info(f"Service {name} created in namespace {namespace}")
            return True, None

        except ApiException as e:
            error_msg = f"Failed to create service {name}: {e}"
            logger.error(error_msg)
            return False, error_msg

    def delete_service(self, project_id: str, name: str) -> bool:
        """Delete a Service"""
        namespace = self.get_project_namespace(project_id)
        try:
            self.core_api.delete_namespaced_service(
                name=name,
                namespace=namespace
            )
            logger.info(f"Service {name} deleted from namespace {namespace}")
            return True
        except ApiException as e:
            if e.status == 404:
                return True
            logger.error(f"Failed to delete service {name}: {e}")
            return False

    # ============ Job Operations ============

    def create_job(
        self,
        project_id: str,
        name: str,
        containers: List[Dict[str, Any]],
        volume_mounts: Optional[List[Dict[str, Any]]] = None,
        ttl_seconds_after_finished: Optional[int] = 3600,
        backoff_limit: int = 3
    ) -> Tuple[bool, Optional[str]]:
        """
        Create a Job with multiple containers

        Args:
            project_id: Project ID
            name: Job name
            containers: List of container configs
            volume_mounts: Global volume mounts
            ttl_seconds_after_finished: TTL after job finishes
            backoff_limit: Backoff limit for retries

        Returns:
            Tuple of (success, error_message)
        """
        namespace = self.get_project_namespace(project_id)

        try:
            # Build containers
            k8s_containers = []
            volumes = []
            pvc_volumes = {}
            volume_index = 0

            for idx, container in enumerate(containers):
                container_name = container.get("name", f"container-{idx}")
                image = container.get("image")
                if not image:
                    return False, f"Container {container_name} has no image"

                # Build container volume mounts
                container_mounts = []
                container_volumes = container.get("volume_mounts", [])

                for vm in container_volumes:
                    pvc_name = vm.get("pvc_name")
                    mount_path = vm.get("mount_path")
                    sub_path = vm.get("sub_path")  # Support subdirectory mounting
                    if not pvc_name or not mount_path:
                        continue

                    if pvc_name not in pvc_volumes:
                        volume_name = f"volume-{volume_index}"
                        pvc_volumes[pvc_name] = volume_name
                        volumes.append(
                            client.V1Volume(
                                name=volume_name,
                                persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                                    claim_name=pvc_name
                                )
                            )
                        )
                        volume_index += 1

                    container_mounts.append(
                        client.V1VolumeMount(
                            name=pvc_volumes[pvc_name],
                            mount_path=mount_path,
                            sub_path=sub_path,  # Add sub_path support
                            read_only=vm.get("read_only", False)
                        )
                    )

                # Add global volume mounts
                if volume_mounts:
                    for vm in volume_mounts:
                        pvc_name = vm.get("pvcName")
                        mount_path = vm.get("mountPath")
                        if not pvc_name or not mount_path:
                            continue

                        if pvc_name not in pvc_volumes:
                            volume_name = f"volume-{volume_index}"
                            pvc_volumes[pvc_name] = volume_name
                            volumes.append(
                                client.V1Volume(
                                    name=volume_name,
                                    persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                                        claim_name=pvc_name
                                    )
                                )
                            )
                            volume_index += 1

                        container_mounts.append(
                            client.V1VolumeMount(
                                name=pvc_volumes[pvc_name],
                                mount_path=mount_path,
                                read_only=vm.get("readOnly", False)
                            )
                        )

                # Build environment variables
                env = []
                env_vars = container.get("env_vars", [])
                for e in env_vars:
                    if e.get("name"):
                        env.append(client.V1EnvVar(name=e["name"], value=e.get("value", "")))

                # Build resources
                resource_requirements = None
                resources = container.get("resources")
                if resources:
                    limits = resources.get("limits", {})
                    requests = resources.get("requests", {})
                    resource_requirements = client.V1ResourceRequirements(
                        limits=limits if limits else None,
                        requests=requests if requests else None
                    )

                # Create container
                k8s_container = client.V1Container(
                    name=container_name,
                    image=image,
                    command=container.get("command"),
                    args=container.get("args"),
                    env=env if env else None,
                    volume_mounts=container_mounts if container_mounts else None,
                    resources=resource_requirements,
                    security_context=client.V1SecurityContext(
                        privileged=container.get("privileged", False)
                    ) if container.get("privileged") else None,
                    image_pull_policy=container.get("image_pull_policy", "IfNotPresent")
                )
                k8s_containers.append(k8s_container)

            # Create job spec
            job_spec = client.V1Job(
                api_version="batch/v1",
                kind="Job",
                metadata=client.V1ObjectMeta(
                    name=name,
                    namespace=namespace,
                    labels={"managed-by": "secflow-workflow"}
                ),
                spec=client.V1JobSpec(
                    ttl_seconds_after_finished=ttl_seconds_after_finished,
                    backoff_limit=backoff_limit,
                    template=client.V1PodTemplateSpec(
                        metadata=client.V1ObjectMeta(labels={"job-name": name}),
                        spec=client.V1PodSpec(
                            restart_policy="Never",
                            containers=k8s_containers,
                            volumes=volumes if volumes else None
                        )
                    )
                )
            )

            self.batch_api.create_namespaced_job(
                namespace=namespace,
                body=job_spec
            )
            logger.info(f"Job {name} with {len(k8s_containers)} containers created in namespace {namespace}")
            return True, None

        except ApiException as e:
            error_msg = f"Failed to create job {name}: {e}"
            logger.error(error_msg)
            return False, error_msg

    def delete_job(self, project_id: str, name: str) -> bool:
        """Delete a Job"""
        namespace = self.get_project_namespace(project_id)
        try:
            self.batch_api.delete_namespaced_job(
                name=name,
                namespace=namespace,
                propagation_policy="Foreground"
            )
            logger.info(f"Job {name} deleted from namespace {namespace}")
            return True
        except ApiException as e:
            if e.status == 404:
                return True
            logger.error(f"Failed to delete job {name}: {e}")
            return False

    def get_job_status(self, project_id: str, name: str) -> Optional[Dict[str, Any]]:
        """Get job status"""
        namespace = self.get_project_namespace(project_id)
        try:
            job = self.batch_api.read_namespaced_job(
                name=name,
                namespace=namespace
            )

            status = "Pending"
            if job.status.succeeded and job.status.succeeded > 0:
                status = "Succeeded"
            elif job.status.failed and job.status.failed > 0:
                status = "Failed"
            elif job.status.active and job.status.active > 0:
                status = "Running"

            return {
                "name": job.metadata.name,
                "status": status,
                "succeeded": job.status.succeeded or 0,
                "failed": job.status.failed or 0,
                "active": job.status.active or 0,
                "start_time": job.status.start_time,
                "completion_time": job.status.completion_time
            }
        except ApiException as e:
            if e.status != 404:
                logger.error(f"Failed to get job status: {e}")
            return None

    # ============ Pod Operations ============

    def get_deployment_pods(self, project_id: str, deployment_name: str) -> List[Dict[str, Any]]:
        """Get pods for a deployment"""
        namespace = self.get_project_namespace(project_id)
        try:
            pods = self.core_api.list_namespaced_pod(
                namespace=namespace,
                label_selector=f"app={deployment_name}"
            )
            return [
                {
                    "name": pod.metadata.name,
                    "status": pod.status.phase,
                    "ip": pod.status.pod_ip,
                    "node": pod.spec.node_name,
                    "created_at": pod.metadata.creation_timestamp
                }
                for pod in pods.items
            ]
        except ApiException as e:
            logger.error(f"Failed to get deployment pods: {e}")
            return []

    def get_job_pods(self, project_id: str, job_name: str) -> List[Dict[str, Any]]:
        """Get pods for a job"""
        namespace = self.get_project_namespace(project_id)
        try:
            pods = self.core_api.list_namespaced_pod(
                namespace=namespace,
                label_selector=f"job-name={job_name}"
            )
            return [
                {
                    "name": pod.metadata.name,
                    "status": pod.status.phase,
                    "ip": pod.status.pod_ip,
                    "node": pod.spec.node_name,
                    "created_at": pod.metadata.creation_timestamp
                }
                for pod in pods.items
            ]
        except ApiException as e:
            logger.error(f"Failed to get job pods: {e}")
            return []

    def get_pod_logs(
        self,
        project_id: str,
        pod_name: str,
        container: Optional[str] = None,
        tail_lines: int = 100,
        previous: bool = False,
        timestamps: bool = True
    ) -> Optional[str]:
        """
        Get pod logs

        Args:
            project_id: Project ID
            pod_name: Pod name
            container: Container name (for multi-container pods)
            tail_lines: Number of lines to return
            previous: Get previous container logs
            timestamps: Include timestamps

        Returns:
            Log content or None if failed
        """
        namespace = self.get_project_namespace(project_id)
        try:
            kwargs = {
                "name": pod_name,
                "namespace": namespace,
                "tail_lines": tail_lines,
                "previous": previous,
                "timestamps": timestamps
            }
            if container:
                kwargs["container"] = container

            logs = self.core_api.read_namespaced_pod_log(**kwargs)
            return logs
        except ApiException as e:
            logger.error(f"Failed to get pod logs: {e}")
            return None

    # ============ List Resources Operations ============

    def list_deployments(self, project_id: str, label_selector: Optional[str] = None) -> List[Dict[str, Any]]:
        """List deployments in namespace"""
        namespace = self.get_project_namespace(project_id)
        try:
            deployments = self.apps_api.list_namespaced_deployment(
                namespace=namespace,
                label_selector=label_selector
            )
            return [
                {
                    "name": dep.metadata.name,
                    "replicas": dep.spec.replicas,
                    "available_replicas": dep.status.available_replicas or 0,
                    "ready_replicas": dep.status.ready_replicas or 0,
                }
                for dep in deployments.items
            ]
        except ApiException as e:
            logger.error(f"Failed to list deployments: {e}")
            return []

    def list_services(self, project_id: str, label_selector: Optional[str] = None) -> List[Dict[str, Any]]:
        """List services in namespace"""
        namespace = self.get_project_namespace(project_id)
        try:
            services = self.core_api.list_namespaced_service(
                namespace=namespace,
                label_selector=label_selector
            )
            return [
                {
                    "name": svc.metadata.name,
                    "type": svc.spec.type,
                    "ports": [{"port": p.port, "target_port": p.target_port} for p in (svc.spec.ports or [])],
                }
                for svc in services.items
            ]
        except ApiException as e:
            logger.error(f"Failed to list services: {e}")
            return []

    def list_jobs(self, project_id: str, label_selector: Optional[str] = None) -> List[Dict[str, Any]]:
        """List jobs in namespace"""
        namespace = self.get_project_namespace(project_id)
        try:
            jobs = self.batch_api.list_namespaced_job(
                namespace=namespace,
                label_selector=label_selector
            )
            return [
                {
                    "name": job.metadata.name,
                    "status": job.status.conditions[0].type if job.status.conditions else "Unknown",
                }
                for job in jobs.items
            ]
        except ApiException as e:
            logger.error(f"Failed to list jobs: {e}")
            return []


# Singleton instance
_k8s_client: Optional[K8SClient] = None


def get_k8s_client() -> K8SClient:
    """Get K8S client instance"""
    global _k8s_client
    if _k8s_client is None:
        _k8s_client = K8SClient()
    return _k8s_client
