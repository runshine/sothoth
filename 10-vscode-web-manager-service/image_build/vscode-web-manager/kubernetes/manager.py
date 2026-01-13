import os
import yaml
import hashlib
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from kubernetes import client, config
from kubernetes.client.rest import ApiException
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential

from app.config import settings

logger = logging.getLogger(__name__)


class KubernetesManager:
    def __init__(self):
        """初始化Kubernetes客户端"""
        try:
            if settings.IN_K8S:
                # 在K8S集群内部运行
                config.load_incluster_config()
            else:
                # 在集群外部运行
                config.load_kube_config()

            self.v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            self.networking_v1 = client.NetworkingV1Api()
            self.batch_v1 = client.BatchV1Api()

            self.namespace = settings.K8S_NAMESPACE
            self.storage_class = settings.K8S_STORAGE_CLASS

        except Exception as e:
            logger.error(f"Failed to initialize Kubernetes client: {e}")
            raise

    def generate_resource_name(self, project_id: str, resource_type: str) -> str:
        """生成K8S资源名称"""
        # 限制名称长度（K8S要求最多63字符）
        prefix = f"code-server-{resource_type}"
        suffix = project_id[:20]
        return f"{prefix}-{suffix}"

    def create_pvc(self, project_id: str, storage_size: str = "5Gi") -> Dict[str, Any]:
        """创建PVC"""
        pvc_name = self.generate_resource_name(project_id, "pvc")

        pvc_body = {
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": pvc_name,
                "namespace": self.namespace,
                "labels": {
                    "app": "code-server",
                    "project-id": project_id,
                    "managed-by": "source-manager"
                }
            },
            "spec": {
                "accessModes": ["ReadWriteMany"],
                "storageClassName": self.storage_class,
                "resources": {
                    "requests": {
                        "storage": storage_size
                    }
                }
            }
        }

        try:
            logger.info(f"Creating PVC {pvc_name} in namespace {self.namespace}")
            pvc = self.v1.create_namespaced_persistent_volume_claim(
                namespace=self.namespace,
                body=pvc_body
            )

            return {
                "name": pvc.metadata.name,
                "status": pvc.status.phase,
                "created": True
            }
        except ApiException as e:
            if e.status == 409:  # Already exists
                logger.warning(f"PVC {pvc_name} already exists")
                return {"name": pvc_name, "status": "Exists", "created": False}
            else:
                logger.error(f"Failed to create PVC: {e}")
                raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    def wait_for_pvc_bound(self, pvc_name: str, timeout: int = 300) -> bool:
        """等待PVC绑定"""
        import time
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                pvc = self.v1.read_namespaced_persistent_volume_claim(
                    name=pvc_name,
                    namespace=self.namespace
                )

                if pvc.status.phase == "Bound":
                    logger.info(f"PVC {pvc_name} is Bound")
                    return True
                elif pvc.status.phase == "Pending":
                    logger.info(f"PVC {pvc_name} is still Pending")
                else:
                    logger.warning(f"PVC {pvc_name} status: {pvc.status.phase}")

                time.sleep(5)
            except ApiException as e:
                logger.error(f"Error checking PVC status: {e}")
                time.sleep(5)

        logger.error(f"Timeout waiting for PVC {pvc_name} to be Bound")
        return False

    def create_deployment(self, project_id: str, password: str,
                          cpu_limit: str = "1000m", memory_limit: str = "1024Mi",
                          pvc_name: str = None) -> Dict[str, Any]:
        """创建Code-Server Deployment"""
        if not pvc_name:
            pvc_name = self.generate_resource_name(project_id, "pvc")

        deployment_name = self.generate_resource_name(project_id, "deploy")

        # 环境变量
        env_vars = [
            {"name": "PUID", "value": "1000"},
            {"name": "PGID", "value": "1000"},
            {"name": "TZ", "value": "Asia/Shanghai"},
            {"name": "PASSWORD", "value": password},
            {"name": "SUDO_PASSWORD", "value": password},
            {"name": "PROJECT_ID", "value": project_id}
        ]

        deployment_body = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": deployment_name,
                "namespace": self.namespace,
                "labels": {
                    "app": "code-server",
                    "project-id": project_id,
                    "managed-by": "source-manager"
                }
            },
            "spec": {
                "replicas": 1,
                "selector": {
                    "matchLabels": {
                        "app": "code-server",
                        "project-id": project_id
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": "code-server",
                            "project-id": project_id
                        }
                    },
                    "spec": {
                        "securityContext": {
                            "runAsUser": 1000,
                            "runAsGroup": 1000,
                            "fsGroup": 1000
                        },
                        "containers": [{
                            "name": "code-server",
                            "image": settings.K8S_CODE_SERVER_IMAGE,
                            "ports": [{
                                "containerPort": 8443
                            }],
                            "env": env_vars,
                            "resources": {
                                "requests": {
                                    "cpu": "500m",
                                    "memory": "512Mi"
                                },
                                "limits": {
                                    "cpu": cpu_limit,
                                    "memory": memory_limit
                                }
                            },
                            "volumeMounts": [{
                                "name": "project-data",
                                "mountPath": "/config/workspace"
                            }],
                            "livenessProbe": {
                                "httpGet": {
                                    "path": "/",
                                    "port": 8443,
                                    "scheme": "HTTPS"
                                },
                                "initialDelaySeconds": 30,
                                "periodSeconds": 10
                            },
                            "readinessProbe": {
                                "httpGet": {
                                    "path": "/",
                                    "port": 8443,
                                    "scheme": "HTTPS"
                                },
                                "initialDelaySeconds": 5,
                                "periodSeconds": 5
                            }
                        }],
                        "volumes": [{
                            "name": "project-data",
                            "persistentVolumeClaim": {
                                "claimName": pvc_name
                            }
                        }]
                    }
                }
            }
        }

        try:
            logger.info(f"Creating Deployment {deployment_name}")
            deployment = self.apps_v1.create_namespaced_deployment(
                namespace=self.namespace,
                body=deployment_body
            )

            return {
                "name": deployment.metadata.name,
                "created": True
            }
        except ApiException as e:
            logger.error(f"Failed to create Deployment: {e}")
            raise

    def create_service(self, project_id: str) -> Dict[str, Any]:
        """创建Service"""
        service_name = self.generate_resource_name(project_id, "svc")

        service_body = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": service_name,
                "namespace": self.namespace,
                "labels": {
                    "app": "code-server",
                    "project-id": project_id,
                    "managed-by": "source-manager"
                }
            },
            "spec": {
                "type": settings.K8S_SERVICE_TYPE,
                "selector": {
                    "app": "code-server",
                    "project-id": project_id
                },
                "ports": [{
                    "protocol": "TCP",
                    "port": 80,
                    "targetPort": 8443
                }]
            }
        }

        try:
            logger.info(f"Creating Service {service_name}")
            service = self.v1.create_namespaced_service(
                namespace=self.namespace,
                body=service_body
            )

            # 获取访问信息
            access_info = {"name": service.metadata.name}

            if service.spec.type == "LoadBalancer":
                if service.status.load_balancer.ingress:
                    ingress = service.status.load_balancer.ingress[0]
                    if ingress.hostname:
                        access_info["hostname"] = ingress.hostname
                    if ingress.ip:
                        access_info["ip"] = ingress.ip
                access_info["port"] = service.spec.ports[0].port

            return access_info

        except ApiException as e:
            logger.error(f"Failed to create Service: {e}")
            raise

    def check_deployment_ready(self, deployment_name: str) -> Dict[str, Any]:
        """检查Deployment状态"""
        try:
            deployment = self.apps_v1.read_namespaced_deployment(
                name=deployment_name,
                namespace=self.namespace
            )

            # 获取关联的Pod
            pods = self.v1.list_namespaced_pod(
                namespace=self.namespace,
                label_selector=f"app=code-server,project-id={deployment.metadata.labels.get('project-id', '')}"
            )

            pod_info = None
            if pods.items:
                pod = pods.items[0]
                pod_info = {
                    "name": pod.metadata.name,
                    "status": pod.status.phase,
                    "node": pod.spec.node_name if pod.spec else None,
                    "conditions": [c.type for c in pod.status.conditions or [] if c.status == "True"]
                }

            return {
                "ready": deployment.status.ready_replicas or 0,
                "available": deployment.status.available_replicas or 0,
                "unavailable": deployment.status.unavailable_replicas or 0,
                "updated": deployment.status.updated_replicas or 0,
                "pod": pod_info
            }
        except ApiException as e:
            logger.error(f"Error checking deployment status: {e}")
            raise

    def delete_resources(self, project_id: str) -> Dict[str, Any]:
        """删除所有相关资源"""
        results = {}

        # 删除Service
        service_name = self.generate_resource_name(project_id, "svc")
        try:
            self.v1.delete_namespaced_service(
                name=service_name,
                namespace=self.namespace
            )
            results["service"] = {"deleted": True, "name": service_name}
        except ApiException as e:
            if e.status != 404:  # Not Found
                results["service"] = {"deleted": False, "error": str(e)}

        # 删除Deployment
        deployment_name = self.generate_resource_name(project_id, "deploy")
        try:
            self.apps_v1.delete_namespaced_deployment(
                name=deployment_name,
                namespace=self.namespace
            )
            results["deployment"] = {"deleted": True, "name": deployment_name}
        except ApiException as e:
            if e.status != 404:
                results["deployment"] = {"deleted": False, "error": str(e)}

        # 删除PVC
        pvc_name = self.generate_resource_name(project_id, "pvc")
        try:
            self.v1.delete_namespaced_persistent_volume_claim(
                name=pvc_name,
                namespace=self.namespace
            )
            results["pvc"] = {"deleted": True, "name": pvc_name}
        except ApiException as e:
            if e.status != 404:
                results["pvc"] = {"deleted": False, "error": str(e)}

        return results

    def copy_files_to_pvc(self, project_id: str, source_path: str,
                          pvc_name: str = None) -> bool:
        """复制文件到PVC（使用临时Pod）"""
        if not pvc_name:
            pvc_name = self.generate_resource_name(project_id, "pvc")

        # 创建临时Job来复制文件
        job_name = f"copy-files-{project_id[:10]}"

        job_body = {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": job_name,
                "namespace": self.namespace,
                "labels": {
                    "app": "file-copy",
                    "project-id": project_id,
                    "managed-by": "source-manager"
                }
            },
            "spec": {
                "ttlSecondsAfterFinished": 300,  # 完成后5分钟自动删除
                "template": {
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": [{
                            "name": "copy-container",
                            "image": "alpine:latest",
                            "command": ["/bin/sh", "-c"],
                            "args": [f"""
                                echo "Starting file copy from {source_path} to /workspace";
                                mkdir -p /workspace;
                                cp -r {source_path}/* /workspace/ || true;
                                echo "File copy completed";
                                ls -la /workspace/
                            """],
                            "volumeMounts": [{
                                "name": "project-data",
                                "mountPath": "/workspace"
                            }]
                        }],
                        "volumes": [{
                            "name": "project-data",
                            "persistentVolumeClaim": {
                                "claimName": pvc_name
                            }
                        }]
                    }
                }
            }
        }

        try:
            # 创建Job
            logger.info(f"Creating copy Job {job_name}")
            job = self.batch_v1.create_namespaced_job(
                namespace=self.namespace,
                body=job_body
            )

            # 等待Job完成
            return self.wait_for_job_completion(job_name)

        except ApiException as e:
            logger.error(f"Failed to create copy Job: {e}")
            raise

    def wait_for_job_completion(self, job_name: str, timeout: int = 600) -> bool:
        """等待Job完成"""
        import time
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                job = self.batch_v1.read_namespaced_job(
                    name=job_name,
                    namespace=self.namespace
                )

                if job.status.succeeded:
                    logger.info(f"Job {job_name} completed successfully")
                    return True
                elif job.status.failed:
                    logger.error(f"Job {job_name} failed")
                    return False

                time.sleep(5)
            except ApiException as e:
                logger.error(f"Error checking job status: {e}")
                time.sleep(5)

        logger.error(f"Timeout waiting for Job {job_name}")
        return False