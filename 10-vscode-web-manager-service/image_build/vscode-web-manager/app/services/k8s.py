"""
Code Server Manager - K8S客户端服务
"""

import logging
from typing import Optional, List, Dict, Any

from kubernetes import client, config
from kubernetes.client import ApiClient
from kubernetes.client.rest import ApiException

from app.config import get_config

logger = logging.getLogger(__name__)


class K8SService:
    """K8S服务类"""

    def __init__(self):
        self.config = get_config()
        self.client: Optional[ApiClient] = None
        self.core_v1 = None
        self.apps_v1 = None
        self.networking_v1 = None

    def connect(self) -> bool:
        """连接K8S集群"""
        try:
            if self.config.kubernetes.in_cluster:
                config.load_incluster_config()
                logger.info("使用ServiceAccount加载K8S配置")
            else:
                kubeconfig_path = self.config.kubernetes.kubeconfig or "~/.kube/config"
                config.load_kube_config(config_file=kubeconfig_path)
                logger.info(f"使用kubeconfig加载K8S配置: {kubeconfig_path}")

            self.client = client.ApiClient()
            self.core_v1 = client.CoreV1Api(self.client)
            self.apps_v1 = client.AppsV1Api(self.client)
            self.networking_v1 = client.NetworkingV1Api(self.client)

            # 验证连接
            self.core_v1.read_namespace_status("default")
            logger.info("K8S连接验证成功")
            return True

        except Exception as e:
            logger.error(f"K8S连接失败: {e}")
            return False

    def check_namespace_exists(self, namespace: str) -> bool:
        """检查Namespace是否存在"""
        try:
            self.core_v1.read_namespace(name=namespace)
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            raise

    def check_pvc_exists(self, namespace: str, pvc_name: str) -> bool:
        """检查PVC是否存在"""
        try:
            self.core_v1.read_namespaced_persistent_volume_claim(
                name=pvc_name, namespace=namespace
            )
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            raise

    def create_pvc(self, namespace: str, pvc_name: str, storage_size: str,
                   storage_class: str = None, access_mode: str = "ReadWriteOnce") -> bool:
        """创建PVC"""
        try:
            pvc_manifest = {
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                "metadata": {
                    "name": pvc_name,
                    "namespace": namespace,
                    "labels": {
                        "app": "code-server",
                        "managed-by": "vscode-web-manager"
                    }
                },
                "spec": {
                    "accessModes": [access_mode],
                    "resources": {
                        "requests": {
                            "storage": storage_size
                        }
                    }
                }
            }

            # 添加storageClassName
            sc = storage_class or self.config.pvc.storage_class
            if sc:
                pvc_manifest["spec"]["storageClassName"] = sc

            self.core_v1.create_namespaced_persistent_volume_claim(
                namespace=namespace, body=pvc_manifest
            )
            logger.info(f"PVC {pvc_name} 在Namespace {namespace} 创建成功")
            return True

        except ApiException as e:
            if e.status == 409:
                logger.info(f"PVC {pvc_name} 已存在")
                return True
            logger.error(f"创建PVC失败: {e}")
            return False

    def delete_pvc(self, namespace: str, pvc_name: str) -> bool:
        """删除PVC"""
        try:
            self.core_v1.delete_namespaced_persistent_volume_claim(
                name=pvc_name, namespace=namespace
            )
            logger.info(f"PVC {pvc_name} 在Namespace {namespace} 删除成功")
            return True
        except ApiException as e:
            if e.status == 404:
                return True
            logger.error(f"删除PVC失败: {e}")
            return False

    def create_deployment(self, namespace: str, name: str, code_server_id: str,
                         source_pvcs: List[Dict], output_pvcs: List[Dict],
                         custom_env: Dict[str, str] = None,
                         code_server_env: Dict[str, Any] = None,
                         image: str = None) -> tuple[bool, Optional[Dict[str, Any]]]:
        """创建Deployment

        Args:
            namespace: 命名空间
            name: Deployment名称
            code_server_id: Code Server ID
            source_pvcs: 源码PVC列表
            output_pvcs: 输出PVC列表
            custom_env: 自定义环境变量
            code_server_env: Code Server镜像环境变量配置
            image: 自定义镜像地址，如果为None则使用配置文件中的默认镜像

        Returns:
            tuple: (success: bool, env_vars: dict or None)
        """
        try:
            config = self.config.code_server

            # 构建卷和卷挂载
            volumes = []
            volume_mounts = []
            volume_index = 0

            # 源码PVC
            for pvc_info in source_pvcs:
                volume_name = f"source-volume-{volume_index}"
                volumes.append({
                    "name": volume_name,
                    "persistentVolumeClaim": {
                        "claimName": pvc_info["pvc_name"]
                    }
                })
                volume_mounts.append({
                    "name": volume_name,
                    "mountPath": pvc_info["mount_path"]
                })
                volume_index += 1

            # 输出PVC
            for pvc_info in output_pvcs:
                volume_name = f"output-volume-{volume_index}"
                volumes.append({
                    "name": volume_name,
                    "persistentVolumeClaim": {
                        "claimName": pvc_info["pvc_name"]
                    }
                })
                volume_mounts.append({
                    "name": volume_name,
                    "mountPath": pvc_info["mount_path"]
                })
                volume_index += 1

            # 构建Code Server环境变量
            import secrets
            final_code_server_env = {}
            cs_env_config = config.code_server_env

            # 如果请求中提供了环境变量，使用请求中的值，否则使用配置中的值
            if code_server_env:
                final_code_server_env["PUID"] = str(code_server_env.get("PUID", cs_env_config.PUID))
                final_code_server_env["PGID"] = str(code_server_env.get("PGID", cs_env_config.PGID))
                final_code_server_env["TZ"] = code_server_env.get("TZ", cs_env_config.TZ)
                final_code_server_env["DEFAULT_WORKSPACE"] = code_server_env.get("DEFAULT_WORKSPACE", cs_env_config.DEFAULT_WORKSPACE)
                final_code_server_env["PWA_APPNAME"] = code_server_env.get("PWA_APPNAME", cs_env_config.PWA_APPNAME)

                # 密码：优先使用请求中的，其次是配置中的，最后随机生成
                if code_server_env.get("HASHED_PASSWORD"):
                    final_code_server_env["HASHED_PASSWORD"] = code_server_env["HASHED_PASSWORD"]
                elif code_server_env.get("PASSWORD"):
                    final_code_server_env["PASSWORD"] = code_server_env["PASSWORD"]
                elif cs_env_config.HASHED_PASSWORD:
                    final_code_server_env["HASHED_PASSWORD"] = cs_env_config.HASHED_PASSWORD
                elif cs_env_config.PASSWORD:
                    final_code_server_env["PASSWORD"] = cs_env_config.PASSWORD
                else:
                    final_code_server_env["PASSWORD"] = secrets.token_urlsafe(16)

                # Sudo密码
                if code_server_env.get("SUDO_PASSWORD_HASH"):
                    final_code_server_env["SUDO_PASSWORD_HASH"] = code_server_env["SUDO_PASSWORD_HASH"]
                elif code_server_env.get("SUDO_PASSWORD"):
                    final_code_server_env["SUDO_PASSWORD"] = code_server_env["SUDO_PASSWORD"]
                elif cs_env_config.SUDO_PASSWORD_HASH:
                    final_code_server_env["SUDO_PASSWORD_HASH"] = cs_env_config.SUDO_PASSWORD_HASH
                elif cs_env_config.SUDO_PASSWORD:
                    final_code_server_env["SUDO_PASSWORD"] = cs_env_config.SUDO_PASSWORD
                else:
                    final_code_server_env["SUDO_PASSWORD"] = secrets.token_urlsafe(16)

                # 代理域名
                proxy_domain = code_server_env.get("PROXY_DOMAIN", cs_env_config.PROXY_DOMAIN)
                if proxy_domain:
                    final_code_server_env["PROXY_DOMAIN"] = proxy_domain
            else:
                # 使用配置中的值
                final_code_server_env["PUID"] = str(cs_env_config.PUID)
                final_code_server_env["PGID"] = str(cs_env_config.PGID)
                final_code_server_env["TZ"] = cs_env_config.TZ
                final_code_server_env["DEFAULT_WORKSPACE"] = cs_env_config.DEFAULT_WORKSPACE
                final_code_server_env["PWA_APPNAME"] = cs_env_config.PWA_APPNAME

                if cs_env_config.HASHED_PASSWORD:
                    final_code_server_env["HASHED_PASSWORD"] = cs_env_config.HASHED_PASSWORD
                elif cs_env_config.PASSWORD:
                    final_code_server_env["PASSWORD"] = cs_env_config.PASSWORD
                else:
                    final_code_server_env["PASSWORD"] = secrets.token_urlsafe(16)

                if cs_env_config.SUDO_PASSWORD_HASH:
                    final_code_server_env["SUDO_PASSWORD_HASH"] = cs_env_config.SUDO_PASSWORD_HASH
                elif cs_env_config.SUDO_PASSWORD:
                    final_code_server_env["SUDO_PASSWORD"] = cs_env_config.SUDO_PASSWORD
                else:
                    final_code_server_env["SUDO_PASSWORD"] = secrets.token_urlsafe(16)

                if cs_env_config.PROXY_DOMAIN:
                    final_code_server_env["PROXY_DOMAIN"] = cs_env_config.PROXY_DOMAIN

            # 构建完整的环境变量列表
            env = []

            # 1. Code Server镜像环境变量（最重要，放最前面）
            for key, value in final_code_server_env.items():
                env.append({"name": key, "value": value})

            # 2. 配置中的其他环境变量
            for key, value in config.env.items():
                # 避免覆盖Code Server的特殊环境变量
                if key not in final_code_server_env:
                    env.append({"name": key, "value": value})

            # 3. 请求中的自定义环境变量
            if custom_env:
                for key, value in custom_env.items():
                    # 避免覆盖Code Server的特殊环境变量
                    if key not in final_code_server_env:
                        env.append({"name": key, "value": value})

            # 确定使用的镜像：优先使用传入的自定义镜像，否则使用配置文件中的默认镜像
            container_image = image if image else config.image

            deployment_manifest = {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": name,
                    "namespace": namespace,
                    "labels": {
                        "app": "code-server",
                        "code-server-id": code_server_id,
                        "managed-by": "vscode-web-manager"
                    }
                },
                "spec": {
                    "replicas": 1,
                    "selector": {
                        "matchLabels": {
                            "app": "code-server",
                            "code-server-id": code_server_id
                        }
                    },
                    "template": {
                        "metadata": {
                            "labels": {
                                "app": "code-server",
                                "code-server-id": code_server_id
                            }
                        },
                        "spec": {
                            "containers": [{
                                "name": "code-server",
                                "image": container_image,
                                "imagePullPolicy": config.image_pull_policy,
                                "ports": [{
                                    "containerPort": 8443,
                                    "name": "http"
                                }],
                                "env": env,
                                "volumeMounts": volume_mounts,
                                "resources": config.resources
                            }],
                            "volumes": volumes
                        }
                    }
                }
            }

            self.apps_v1.create_namespaced_deployment(
                namespace=namespace, body=deployment_manifest
            )
            logger.info(f"Deployment {name} 在Namespace {namespace} 创建成功")
            return True, final_code_server_env

        except ApiException as e:
            logger.error(f"创建Deployment失败: {e}")
            return False, None

    def delete_deployment(self, namespace: str, name: str) -> bool:
        """删除Deployment"""
        try:
            self.apps_v1.delete_namespaced_deployment(
                name=name, namespace=namespace
            )
            logger.info(f"Deployment {name} 在Namespace {namespace} 删除成功")
            return True
        except ApiException as e:
            if e.status == 404:
                return True
            logger.error(f"删除Deployment失败: {e}")
            return False

    def scale_deployment(self, namespace: str, name: str, replicas: int) -> bool:
        """调整Deployment副本数"""
        try:
            patch = {"spec": {"replicas": replicas}}
            self.apps_v1.patch_namespaced_deployment_scale(
                name=name, namespace=namespace, body=patch
            )
            logger.info(f"Deployment {name} 副本数调整到 {replicas}")
            return True
        except ApiException as e:
            logger.error(f"调整Deployment副本数失败: {e}")
            return False

    def get_deployment_status(self, namespace: str, name: str) -> Optional[Dict]:
        """获取Deployment状态"""
        try:
            dep = self.apps_v1.read_namespaced_deployment(name=name, namespace=namespace)
            return {
                "name": dep.metadata.name,
                "replicas": dep.spec.replicas,
                "ready_replicas": dep.status.ready_replicas or 0,
                "available_replicas": dep.status.available_replicas or 0,
            }
        except ApiException as e:
            if e.status == 404:
                return None
            raise

    def create_service(self, namespace: str, name: str, code_server_id: str) -> Optional[str]:
        """创建Service"""
        try:
            config = self.config.code_server

            service_manifest = {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "name": name,
                    "namespace": namespace,
                    "labels": {
                        "app": "code-server",
                        "code-server-id": code_server_id,
                        "managed-by": "vscode-web-manager"
                    }
                },
                "spec": {
                    "type": config.service_type,
                    "selector": {
                        "app": "code-server",
                        "code-server-id": code_server_id
                    },
                    "ports": [{
                        "port": 8443,
                        "targetPort": 8443,
                        "protocol": "TCP",
                        "name": "http"
                    }]
                }
            }

            # NodePort和LoadBalancer时添加额外配置
            if config.service_type == "NodePort":
                service_manifest["spec"]["ports"][0]["nodePort"] = None  # 自动分配

            svc = self.core_v1.create_namespaced_service(
                namespace=namespace, body=service_manifest
            )
            logger.info(f"Service {name} 在Namespace {namespace} 创建成功")
            return svc.spec.cluster_ip

        except ApiException as e:
            if e.status == 409:
                # 已存在，获取cluster_ip
                try:
                    svc = self.core_v1.read_namespaced_service(name=name, namespace=namespace)
                    return svc.spec.cluster_ip
                except:
                    return None
            logger.error(f"创建Service失败: {e}")
            return None

    def delete_service(self, namespace: str, name: str) -> bool:
        """删除Service"""
        try:
            self.core_v1.delete_namespaced_service(
                name=name, namespace=namespace
            )
            logger.info(f"Service {name} 在Namespace {namespace} 删除成功")
            return True
        except ApiException as e:
            if e.status == 404:
                return True
            logger.error(f"删除Service失败: {e}")
            return False

    def create_ingress(self, namespace: str, name: str, code_server_id: str,
                       service_name: str) -> Optional[str]:
        """创建Ingress"""
        try:
            config = self.config.ingress

            # 生成访问域名
            host = f"{code_server_id}.{config.base_domain}"

            ingress_manifest = {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "Ingress",
                "metadata": {
                    "name": name,
                    "namespace": namespace,
                    "labels": {
                        "app": "code-server",
                        "code-server-id": code_server_id,
                        "managed-by": "vscode-web-manager"
                    },
                    "annotations": {
                        "nginx.ingress.kubernetes.io/proxy-body-size": "100m",
                        "nginx.ingress.kubernetes.io/proxy-read-timeout": "3600",
                        "nginx.ingress.kubernetes.io/proxy-send-timeout": "3600",
                        "nginx.ingress.kubernetes.io/backend-protocol": "HTTP",
                        "nginx.ingress.kubernetes.io/proxy-ssl-verify": "off"
                    }
                },
                "spec": {
                    "ingressClassName": config.ingress_class,
                    "rules": [{
                        "host": host,
                        "http": {
                            "paths": [{
                                "path": "/",
                                "pathType": "Prefix",
                                "backend": {
                                    "service": {
                                        "name": service_name,
                                        "port": {
                                            "number": 8443
                                        }
                                    }
                                }
                            }]
                        }
                    }]
                }
            }

            # 添加TLS配置
            if config.tls_enabled and config.tls_secret_name:
                ingress_manifest["spec"]["tls"] = [{
                    "hosts": [host],
                    "secretName": config.tls_secret_name
                }]

            self.networking_v1.create_namespaced_ingress(
                namespace=namespace, body=ingress_manifest
            )
            logger.info(f"Ingress {name} 在Namespace {namespace} 创建成功")
            return host

        except ApiException as e:
            if e.status == 409:
                try:
                    ing = self.networking_v1.read_namespaced_ingress(name=name, namespace=namespace)
                    if ing.spec.rules:
                        return ing.spec.rules[0].host
                except:
                    pass
            logger.error(f"创建Ingress失败: {e}")
            return None

    def delete_ingress(self, namespace: str, name: str) -> bool:
        """删除Ingress"""
        try:
            self.networking_v1.delete_namespaced_ingress(
                name=name, namespace=namespace
            )
            logger.info(f"Ingress {name} 在Namespace {namespace} 删除成功")
            return True
        except ApiException as e:
            if e.status == 404:
                return True
            logger.error(f"删除Ingress失败: {e}")
            return False

    def get_pod_by_deployment(self, namespace: str, deployment_name: str) -> Optional[Dict]:
        """通过Deployment获取Pod信息"""
        try:
            # 先获取Deployment的标签选择器
            dep = self.apps_v1.read_namespaced_deployment(
                name=deployment_name, namespace=namespace
            )
            selector = dep.spec.selector.match_labels

            # 构建标签选择器字符串
            label_selector = ",".join([f"{k}={v}" for k, v in selector.items()])

            # 获取Pod列表
            pods = self.core_v1.list_namespaced_pod(
                namespace=namespace, label_selector=label_selector
            )

            if pods.items:
                pod = pods.items[0]
                return {
                    "name": pod.metadata.name,
                    "status": pod.status.phase,
                    "ip": pod.status.pod_ip,
                    "node_name": pod.spec.node_name,
                    "start_time": pod.status.start_time
                }
            return None

        except Exception as e:
            logger.error(f"获取Pod信息失败: {e}")
            return None

    def get_pod_logs(self, namespace: str, pod_name: str,
                     container: str = None, tail_lines: int = 100) -> Optional[str]:
        """获取Pod日志"""
        try:
            kwargs = {
                "name": pod_name,
                "namespace": namespace,
                "tail_lines": tail_lines
            }
            if container:
                kwargs["container"] = container

            logs = self.core_v1.read_namespaced_pod_log(**kwargs)
            return logs

        except ApiException as e:
            logger.error(f"获取Pod日志失败: {e}")
            return None


# 单例实例
_k8s_service: Optional[K8SService] = None


def get_k8s_service() -> K8SService:
    """获取K8S服务实例"""
    global _k8s_service
    if _k8s_service is None:
        _k8s_service = K8SService()
    return _k8s_service
