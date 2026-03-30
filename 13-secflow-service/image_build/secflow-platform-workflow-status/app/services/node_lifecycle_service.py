"""
节点生命周期管理服务
负责节点的初始化、反初始化、启动执行、停止等有状态操作
通过 K8S 微服务实现实际的资源操作
"""

import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

from app.services.k8s_client import get_k8s_client
from app.schemas.schemas import (
    NodeOperationResult,
    AppNodeStatus,
    JobNodeStatus,
    NodeType,
)

logger = logging.getLogger(__name__)


class NodeLifecycleService:
    """节点生命周期管理服务"""

    def __init__(self):
        self.k8s_client = get_k8s_client()

    async def initialize_node(
        self,
        node_id: str,
        instance_id: str,
        project_id: str,
        node_type: str,
        node_name: str,
        deployment_name: Optional[str] = None,
        service_name: Optional[str] = None,
        ingress_config: Optional[Dict[str, Any]] = None,
        containers: Optional[List[Dict[str, Any]]] = None,
        volume_mounts: Optional[List[Dict[str, Any]]] = None,
        replicas: int = 1,
        service_ports: Optional[List[Dict[str, Any]]] = None,
        service_type: str = "ClusterIP"
    ) -> NodeOperationResult:
        """
        初始化节点

        对于 APP 节点：
        - 确保 namespace 存在
        - 创建 Deployment
        - 创建 Service
        - 创建 Ingress（可选）

        对于 JOB 节点：
        - 仅记录状态，实际创建在执行时进行

        Args:
            node_id: 节点ID
            instance_id: 工作流实例ID
            project_id: 项目ID
            node_type: 节点类型 (app/job)
            node_name: 节点名称
            deployment_name: Deployment名称（APP节点专用）
            service_name: Service名称（APP节点专用）
            ingress_config: Ingress配置（可选）
            containers: 容器配置列表
            volume_mounts: 卷挂载配置
            replicas: 副本数
            service_ports: Service端口配置
            service_type: Service类型

        Returns:
            NodeOperationResult: 操作结果
        """
        logger.info(f"[NodeLifecycle] 开始初始化节点: node_id={node_id}, type={node_type}")

        try:
            # 确保 namespace 存在
            namespace_ok, namespace_error = self.k8s_client.ensure_namespace(project_id)
            if not namespace_ok:
                error_msg = f"Namespace检查失败: {namespace_error}"
                logger.error(f"[NodeLifecycle] {error_msg}")
                return NodeOperationResult(
                    success=False,
                    node_id=node_id,
                    status=AppNodeStatus.PENDING,
                    error=error_msg
                )

            if node_type.lower() == NodeType.APP:
                # APP 节点：创建 Deployment + Service + Ingress
                return await self._initialize_app_node(
                    node_id=node_id,
                    project_id=project_id,
                    deployment_name=deployment_name or f"app-{node_id[:8]}",
                    service_name=service_name or f"svc-{node_id[:8]}",
                    ingress_config=ingress_config,
                    containers=containers or [],
                    volume_mounts=volume_mounts,
                    replicas=replicas,
                    service_ports=service_ports or [],
                    service_type=service_type
                )
            else:
                # JOB 节点：初始化阶段不创建资源，仅返回状态
                logger.info(f"[NodeLifecycle] JOB节点初始化完成(延迟创建): node_id={node_id}")
                return NodeOperationResult(
                    success=True,
                    node_id=node_id,
                    status=JobNodeStatus.PENDING,
                    message="JOB node initialized, will be created on execution"
                )

        except Exception as e:
            error_msg = f"节点初始化异常: {str(e)}"
            logger.error(f"[NodeLifecycle] {error_msg}", exc_info=True)
            return NodeOperationResult(
                success=False,
                node_id=node_id,
                status=AppNodeStatus.PENDING,
                error=error_msg
            )

    async def _initialize_app_node(
        self,
        node_id: str,
        project_id: str,
        deployment_name: str,
        service_name: str,
        ingress_config: Optional[Dict[str, Any]],
        containers: List[Dict[str, Any]],
        volume_mounts: Optional[List[Dict[str, Any]]],
        replicas: int,
        service_ports: List[Dict[str, Any]],
        service_type: str
    ) -> NodeOperationResult:
        """
        初始化 APP 节点：创建 Deployment + Service + Ingress
        包含事务回滚机制
        """
        created_resources = []  # 记录已创建的资源，用于回滚
        ingress_result: Optional[Dict[str, Any]] = None

        try:
            # 1. 创建 Deployment
            logger.info(f"[NodeLifecycle] 创建Deployment: {deployment_name}")
            success, error = self.k8s_client.create_deployment(
                project_id=project_id,
                name=deployment_name,
                containers=containers,
                ports=service_ports,
                volume_mounts=volume_mounts,
                replicas=replicas
            )
            if not success:
                raise Exception(f"Deployment创建失败: {error}")
            created_resources.append(("deployment", deployment_name))

            # 2. 创建 Service（如果有端口配置）
            if service_ports:
                logger.info(f"[NodeLifecycle] 创建Service: {service_name}")
                # 构建 selector
                selector = {"app": deployment_name}
                success, error = self.k8s_client.create_service(
                    project_id=project_id,
                    name=service_name,
                    selector=selector,
                    ports=service_ports,
                    service_type=service_type
                )
                if not success:
                    raise Exception(f"Service创建失败: {error}")
                created_resources.append(("service", service_name))

            # 3. 创建 Ingress（可选）
            if ingress_config and service_name and service_ports:
                service_port = service_ports[0].get("port", 80) if service_ports else 80
                logger.info(f"[NodeLifecycle] 为Service创建workflow ingress: service_name={service_name}")
                success, error, ingress_result = self.k8s_client.create_workflow_app_ingress(
                    project_id=project_id,
                    service_name=service_name,
                    service_port=service_port,
                    host=ingress_config.get("host"),
                    host_prefix=ingress_config.get("host_prefix"),
                    ingress_type=ingress_config.get("ingress_type", "nginx"),
                    ingress_ip=ingress_config.get("ingress_ip"),
                    path=ingress_config.get("path", "/"),
                    path_type=ingress_config.get("path_type", "Prefix"),
                    tls_enabled=ingress_config.get("tls_enabled"),
                    tls_secret_name=ingress_config.get("tls_secret_name"),
                    backend_protocol=ingress_config.get("backend_protocol"),
                    websocket_enabled=ingress_config.get("websocket_enabled"),
                    proxy_body_size=ingress_config.get("proxy_body_size"),
                    proxy_connect_timeout=ingress_config.get("proxy_connect_timeout"),
                    proxy_send_timeout=ingress_config.get("proxy_send_timeout"),
                    proxy_read_timeout=ingress_config.get("proxy_read_timeout"),
                    ssl_redirect=ingress_config.get("ssl_redirect"),
                )
                if not success:
                    # Ingress 创建失败视为警告而非错误
                    logger.warning(f"[NodeLifecycle] Ingress创建失败(非致命): {error}")
                else:
                    ingress_name = (ingress_result or {}).get("ingress_name")
                    if ingress_name:
                        created_resources.append(("ingress", ingress_name))

            logger.info(f"[NodeLifecycle] APP节点初始化成功: node_id={node_id}, resources={created_resources}")
            return NodeOperationResult(
                success=True,
                node_id=node_id,
                status=AppNodeStatus.PENDING,
                k8s_resource_name=deployment_name,
                service_name=service_name if service_ports else None,
                ingress_name=(ingress_result or {}).get("ingress_name"),
                ingress_host=(ingress_result or {}).get("host"),
                ingress_access_url=(ingress_result or {}).get("access_url"),
                ingress_tls_enabled=(ingress_result or {}).get("tls_enabled"),
                message=f"APP node initialized with {len(created_resources)} resources"
            )

        except Exception as e:
            # 回滚已创建的资源
            error_msg = str(e)
            logger.error(f"[NodeLifecycle] APP节点初始化失败，开始回滚: {error_msg}")
            await self._rollback_resources(project_id, created_resources)
            return NodeOperationResult(
                success=False,
                node_id=node_id,
                status=AppNodeStatus.PENDING,
                error=error_msg
            )

    async def _rollback_resources(
        self,
        project_id: str,
        resources: List[Tuple[str, str]]
    ):
        """回滚已创建的 K8S 资源"""
        # 按创建顺序的逆序删除
        for resource_type, resource_name in reversed(resources):
            try:
                if resource_type == "deployment":
                    self.k8s_client.delete_deployment(project_id, resource_name)
                elif resource_type == "service":
                    self.k8s_client.delete_service(project_id, resource_name)
                elif resource_type == "ingress":
                    self.k8s_client.delete_ingress(project_id, resource_name)
                elif resource_type == "job":
                    self.k8s_client.delete_job(project_id, resource_name)
                logger.info(f"[NodeLifecycle] 回滚资源成功: {resource_type}/{resource_name}")
            except Exception as rollback_error:
                logger.error(f"[NodeLifecycle] 回滚资源失败: {resource_type}/{resource_name}, error={rollback_error}")

    async def uninitialize_node(
        self,
        node_id: str,
        instance_id: str,
        project_id: str,
        node_type: str,
        k8s_resource_name: str,
        service_name: Optional[str] = None,
        has_ingress: bool = False,
        ingress_name: Optional[str] = None,
    ) -> NodeOperationResult:
        """
        反初始化节点：删除所有关联的 K8S 资源

        Args:
            node_id: 节点ID
            instance_id: 工作流实例ID
            project_id: 项目ID
            node_type: 节点类型 (app/job)
            k8s_resource_name: K8S资源名称
            service_name: Service名称
            has_ingress: 是否有Ingress

        Returns:
            NodeOperationResult: 操作结果
        """
        logger.info(f"[NodeLifecycle] 开始反初始化节点: node_id={node_id}, type={node_type}")

        errors = []

        try:
            if node_type.lower() == NodeType.APP:
                # APP 节点：删除 Ingress -> Service -> Deployment

                # 1. 删除 Ingress
                if has_ingress and (ingress_name or service_name):
                    ingress_name = ingress_name or (f"ing-{service_name}" if service_name else None)
                    logger.info(f"[NodeLifecycle] 删除Ingress: {ingress_name}")
                    if ingress_name and not self.k8s_client.delete_ingress(project_id, ingress_name):
                        errors.append(f"Ingress {ingress_name} 删除失败")

                # 2. 删除 Service
                if service_name:
                    logger.info(f"[NodeLifecycle] 删除Service: {service_name}")
                    if not self.k8s_client.delete_service(project_id, service_name):
                        errors.append(f"Service {service_name} 删除失败")

                # 3. 删除 Deployment
                if k8s_resource_name:
                    logger.info(f"[NodeLifecycle] 删除Deployment: {k8s_resource_name}")
                    if not self.k8s_client.delete_deployment(project_id, k8s_resource_name):
                        errors.append(f"Deployment {k8s_resource_name} 删除失败")

            else:
                # JOB 节点：删除 Job
                if k8s_resource_name:
                    logger.info(f"[NodeLifecycle] 删除Job: {k8s_resource_name}")
                    if not self.k8s_client.delete_job(project_id, k8s_resource_name):
                        errors.append(f"Job {k8s_resource_name} 删除失败")

            if errors:
                logger.warning(f"[NodeLifecycle] 反初始化完成但有错误: {errors}")
                return NodeOperationResult(
                    success=True,  # 部分成功
                    node_id=node_id,
                    status=AppNodeStatus.PENDING,
                    message=f"反初始化完成，部分资源删除失败: {'; '.join(errors)}"
                )

            logger.info(f"[NodeLifecycle] 节点反初始化成功: node_id={node_id}")
            return NodeOperationResult(
                success=True,
                node_id=node_id,
                status=AppNodeStatus.PENDING,
                message="节点反初始化成功"
            )

        except Exception as e:
            error_msg = f"节点反初始化异常: {str(e)}"
            logger.error(f"[NodeLifecycle] {error_msg}", exc_info=True)
            return NodeOperationResult(
                success=False,
                node_id=node_id,
                status=AppNodeStatus.PENDING,
                error=error_msg
            )

    async def start_node(
        self,
        node_id: str,
        instance_id: str,
        project_id: str,
        node_type: str,
        k8s_resource_name: Optional[str] = None,
        job_config: Optional[Dict[str, Any]] = None
    ) -> NodeOperationResult:
        """
        启动节点执行

        对于 APP 节点：
        - 检查 Deployment 状态，确认 Pod 正在运行

        对于 JOB 节点：
        - 创建 Job 资源

        Args:
            node_id: 节点ID
            instance_id: 工作流实例ID
            project_id: 项目ID
            node_type: 节点类型 (app/job)
            k8s_resource_name: K8S资源名称
            job_config: Job配置（JOB节点专用）

        Returns:
            NodeOperationResult: 操作结果
        """
        logger.info(f"[NodeLifecycle] 启动节点执行: node_id={node_id}, type={node_type}")

        try:
            if node_type.lower() == NodeType.APP:
                # APP 节点：检查 Deployment 状态
                if not k8s_resource_name:
                    return NodeOperationResult(
                        success=False,
                        node_id=node_id,
                        status=AppNodeStatus.PENDING,
                        error="APP节点缺少k8s_resource_name"
                    )

                status = self.k8s_client.get_deployment_status(project_id, k8s_resource_name)
                if not status:
                    return NodeOperationResult(
                        success=False,
                        node_id=node_id,
                        status=AppNodeStatus.PENDING,
                        error=f"Deployment {k8s_resource_name} 不存在"
                    )

                # 根据状态判断
                ready_replicas = status.get("ready_replicas", 0)
                replicas = status.get("replicas", 0)

                if ready_replicas >= replicas and replicas > 0:
                    node_status = AppNodeStatus.READY
                elif status.get("available_replicas", 0) > 0:
                    node_status = AppNodeStatus.NOT_READY
                else:
                    node_status = AppNodeStatus.PENDING

                logger.info(f"[NodeLifecycle] APP节点状态: {node_status}")
                return NodeOperationResult(
                    success=True,
                    node_id=node_id,
                    status=node_status,
                    k8s_resource_name=k8s_resource_name,
                    message=f"Deployment状态: ready={ready_replicas}/{replicas}"
                )

            else:
                # JOB 节点：创建 Job
                if not job_config:
                    return NodeOperationResult(
                        success=False,
                        node_id=node_id,
                        status=JobNodeStatus.PENDING,
                        error="JOB节点缺少job_config"
                    )

                job_name = k8s_resource_name or f"job-{node_id[:8]}"
                containers = job_config.get("containers", [])
                volume_mounts = job_config.get("volume_mounts")
                ttl_seconds = job_config.get("ttl_seconds_after_finished", 3600)
                backoff_limit = job_config.get("backoff_limit", 3)

                logger.info(f"[NodeLifecycle] 创建Job: {job_name}")
                success, error = self.k8s_client.create_job(
                    project_id=project_id,
                    name=job_name,
                    containers=containers,
                    volume_mounts=volume_mounts,
                    ttl_seconds_after_finished=ttl_seconds,
                    backoff_limit=backoff_limit
                )

                if not success:
                    return NodeOperationResult(
                        success=False,
                        node_id=node_id,
                        status=JobNodeStatus.PENDING,
                        error=f"Job创建失败: {error}"
                    )

                logger.info(f"[NodeLifecycle] JOB节点启动成功: {job_name}")
                return NodeOperationResult(
                    success=True,
                    node_id=node_id,
                    status=JobNodeStatus.RUNNING,
                    k8s_resource_name=job_name,
                    message="Job已创建并开始执行"
                )

        except Exception as e:
            error_msg = f"启动节点异常: {str(e)}"
            logger.error(f"[NodeLifecycle] {error_msg}", exc_info=True)
            return NodeOperationResult(
                success=False,
                node_id=node_id,
                status=JobNodeStatus.PENDING,
                error=error_msg
            )

    async def stop_node(
        self,
        node_id: str,
        instance_id: str,
        project_id: str,
        node_type: str,
        k8s_resource_name: str,
        service_name: Optional[str] = None,
        has_ingress: bool = False,
        ingress_name: Optional[str] = None,
    ) -> NodeOperationResult:
        """
        停止节点

        对于 APP 节点：
        - 删除 Ingress -> Service -> Deployment

        对于 JOB 节点：
        - 删除 Job

        Args:
            node_id: 节点ID
            instance_id: 工作流实例ID
            project_id: 项目ID
            node_type: 节点类型 (app/job)
            k8s_resource_name: K8S资源名称
            service_name: Service名称
            has_ingress: 是否有Ingress

        Returns:
            NodeOperationResult: 操作结果
        """
        logger.info(f"[NodeLifecycle] 停止节点: node_id={node_id}, type={node_type}")

        # 停止操作与反初始化操作类似
        return await self.uninitialize_node(
            node_id=node_id,
            instance_id=instance_id,
            project_id=project_id,
            node_type=node_type,
            k8s_resource_name=k8s_resource_name,
            service_name=service_name,
            has_ingress=has_ingress,
            ingress_name=ingress_name,
        )


# 单例实例
_node_lifecycle_service: Optional[NodeLifecycleService] = None


def get_node_lifecycle_service() -> NodeLifecycleService:
    """获取节点生命周期服务实例"""
    global _node_lifecycle_service
    if _node_lifecycle_service is None:
        _node_lifecycle_service = NodeLifecycleService()
    return _node_lifecycle_service
