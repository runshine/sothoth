"""
工作流生命周期管理服务
负责工作流实例级别的生命周期操作：初始化、反初始化、停止
通过调用 node_lifecycle_service 实现节点级别的操作
"""

import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any

from app.services.node_lifecycle_service import get_node_lifecycle_service
from app.services.status_sync_service import get_status_sync_service
from app.services.workflow_monitor_engine import get_workflow_monitor_engine
from app.models.database import (
    NodeStatusRecord,
    WorkflowStatusRecord,
    NodeStatusHistory,
    get_db_session,
)
from app.schemas.schemas import (
    WorkflowNodeResult,
    WorkflowLifecycleResponse,
    AppNodeStatus,
    JobNodeStatus,
    NodeType,
)

logger = logging.getLogger(__name__)


class WorkflowLifecycleService:
    """工作流生命周期管理服务"""

    def __init__(self):
        self.node_lifecycle_service = get_node_lifecycle_service()
        self.status_sync_service = get_status_sync_service()

    def _normalize_status(self, status: Any, default: str = "Pending") -> str:
        if status is None:
            return default
        if hasattr(status, "value"):
            status = status.value
        status_value = str(status).strip()
        return status_value or default

    def _resolve_task_status(self, operation: str, success: bool, status: Any) -> str:
        normalized_status = self._normalize_status(status, default="Failed" if not success else "Pending")
        if success and operation in {"deinitialize", "stop"}:
            return "Stopped"
        if not success and normalized_status in {"Pending", "Unknown"}:
            return "Failed"
        return normalized_status

    def _build_lifecycle_logs(
        self,
        operation: str,
        node_id: str,
        instance_id: str,
        project_id: str,
        node_type: str,
        success: bool,
        status: str,
        message: Optional[str],
        error: Optional[str],
        k8s_resource_name: Optional[str] = None,
        service_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        lines = [
            f"operation={operation}",
            f"node_id={node_id}",
            f"instance_id={instance_id}",
            f"project_id={project_id}",
            f"node_type={node_type}",
            f"success={success}",
            f"status={status}",
            f"timestamp={datetime.utcnow().isoformat()}",
        ]
        if k8s_resource_name:
            lines.append(f"k8s_resource_name={k8s_resource_name}")
        if service_name:
            lines.append(f"service_name={service_name}")
        if message:
            lines.append(f"message={message}")
        if error:
            lines.append(f"error={error}")
        if metadata:
            for key, value in metadata.items():
                if value not in (None, "", [], {}):
                    lines.append(f"{key}={value}")
        return "\n".join(lines)

    def _build_task_metadata(
        self,
        operation: str,
        service_name: Optional[str] = None,
        has_ingress: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        task_metadata = {
            "service_name": service_name,
            "has_ingress": has_ingress,
            "lifecycle_operation": operation,
        }
        if metadata:
            task_metadata.update(metadata)
        return task_metadata

    async def _create_lifecycle_task_record(
        self,
        operation: str,
        node_id: str,
        instance_id: str,
        project_id: str,
        node_type: str,
        k8s_resource_name: Optional[str] = None,
        service_name: Optional[str] = None,
        has_ingress: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
        initial_status: Any = "Pending",
    ) -> Dict[str, Any]:
        normalized_node_type = self._normalize_status(node_type, default=NodeType.APP)
        task_metadata = self._build_task_metadata(
            operation=operation,
            service_name=service_name,
            has_ingress=has_ingress,
            metadata=metadata,
        )
        record = await self.status_sync_service.create_node_task_record(
            node_id=node_id,
            instance_id=instance_id,
            project_id=project_id,
            node_type=normalized_node_type,
            k8s_resource_name=k8s_resource_name,
            initial_status=self._normalize_status(initial_status, default="Pending"),
            metadata=task_metadata,
        )
        return {
            "task_id": record["task_id"],
            "metadata": task_metadata,
        }

    async def _collect_runtime_logs_for_task(
        self,
        task_id: str,
        project_id: str,
        log_field_override: Optional[str] = None,
    ) -> bool:
        try:
            log_result = await self.status_sync_service.get_task_logs(
                task_id=task_id,
                project_id=project_id,
                tail_lines=500,
                persist=True,
                log_field_override=log_field_override,
            )
            return bool(log_result.get("logs")) and bool(log_result.get("pod_name"))
        except Exception as e:
            logger.debug(
                f"[WorkflowLifecycle] Failed to collect runtime logs: "
                f"task_id={task_id}, project_id={project_id}, error={e}"
            )
            return False

    async def _finalize_lifecycle_task_record(
        self,
        task_id: str,
        operation: str,
        node_id: str,
        instance_id: str,
        project_id: str,
        node_type: str,
        success: bool,
        status: Any,
        message: Optional[str] = None,
        error: Optional[str] = None,
        k8s_resource_name: Optional[str] = None,
        service_name: Optional[str] = None,
        has_ingress: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
        persist_summary_logs: bool = True,
    ) -> Dict[str, Any]:
        normalized_node_type = self._normalize_status(node_type, default=NodeType.APP)
        task_status = self._resolve_task_status(operation, success, status)
        task_message = message or error or f"Workflow {operation}"
        logs = self._build_lifecycle_logs(
            operation=operation,
            node_id=node_id,
            instance_id=instance_id,
            project_id=project_id,
            node_type=normalized_node_type,
            success=success,
            status=task_status,
            message=message,
            error=error,
            k8s_resource_name=k8s_resource_name,
            service_name=service_name,
            metadata=metadata,
        )

        if persist_summary_logs:
            if operation == "initialize":
                collected_real_logs = False
                if normalized_node_type.lower() == NodeType.APP and success and k8s_resource_name:
                    collected_real_logs = await self._collect_runtime_logs_for_task(
                        task_id=task_id,
                        project_id=project_id,
                    )

                # APP 节点初始化成功时，init_logs 只保留真实 Pod/容器日志。
                # 如果此刻 Pod 还没起来，就先留空，后续由监控同步补抓真实日志。
                if not collected_real_logs and (normalized_node_type.lower() != NodeType.APP or not success):
                    await self.status_sync_service.save_init_logs(
                        node_id=node_id,
                        logs=logs,
                        task_id=task_id,
                    )
            else:
                await self.status_sync_service.save_execution_logs(
                    node_id=node_id,
                    logs=logs,
                    task_id=task_id,
                )

        await self.status_sync_service.update_node_status(
            node_id=node_id,
            status=task_status,
            message=task_message,
            task_id=task_id,
        )

        return {
            "task_id": task_id,
            "status": task_status,
            "message": task_message,
        }

    async def _record_lifecycle_task(
        self,
        operation: str,
        node_id: str,
        instance_id: str,
        project_id: str,
        node_type: str,
        success: bool,
        status: Any,
        message: Optional[str] = None,
        error: Optional[str] = None,
        k8s_resource_name: Optional[str] = None,
        service_name: Optional[str] = None,
        has_ingress: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        task_context = await self._create_lifecycle_task_record(
            operation=operation,
            node_id=node_id,
            instance_id=instance_id,
            project_id=project_id,
            node_type=node_type,
            k8s_resource_name=k8s_resource_name,
            service_name=service_name,
            has_ingress=has_ingress,
            metadata=metadata,
            initial_status=status,
        )
        return await self._finalize_lifecycle_task_record(
            task_id=task_context["task_id"],
            operation=operation,
            node_id=node_id,
            instance_id=instance_id,
            project_id=project_id,
            node_type=node_type,
            success=success,
            status=status,
            message=message,
            error=error,
            k8s_resource_name=k8s_resource_name,
            service_name=service_name,
            has_ingress=has_ingress,
            metadata=metadata,
        )

    async def initialize_workflow(
        self,
        instance_id: str,
        project_id: str,
        nodes: List[Dict[str, Any]]
    ) -> WorkflowLifecycleResponse:
        """
        初始化工作流实例

        为工作流实例创建所有节点的K8S资源：
        - APP节点：创建 Deployment + Service + Ingress(可选)
        - JOB节点：仅记录状态，延迟到执行时创建

        Args:
            instance_id: 工作流实例ID
            project_id: 项目ID
            nodes: 节点配置列表

        Returns:
            WorkflowLifecycleResponse: 操作结果
        """
        logger.info(
            f"[WorkflowLifecycle] 开始初始化工作流: "
            f"instance_id={instance_id}, nodes_count={len(nodes)}"
        )

        results = []
        succeeded_count = 0
        failed_count = 0

        # 创建工作流状态记录
        await self._ensure_workflow_status_record(instance_id, project_id)

        for node_config in nodes:
            node_id = node_config.get("node_id")
            node_type = node_config.get("node_type", NodeType.APP)

            try:
                # 调用节点生命周期服务初始化节点
                result = await self.node_lifecycle_service.initialize_node(
                    node_id=node_id,
                    instance_id=instance_id,
                    project_id=project_id,
                    node_type=node_type,
                    node_name=node_config.get("node_name", f"node-{node_id[:8]}"),
                    deployment_name=node_config.get("deployment_name"),
                    service_name=node_config.get("service_name"),
                    ingress_config=node_config.get("ingress_config"),
                    containers=node_config.get("containers", []),
                    volume_mounts=node_config.get("volume_mounts"),
                    replicas=node_config.get("replicas", 1),
                    service_ports=node_config.get("service_ports", []),
                    service_type=node_config.get("service_type", "ClusterIP")
                )

                # 记录节点初始状态
                task_record = await self._record_lifecycle_task(
                    operation="initialize",
                    node_id=node_id,
                    instance_id=instance_id,
                    project_id=project_id,
                    node_type=node_type,
                    success=result.success,
                    status=result.status,
                    message=result.message,
                    error=result.error,
                    k8s_resource_name=result.k8s_resource_name,
                    service_name=result.service_name,
                )

                node_result = WorkflowNodeResult(
                    node_id=node_id,
                    task_id=task_record["task_id"],
                    success=result.success,
                    status=task_record["status"],
                    message=task_record["message"],
                    k8s_resource_name=result.k8s_resource_name,
                    service_name=result.service_name,
                    ingress_name=result.ingress_name,
                    ingress_host=result.ingress_host,
                    ingress_access_url=result.ingress_access_url,
                    ingress_tls_enabled=result.ingress_tls_enabled,
                    error=result.error
                )

                if result.success:
                    succeeded_count += 1
                    logger.info(f"[WorkflowLifecycle] 节点初始化成功: {node_id}")
                else:
                    failed_count += 1
                    logger.warning(f"[WorkflowLifecycle] 节点初始化失败: {node_id}, error={result.error}")

            except Exception as e:
                failed_count += 1
                error_msg = f"节点初始化异常: {str(e)}"
                logger.error(f"[WorkflowLifecycle] {error_msg}", exc_info=True)

                task_record = await self._record_lifecycle_task(
                    operation="initialize",
                    node_id=node_id,
                    instance_id=instance_id,
                    project_id=project_id,
                    node_type=node_type,
                    success=False,
                    status="Failed",
                    error=error_msg,
                    k8s_resource_name=node_config.get("deployment_name"),
                    service_name=node_config.get("service_name"),
                )

                node_result = WorkflowNodeResult(
                    node_id=node_id,
                    task_id=task_record["task_id"],
                    success=False,
                    status=task_record["status"],
                    message=task_record["message"],
                    error=error_msg
                )

            results.append(node_result)

        # 更新工作流状态
        workflow_status = "Pending"
        if failed_count == 0:
            workflow_status = "Pending"
            message = f"工作流初始化成功，共 {succeeded_count} 个节点"
        elif succeeded_count == 0:
            workflow_status = "Failed"
            message = "工作流初始化失败，所有节点初始化失败"
        else:
            workflow_status = "Pending"
            message = f"工作流部分初始化成功: {succeeded_count} 成功, {failed_count} 失败"

        await self._update_workflow_status(
            instance_id=instance_id,
            project_id=project_id,
            status=workflow_status,
            message=message,
            total_nodes=len(nodes),
            pending_nodes=len(nodes),
            running_nodes=0,
            succeeded_nodes=0,
            failed_nodes=failed_count
        )

        overall_success = failed_count == 0

        logger.info(
            f"[WorkflowLifecycle] 工作流初始化完成: instance_id={instance_id}, "
            f"success={overall_success}, succeeded={succeeded_count}, failed={failed_count}"
        )

        await self._ensure_app_monitoring(
            instance_id=instance_id,
            project_id=project_id,
            node_configs=nodes,
            results=results,
        )

        return WorkflowLifecycleResponse(
            success=overall_success,
            instance_id=instance_id,
            project_id=project_id,
            total_nodes=len(nodes),
            succeeded_nodes=succeeded_count,
            failed_nodes=failed_count,
            nodes=results,
            message=message
        )

    async def deinitialize_workflow(
        self,
        instance_id: str,
        project_id: str,
        nodes: Optional[List[Dict[str, Any]]] = None
    ) -> WorkflowLifecycleResponse:
        """
        反初始化工作流实例

        删除工作流实例所有节点的K8S资源：
        - APP节点：删除 Ingress -> Service -> Deployment
        - JOB节点：删除 Job

        Args:
            instance_id: 工作流实例ID
            project_id: 项目ID
            nodes: 节点信息列表（可选，不提供时从数据库获取）

        Returns:
            WorkflowLifecycleResponse: 操作结果
        """
        logger.info(
            f"[WorkflowLifecycle] 开始反初始化工作流: instance_id={instance_id}"
        )

        # 获取节点信息
        await self._stop_workflow_monitoring(instance_id)

        if nodes is None:
            nodes = await self._get_nodes_from_db(instance_id, project_id)

        if not nodes:
            logger.warning(f"[WorkflowLifecycle] 工作流无节点记录: {instance_id}")
            return WorkflowLifecycleResponse(
                success=True,
                instance_id=instance_id,
                project_id=project_id,
                total_nodes=0,
                succeeded_nodes=0,
                failed_nodes=0,
                nodes=[],
                message="工作流无节点记录"
            )

        results = []
        succeeded_count = 0
        failed_count = 0

        for node_info in nodes:
            node_id = node_info.get("node_id")
            node_type = node_info.get("node_type", NodeType.APP)
            k8s_resource_name = node_info.get("k8s_resource_name")
            service_name = node_info.get("service_name") or node_info.get("metadata", {}).get("service_name")
            ingress_name = node_info.get("ingress_name") or node_info.get("metadata", {}).get("ingress_name")

            # 检查是否有Ingress
            has_ingress = node_info.get("has_ingress", False)
            if not has_ingress:
                metadata = node_info.get("metadata") or {}
                has_ingress = metadata.get("has_ingress", False)

            task_id: Optional[str] = None
            try:
                task_context = await self._create_lifecycle_task_record(
                    operation="deinitialize",
                    node_id=node_id,
                    instance_id=instance_id,
                    project_id=project_id,
                    node_type=node_type,
                    k8s_resource_name=k8s_resource_name,
                    service_name=service_name,
                    has_ingress=has_ingress,
                    initial_status=node_info.get("status", "Pending"),
                )
                task_id = task_context["task_id"]
                await self._collect_runtime_logs_for_task(
                    task_id=task_id,
                    project_id=project_id,
                    log_field_override="execution_logs",
                )

                result = await self.node_lifecycle_service.uninitialize_node(
                    node_id=node_id,
                    instance_id=instance_id,
                    project_id=project_id,
                    node_type=node_type,
                    k8s_resource_name=k8s_resource_name,
                    service_name=service_name,
                    has_ingress=has_ingress,
                    ingress_name=ingress_name,
                )

                if task_id:
                    task_record = await self._finalize_lifecycle_task_record(
                        task_id=task_id,
                        operation="deinitialize",
                        node_id=node_id,
                        instance_id=instance_id,
                        project_id=project_id,
                        node_type=node_type,
                        success=result.success,
                        status="Stopped" if result.success else "Failed",
                        message=result.message or "Workflow deinitialized",
                        error=result.error,
                        k8s_resource_name=k8s_resource_name,
                        service_name=service_name,
                        has_ingress=has_ingress,
                        persist_summary_logs=False,
                    )
                else:
                    task_record = await self._record_lifecycle_task(
                        operation="deinitialize",
                        node_id=node_id,
                        instance_id=instance_id,
                        project_id=project_id,
                        node_type=node_type,
                        success=result.success,
                        status="Stopped" if result.success else "Failed",
                        message=result.message or "Workflow deinitialized",
                        error=result.error,
                        k8s_resource_name=k8s_resource_name,
                        service_name=service_name,
                        has_ingress=has_ingress,
                    )

                node_result = WorkflowNodeResult(
                    node_id=node_id,
                    task_id=task_record["task_id"],
                    success=result.success,
                    status=task_record["status"],
                    message=task_record["message"],
                    k8s_resource_name=k8s_resource_name,
                    service_name=service_name,
                    ingress_name=ingress_name,
                    error=result.error
                )

                if result.success:
                    succeeded_count += 1
                    logger.info(f"[WorkflowLifecycle] 节点反初始化成功: {node_id}")
                else:
                    failed_count += 1
                    logger.warning(f"[WorkflowLifecycle] 节点反初始化失败: {node_id}")

            except Exception as e:
                failed_count += 1
                error_msg = f"节点反初始化异常: {str(e)}"
                logger.error(f"[WorkflowLifecycle] {error_msg}", exc_info=True)

                if task_id:
                    task_record = await self._finalize_lifecycle_task_record(
                        task_id=task_id,
                        operation="deinitialize",
                        node_id=node_id,
                        instance_id=instance_id,
                        project_id=project_id,
                        node_type=node_type,
                        success=False,
                        status="Failed",
                        error=error_msg,
                        k8s_resource_name=k8s_resource_name,
                        service_name=service_name,
                        has_ingress=has_ingress,
                        persist_summary_logs=False,
                    )
                else:
                    task_record = await self._record_lifecycle_task(
                        operation="deinitialize",
                        node_id=node_id,
                        instance_id=instance_id,
                        project_id=project_id,
                        node_type=node_type,
                        success=False,
                        status="Failed",
                        error=error_msg,
                        k8s_resource_name=k8s_resource_name,
                        service_name=service_name,
                        has_ingress=has_ingress,
                    )

                node_result = WorkflowNodeResult(
                    node_id=node_id,
                    task_id=task_record["task_id"],
                    success=False,
                    status=task_record["status"],
                    message=task_record["message"],
                    error=error_msg
                )

            results.append(node_result)

        # 更新工作流状态为已清理
        message = f"工作流反初始化完成: {succeeded_count} 成功, {failed_count} 失败"
        await self._update_workflow_status(
            instance_id=instance_id,
            project_id=project_id,
            status="Stopped",
            message=message,
            stopped_nodes=len(nodes)
        )

        # 反初始化视为成功，只要有部分节点成功
        overall_success = succeeded_count > 0 or len(nodes) == 0

        logger.info(
            f"[WorkflowLifecycle] 工作流反初始化完成: instance_id={instance_id}"
        )

        return WorkflowLifecycleResponse(
            success=overall_success,
            instance_id=instance_id,
            project_id=project_id,
            total_nodes=len(nodes),
            succeeded_nodes=succeeded_count,
            failed_nodes=failed_count,
            nodes=results,
            message=message
        )

    async def stop_workflow(
        self,
        instance_id: str,
        project_id: str,
        nodes: Optional[List[Dict[str, Any]]] = None
    ) -> WorkflowLifecycleResponse:
        """
        停止工作流实例

        停止所有正在运行的节点并清理资源：
        - APP节点：删除 Ingress -> Service -> Deployment
        - JOB节点：删除 Job

        Args:
            instance_id: 工作流实例ID
            project_id: 项目ID
            nodes: 节点信息列表（可选，不提供时从数据库获取）

        Returns:
            WorkflowLifecycleResponse: 操作结果
        """
        logger.info(
            f"[WorkflowLifecycle] 开始停止工作流: instance_id={instance_id}"
        )

        # 获取节点信息
        await self._stop_workflow_monitoring(instance_id)

        if nodes is None:
            nodes = await self._get_nodes_from_db(instance_id, project_id)

        if not nodes:
            logger.warning(f"[WorkflowLifecycle] 工作流无节点记录: {instance_id}")
            return WorkflowLifecycleResponse(
                success=True,
                instance_id=instance_id,
                project_id=project_id,
                total_nodes=0,
                succeeded_nodes=0,
                failed_nodes=0,
                nodes=[],
                message="工作流无节点记录"
            )

        results = []
        succeeded_count = 0
        failed_count = 0

        for node_info in nodes:
            node_id = node_info.get("node_id")
            node_type = node_info.get("node_type", NodeType.APP)
            k8s_resource_name = node_info.get("k8s_resource_name")
            service_name = node_info.get("service_name") or node_info.get("metadata", {}).get("service_name")
            ingress_name = node_info.get("ingress_name") or node_info.get("metadata", {}).get("ingress_name")

            has_ingress = node_info.get("has_ingress", False)
            if not has_ingress:
                metadata = node_info.get("metadata") or {}
                has_ingress = metadata.get("has_ingress", False)

            task_id: Optional[str] = None
            try:
                task_context = await self._create_lifecycle_task_record(
                    operation="stop",
                    node_id=node_id,
                    instance_id=instance_id,
                    project_id=project_id,
                    node_type=node_type,
                    k8s_resource_name=k8s_resource_name,
                    service_name=service_name,
                    has_ingress=has_ingress,
                    initial_status=node_info.get("status", "Pending"),
                )
                task_id = task_context["task_id"]
                await self._collect_runtime_logs_for_task(
                    task_id=task_id,
                    project_id=project_id,
                    log_field_override="execution_logs",
                )

                result = await self.node_lifecycle_service.stop_node(
                    node_id=node_id,
                    instance_id=instance_id,
                    project_id=project_id,
                    node_type=node_type,
                    k8s_resource_name=k8s_resource_name,
                    service_name=service_name,
                    has_ingress=has_ingress,
                    ingress_name=ingress_name,
                )

                if task_id:
                    task_record = await self._finalize_lifecycle_task_record(
                        task_id=task_id,
                        operation="stop",
                        node_id=node_id,
                        instance_id=instance_id,
                        project_id=project_id,
                        node_type=node_type,
                        success=result.success,
                        status="Stopped" if result.success else "Failed",
                        message=result.message or "Workflow stopped",
                        error=result.error,
                        k8s_resource_name=k8s_resource_name,
                        service_name=service_name,
                        has_ingress=has_ingress,
                        persist_summary_logs=False,
                    )
                else:
                    task_record = await self._record_lifecycle_task(
                        operation="stop",
                        node_id=node_id,
                        instance_id=instance_id,
                        project_id=project_id,
                        node_type=node_type,
                        success=result.success,
                        status="Stopped" if result.success else "Failed",
                        message=result.message or "Workflow stopped",
                        error=result.error,
                        k8s_resource_name=k8s_resource_name,
                        service_name=service_name,
                        has_ingress=has_ingress,
                    )

                node_result = WorkflowNodeResult(
                    node_id=node_id,
                    task_id=task_record["task_id"],
                    success=result.success,
                    status=task_record["status"],
                    message=task_record["message"],
                    k8s_resource_name=k8s_resource_name,
                    service_name=service_name,
                    ingress_name=ingress_name,
                    error=result.error
                )

                if result.success:
                    succeeded_count += 1
                    logger.info(f"[WorkflowLifecycle] 节点停止成功: {node_id}")
                else:
                    failed_count += 1
                    logger.warning(f"[WorkflowLifecycle] 节点停止失败: {node_id}")

            except Exception as e:
                failed_count += 1
                error_msg = f"节点停止异常: {str(e)}"
                logger.error(f"[WorkflowLifecycle] {error_msg}", exc_info=True)

                if task_id:
                    task_record = await self._finalize_lifecycle_task_record(
                        task_id=task_id,
                        operation="stop",
                        node_id=node_id,
                        instance_id=instance_id,
                        project_id=project_id,
                        node_type=node_type,
                        success=False,
                        status="Failed",
                        error=error_msg,
                        k8s_resource_name=k8s_resource_name,
                        service_name=service_name,
                        has_ingress=has_ingress,
                        persist_summary_logs=False,
                    )
                else:
                    task_record = await self._record_lifecycle_task(
                        operation="stop",
                        node_id=node_id,
                        instance_id=instance_id,
                        project_id=project_id,
                        node_type=node_type,
                        success=False,
                        status="Failed",
                        error=error_msg,
                        k8s_resource_name=k8s_resource_name,
                        service_name=service_name,
                        has_ingress=has_ingress,
                    )

                node_result = WorkflowNodeResult(
                    node_id=node_id,
                    task_id=task_record["task_id"],
                    success=False,
                    status=task_record["status"],
                    message=task_record["message"],
                    error=error_msg
                )

            results.append(node_result)

        # 更新工作流状态
        message = f"工作流已停止: {succeeded_count} 成功, {failed_count} 失败"
        await self._update_workflow_status(
            instance_id=instance_id,
            project_id=project_id,
            status="Stopped",
            message=message,
            stopped_nodes=len(nodes)
        )

        overall_success = succeeded_count > 0 or len(nodes) == 0

        logger.info(
            f"[WorkflowLifecycle] 工作流停止完成: instance_id={instance_id}"
        )

        return WorkflowLifecycleResponse(
            success=overall_success,
            instance_id=instance_id,
            project_id=project_id,
            total_nodes=len(nodes),
            succeeded_nodes=succeeded_count,
            failed_nodes=failed_count,
            nodes=results,
            message=message
        )

    async def _ensure_app_monitoring(
        self,
        instance_id: str,
        project_id: str,
        node_configs: List[Dict[str, Any]],
        results: List[WorkflowNodeResult],
    ) -> None:
        """Start APP monitoring after initialize so logs/status begin syncing immediately."""
        result_map = {result.node_id: result for result in results}
        app_nodes = []

        for node_config in node_configs:
            node_id = node_config.get("node_id")
            node_type = node_config.get("node_type", NodeType.APP)
            node_type_value = node_type.value if hasattr(node_type, "value") else str(node_type)
            if (node_type_value or "").lower() != "app":
                continue

            result = result_map.get(node_id)
            if not result or not result.success or not result.k8s_resource_name:
                continue

            app_nodes.append(
                {
                    "node_id": node_id,
                    "task_id": result.task_id,
                    "node_type": "app",
                    "k8s_resource_name": result.k8s_resource_name,
                    "timeout_seconds": None,
                }
            )

        if not app_nodes:
            await self._stop_workflow_monitoring(instance_id)
            logger.info(
                f"[WorkflowLifecycle] No APP nodes eligible for monitoring: instance_id={instance_id}"
            )
            return

        try:
            monitor_engine = get_workflow_monitor_engine()
            session_id = await monitor_engine.start_monitoring(
                instance_id=instance_id,
                project_id=project_id,
                nodes=app_nodes,
                poll_interval=10,
            )
            logger.info(
                f"[WorkflowLifecycle] APP monitoring started: instance_id={instance_id}, "
                f"session_id={session_id}, nodes={len(app_nodes)}"
            )
        except Exception as e:
            logger.warning(
                f"[WorkflowLifecycle] Failed to start APP monitoring: "
                f"instance_id={instance_id}, error={e}"
            )
            return

        try:
            await self.status_sync_service.sync_all_nodes(
                instance_id=instance_id,
                project_id=project_id,
                nodes=app_nodes,
            )
            logger.info(
                f"[WorkflowLifecycle] Initial APP status sync finished after initialize: "
                f"instance_id={instance_id}"
            )
        except Exception as e:
            logger.warning(
                f"[WorkflowLifecycle] Initial APP status sync failed after initialize: "
                f"instance_id={instance_id}, error={e}"
            )

    async def _stop_workflow_monitoring(self, instance_id: str) -> None:
        """Best-effort stop for the workflow monitoring session."""
        try:
            stopped = await get_workflow_monitor_engine().stop_monitoring(instance_id)
            if stopped:
                logger.info(f"[WorkflowLifecycle] Monitoring stopped: instance_id={instance_id}")
        except Exception as e:
            logger.warning(
                f"[WorkflowLifecycle] Failed to stop monitoring: "
                f"instance_id={instance_id}, error={e}"
            )

    async def _ensure_workflow_status_record(
        self,
        instance_id: str,
        project_id: str
    ):
        """确保工作流状态记录存在"""
        db = get_db_session()
        try:
            record = db.query(WorkflowStatusRecord).filter(
                WorkflowStatusRecord.instance_id == instance_id
            ).first()

            if not record:
                record = WorkflowStatusRecord(
                    id=str(uuid.uuid4()),
                    instance_id=instance_id,
                    project_id=project_id,
                    status="Pending",
                    message="Workflow initialized",
                    total_nodes=0,
                    started_at=datetime.utcnow()
                )
                db.add(record)
                db.commit()
        except Exception as e:
            logger.error(f"创建工作流状态记录失败: {e}")
            db.rollback()
            raise
        finally:
            db.close()

    async def _get_nodes_from_db(
        self,
        instance_id: str,
        project_id: str
    ) -> List[Dict[str, Any]]:
        """从数据库获取节点列表"""
        db = get_db_session()
        try:
            records = db.query(NodeStatusRecord).filter(
                NodeStatusRecord.instance_id == instance_id,
                NodeStatusRecord.project_id == project_id
            ).order_by(
                NodeStatusRecord.created_at.desc(),
                NodeStatusRecord.id.desc(),
            ).all()

            latest_records = []
            seen_node_ids = set()
            for record in records:
                if record.node_id in seen_node_ids:
                    continue
                seen_node_ids.add(record.node_id)
                latest_records.append(record)

            return [
                {
                    "node_id": r.node_id,
                    "node_type": r.node_type,
                    "k8s_resource_name": r.k8s_resource_name,
                    "status": r.status,
                    "service_name": r.extra_data.get("service_name") if r.extra_data else None,
                    "has_ingress": r.extra_data.get("has_ingress", False) if r.extra_data else False,
                    "metadata": r.extra_data
                }
                for r in latest_records
            ]
        finally:
            db.close()

    async def _record_node_initial_status(
        self,
        node_id: str,
        instance_id: str,
        project_id: str,
        node_type: str,
        k8s_resource_name: Optional[str],
        service_name: Optional[str],
        initial_status: str
    ):
        """记录节点初始状态"""
        db = get_db_session()
        try:
            # 检查是否已存在
            existing = db.query(NodeStatusRecord).filter(
                NodeStatusRecord.node_id == node_id
            ).order_by(
                NodeStatusRecord.created_at.desc(),
                NodeStatusRecord.id.desc(),
            ).first()

            if existing:
                logger.debug(f"节点状态记录已存在: {node_id}")
                return

            k8s_resource_type = "Deployment" if node_type.lower() == NodeType.APP else "Job"

            # 构建metadata
            metadata = {
                "service_name": service_name,
                "has_ingress": False
            }

            record = NodeStatusRecord(
                id=str(uuid.uuid4()),
                task_id=f"{node_id}-{uuid.uuid4().hex[:6]}"[:64],
                node_id=node_id,
                instance_id=instance_id,
                project_id=project_id,
                node_type=node_type,
                k8s_resource_name=k8s_resource_name,
                k8s_resource_type=k8s_resource_type,
                status=initial_status,
                message="Node initialized via workflow lifecycle",
                extra_data=metadata
            )
            db.add(record)

            history = NodeStatusHistory(
                node_id=node_id,
                instance_id=instance_id,
                project_id=project_id,
                from_status=None,
                to_status=initial_status,
                reason="Node initialized",
                operator="system"
            )
            db.add(history)

            db.commit()
        except Exception as e:
            logger.error(f"记录节点初始状态失败: {e}")
            db.rollback()
            raise
        finally:
            db.close()

    async def _update_node_status(
        self,
        node_id: str,
        status: str,
        message: Optional[str] = None
    ):
        """更新节点状态"""
        db = get_db_session()
        try:
            record = db.query(NodeStatusRecord).filter(
                NodeStatusRecord.node_id == node_id
            ).order_by(
                NodeStatusRecord.created_at.desc(),
                NodeStatusRecord.id.desc(),
            ).first()

            if record:
                old_status = record.status
                record.status = status
                record.message = message
                if status in ["Succeeded", "Failed", "Stopped"]:
                    record.finished_at = datetime.utcnow()

                # 记录状态变更历史
                history = NodeStatusHistory(
                    node_id=node_id,
                    instance_id=record.instance_id,
                    project_id=record.project_id,
                    from_status=old_status,
                    to_status=status,
                    reason=message,
                    operator="system"
                )
                db.add(history)

                db.commit()
        except Exception as e:
            logger.error(f"更新节点状态失败: {e}")
            db.rollback()
        finally:
            db.close()

    async def _update_workflow_status(
        self,
        instance_id: str,
        project_id: str,
        status: str,
        message: str,
        total_nodes: int = 0,
        pending_nodes: int = 0,
        running_nodes: int = 0,
        succeeded_nodes: int = 0,
        failed_nodes: int = 0,
        stopped_nodes: int = 0
    ):
        """更新工作流状态"""
        db = get_db_session()
        try:
            record = db.query(WorkflowStatusRecord).filter(
                WorkflowStatusRecord.instance_id == instance_id
            ).first()

            if record:
                record.status = status
                record.message = message
                if total_nodes > 0:
                    record.total_nodes = total_nodes
                    record.pending_nodes = pending_nodes
                    record.running_nodes = running_nodes
                    record.succeeded_nodes = succeeded_nodes
                    record.failed_nodes = failed_nodes
                    record.stopped_nodes = stopped_nodes

                if status in ["Succeeded", "Failed", "Stopped"]:
                    record.finished_at = datetime.utcnow()

                db.commit()
            else:
                # 如果记录不存在，创建一个
                record = WorkflowStatusRecord(
                    id=str(uuid.uuid4()),
                    instance_id=instance_id,
                    project_id=project_id,
                    status=status,
                    message=message,
                    total_nodes=total_nodes,
                    pending_nodes=pending_nodes,
                    running_nodes=running_nodes,
                    succeeded_nodes=succeeded_nodes,
                    failed_nodes=failed_nodes,
                    stopped_nodes=stopped_nodes,
                    started_at=datetime.utcnow(),
                    finished_at=datetime.utcnow() if status in ["Succeeded", "Failed", "Stopped"] else None
                )
                db.add(record)
                db.commit()
        except Exception as e:
            logger.error(f"更新工作流状态失败: {e}")
            db.rollback()
        finally:
            db.close()


# 单例实例
_workflow_lifecycle_service: Optional[WorkflowLifecycleService] = None


def get_workflow_lifecycle_service() -> WorkflowLifecycleService:
    """获取工作流生命周期服务实例"""
    global _workflow_lifecycle_service
    if _workflow_lifecycle_service is None:
        _workflow_lifecycle_service = WorkflowLifecycleService()
    return _workflow_lifecycle_service
