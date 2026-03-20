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
                await self._record_node_initial_status(
                    node_id=node_id,
                    instance_id=instance_id,
                    project_id=project_id,
                    node_type=node_type,
                    k8s_resource_name=result.k8s_resource_name,
                    service_name=result.service_name,
                    initial_status=result.status
                )

                node_result = WorkflowNodeResult(
                    node_id=node_id,
                    success=result.success,
                    status=result.status,
                    message=result.message,
                    k8s_resource_name=result.k8s_resource_name,
                    service_name=result.service_name,
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

                node_result = WorkflowNodeResult(
                    node_id=node_id,
                    success=False,
                    status=AppNodeStatus.PENDING,
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

            # 检查是否有Ingress
            has_ingress = node_info.get("has_ingress", False)
            if not has_ingress:
                metadata = node_info.get("metadata") or {}
                has_ingress = metadata.get("has_ingress", False)

            try:
                result = await self.node_lifecycle_service.uninitialize_node(
                    node_id=node_id,
                    instance_id=instance_id,
                    project_id=project_id,
                    node_type=node_type,
                    k8s_resource_name=k8s_resource_name,
                    service_name=service_name,
                    has_ingress=has_ingress
                )

                # 更新节点状态为已清理
                await self._update_node_status(
                    node_id=node_id,
                    status="Stopped",
                    message="Workflow deinitialized"
                )

                node_result = WorkflowNodeResult(
                    node_id=node_id,
                    success=result.success,
                    status="Stopped",
                    message=result.message,
                    k8s_resource_name=k8s_resource_name,
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

                node_result = WorkflowNodeResult(
                    node_id=node_id,
                    success=False,
                    status="Unknown",
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

            has_ingress = node_info.get("has_ingress", False)
            if not has_ingress:
                metadata = node_info.get("metadata") or {}
                has_ingress = metadata.get("has_ingress", False)

            try:
                result = await self.node_lifecycle_service.stop_node(
                    node_id=node_id,
                    instance_id=instance_id,
                    project_id=project_id,
                    node_type=node_type,
                    k8s_resource_name=k8s_resource_name,
                    service_name=service_name,
                    has_ingress=has_ingress
                )

                # 更新节点状态为Stopped
                await self._update_node_status(
                    node_id=node_id,
                    status="Stopped",
                    message="Workflow stopped"
                )

                node_result = WorkflowNodeResult(
                    node_id=node_id,
                    success=result.success,
                    status="Stopped",
                    message=result.message,
                    k8s_resource_name=k8s_resource_name,
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

                node_result = WorkflowNodeResult(
                    node_id=node_id,
                    success=False,
                    status="Stopped",
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
            ).all()

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
                for r in records
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
