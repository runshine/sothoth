"""
节点状态同步服务
负责从K8S同步节点状态并记录状态变更历史
"""

import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any

from sqlalchemy.orm import Session

from app.models.database import (
    NodeStatusRecord,
    WorkflowStatusRecord,
    NodeStatusHistory,
    get_db_session,
)
from app.services.k8s_client import get_k8s_client
from app.services.workflow_client import get_workflow_client

logger = logging.getLogger(__name__)


class StatusSyncService:
    """节点状态同步服务"""

    def __init__(self):
        self.k8s_client = get_k8s_client()

    def _generate_task_id(self, node_id: str) -> str:
        """Generate a short task id for one collection trigger."""
        base = (node_id or "node").strip() or "node"
        suffix = uuid.uuid4().hex[:6]
        task_id = f"{base}-{suffix}"
        return task_id[:64]

    def _resolve_k8s_resource_type(
        self,
        node_type: str,
        k8s_resource_type: Optional[str] = None,
    ) -> str:
        if k8s_resource_type:
            return k8s_resource_type
        return "Deployment" if (node_type or "").lower() == "app" else "Job"

    def _get_latest_record_by_node_id(self, db: Session, node_id: str) -> Optional[NodeStatusRecord]:
        return db.query(NodeStatusRecord).filter(
            NodeStatusRecord.node_id == node_id
        ).order_by(
            NodeStatusRecord.created_at.desc(),
            NodeStatusRecord.id.desc(),
        ).first()

    def _get_record_by_task_id(self, db: Session, task_id: str) -> Optional[NodeStatusRecord]:
        return db.query(NodeStatusRecord).filter(
            NodeStatusRecord.task_id == task_id
        ).first()

    def _get_record(
        self,
        db: Session,
        node_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> Optional[NodeStatusRecord]:
        if task_id:
            return self._get_record_by_task_id(db, task_id)
        if node_id:
            return self._get_latest_record_by_node_id(db, node_id)
        return None

    def _query_pods(
        self,
        project_id: str,
        node_type: str,
        k8s_resource_name: str,
    ) -> List[Dict[str, Any]]:
        if (node_type or "").lower() == "app":
            return self.k8s_client.get_deployment_pods(project_id, k8s_resource_name)
        return self.k8s_client.get_job_pods(project_id, k8s_resource_name)

    def _save_logs_to_record(
        self,
        record: NodeStatusRecord,
        log_field: str,
        logs: str,
        pod_name: Optional[str] = None,
        container: Optional[str] = None,
        tail_lines: Optional[int] = None,
        previous: bool = False,
        status_when_fetched: Optional[str] = None,
    ) -> None:
        payload = {
            "task_id": record.task_id,
            "pod_name": pod_name,
            "container": container,
            "logs": logs,
            "fetched_at": datetime.utcnow().isoformat(),
            "tail_lines": tail_lines if tail_lines is not None else (len(logs.split("\n")) if logs else 0),
            "previous": previous,
        }
        if status_when_fetched:
            payload["status_when_fetched"] = status_when_fetched

        setattr(record, log_field, payload)
        record.log_updated_at = datetime.utcnow()

    async def create_node_task_record(
        self,
        node_id: str,
        instance_id: str,
        project_id: str,
        node_type: str,
        k8s_resource_name: str,
        k8s_resource_type: Optional[str] = None,
        initial_status: str = "Pending",
        init_logs: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create one record for one external collection trigger."""
        db = get_db_session()
        try:
            resolved_task_id = task_id or self._generate_task_id(node_id)
            record = NodeStatusRecord(
                id=str(uuid.uuid4()),
                task_id=resolved_task_id,
                node_id=node_id,
                instance_id=instance_id,
                project_id=project_id,
                node_type=node_type,
                k8s_resource_name=k8s_resource_name,
                k8s_resource_type=self._resolve_k8s_resource_type(node_type, k8s_resource_type),
                status=initial_status,
                message="Node task created",
                extra_data=metadata,
            )
            if init_logs is not None:
                self._save_logs_to_record(
                    record=record,
                    log_field="init_logs",
                    logs=init_logs,
                    tail_lines=len(init_logs.split("\n")) if init_logs else 0,
                    status_when_fetched=initial_status,
                )

            db.add(record)
            history = NodeStatusHistory(
                node_id=node_id,
                instance_id=instance_id,
                project_id=project_id,
                from_status=None,
                to_status=initial_status,
                reason=f"Node task created: {resolved_task_id}",
                operator="system",
            )
            db.add(history)
            db.commit()
            db.refresh(record)
            return record.to_dict()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    async def sync_node_status(
        self,
        node_id: str,
        project_id: str,
        instance_id: str,
        node_type: str,
        k8s_resource_name: str,
        timeout_seconds: Optional[int] = None,
        task_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        同步单个节点状态

        Args:
            node_id: 节点ID
            project_id: 项目ID
            instance_id: 工作流实例ID
            node_type: 节点类型 (app/job)
            k8s_resource_name: K8S资源名称
            timeout_seconds: 超时时间（秒）

        Returns:
            更新后的状态信息
        """
        db = get_db_session()
        try:
            # 获取当前状态记录
            if task_id:
                record = self._get_record_by_task_id(db, task_id)
            else:
                record = self._get_latest_record_by_node_id(db, node_id)

            if not record:
                # 如果记录不存在，创建新记录
                record = NodeStatusRecord(
                    id=str(uuid.uuid4()),
                    task_id=task_id or self._generate_task_id(node_id),
                    node_id=node_id,
                    instance_id=instance_id,
                    project_id=project_id,
                    node_type=node_type,
                    k8s_resource_name=k8s_resource_name,
                    k8s_resource_type=self._resolve_k8s_resource_type(node_type),
                    status="Pending"
                )
                db.add(record)
                db.commit()
                db.refresh(record)

            # 记录旧状态
            old_status = record.status

            # 从K8S获取实际状态
            if node_type.lower() == "app":
                k8s_status = self.k8s_client.get_deployment_status(
                    project_id, k8s_resource_name
                )
                new_status = self._determine_app_node_status(
                    k8s_status, record.status
                )
            else:  # job
                k8s_status = self.k8s_client.get_job_status(
                    project_id, k8s_resource_name
                )
                new_status = self._determine_job_node_status(
                    k8s_status, record.status, timeout_seconds, record.started_at
                )

            # 检查状态是否变化
            if new_status["status"] != record.status:
                # 记录状态变更历史
                self._record_status_history(
                    db, node_id, instance_id, project_id,
                    record.status, new_status["status"], new_status.get("message")
                )

                # 更新状态记录
                record.status = new_status["status"]
                record.message = new_status.get("message")
                if new_status.get("started_at"):
                    record.started_at = new_status["started_at"]
                if new_status.get("finished_at"):
                    record.finished_at = new_status["finished_at"]

                db.commit()
                db.refresh(record)

                # APP节点状态变化时获取并保存Pod日志
                if node_type.lower() == "app" and new_status["status"] in ["Not_ready", "Ready"]:
                    await self._fetch_and_save_app_logs(
                        db, record, project_id, k8s_resource_name, new_status["status"]
                    )

                # 回调通知 workflow 服务更新节点状态
                try:
                    workflow_client = get_workflow_client()
                    callback_result = await workflow_client.update_node_status(
                        node_id=node_id,
                        instance_id=instance_id,
                        status=new_status["status"],
                        message=new_status.get("message"),
                        started_at=record.started_at,
                        finished_at=record.finished_at
                    )
                    if callback_result.get("success"):
                        logger.info(f"节点状态回调成功: {node_id} -> {new_status['status']}")
                    else:
                        logger.warning(f"节点状态回调返回失败: {node_id}, {callback_result.get('message')}")
                except Exception as e:
                    # 回调失败不影响主流程，仅记录日志
                    logger.error(f"节点状态回调异常: {node_id}, error={e}")

            return record.to_dict()

        except Exception as e:
            logger.error(f"同步节点状态失败: {e}")
            db.rollback()
            raise
        finally:
            db.close()

    async def _fetch_and_save_app_logs(
        self,
        db: Session,
        record: NodeStatusRecord,
        project_id: str,
        k8s_resource_name: str,
        status: str
    ):
        """
        获取并保存APP节点的Pod日志

        Args:
            db: 数据库会话
            record: 节点状态记录
            project_id: 项目ID
            k8s_resource_name: K8S资源名称
            status: 当前状态
        """
        try:
            # 检查是否已有日志
            if record.init_logs and record.init_logs.get("logs"):
                logger.debug(f"节点 {record.node_id} 已有初始化日志，跳过获取")
                return

            # 获取Pod列表
            pods = self.k8s_client.get_deployment_pods(project_id, k8s_resource_name)
            if not pods:
                logger.warning(f"节点 {record.node_id} 没有找到 Pod")
                return

            # 获取第一个Pod的日志
            pod_name = pods[0].get("name") or pods[0].get("metadata", {}).get("name")
            if not pod_name:
                logger.warning(f"节点 {record.node_id} 无法获取 Pod 名称")
                return

            # 获取日志
            logs = self.k8s_client.get_pod_logs(
                project_id=project_id,
                pod_name=pod_name,
                tail_lines=500
            )

            if logs:
                # 保存为JSON格式
                self._save_logs_to_record(
                    record=record,
                    log_field="init_logs",
                    logs=logs,
                    pod_name=pod_name,
                    tail_lines=500,
                    status_when_fetched=status,
                )
                db.commit()
                logger.info(f"已保存节点 {record.node_id} 初始化日志 (Pod: {pod_name})")

        except Exception as e:
            logger.error(f"获取节点 {record.node_id} 日志失败: {e}")

    def _determine_app_node_status(
        self,
        k8s_status: Optional[Dict[str, Any]],
        current_status: str
    ) -> Dict[str, Any]:
        """
        确定APP节点状态

        APP节点状态判断逻辑（仅三种状态）:
        - Pending: Pod未运行，等待启动
        - Not_ready: Pod已运行但未就绪
        - Ready: Pod全部就绪，服务可用
        """
        if not k8s_status:
            # Deployment不存在，保持Pending状态
            return {
                "status": "Pending",
                "message": "Deployment not found, waiting for creation"
            }

        replicas = k8s_status.get("replicas", 0)
        ready_replicas = k8s_status.get("ready_replicas", 0)
        available_replicas = k8s_status.get("available_replicas", 0)

        if ready_replicas >= replicas and replicas > 0:
            return {"status": "Ready", "message": "Deployment is ready"}
        elif available_replicas > 0 or ready_replicas > 0:
            return {
                "status": "Not_ready",
                "message": f"Running but not ready ({ready_replicas}/{replicas})"
            }
        else:
            return {
                "status": "Pending",
                "message": f"Waiting for Pod ({ready_replicas}/{replicas})"
            }

    def _determine_job_node_status(
        self,
        k8s_status: Optional[Dict[str, Any]],
        current_status: str,
        timeout_seconds: Optional[int],
        started_at: Optional[datetime]
    ) -> Dict[str, Any]:
        """
        确定JOB节点状态

        JOB节点状态判断逻辑:
        - Pending: 等待执行
        - Running: 执行中
        - Succeeded: 执行成功
        - Failed: 执行失败（含超时）
        """
        if not k8s_status:
            return {"status": "Failed", "message": "Job not found"}

        # 检查超时
        if started_at and timeout_seconds:
            elapsed = (datetime.utcnow() - started_at).total_seconds()
            k8s_job_status = k8s_status.get("status", "")
            if elapsed > timeout_seconds and k8s_job_status in ["Pending", "Running"]:
                return {
                    "status": "Failed",
                    "message": f"Job timeout after {elapsed:.0f}s",
                    "finished_at": datetime.utcnow()
                }

        k8s_job_status = k8s_status.get("status", "")

        if k8s_job_status == "Succeeded":
            return {
                "status": "Succeeded",
                "message": "Job completed successfully",
                "finished_at": datetime.utcnow()
            }
        elif k8s_job_status == "Failed":
            return {
                "status": "Failed",
                "message": f"Job failed: {k8s_status.get('failed', 0)} failures",
                "finished_at": datetime.utcnow()
            }
        elif k8s_job_status == "Running":
            return {
                "status": "Running",
                "message": "Job is running",
                "started_at": started_at or datetime.utcnow()
            }
        else:
            return {"status": "Pending", "message": "Job is pending"}

    def _record_status_history(
        self,
        db: Session,
        node_id: str,
        instance_id: str,
        project_id: str,
        from_status: str,
        to_status: str,
        reason: Optional[str]
    ):
        """记录状态变更历史"""
        history = NodeStatusHistory(
            node_id=node_id,
            instance_id=instance_id,
            project_id=project_id,
            from_status=from_status,
            to_status=to_status,
            reason=reason,
            operator="system"
        )
        db.add(history)

    async def sync_all_nodes(
        self,
        instance_id: str,
        project_id: str,
        nodes: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        同步工作流所有节点状态

        Args:
            instance_id: 工作流实例ID
            project_id: 项目ID
            nodes: 节点列表，每个节点包含:
                - node_id: 节点ID
                - node_type: 节点类型 (app/job)
                - k8s_resource_name: K8S资源名称
                - timeout_seconds: 超时时间（可选）

        Returns:
            工作流状态和节点状态列表
        """
        db = get_db_session()
        try:
            updated_nodes = []

            for node in nodes:
                node_id = node.get("node_id")
                node_type = node.get("node_type")
                k8s_resource_name = node.get("k8s_resource_name")
                timeout_seconds = node.get("timeout_seconds")
                task_id = node.get("task_id")

                if not node_id or not k8s_resource_name:
                    continue

                # 同步节点状态
                result = await self.sync_node_status(
                    node_id=node_id,
                    project_id=project_id,
                    instance_id=instance_id,
                    node_type=node_type,
                    k8s_resource_name=k8s_resource_name,
                    timeout_seconds=timeout_seconds,
                    task_id=task_id,
                )
                updated_nodes.append(result)

            # 聚合工作流状态
            workflow_status = await self._aggregate_workflow_status(
                db, instance_id, project_id, updated_nodes
            )

            return {
                "instance_id": instance_id,
                "workflow_status": workflow_status,
                "nodes": updated_nodes
            }

        finally:
            db.close()

    async def _aggregate_workflow_status(
        self,
        db: Session,
        instance_id: str,
        project_id: str,
        nodes: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        聚合工作流状态

        工作流状态判断逻辑（优先级从高到低）:
        1. Failed: 有Job节点失败
        2. Running: 有节点正在执行中（Job的Running 或 APP的Not_ready）
        3. Succeeded: 全部节点完成（APP的Ready 或 Job的Succeeded）
        4. Pending: 其他情况（APP节点Pending或Job节点Pending）
        """
        if not nodes:
            return {"status": "Pending", "message": "No nodes found"}

        # 统计各状态节点数量
        status_counts = {
            "Pending": 0,
            "Not_ready": 0,
            "Ready": 0,
            "Running": 0,
            "Succeeded": 0,
            "Failed": 0,
        }

        for node in nodes:
            status = node.get("status", "Pending")
            if status in status_counts:
                status_counts[status] += 1

        total = len(nodes)

        # 计算正在执行的节点数量（Job的Running + APP的Not_ready）
        executing_count = status_counts["Running"] + status_counts["Not_ready"]

        # 确定工作流状态
        if status_counts["Failed"] > 0:
            workflow_status = {
                "status": "Failed",
                "message": f"Workflow failed: {status_counts['Failed']} node(s) failed",
                "finished_at": datetime.utcnow().isoformat()
            }
        elif executing_count > 0:
            workflow_status = {
                "status": "Running",
                "message": f"Workflow running: {executing_count} node(s) executing"
            }
        elif status_counts["Ready"] + status_counts["Succeeded"] == total:
            workflow_status = {
                "status": "Succeeded",
                "message": "All nodes completed successfully",
                "finished_at": datetime.utcnow().isoformat()
            }
        else:
            workflow_status = {
                "status": "Pending",
                "message": "Workflow waiting for nodes to start"
            }

        # 更新工作流状态记录
        record = db.query(WorkflowStatusRecord).filter(
            WorkflowStatusRecord.instance_id == instance_id
        ).first()

        if record:
            record.status = workflow_status["status"]
            record.message = workflow_status["message"]
            record.total_nodes = total
            record.pending_nodes = status_counts["Pending"]
            record.not_ready_nodes = status_counts["Not_ready"]
            record.ready_nodes = status_counts["Ready"]
            record.running_nodes = status_counts["Running"]
            record.succeeded_nodes = status_counts["Succeeded"]
            record.failed_nodes = status_counts["Failed"]

            if workflow_status.get("finished_at"):
                record.finished_at = datetime.utcnow()

            db.commit()
        else:
            # 创建新记录
            record = WorkflowStatusRecord(
                id=str(uuid.uuid4()),
                instance_id=instance_id,
                project_id=project_id,
                status=workflow_status["status"],
                message=workflow_status["message"],
                total_nodes=total,
                pending_nodes=status_counts["Pending"],
                not_ready_nodes=status_counts["Not_ready"],
                ready_nodes=status_counts["Ready"],
                running_nodes=status_counts["Running"],
                succeeded_nodes=status_counts["Succeeded"],
                failed_nodes=status_counts["Failed"],
                stopped_nodes=0
            )
            db.add(record)
            db.commit()

        return workflow_status

    async def record_node_initial_status(
        self,
        node_id: str,
        instance_id: str,
        project_id: str,
        node_type: str,
        k8s_resource_name: str,
        k8s_resource_type: Optional[str] = None,
        initial_status: str = "Pending",
        init_logs: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        记录节点初始状态

        Args:
            node_id: 节点ID
            instance_id: 工作流实例ID
            project_id: 项目ID
            node_type: 节点类型 (app/job)
            k8s_resource_name: K8S资源名称
            k8s_resource_type: K8S资源类型 (Deployment/Job)
            initial_status: 初始状态
            init_logs: 初始化日志

        Returns:
            创建的状态记录
        """
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
                logger.warning(f"节点状态记录已存在: {node_id}")
                return existing.to_dict()

            # 确定K8S资源类型
            if not k8s_resource_type:
                k8s_resource_type = "Deployment" if node_type.lower() == "app" else "Job"

            # 创建状态记录
            record = NodeStatusRecord(
                id=str(uuid.uuid4()),
                task_id=self._generate_task_id(node_id),
                node_id=node_id,
                instance_id=instance_id,
                project_id=project_id,
                node_type=node_type,
                k8s_resource_name=k8s_resource_name,
                k8s_resource_type=k8s_resource_type,
                status=initial_status,
                message="Node initialized",
                init_logs=init_logs,
                log_updated_at=datetime.utcnow() if init_logs else None
            )
            db.add(record)

            # 记录初始状态历史
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
            db.refresh(record)

            return record.to_dict()

        except Exception as e:
            logger.error(f"记录节点初始状态失败: {e}")
            db.rollback()
            raise
        finally:
            db.close()

    async def update_node_status(
        self,
        node_id: str,
        status: str,
        message: Optional[str] = None,
        task_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        更新节点状态

        APP节点状态: Pending, Not_ready, Ready
        Job节点状态: Pending, Running, Succeeded, Failed

        Args:
            node_id: 节点ID
            status: 新状态
            message: 状态消息

        Returns:
            更新后的状态记录
        """
        db = get_db_session()
        try:
            record = self._get_record(db, node_id=node_id, task_id=task_id)

            if not record:
                raise ValueError(f"Node status record not found: {task_id or node_id}")

            old_status = record.status

            # 记录状态变更历史
            if old_status != status:
                history = NodeStatusHistory(
                    node_id=node_id,
                    instance_id=record.instance_id,
                    project_id=record.project_id,
                    from_status=old_status,
                    to_status=status,
                    reason=message,
                    operator="user"
                )
                db.add(history)

            # 更新状态
            record.status = status
            record.message = message or f"Status updated to {status}"

            # Job节点完成或失败时记录结束时间
            if status in ["Succeeded", "Failed", "Stopped"]:
                record.finished_at = datetime.utcnow()

            db.commit()
            db.refresh(record)

            return record.to_dict()

        except Exception as e:
            logger.error(f"更新节点状态失败: {e}")
            db.rollback()
            raise
        finally:
            db.close()

    async def get_node_logs(
        self,
        node_id: str,
        project_id: str,
        tail_lines: int = 100,
        container: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        获取节点日志

        Args:
            node_id: 节点ID
            project_id: 项目ID
            tail_lines: 返回日志行数
            container: 容器名称

        Returns:
            日志信息，包含:
            - node_id: 节点ID
            - logs: 日志内容
            - pod_name: Pod名称
        """
        db = get_db_session()
        try:
            # 获取节点状态记录
            record = db.query(NodeStatusRecord).filter(
                NodeStatusRecord.node_id == node_id
            ).order_by(
                NodeStatusRecord.created_at.desc(),
                NodeStatusRecord.id.desc(),
            ).first()

            if not record:
                raise ValueError(f"Node status record not found: {node_id}")

            k8s_resource_name = record.k8s_resource_name
            node_type = record.node_type

            # 获取Pod列表
            if node_type.lower() == "app":
                pods = self.k8s_client.get_deployment_pods(project_id, k8s_resource_name)
            else:
                pods = self.k8s_client.get_job_pods(project_id, k8s_resource_name)

            if not pods:
                return {
                    "task_id": record.task_id,
                    "node_id": node_id,
                    "resource_name": k8s_resource_name,
                    "namespace": self.k8s_client.get_project_namespace(project_id),
                    "logs": "",
                    "pod_name": None,
                    "message": "No pods found"
                }

            # 获取第一个Pod的日志
            pod_name = pods[0].get("name") or pods[0].get("metadata", {}).get("name")
            if not pod_name:
                return {
                    "task_id": record.task_id,
                    "node_id": node_id,
                    "resource_name": k8s_resource_name,
                    "namespace": self.k8s_client.get_project_namespace(project_id),
                    "logs": "",
                    "pod_name": None,
                    "message": "Pod name not found"
                }

            logs = self.k8s_client.get_pod_logs(
                project_id=project_id,
                pod_name=pod_name,
                container=container,
                tail_lines=tail_lines
            )

            return {
                "task_id": record.task_id,
                "node_id": node_id,
                "resource_name": k8s_resource_name,
                "namespace": self.k8s_client.get_project_namespace(project_id),
                "logs": logs or "",
                "pod_name": pod_name,
                "container": container,
            }

        finally:
            db.close()

    async def save_init_logs(
        self,
        node_id: str,
        logs: str,
        pod_name: Optional[str] = None,
        container: Optional[str] = None,
        task_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        保存节点初始化日志

        Args:
            node_id: 节点ID
            logs: 日志内容
            pod_name: Pod名称
            container: 容器名称

        Returns:
            更新后的状态记录
        """
        db = get_db_session()
        try:
            record = self._get_record(db, node_id=node_id, task_id=task_id)

            if not record:
                raise ValueError(f"Node status record not found: {task_id or node_id}")

            # 保存为JSON格式
            self._save_logs_to_record(
                record=record,
                log_field="init_logs",
                logs=logs,
                pod_name=pod_name,
                container=container,
            )

            db.commit()
            db.refresh(record)

            return record.to_dict()

        except Exception as e:
            logger.error(f"保存初始化日志失败: {e}")
            db.rollback()
            raise
        finally:
            db.close()

    async def save_execution_logs(
        self,
        node_id: str,
        logs: str,
        pod_name: Optional[str] = None,
        container: Optional[str] = None,
        task_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        保存节点执行日志

        Args:
            node_id: 节点ID
            logs: 日志内容
            pod_name: Pod名称
            container: 容器名称

        Returns:
            更新后的状态记录
        """
        db = get_db_session()
        try:
            record = self._get_record(db, node_id=node_id, task_id=task_id)

            if not record:
                raise ValueError(f"Node status record not found: {task_id or node_id}")

            # 保存为JSON格式
            self._save_logs_to_record(
                record=record,
                log_field="execution_logs",
                logs=logs,
                pod_name=pod_name,
                container=container,
            )

            db.commit()
            db.refresh(record)

            return record.to_dict()

        except Exception as e:
            logger.error(f"保存执行日志失败: {e}")
            db.rollback()
            raise
        finally:
            db.close()

    async def get_stored_logs(
        self,
        node_id: Optional[str] = None,
        task_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        获取节点存储的日志

        Args:
            node_id: 节点ID

        Returns:
            日志信息，包含初始化日志和执行日志
        """
        db = get_db_session()
        try:
            if not node_id and not task_id:
                raise ValueError("Either node_id or task_id is required")

            record = self._get_record(db, node_id=node_id, task_id=task_id)

            if not record:
                raise ValueError(f"Node status record not found: {task_id or node_id}")

            return {
                "task_id": record.task_id,
                "node_id": record.node_id,
                "init_logs": record.init_logs or "",
                "execution_logs": record.execution_logs or "",
                "log_updated_at": record.log_updated_at.isoformat() if record.log_updated_at else None
            }

        finally:
            db.close()

    async def query_instance_node_logs(
        self,
        instance_id: str,
        project_id: str,
        node_ids: List[str],
        node_id: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> Dict[str, Any]:
        """Query stored node log records for one workflow instance."""
        normalized_node_ids = [item for item in dict.fromkeys(node_ids or []) if item]
        if not normalized_node_ids:
            return {
                "total": 0,
                "page": page,
                "page_size": page_size,
                "items": [],
            }

        if node_id and node_id not in normalized_node_ids:
            return {
                "total": 0,
                "page": page,
                "page_size": page_size,
                "items": [],
            }

        db = get_db_session()
        try:
            query = db.query(NodeStatusRecord).filter(
                NodeStatusRecord.instance_id == instance_id,
                NodeStatusRecord.project_id == project_id,
                NodeStatusRecord.node_id.in_(normalized_node_ids),
            )

            if node_id:
                query = query.filter(NodeStatusRecord.node_id == node_id)

            total = query.count()
            records = query.order_by(
                NodeStatusRecord.created_at.desc(),
                NodeStatusRecord.id.desc(),
            ).offset((page - 1) * page_size).limit(page_size).all()

            return {
                "total": total,
                "page": page,
                "page_size": page_size,
                "items": [record.to_dict() for record in records],
            }
        finally:
            db.close()


    async def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Get a node record by task_id."""
        db = get_db_session()
        try:
            record = self._get_record_by_task_id(db, task_id)
            if not record:
                raise ValueError(f"Node status record not found: {task_id}")
            return record.to_dict()
        finally:
            db.close()


    async def get_task_stored_logs(self, task_id: str) -> Dict[str, Any]:
        """Get stored logs by task_id."""
        db = get_db_session()
        try:
            record = self._get_record_by_task_id(db, task_id)
            if not record:
                raise ValueError(f"Node status record not found: {task_id}")
            return {
                "task_id": task_id,
                "node_id": record.node_id,
                "init_logs": record.init_logs or "",
                "execution_logs": record.execution_logs or "",
                "log_updated_at": record.log_updated_at.isoformat() if record.log_updated_at else None,
            }
        finally:
            db.close()


    async def get_task_logs(
        self,
        task_id: str,
        project_id: str,
        tail_lines: int = 500,
        container: Optional[str] = None,
        previous: bool = False,
        persist: bool = True,
    ) -> Dict[str, Any]:
        """Fetch logs for the specific task record and optionally persist them."""
        db = get_db_session()
        try:
            record = self._get_record_by_task_id(db, task_id)
            if not record:
                raise ValueError(f"Node status record not found: {task_id}")

            pods = self._query_pods(project_id, record.node_type, record.k8s_resource_name)
            namespace = self.k8s_client.get_project_namespace(project_id)
            if not pods:
                return {
                    "task_id": task_id,
                    "node_id": record.node_id,
                    "resource_name": record.k8s_resource_name,
                    "namespace": namespace,
                    "logs": "",
                    "pod_name": None,
                    "container": container,
                    "message": "No pods found",
                }

            pod_name = pods[0].get("name") or pods[0].get("metadata", {}).get("name")
            if not pod_name:
                return {
                    "task_id": task_id,
                    "node_id": record.node_id,
                    "resource_name": record.k8s_resource_name,
                    "namespace": namespace,
                    "logs": "",
                    "pod_name": None,
                    "container": container,
                    "message": "Pod name not found",
                }

            logs = self.k8s_client.get_pod_logs(
                project_id=project_id,
                pod_name=pod_name,
                container=container,
                tail_lines=tail_lines,
                previous=previous,
            ) or ""

            if persist:
                log_field = "init_logs" if (record.node_type or "").lower() == "app" else "execution_logs"
                self._save_logs_to_record(
                    record=record,
                    log_field=log_field,
                    logs=logs,
                    pod_name=pod_name,
                    container=container,
                    tail_lines=tail_lines,
                    previous=previous,
                    status_when_fetched=record.status,
                )
                db.commit()
                db.refresh(record)

            return {
                "task_id": task_id,
                "node_id": record.node_id,
                "resource_name": record.k8s_resource_name,
                "namespace": namespace,
                "logs": logs,
                "pod_name": pod_name,
                "container": container,
            }
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()


    async def create_task_and_collect(
        self,
        node_id: str,
        instance_id: str,
        project_id: str,
        node_type: str,
        k8s_resource_name: str,
        k8s_resource_type: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        tail_lines: int = 500,
        container: Optional[str] = None,
        previous: bool = False,
        initial_status: str = "Pending",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a task-scoped record, sync status, then fetch and store logs."""
        record = await self.create_node_task_record(
            node_id=node_id,
            instance_id=instance_id,
            project_id=project_id,
            node_type=node_type,
            k8s_resource_name=k8s_resource_name,
            k8s_resource_type=k8s_resource_type,
            initial_status=initial_status,
            metadata=metadata,
        )
        task_id = record["task_id"]
        node = await self.sync_node_status(
            node_id=node_id,
            project_id=project_id,
            instance_id=instance_id,
            node_type=node_type,
            k8s_resource_name=k8s_resource_name,
            timeout_seconds=timeout_seconds,
            task_id=task_id,
        )
        logs = await self.get_task_logs(
            task_id=task_id,
            project_id=project_id,
            tail_lines=tail_lines,
            container=container,
            previous=previous,
            persist=True,
        )
        return {
            "task_id": task_id,
            "node": node,
            "logs": logs,
        }


    async def reset_node_status(
        self,
        node_id: str,
        reset_logs: bool = False
    ) -> Dict[str, Any]:
        """
        重置节点状态为Pending

        用于重新触发工作流时重置节点状态，使其可以重新执行

        Args:
            node_id: 节点ID
            reset_logs: 是否清空日志（默认False）

        Returns:
            重置后的状态记录
        """
        db = get_db_session()
        try:
            record = db.query(NodeStatusRecord).filter(
                NodeStatusRecord.node_id == node_id
            ).order_by(
                NodeStatusRecord.created_at.desc(),
                NodeStatusRecord.id.desc(),
            ).first()

            if not record:
                raise ValueError(f"Node status record not found: {node_id}")

            old_status = record.status

            # 记录状态变更历史
            history = NodeStatusHistory(
                node_id=node_id,
                instance_id=record.instance_id,
                project_id=record.project_id,
                from_status=old_status,
                to_status="Pending",
                reason="Reset for retrigger",
                operator="system"
            )
            db.add(history)

            # 重置状态
            record.status = "Pending"
            record.message = "Reset for retrigger"
            record.started_at = None
            record.finished_at = None
            record.duration_seconds = None

            # 可选：清空日志
            if reset_logs:
                record.init_logs = None
                record.execution_logs = None
                record.log_updated_at = None

            db.commit()
            db.refresh(record)

            logger.info(f"节点 {node_id} 状态已重置: {old_status} -> Pending")
            return record.to_dict()

        except Exception as e:
            logger.error(f"重置节点状态失败: {e}")
            db.rollback()
            raise
        finally:
            db.close()

    async def reset_job_nodes_for_instance(
        self,
        instance_id: str,
        project_id: str,
        reset_logs: bool = False
    ) -> Dict[str, Any]:
        """
        重置工作流中所有JOB节点状态为Pending

        用于重新触发工作流时，将所有JOB类型节点状态重置

        Args:
            instance_id: 工作流实例ID
            project_id: 项目ID
            reset_logs: 是否清空日志（默认False）

        Returns:
            重置结果，包含重置的节点列表
        """
        db = get_db_session()
        try:
            # 查询所有JOB类型节点
            records = db.query(NodeStatusRecord).filter(
                NodeStatusRecord.instance_id == instance_id,
                NodeStatusRecord.project_id == project_id,
                NodeStatusRecord.node_type == "job"
            ).all()

            reset_nodes = []
            for record in records:
                old_status = record.status

                # 只重置非Pending状态的节点
                if old_status == "Pending":
                    continue

                # 记录状态变更历史
                history = NodeStatusHistory(
                    node_id=record.node_id,
                    instance_id=instance_id,
                    project_id=project_id,
                    from_status=old_status,
                    to_status="Pending",
                    reason="Reset for retrigger",
                    operator="system"
                )
                db.add(history)

                # 重置状态
                record.status = "Pending"
                record.message = "Reset for retrigger"
                record.started_at = None
                record.finished_at = None
                record.duration_seconds = None

                # 可选：清空日志
                if reset_logs:
                    record.execution_logs = None
                    record.log_updated_at = None

                reset_nodes.append({
                    "node_id": record.node_id,
                    "old_status": old_status,
                    "new_status": "Pending"
                })

                logger.info(f"节点 {record.node_id} 状态已重置: {old_status} -> Pending")

            # 同时重置工作流状态记录
            workflow_record = db.query(WorkflowStatusRecord).filter(
                WorkflowStatusRecord.instance_id == instance_id
            ).first()

            if workflow_record:
                workflow_record.status = "Pending"
                workflow_record.message = "Workflow reset for retrigger"
                workflow_record.finished_at = None
                # 更新节点统计
                workflow_record.running_nodes = 0
                workflow_record.succeeded_nodes = 0
                workflow_record.failed_nodes = 0
                workflow_record.pending_nodes = len(reset_nodes)

            db.commit()

            return {
                "instance_id": instance_id,
                "project_id": project_id,
                "reset_count": len(reset_nodes),
                "reset_nodes": reset_nodes
            }

        except Exception as e:
            logger.error(f"重置工作流JOB节点状态失败: {e}")
            db.rollback()
            raise
        finally:
            db.close()

    async def get_nodes_by_instance(
        self,
        instance_id: str,
        project_id: str
    ) -> List[Dict[str, Any]]:
        """
        获取工作流实例下所有节点状态记录

        Args:
            instance_id: 工作流实例ID
            project_id: 项目ID

        Returns:
            节点状态记录列表
        """
        db = get_db_session()
        try:
            records = db.query(NodeStatusRecord).filter(
                NodeStatusRecord.instance_id == instance_id,
                NodeStatusRecord.project_id == project_id
            ).all()

            return [record.to_dict() for record in records]

        finally:
            db.close()


# 单例实例
_status_sync_service: Optional[StatusSyncService] = None


def get_status_sync_service() -> StatusSyncService:
    """获取状态同步服务实例"""
    global _status_sync_service
    if _status_sync_service is None:
        _status_sync_service = StatusSyncService()
    return _status_sync_service
