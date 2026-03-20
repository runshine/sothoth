"""
工作流状态聚合服务
负责根据节点状态计算工作流整体状态
"""

import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any

from sqlalchemy.orm import Session

from app.models.database import (
    NodeStatusRecord,
    WorkflowStatusRecord,
    get_db_session,
)

logger = logging.getLogger(__name__)


class WorkflowStatusAggregator:
    """工作流状态聚合服务"""

    async def aggregate_workflow_status(
        self,
        instance_id: str,
        project_id: str
    ) -> Dict[str, Any]:
        """
        聚合工作流状态

        根据所有节点状态计算工作流整体状态

        Args:
            instance_id: 工作流实例ID
            project_id: 项目ID

        Returns:
            工作流状态信息
        """
        db = get_db_session()
        try:
            # 获取所有节点状态
            node_records = db.query(NodeStatusRecord).filter(
                NodeStatusRecord.instance_id == instance_id,
                NodeStatusRecord.project_id == project_id
            ).all()

            if not node_records:
                return {"status": "Pending", "message": "No nodes found"}

            # 转换为字典列表
            nodes = [record.to_dict() for record in node_records]

            # 计算状态
            result = self._calculate_workflow_status(nodes)

            # 更新工作流状态记录
            self._update_workflow_record(db, instance_id, project_id, result, nodes)

            return result

        finally:
            db.close()

    def _calculate_workflow_status(self, nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        计算工作流状态

        工作流状态判断逻辑（优先级从高到低）:
        1. Failed: 有任何节点失败
        2. Running: 有节点正在执行中（JOB的Running 或 APP的Not_ready）
        3. Succeeded: 全部节点完成（Ready 或 Succeeded）
        4. Stopped: 有节点被停止
        5. Pending: 其他情况
        """
        # 统计各状态节点数量
        status_counts = {
            "Pending": 0,
            "Not_ready": 0,
            "Ready": 0,
            "Running": 0,
            "Succeeded": 0,
            "Failed": 0,
            "Stopped": 0
        }

        for node in nodes:
            status = node.get("status", "Pending")
            if status in status_counts:
                status_counts[status] += 1

        total = len(nodes)

        # 计算正在执行的节点（JOB的Running + APP的Not_ready）
        executing_count = status_counts["Running"] + status_counts["Not_ready"]

        # 确定工作流状态
        if status_counts["Failed"] > 0:
            return {
                "status": "Failed",
                "message": f"Workflow failed: {status_counts['Failed']} node(s) failed",
                "finished_at": datetime.utcnow().isoformat(),
                "node_counts": status_counts
            }

        if executing_count > 0:
            return {
                "status": "Running",
                "message": f"Workflow running: {executing_count} node(s) executing",
                "node_counts": status_counts
            }

        # 全部节点完成
        completed = status_counts["Ready"] + status_counts["Succeeded"]
        if completed == total:
            return {
                "status": "Succeeded",
                "message": "All nodes completed successfully",
                "finished_at": datetime.utcnow().isoformat(),
                "node_counts": status_counts
            }

        # 有节点被停止
        if status_counts["Stopped"] > 0:
            return {
                "status": "Stopped",
                "message": "Workflow stopped",
                "finished_at": datetime.utcnow().isoformat(),
                "node_counts": status_counts
            }

        # 默认等待状态
        return {
            "status": "Pending",
            "message": "Workflow waiting for nodes to start",
            "node_counts": status_counts
        }

    def _update_workflow_record(
        self,
        db: Session,
        instance_id: str,
        project_id: str,
        status_result: Dict[str, Any],
        nodes: List[Dict[str, Any]]
    ):
        """更新工作流状态记录"""
        # 查找现有记录
        record = db.query(WorkflowStatusRecord).filter(
            WorkflowStatusRecord.instance_id == instance_id
        ).first()

        status_counts = status_result.get("node_counts", {})
        total = len(nodes)

        if record:
            # 更新现有记录
            old_status = record.status
            record.status = status_result["status"]
            record.message = status_result["message"]
            record.total_nodes = total
            record.pending_nodes = status_counts.get("Pending", 0)
            record.not_ready_nodes = status_counts.get("Not_ready", 0)
            record.ready_nodes = status_counts.get("Ready", 0)
            record.running_nodes = status_counts.get("Running", 0)
            record.succeeded_nodes = status_counts.get("Succeeded", 0)
            record.failed_nodes = status_counts.get("Failed", 0)
            record.stopped_nodes = status_counts.get("Stopped", 0)

            if status_result.get("finished_at"):
                record.finished_at = datetime.utcnow()

            db.commit()
            logger.info(f"工作流状态更新: {instance_id} {old_status} -> {record.status}")

        else:
            # 创建新记录
            record = WorkflowStatusRecord(
                id=str(uuid.uuid4()),
                instance_id=instance_id,
                project_id=project_id,
                status=status_result["status"],
                message=status_result["message"],
                total_nodes=total,
                pending_nodes=status_counts.get("Pending", 0),
                not_ready_nodes=status_counts.get("Not_ready", 0),
                ready_nodes=status_counts.get("Ready", 0),
                running_nodes=status_counts.get("Running", 0),
                succeeded_nodes=status_counts.get("Succeeded", 0),
                failed_nodes=status_counts.get("Failed", 0),
                stopped_nodes=status_counts.get("Stopped", 0)
            )
            db.add(record)
            db.commit()
            logger.info(f"工作流状态记录创建: {instance_id} {record.status}")

    async def get_workflow_status(
        self,
        instance_id: str,
        project_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        获取工作流状态

        Args:
            instance_id: 工作流实例ID
            project_id: 项目ID

        Returns:
            工作流状态信息，如果不存在返回None
        """
        db = get_db_session()
        try:
            record = db.query(WorkflowStatusRecord).filter(
                WorkflowStatusRecord.instance_id == instance_id
            ).first()

            if not record:
                return None

            return record.to_dict()

        finally:
            db.close()

    async def get_workflow_nodes(
        self,
        instance_id: str,
        project_id: str
    ) -> List[Dict[str, Any]]:
        """
        获取工作流所有节点状态

        Args:
            instance_id: 工作流实例ID
            project_id: 项目ID

        Returns:
            节点状态列表
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

    async def get_statistics(
        self,
        project_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        获取状态统计

        Args:
            project_id: 项目ID
            start_time: 统计开始时间
            end_time: 统计结束时间

        Returns:
            统计信息
        """
        db = get_db_session()
        try:
            # 工作流统计
            workflow_query = db.query(WorkflowStatusRecord).filter(
                WorkflowStatusRecord.project_id == project_id
            )
            if start_time:
                workflow_query = workflow_query.filter(
                    WorkflowStatusRecord.created_at >= start_time
                )
            if end_time:
                workflow_query = workflow_query.filter(
                    WorkflowStatusRecord.created_at <= end_time
                )

            workflow_records = workflow_query.all()
            workflow_stats = self._calculate_statistics(workflow_records)

            # 节点统计
            node_query = db.query(NodeStatusRecord).filter(
                NodeStatusRecord.project_id == project_id
            )
            if start_time:
                node_query = node_query.filter(
                    NodeStatusRecord.created_at >= start_time
                )
            if end_time:
                node_query = node_query.filter(
                    NodeStatusRecord.created_at <= end_time
                )

            node_records = node_query.all()
            node_stats = self._calculate_statistics(node_records)

            return {
                "project_id": project_id,
                "workflows": workflow_stats,
                "nodes": node_stats,
                "period_start": start_time.isoformat() if start_time else None,
                "period_end": end_time.isoformat() if end_time else None
            }

        finally:
            db.close()

    def _calculate_statistics(self, records: List) -> Dict[str, int]:
        """计算统计信息"""
        stats = {
            "total": len(records),
            "Pending": 0,
            "Running": 0,
            "Not_ready": 0,
            "Ready": 0,
            "Succeeded": 0,
            "Failed": 0,
            "Stopped": 0
        }

        for record in records:
            status = record.status
            if status in stats:
                stats[status] += 1

        return stats


# 单例实例
_workflow_aggregator: Optional[WorkflowStatusAggregator] = None


def get_workflow_aggregator() -> WorkflowStatusAggregator:
    """获取工作流状态聚合服务实例"""
    global _workflow_aggregator
    if _workflow_aggregator is None:
        _workflow_aggregator = WorkflowStatusAggregator()
    return _workflow_aggregator
