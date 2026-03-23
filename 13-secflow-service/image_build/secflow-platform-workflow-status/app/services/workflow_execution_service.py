"""
Workflow trigger execution orchestration.

This service is responsible for re-triggering one workflow instance by:
- validating the DAG and instance mode
- executing nodes level-by-level with parallel branches
- generating unique K8S resource names for jobs
- polling node status until terminal states
- persisting task-scoped execution records and logs
"""

import asyncio
import logging
import uuid
from collections import deque
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from app.config import get_config
from app.services.k8s_client import get_k8s_client
from app.services.node_lifecycle_service import get_node_lifecycle_service
from app.services.status_sync_service import get_status_sync_service

logger = logging.getLogger(__name__)


SUCCESS_STATUSES = {"Ready", "Succeeded"}
FAILED_STATUSES = {"Failed", "Stopped"}
TERMINAL_STATUSES = SUCCESS_STATUSES | FAILED_STATUSES


class WorkflowExecutionService:
    """Trigger execution orchestration for workflow instances."""

    def __init__(
        self,
        *,
        node_lifecycle_service=None,
        status_sync_service=None,
        k8s_client=None,
        config=None,
    ) -> None:
        self.node_lifecycle_service = node_lifecycle_service or get_node_lifecycle_service()
        self.status_sync_service = status_sync_service or get_status_sync_service()
        self.k8s_client = k8s_client or get_k8s_client()
        self.config = config or get_config()
        self.poll_interval = max(1, int(getattr(self.config.status_sync, "retry_interval", 2)))
        self.max_retry_count = max(1, int(getattr(self.config.status_sync, "retry_count", 3)))
        self._running_instances: Set[str] = set()
        self._running_lock = asyncio.Lock()

    def is_instance_running(self, instance_id: str) -> bool:
        """Return whether one workflow instance is currently being executed."""
        return instance_id in self._running_instances

    def validate_execution_plan(
        self,
        *,
        run_mode: str,
        nodes: List[Dict[str, Any]],
        edges: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Validate workflow trigger request and compute topological levels."""
        if not nodes:
            raise ValueError("Workflow trigger requires at least one node")

        normalized_nodes: Dict[str, Dict[str, Any]] = {}
        dependency_graph: Dict[str, List[str]] = {}
        reverse_graph: Dict[str, List[str]] = {}

        for raw_node in nodes:
            node_id = raw_node.get("node_id")
            if not node_id:
                raise ValueError("Node payload is missing node_id")
            if node_id in normalized_nodes:
                raise ValueError(f"Duplicate node_id detected: {node_id}")

            normalized_node = dict(raw_node)
            normalized_node["node_type"] = str(raw_node.get("node_type", "")).lower()
            normalized_node["depends_on"] = list(dict.fromkeys(raw_node.get("depends_on") or []))
            normalized_nodes[node_id] = normalized_node
            dependency_graph[node_id] = []
            reverse_graph[node_id] = []

        for node_id, node in normalized_nodes.items():
            for upstream_id in node.get("depends_on") or []:
                if upstream_id not in normalized_nodes:
                    raise ValueError(f"Node {node_id} depends on missing node {upstream_id}")
                if upstream_id not in dependency_graph[node_id]:
                    dependency_graph[node_id].append(upstream_id)
                    reverse_graph[upstream_id].append(node_id)

        for edge in edges or []:
            source = edge.get("source")
            target = edge.get("target")
            if not source or not target:
                raise ValueError("Workflow edge must include source and target")
            if source not in normalized_nodes:
                raise ValueError(f"Workflow edge source does not exist: {source}")
            if target not in normalized_nodes:
                raise ValueError(f"Workflow edge target does not exist: {target}")
            if source not in dependency_graph[target]:
                dependency_graph[target].append(source)
                reverse_graph[source].append(target)

        in_degree = {node_id: len(deps) for node_id, deps in dependency_graph.items()}
        queue = deque([node_id for node_id, degree in in_degree.items() if degree == 0])
        levels: List[List[str]] = []
        visited_count = 0

        while queue:
            current_level: List[str] = []
            next_queue: deque[str] = deque()
            while queue:
                node_id = queue.popleft()
                current_level.append(node_id)
                visited_count += 1
                for downstream_id in reverse_graph[node_id]:
                    in_degree[downstream_id] -= 1
                    if in_degree[downstream_id] == 0:
                        next_queue.append(downstream_id)
            levels.append(current_level)
            queue = next_queue

        if visited_count != len(normalized_nodes):
            raise ValueError("Workflow graph contains a cycle and cannot be triggered")

        head_nodes = levels[0] if levels else []
        run_mode_value = (run_mode or "").lower()
        if run_mode_value == "persistent":
            invalid_heads = [
                node_id for node_id in head_nodes
                if normalized_nodes[node_id].get("node_type") != "app"
            ]
            if invalid_heads:
                raise ValueError("Persistent workflow head nodes must all be APP nodes")
        elif run_mode_value == "once":
            invalid_nodes = [
                node_id for node_id, node in normalized_nodes.items()
                if node.get("node_type") != "job"
            ]
            if invalid_nodes:
                raise ValueError("Once workflow instances can only contain JOB nodes")

        return {
            "nodes": normalized_nodes,
            "dependency_graph": dependency_graph,
            "reverse_graph": reverse_graph,
            "levels": levels,
        }

    def generate_unique_resource_name(
        self,
        *,
        project_id: str,
        instance_id: str,
        node_id: str,
        resource_type: str,
    ) -> str:
        """Generate a unique K8S resource name and verify it does not already exist."""
        existing_names = self._list_resource_names(project_id, resource_type)
        base = f"wf-{instance_id[:8]}-{node_id[:8]}".lower()
        base = "".join(ch if ch.isalnum() or ch == "-" else "-" for ch in base).strip("-") or "wf"
        base = base[:40].rstrip("-")

        for _ in range(20):
            timestamp = datetime.utcnow().strftime("%H%M%S")
            suffix = uuid.uuid4().hex[:4]
            candidate = f"{base}-{timestamp}-{suffix}"[:63].rstrip("-")
            if candidate not in existing_names:
                return candidate

        raise RuntimeError(f"Unable to generate unique {resource_type} name for node {node_id}")

    def _list_resource_names(self, project_id: str, resource_type: str) -> Set[str]:
        resource_type_value = (resource_type or "").lower()
        if resource_type_value == "job":
            items = self.k8s_client.list_jobs(project_id)
        elif resource_type_value in {"deployment", "app"}:
            items = self.k8s_client.list_deployments(project_id)
        elif resource_type_value == "service":
            items = self.k8s_client.list_services(project_id)
        else:
            items = []
        names = set()
        for item in items or []:
            name = item.get("name") or item.get("metadata", {}).get("name")
            if name:
                names.add(name)
        return names

    async def execute_trigger(
        self,
        *,
        instance_id: str,
        project_id: str,
        run_mode: str,
        nodes: List[Dict[str, Any]],
        edges: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Execute a workflow trigger in background-safe orchestration."""
        async with self._running_lock:
            if instance_id in self._running_instances:
                raise ValueError(f"Workflow instance {instance_id} is already executing")
            self._running_instances.add(instance_id)

        plan = self.validate_execution_plan(run_mode=run_mode, nodes=nodes, edges=edges)
        try:
            execution_results: Dict[str, Dict[str, Any]] = {}
            final_message = "Workflow trigger completed successfully"

            for level in plan["levels"]:
                logger.info(
                    "[WorkflowTrigger] Executing level for instance=%s nodes=%s",
                    instance_id,
                    level,
                )
                level_results = await asyncio.gather(
                    *[
                        self._execute_node_with_retries(
                            instance_id=instance_id,
                            project_id=project_id,
                            node=plan["nodes"][node_id],
                        )
                        for node_id in level
                    ],
                    return_exceptions=True,
                )

                level_failed = False
                for node_id, node_result in zip(level, level_results):
                    if isinstance(node_result, Exception):
                        level_failed = True
                        execution_results[node_id] = {
                            "success": False,
                            "status": "Failed",
                            "error": str(node_result),
                        }
                        logger.error(
                            "[ALERT][WorkflowTrigger] Node execution crashed: instance=%s node=%s error=%s",
                            instance_id,
                            node_id,
                            node_result,
                        )
                        continue

                    execution_results[node_id] = node_result
                    if not node_result.get("success"):
                        level_failed = True

                if level_failed:
                    failed_nodes = [
                        node_id for node_id in level
                        if not execution_results.get(node_id, {}).get("success")
                    ]
                    final_message = f"Workflow trigger failed on nodes: {', '.join(failed_nodes)}"
                    break

            success = all(result.get("success") for result in execution_results.values()) and (
                len(execution_results) == len(plan["nodes"])
            )
            return {
                "success": success,
                "instance_id": instance_id,
                "project_id": project_id,
                "message": final_message if not success else "Workflow trigger finished",
                "results": execution_results,
            }
        finally:
            async with self._running_lock:
                self._running_instances.discard(instance_id)

    async def _execute_node_with_retries(
        self,
        *,
        instance_id: str,
        project_id: str,
        node: Dict[str, Any],
    ) -> Dict[str, Any]:
        node_id = node["node_id"]
        node_name = node.get("node_name") or node_id
        node_type = (node.get("node_type") or "").lower()
        timeout_seconds = node.get("timeout_seconds")

        last_result: Dict[str, Any] = {
            "success": False,
            "status": "Failed",
            "error": "Node was not executed",
        }

        for attempt in range(1, self.max_retry_count + 1):
            resource_name = node.get("k8s_resource_name")
            if node_type == "job":
                resource_name = self.generate_unique_resource_name(
                    project_id=project_id,
                    instance_id=instance_id,
                    node_id=node_id,
                    resource_type="job",
                )

            metadata = {
                "attempt": attempt,
                "node_name": node_name,
                "resource_name": resource_name,
                "run_mode": node.get("run_mode"),
            }
            task_record = await self.status_sync_service.create_node_task_record(
                node_id=node_id,
                instance_id=instance_id,
                project_id=project_id,
                node_type=node_type,
                k8s_resource_name=resource_name,
                k8s_resource_type="Deployment" if node_type == "app" else "Job",
                initial_status="Pending",
                metadata=metadata,
            )
            task_id = task_record["task_id"]

            try:
                if node_type == "app":
                    start_result = await self.node_lifecycle_service.start_node(
                        node_id=node_id,
                        instance_id=instance_id,
                        project_id=project_id,
                        node_type="app",
                        k8s_resource_name=resource_name,
                    )
                elif node_type == "job":
                    start_result = await self.node_lifecycle_service.start_node(
                        node_id=node_id,
                        instance_id=instance_id,
                        project_id=project_id,
                        node_type="job",
                        k8s_resource_name=resource_name,
                        job_config=node.get("job_config"),
                    )
                else:
                    raise ValueError(f"Unsupported node type: {node_type}")

                if not start_result.success:
                    raise RuntimeError(start_result.error or start_result.message or "Node start failed")

                last_result = await self._wait_for_terminal_status(
                    node=node,
                    project_id=project_id,
                    instance_id=instance_id,
                    resource_name=resource_name,
                    task_id=task_id,
                    timeout_seconds=timeout_seconds,
                )

                if last_result.get("success"):
                    return {
                        **last_result,
                        "task_id": task_id,
                        "k8s_resource_name": resource_name,
                    }
            except Exception as exc:
                last_result = {
                    "success": False,
                    "status": "Failed",
                    "error": str(exc),
                    "task_id": task_id,
                    "k8s_resource_name": resource_name,
                }
                await self.status_sync_service.update_node_status(
                    node_id=node_id,
                    status="Failed",
                    message=str(exc),
                    task_id=task_id,
                )
                logger.error(
                    "[ALERT][WorkflowTrigger] Node execution failed: instance=%s node=%s attempt=%s error=%s",
                    instance_id,
                    node_id,
                    attempt,
                    exc,
                )
            finally:
                await self._persist_runtime_logs(
                    task_id=task_id,
                    project_id=project_id,
                    node_type=node_type,
                )

            if attempt < self.max_retry_count:
                logger.warning(
                    "[WorkflowTrigger] Retrying node execution: instance=%s node=%s attempt=%s/%s",
                    instance_id,
                    node_id,
                    attempt + 1,
                    self.max_retry_count,
                )
                await asyncio.sleep(self.poll_interval)

        return last_result

    async def _wait_for_terminal_status(
        self,
        *,
        node: Dict[str, Any],
        project_id: str,
        instance_id: str,
        resource_name: str,
        task_id: str,
        timeout_seconds: Optional[int],
    ) -> Dict[str, Any]:
        node_id = node["node_id"]
        node_type = (node.get("node_type") or "").lower()
        started_at = datetime.utcnow()

        while True:
            result = await self.status_sync_service.sync_node_status(
                node_id=node_id,
                project_id=project_id,
                instance_id=instance_id,
                node_type=node_type,
                k8s_resource_name=resource_name,
                timeout_seconds=timeout_seconds,
                task_id=task_id,
            )
            status_value = result.get("status", "Pending")
            if status_value in SUCCESS_STATUSES:
                return {
                    "success": True,
                    "status": status_value,
                    "message": result.get("message"),
                    "started_at": result.get("started_at"),
                    "finished_at": result.get("finished_at"),
                }
            if status_value in FAILED_STATUSES:
                return {
                    "success": False,
                    "status": status_value,
                    "error": result.get("message") or f"Node {node_id} failed",
                    "started_at": result.get("started_at"),
                    "finished_at": result.get("finished_at"),
                }
            if timeout_seconds and (datetime.utcnow() - started_at).total_seconds() > timeout_seconds:
                timeout_message = f"Node execution timed out after {timeout_seconds}s"
                await self.status_sync_service.update_node_status(
                    node_id=node_id,
                    status="Failed",
                    message=timeout_message,
                    task_id=task_id,
                )
                return {
                    "success": False,
                    "status": "Failed",
                    "error": timeout_message,
                }
            await asyncio.sleep(self.poll_interval)

    async def _persist_runtime_logs(
        self,
        *,
        task_id: str,
        project_id: str,
        node_type: str,
    ) -> None:
        try:
            await self.status_sync_service.get_task_logs(
                task_id=task_id,
                project_id=project_id,
                tail_lines=500,
                persist=True,
                log_field_override="execution_logs",
            )
        except Exception as exc:
            logger.debug(
                "[WorkflowTrigger] Skip runtime log persistence: task_id=%s error=%s",
                task_id,
                exc,
            )


_workflow_execution_service: Optional[WorkflowExecutionService] = None


def get_workflow_execution_service() -> WorkflowExecutionService:
    """Return the singleton workflow execution orchestration service."""
    global _workflow_execution_service
    if _workflow_execution_service is None:
        _workflow_execution_service = WorkflowExecutionService()
    return _workflow_execution_service
