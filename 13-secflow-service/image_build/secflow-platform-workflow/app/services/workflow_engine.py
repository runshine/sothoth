"""
Workflow execution engine for SecFlow
Handles dependency management, topological execution, and node lifecycle
"""

import asyncio
import logging
from collections import deque
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Tuple

from sqlalchemy.orm import Session

from app.models.database import (
    WorkflowInstance, WorkflowNodeInstance,
    WorkflowStatus, NodeStatus, NodeType,
    AppTemplate, JobTemplate
)
from app.services.workflow_status_client import get_workflow_status_client

logger = logging.getLogger(__name__)


class WorkflowEngine:
    """
    Workflow execution engine with topological sorting and concurrent execution
    """

    # Node status that indicate completion
    # READY (APP) and SUCCEEDED (JOB) are considered completed
    COMPLETED_STATUSES = {NodeStatus.READY, NodeStatus.SUCCEEDED, NodeStatus.STOPPED}
    FAILED_STATUSES = {NodeStatus.FAILED}

    def __init__(self, instance_id: str, db: Session, k8s_client=None):
        self.instance_id = instance_id
        self.db = db
        # K8S operations are migrated to workflow-status service; keep parameter for compatibility.
        self.k8s_client = k8s_client
        # 鍒濆鍖栫姸鎬佹湇鍔″鎴风
        self.status_client = get_workflow_status_client()
        self._monitoring_started = False
        self.instance: Optional[WorkflowInstance] = None
        self.nodes: List[WorkflowNodeInstance] = []
        self.node_map: Dict[str, WorkflowNodeInstance] = {}
        self.dependency_graph: Dict[str, List[str]] = {}  # node_id -> [dependency_node_ids]
        self.reverse_graph: Dict[str, List[str]] = {}  # node_id -> [downstream_node_ids]

    async def initialize(self):
        """Initialize the engine by loading instance and node"""
        self.instance = self.db.query(WorkflowInstance).filter(
            WorkflowInstance.id == self.instance_id
        ).first()

        if not self.instance:
            raise ValueError(f"Workflow instance {self.instance_id} not found")

        self.nodes = self.db.query(WorkflowNodeInstance).filter(
            WorkflowNodeInstance.instance_id == self.instance_id
        ).all()

        self.node_map = {node.node_id: node for node in self.nodes}
        self._build_dependency_graph()

        logger.info(f"WorkflowEngine initialized for instance {self.instance_id} "
                    f"with {len(self.nodes)} node")

    def _build_dependency_graph(self):
        """
        Build dependency graph from edges and depends_on configuration
        edges define source -> target (target depends on source)
        depends_on explicitly defines dependencies
        """
        # Initialize empty graphs
        for node in self.nodes:
            self.dependency_graph[node.node_id] = []
            self.reverse_graph[node.node_id] = []

        # Build from workflow template edges
        edges = self.instance.edges or []
        for edge in edges:
            source = edge.get("source")
            target = edge.get("target")
            if source and target and source in self.node_map and target in self.node_map:
                self.dependency_graph[target].append(source)
                self.reverse_graph[source].append(target)

        # Build from node-level depends_on configuration
        for node in self.nodes:
            depends_on = node.depends_on or []
            for dep_node_id in depends_on:
                if dep_node_id in self.node_map and dep_node_id not in self.dependency_graph[node.node_id]:
                    self.dependency_graph[node.node_id].append(dep_node_id)
                    self.reverse_graph[dep_node_id].append(node.node_id)

        logger.debug(f"Dependency graph built: {self.dependency_graph}")

    def detect_cycle(self) -> Optional[List[str]]:
        """
        Detect cycle in the dependency graph using DFS
        Returns the cycle path if found, None otherwise
        """
        WHITE, GRAY, BLACK = 0, 1, 2
        color = {node_id: WHITE for node_id in self.node_map}
        parent = {}

        def dfs(node_id: str, path: List[str]) -> Optional[List[str]]:
            color[node_id] = GRAY
            path.append(node_id)

            for neighbor in self.dependency_graph.get(node_id, []):
                if color[neighbor] == GRAY:
                    # Found a cycle
                    cycle_start = path.index(neighbor)
                    return path[cycle_start:] + [neighbor]

                if color[neighbor] == WHITE:
                    parent[neighbor] = node_id
                    result = dfs(neighbor, path)
                    if result:
                        return result

            path.pop()
            color[node_id] = BLACK
            return None

        for node_id in self.node_map:
            if color[node_id] == WHITE:
                cycle = dfs(node_id, [])
                if cycle:
                    return cycle

        return None

    def get_in_degree(self) -> Dict[str, int]:
        """Get in-degree (number of dependencies) for each node"""
        return {node_id: len(deps) for node_id, deps in self.dependency_graph.items()}

    def get_ready_nodes(self) -> List[WorkflowNodeInstance]:
        """
        Get nodes that are ready to execute (dependencies satisfied)
        """
        ready = []
        for node in self.nodes:
            if node.status != NodeStatus.PENDING:
                continue

            # Check if all dependencies are completed
            deps = self.dependency_graph.get(node.node_id, [])
            all_deps_completed = all(
                self.node_map[dep_id].status in self.COMPLETED_STATUSES
                for dep_id in deps
            )

            if all_deps_completed:
                ready.append(node)

        return ready

    def check_node_dependencies_complete(self, node: WorkflowNodeInstance) -> bool:
        """
        Check if a node's dependencies are all completed
        For APP: status must be READY
        For JOB: status must be SUCCEEDED
        """
        deps = self.dependency_graph.get(node.node_id, [])

        for dep_id in deps:
            dep_node = self.node_map.get(dep_id)
            if not dep_node:
                return False

            if dep_node.node_type == NodeType.JOB:
                # Job must be succeeded
                if dep_node.status != NodeStatus.SUCCEEDED:
                    return False
            else:
                # APP must be ready (Pod鍏ㄩ儴灏辩华)
                if dep_node.status != NodeStatus.READY:
                    return False

        return True

    async def sync_node_status_from_k8s(self, node: WorkflowNodeInstance):
        """
        Sync node status via workflow-status service and persist to local DB cache.
        """
        if not node.k8s_resource_name:
            return

        try:
            result = await self.status_client.sync_node_status(
                node_id=node.node_id,
                project_id=self.instance.project_id,
                instance_id=self.instance_id,
                node_type=node.node_type.value if hasattr(node.node_type, "value") else str(node.node_type),
                k8s_resource_name=node.k8s_resource_name,
                timeout_seconds=node.timeout_seconds,
            )

            if not result or not result.get("status"):
                return

            status_mapping = {
                "Pending": NodeStatus.PENDING,
                "Not_ready": NodeStatus.NOT_READY,
                "Ready": NodeStatus.READY,
                "Running": NodeStatus.RUNNING,
                "Succeeded": NodeStatus.SUCCEEDED,
                "Failed": NodeStatus.FAILED,
                "Stopped": NodeStatus.STOPPED,
            }
            mapped_status = status_mapping.get(result.get("status"))
            if mapped_status and node.status != NodeStatus.STOPPED:
                node.status = mapped_status
                node.message = result.get("message", "")
                if result.get("started_at"):
                    try:
                        node.started_at = datetime.fromisoformat(result["started_at"].replace("Z", "+00:00"))
                    except Exception:
                        pass
                if result.get("finished_at"):
                    try:
                        node.finished_at = datetime.fromisoformat(result["finished_at"].replace("Z", "+00:00"))
                    except Exception:
                        pass
                self.db.commit()

        except Exception as e:
            logger.error(f"Error syncing node {node.node_id} status via workflow-status: {e}")

    # ============ Sync status via workflow-status service ===========

    async def _record_nodes_to_status_service(self):
        """Record the initial status of all nodes to the workflow-status service."""
        for node in self.nodes:
            try:
                await self.status_client.record_node(
                    node_id=node.node_id,
                    instance_id=self.instance_id,
                    project_id=self.instance.project_id,
                    node_type="app" if node.node_type == NodeType.APP else "job",
                    k8s_resource_name=node.k8s_resource_name,
                    k8s_resource_type="Deployment" if node.node_type == NodeType.APP else "Job",
                    initial_status="Pending"
                )
                logger.debug(f"Node {node.node_id} recorded to workflow-status service")
            except Exception as e:
                logger.warning(f"Failed to record node {node.node_id} to workflow-status service: {e}")

    async def sync_node_status_from_service(self, node: WorkflowNodeInstance):
        """
        Sync node status via the workflow-status service.

        Unlike sync_node_status_from_k8s, this method delegates the status
        query to the workflow-status service, which can pull from K8S and
        persist the synchronized result in its own status database.
        """
        if not node.k8s_resource_name:
            return

        try:
            # 璋冪敤鐘舵€佹湇鍔″悓姝ョ姸鎬?
            result = await self.status_client.sync_node_status(
                node_id=node.node_id,
                project_id=self.instance.project_id,
                instance_id=self.instance_id,
                node_type="app" if node.node_type == NodeType.APP else "job",
                k8s_resource_name=node.k8s_resource_name,
                timeout_seconds=node.timeout_seconds
            )

            # 鏇存柊鏈湴鏁版嵁搴撶紦瀛橈紙鐢ㄤ簬宸ヤ綔娴佹墽琛岄€昏緫锛?
            if result:
                # 鐘舵€佹湇鍔¤繑鍥炵殑鐘舵€佹牸寮忓彲鑳戒笉鍚岋紝闇€瑕佽浆鎹?
                status = result.get("status", "Pending")
                # 杞崲鐘舵€佹牸寮忥紙棣栧瓧姣嶅ぇ鍐欒浆灏忓啓锛?
                status_lower = status.lower() if status else "pending"

                # 鏄犲皠鐘舵€?
                status_map = {
                    "pending": NodeStatus.PENDING,
                    "not_ready": NodeStatus.NOT_READY,
                    "ready": NodeStatus.READY,
                    "running": NodeStatus.RUNNING,
                    "succeeded": NodeStatus.SUCCEEDED,
                    "failed": NodeStatus.FAILED,
                }
                node.status = status_map.get(status_lower, node.status)
                node.message = result.get("message")

                # 澶勭悊鏃堕棿瀛楁
                if result.get("started_at"):
                    try:
                        started_at_str = result["started_at"]
                        if isinstance(started_at_str, str):
                            node.started_at = datetime.fromisoformat(started_at_str.replace("Z", "+00:00"))
                    except Exception:
                        pass

                if result.get("finished_at"):
                    try:
                        finished_at_str = result["finished_at"]
                        if isinstance(finished_at_str, str):
                            node.finished_at = datetime.fromisoformat(finished_at_str.replace("Z", "+00:00"))
                    except Exception:
                        pass

                self.db.commit()
                logger.debug(f"閫氳繃鐘舵€佹湇鍔″悓姝ヨ妭鐐?{node.node_id} 鐘舵€? {status}")

        except Exception as e:
            logger.error(f"閫氳繃鐘舵€佹湇鍔″悓姝ヨ妭鐐?{node.node_id} 鐘舵€佸け璐? {e}")

    async def sync_all_nodes_status_from_service(self):
        """
        閫氳繃 workflow-status 寰湇鍔℃壒閲忓悓姝ユ墍鏈夎妭鐐圭姸鎬?

        浼樺厛浣跨敤鎵归噺鍚屾鎺ュ彛锛屽け璐ユ椂闄嶇骇涓洪€愪釜鍚屾
        """
        # 鏋勫缓鑺傜偣淇℃伅鍒楄〃
        nodes_info = [
            {
                "node_id": node.node_id,
                "node_type": "app" if node.node_type == NodeType.APP else "job",
                "k8s_resource_name": node.k8s_resource_name,
                "timeout_seconds": node.timeout_seconds
            }
            for node in self.nodes
        ]

        try:
            # 璋冪敤鐘舵€佹湇鍔℃壒閲忓悓姝?
            result = await self.status_client.sync_all_nodes(
                instance_id=self.instance_id,
                project_id=self.instance.project_id,
                nodes=nodes_info
            )

            # 鏇存柊鏈湴鏁版嵁搴撶紦瀛?
            if result and result.get("nodes"):
                for node_result in result["nodes"]:
                    node = self.node_map.get(node_result.get("node_id"))
                    if node:
                        status = node_result.get("status", "Pending")
                        status_lower = status.lower() if status else "pending"

                        status_map = {
                            "pending": NodeStatus.PENDING,
                            "not_ready": NodeStatus.NOT_READY,
                            "ready": NodeStatus.READY,
                            "running": NodeStatus.RUNNING,
                            "succeeded": NodeStatus.SUCCEEDED,
                            "failed": NodeStatus.FAILED,
                        }
                        node.status = status_map.get(status_lower, node.status)
                        node.message = node_result.get("message")

            # 鏇存柊宸ヤ綔娴佺姸鎬?
            workflow_status = result.get("workflow_status", {})
            if workflow_status:
                self._update_local_workflow_status(workflow_status)
            else:
                self._update_workflow_status()

            logger.info(f"Synced status for {len(nodes_info)} nodes via workflow-status service")

        except Exception as e:
            logger.error(f"鎵归噺鍚屾鑺傜偣鐘舵€佸け璐? {e}锛岄檷绾т负閫愪釜鍚屾")
            # 闄嶇骇锛氶€愪釜鍚屾
            for node in self.nodes:
                if node.status in [NodeStatus.PENDING, NodeStatus.NOT_READY, NodeStatus.RUNNING, NodeStatus.FAILED]:
                    await self.sync_node_status_from_service(node)
            self._update_workflow_status()

    def _update_local_workflow_status(self, workflow_status: Dict):
        """
        鏍规嵁鐘舵€佹湇鍔¤繑鍥炴洿鏂版湰鍦板伐浣滄祦鐘舵€?

        鏂扮姸鎬佺郴缁熶笅锛岀洿鎺ヨ皟鐢╛update_workflow_status()鏍规嵁APP鑺傜偣鐘舵€佽绠?
        杩欓噷鍙洿鏂癿essage鍜宖inished_at

        Args:
            workflow_status: 鐘舵€佹湇鍔¤繑鍥炵殑宸ヤ綔娴佺姸鎬佷俊鎭?
        """
        # 鏂扮姸鎬佺郴缁燂細鐘舵€佺敱APP鑺傜偣鍐冲畾锛岄€氳繃_update_workflow_status璁＄畻
        # 杩欓噷鍙鐞唌essage鍜宖inished_at

        if workflow_status.get("finished_at"):
            try:
                finished_at_str = workflow_status["finished_at"]
                if isinstance(finished_at_str, str):
                    self.instance.finished_at = datetime.fromisoformat(finished_at_str.replace("Z", "+00:00"))
            except Exception:
                pass

        if workflow_status.get("message"):
            self.instance.message = workflow_status.get("message")

        # 鏍规嵁APP鑺傜偣鐘舵€佽绠楀伐浣滄祦鐘舵€?
        self._update_workflow_status()
        logger.info("Updated local workflow status cache from workflow-status service")

    async def get_node_status_from_service(self, node_id: str) -> Optional[Dict]:
        """
        浠庣姸鎬佹湇鍔¤幏鍙栬妭鐐圭姸鎬?

        Args:
            node_id: 鑺傜偣ID

        Returns:
            鑺傜偣鐘舵€佷俊鎭瓧鍏?
        """
        try:
            result = await self.status_client.get_node_status(
                node_id=node_id,
                project_id=self.instance.project_id
            )
            return result
        except Exception as e:
            logger.error(f"浠庣姸鎬佹湇鍔¤幏鍙栬妭鐐?{node_id} 鐘舵€佸け璐? {e}")
            return None

    async def sync_all_nodes_status(self):
        """Sync all node status from K8S and update workflow status"""
        for node in self.nodes:
            # 鍚屾闈炵粓鎬佺姸鎬佺殑鑺傜偣锛圥ENDING, NOT_READY, RUNNING, FAILED锛?
            # FAILED鐘舵€佺殑鑺傜偣涔熼渶瑕佸悓姝ワ紝鍥犱负鍙兘K8S璧勬簮宸茬粡鎭㈠
            if node.status in [NodeStatus.PENDING, NodeStatus.NOT_READY, NodeStatus.RUNNING, NodeStatus.FAILED]:
                await self.sync_node_status_from_k8s(node)

        # Update workflow status based on node statuses
        self._update_workflow_status()

    def _update_workflow_status(self):
        """Update workflow instance status based on APP nodes only

        宸ヤ綔娴佺姸鎬佸彧鏍规嵁APP鑺傜偣鍒ゆ柇:
        - pending: 鎵€鏈堿PP鑺傜偣閮戒负pending
        - unready: 鏈堿PP鑺傜偣涓簉eady/not_ready/failed/stopped锛堥潪鍏ㄩ儴pending锛?
        - ready: 鎵€鏈堿PP鑺傜偣閮戒负ready
        """
        if not self.nodes:
            return

        # 鍙幏鍙朅PP绫诲瀷鐨勮妭鐐?
        app_nodes = [n for n in self.nodes if n.node_type == NodeType.APP]

        if not app_nodes:
            # 娌℃湁APP鑺傜偣锛屾牴鎹甁ob鑺傜偣鐘舵€佸垽鏂?
            job_nodes = [n for n in self.nodes if n.node_type == NodeType.JOB]
            if not job_nodes:
                return

            # 缁熻Job鑺傜偣鐘舵€?
            pending_count = sum(1 for n in job_nodes if n.status == NodeStatus.PENDING)
            succeeded_count = sum(1 for n in job_nodes if n.status == NodeStatus.SUCCEEDED)
            running_count = sum(1 for n in job_nodes if n.status == NodeStatus.RUNNING)
            failed_count = sum(1 for n in job_nodes if n.status == NodeStatus.FAILED)
            total = len(job_nodes)

            logger.info(f"Workflow {self.instance_id} JOB node status: pending={pending_count}, "
                        f"running={running_count}, succeeded={succeeded_count}, failed={failed_count}")

            # 鍒ゆ柇宸ヤ綔娴佺姸鎬?
            if succeeded_count == total:
                self.instance.status = WorkflowStatus.READY
                self.instance.message = "All JOB nodes succeeded"
                logger.info(f"Workflow {self.instance_id} marked as READY (all JOB nodes succeeded)")
            elif pending_count == total:
                self.instance.status = WorkflowStatus.PENDING
                self.instance.message = "All JOB nodes are pending"
                logger.info(f"Workflow {self.instance_id} marked as PENDING (all JOB nodes pending)")
            else:
                # 姝ｅ湪鎵ц鎴栨湁澶辫触
                self.instance.status = WorkflowStatus.PENDING
                if failed_count > 0:
                    self.instance.message = "Some JOB nodes failed"
                else:
                    self.instance.message = f"JOB nodes: {succeeded_count} succeeded, {running_count} running, {pending_count} pending"
                logger.info(f"Workflow {self.instance_id} marked as PENDING (JOB nodes in progress)")

            self.db.commit()
            return

        # 缁熻APP鑺傜偣鐘舵€?
        pending_count = sum(1 for n in app_nodes if n.status == NodeStatus.PENDING)
        ready_count = sum(1 for n in app_nodes if n.status == NodeStatus.READY)
        not_ready_count = sum(1 for n in app_nodes if n.status == NodeStatus.NOT_READY)
        failed_count = sum(1 for n in app_nodes if n.status == NodeStatus.FAILED)
        stopped_count = sum(1 for n in app_nodes if n.status == NodeStatus.STOPPED)

        total = len(app_nodes)
        logger.info(f"Workflow {self.instance_id} APP node status: pending={pending_count}, "
                    f"not_ready={not_ready_count}, ready={ready_count}, "
                    f"failed={failed_count}, stopped={stopped_count}")

        # 鍒ゆ柇宸ヤ綔娴佺姸鎬?
        if ready_count == total:
            # 鎵€鏈堿PP鑺傜偣閮絩eady
            self.instance.status = WorkflowStatus.READY
            self.instance.message = "All APP nodes are ready"
            logger.info(f"Workflow {self.instance_id} marked as READY")
        elif pending_count == total:
            # 鎵€鏈堿PP鑺傜偣閮絧ending
            self.instance.status = WorkflowStatus.PENDING
            self.instance.message = "All APP nodes are pending"
            logger.info(f"Workflow {self.instance_id} marked as PENDING")
        else:
            # 鏈堿PP鑺傜偣涓嶆槸pending涔熶笉鏄叏閮╮eady
            self.instance.status = WorkflowStatus.UNREADY
            if failed_count > 0:
                self.instance.message = f"Some APP nodes failed or not ready"
            elif stopped_count > 0:
                self.instance.message = f"Some APP nodes are stopped"
            else:
                self.instance.message = f"APP nodes: {ready_count} ready, {not_ready_count} not ready, {pending_count} pending"
            logger.info(f"Workflow {self.instance_id} marked as UNREADY")

        self.db.commit()

    def _get_template(self, node: WorkflowNodeInstance) -> Optional[Any]:
        """Get template for a node"""
        if node.node_type == NodeType.APP:
            return self.db.query(AppTemplate).filter(
                AppTemplate.id == node.template_id
            ).first()
        else:
            return self.db.query(JobTemplate).filter(
                JobTemplate.id == node.template_id
            ).first()

    def _resolve_container_env_vars(self, container: Dict[str, Any], node: WorkflowNodeInstance,
                                     template: Any, global_dep_env_vars: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Resolve environment variable for a single container
        Combines container fixed env_vars with dependency env_vars
        """
        env_vars = []

        # 1. Container fixed env_vars (from template)
        container_env = container.get("env_vars", [])
        for e in container_env:
            if e.get("name"):
                env_vars.append({"name": e["name"], "value": e.get("value", "")})

        # 2. Container input env_vars (from template) - template declares name, not source_node_id
        # The actual source_node_id is specified at node instance level
        # Skip here as global_dep_env_vars already contains all the resolved dependency

        # 3. Global input env_vars (from node instance configuration, includes resolved source_node_id)
        for dep_env in global_dep_env_vars:
            # Check if this env var is not already defined at container level
            if not any(e["name"] == dep_env["name"] for e in env_vars):
                env_vars.append(dep_env)

        return env_vars

    def _resolve_container_volume_mounts(self, container: Dict[str, Any], node: WorkflowNodeInstance,
                                          global_mounts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Resolve volume mount for a single container
        Combines container fixed mount with dependency mount from node instance
        """
        mounts = []

        # 1. Container fixed volume_mounts (from template) - known PVC at template definition
        container_mounts = container.get("volume_mounts", [])
        for vm in container_mounts:
            if vm.get("pvc_name") and vm.get("mount_path"):
                mounts.append({
                    "pvc_name": vm["pvc_name"],
                    "mount_path": vm["mount_path"],
                    "sub_path": vm.get("sub_path"),
                    "read_only": vm.get("read_only", False)
                })

        # 2. Container dependency volume_mounts (from template) - template only declares mount_path
        # The actual source (source_node_id) is specified at workflow node instance level
        # and already resolved in global_mounts. Template-level only declares the need.
        # Skip here as global_mounts already contains all the resolved dependency.

        # 3. Global volume mount (from node instance configuration, includes resolved dependency sources)
        for mount in global_mounts:
            # Convert format from K8S format to internal format
            if mount.get("pvcName") and mount.get("mountPath"):
                if not any(m["mount_path"] == mount["mountPath"] for m in mount):
                    mounts.append({
                        "pvc_name": mount["pvcName"],
                        "mount_path": mount["mountPath"],
                        "sub_path": mount.get("subPath"),
                        "read_only": mount.get("readOnly", False)
                    })

        return mounts

    def _get_node_resources(self, node: WorkflowNodeInstance, container_resources: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Get merged resource requirements for a container
        Node-level resources override template container resources
        """
        # Get node-level resource overrides from workflow template
        node_config = self._get_node_config_from_instance(node)
        node_resources = None

        if node_config:
            node_resources = node_config.get("resources")

        # If no node-level override, use container resources from template
        if not node_resources and container_resources:
            # Convert ResourceRequirements to K8S format
            if isinstance(container_resources, dict):
                return container_resources
            # Handle ResourceRequirements object
            elif hasattr(container_resources, 'request') or hasattr(container_resources, 'limits'):
                result = {}
                if hasattr(container_resources, 'request') and container_resources.request:
                    result["request"] = container_resources.request
                if hasattr(container_resources, 'limits') and container_resources.limits:
                    result["limits"] = container_resources.limits
                return result if result else None

        # If node-level resources exist, convert to K8S format if needed
        if node_resources:
            if isinstance(node_resources, dict):
                return node_resources
            # Handle ResourceRequirements object
            elif hasattr(node_resources, 'request') or hasattr(node_resources, 'limits'):
                result = {}
                if hasattr(node_resources, 'request') and node_resources.request:
                    result["request"] = node_resources.request
                if hasattr(node_resources, 'limits') and node_resources.limits:
                    result["limit"] = node_resources.limits
                return result if result else None

        return None

    def _build_containers_config(self, node: WorkflowNodeInstance, template: Any) -> List[Dict[str, Any]]:
        """
        Build complete container configurations for K8S
        Returns list of container configs ready for K8S
        Supports inheriting resource requirements from task templates with node-level overrides
        """
        # Resolve global dependency env_vars and mount (for backward compatibility)
        global_dep_env_vars = self._resolve_global_input_env_vars(node, template)
        global_mounts = self._resolve_global_input_volume_mounts(node, template)

        # Build container configs
        k8s_containers = []
        template_containers = template.containers or []

        for container in template_containers:
            # Resolve env vars and mount for this container
            env_vars = self._resolve_container_env_vars(container, node, template, global_dep_env_vars)
            volume_mounts = self._resolve_container_volume_mounts(container, node, global_mounts)

            # Resolve resources - merge node-level overrides with template container resources
            resources = self._get_node_resources(node, container.get("resources"))

            # Build container config
            k8s_container = {
                "name": container.get("name", "main"),
                "image": container.get("image"),
                "command": container.get("command"),
                "args": container.get("args"),
                "env_vars": env_vars,
                "volume_mounts": volume_mounts,
                "privileged": container.get("privileged", False),
                "image_pull_policy": container.get("image_pull_policy", "IfNotPresent"),
                "resources": resources,
                "liveness_probe": container.get("liveness_probe"),
                "readiness_probe": container.get("readiness_probe")
            }
            k8s_containers.append(k8s_container)

        return k8s_containers

    def _resolve_global_input_env_vars(self, node: WorkflowNodeInstance, template: Any) -> List[Dict[str, str]]:
        """
        Resolve node-level input environment variables
        """
        env_vars = []

        # Get from node instance configuration (input_env_vars specifies source_node_id)
        input_env_vars = node.input_env_vars or []

        for dep_env in input_env_vars:
            source_node_id = dep_env.get("source_node_id")
            name = dep_env.get("name")
            default_value = dep_env.get("default_value", "")

            if not source_node_id or not name:
                continue

            # Get value from source node
            source_node = self.node_map.get(source_node_id)
            if source_node:
                value = source_node.service_name or default_value
                if not value and source_node.k8s_resource_name:
                    value = f"{source_node.k8s_resource_name}-svc"
                env_vars.append({"name": name, "value": value or default_value})
            else:
                env_vars.append({"name": name, "value": default_value})

        return env_vars

    def _resolve_global_input_volume_mounts(self, node: WorkflowNodeInstance, template: Any) -> List[Dict[str, Any]]:
        """
        Resolve node-level input volume mount (specifies source_node_id)
        """
        mount = []

        # Get from node instance configuration (input_volume_mounts specifies source_node_id)
        input_mounts = node.input_volume_mounts or []

        for dep_mount in input_mounts:
            source_node_id = dep_mount.get("source_node_id")
            mount_path = dep_mount.get("mount_path")

            if not source_node_id or not mount_path:
                continue

            source_node = self.node_map.get(source_node_id)
            if source_node:
                source_pvc = dep_mount.get("source_pvc_name")

                if source_pvc:
                    mount.append({
                        "pvcName": source_pvc,
                        "mountPath": mount_path,
                        "subPath": dep_mount.get("sub_path"),
                        "readOnly": dep_mount.get("read_only", True)
                    })

        return mount

    def _resolve_global_input_env_vars_deprecated(self, node: WorkflowNodeInstance, template: Any) -> List[Dict[str, str]]:
        """DEPRECATED: Use _resolve_global_input_env_vars instead"""
        return self._resolve_global_input_env_vars(node, template)

    def _resolve_global_input_volume_mounts_deprecated(self, node: WorkflowNodeInstance, template: Any) -> List[Dict[str, Any]]:
        """DEPRECATED: Use _resolve_global_input_volume_mounts instead"""
        return self._resolve_global_input_volume_mounts(node, template)

    def _get_node_config_from_instance(self, node: WorkflowNodeInstance) -> Optional[Dict]:
        """Get node configuration from workflow instance"""
        instance_nodes = self.instance.nodes or []
        for n in instance_nodes:
            if n.get("node_id") == node.node_id:
                return n
        return None

    async def start_node(self, node: WorkflowNodeInstance) -> bool:
        """
        Start a single node by creating K8S resources

        APP鑺傜偣锛?
        - 宸插垵濮嬪寲锛堟湁k8s_resource_name锛夛細妫€鏌eployment鐘舵€侊紝璁剧疆PENDING/NOT_READY/READY
        - 鏈垵濮嬪寲锛氫笉搴旇鏄繖绉嶆儏鍐碉紝搴旇鍏堣皟鐢╥nitialize

        JOB鑺傜偣锛?
        - 鍒涘缓Job骞惰缃负RUNNING
        """
        from datetime import datetime

        if node.status in [NodeStatus.READY, NodeStatus.SUCCEEDED, NodeStatus.STOPPED, NodeStatus.FAILED]:
            logger.info(f"Node {node.node_id} is in terminal state {node.status}, skipping")
            return True

        # Get template
        template = self._get_template(node)
        if not template:
            node.status = NodeStatus.FAILED
            node.message = f"Template {node.template_id} not found"
            self.db.commit()
            return False

        # Check if template has containers
        if not template.containers:
            node.status = NodeStatus.FAILED
            node.message = f"Template {node.template_id} has no containers defined"
            self.db.commit()
            return False

        try:
            if node.node_type == NodeType.APP:
                # APP鑺傜偣锛氭鏌ュ凡瀛樺湪鐨凞eployment鐘舵€?
                node.k8s_resource_type = "Deployment"

                if not node.k8s_resource_name:
                    # APP鑺傜偣鏈垵濮嬪寲锛屽簲璇ュ厛璋冪敤initialize
                    node.status = NodeStatus.FAILED
                    node.message = "APP node not initialized, call initialize first"
                    self.db.commit()
                    return False

                k8s_name = node.k8s_resource_name

                result = await self.status_client.start_node(
                    node_id=node.node_id,
                    project_id=self.instance.project_id,
                    instance_id=self.instance_id,
                    node_type="app",
                    k8s_resource_name=k8s_name,
                )
                if not result.get("success"):
                    node.status = NodeStatus.FAILED
                    node.message = result.get("error", "Failed to check APP node status")
                    self.db.commit()
                    return False

                status_str = result.get("status", "Pending")
                status_mapping = {
                    "Pending": NodeStatus.PENDING,
                    "Not_ready": NodeStatus.NOT_READY,
                    "Ready": NodeStatus.READY,
                }
                node.status = status_mapping.get(status_str, NodeStatus.PENDING)
                node.message = result.get("message", "")
                self.db.commit()
                logger.info(f"Checked APP node {node.node_id} via workflow-status, status: {node.status}")
                return True

            else:  # JOB
                # JOB鑺傜偣锛氬垱寤篔ob
                node.k8s_resource_type = "Job"

                # Build container configurations
                containers = self._build_containers_config(node, template)

                # Generate K8S resource name
                k8s_name = f"wf-{self.instance.id[:8]}-{node.node_id[:8]}"
                node.k8s_resource_name = k8s_name

                # 鏋勫缓 job_config
                job_config = {
                    "containers": containers,
                    "ttl_seconds_after_finished": template.ttl_seconds_after_finished if hasattr(template, 'ttl_seconds_after_finished') else 3600,
                    "backoff_limit": template.backoff_limit if hasattr(template, 'backoff_limit') else 3
                }

                result = await self.status_client.start_node(
                    node_id=node.node_id,
                    project_id=self.instance.project_id,
                    instance_id=self.instance_id,
                    node_type="job",
                    k8s_resource_name=k8s_name,
                    job_config=job_config,
                )
                if not result.get("success"):
                    raise RuntimeError(result.get("error", "Failed to start job node"))

                status_str = result.get("status", "Running")
                status_mapping = {
                    "Pending": NodeStatus.PENDING,
                    "Running": NodeStatus.RUNNING,
                    "Succeeded": NodeStatus.SUCCEEDED,
                    "Failed": NodeStatus.FAILED,
                }
                node.status = status_mapping.get(status_str, NodeStatus.RUNNING)
                node.started_at = datetime.utcnow()
                node.message = result.get("message", "Job started successfully")
                self.db.commit()

                logger.info(f"Started JOB node {node.node_id} via workflow-status, status={node.status}")
                return True

        except Exception as e:
            logger.error(f"Failed to start node {node.node_id}: {e}")
            node.status = NodeStatus.FAILED
            node.message = str(e)
            node.finished_at = datetime.utcnow()
            self.db.commit()
            return False

    def _get_max_remaining_timeout(self) -> float:
        """
        Get maximum remaining timeout among all running nodes
        Returns the maximum time to wait for any running node
        """
        max_timeout = 0.0
        for node in self.nodes:
            if node.status == NodeStatus.RUNNING and node.started_at:
                elapsed = (datetime.utcnow() - node.started_at).total_seconds()
                timeout = node.timeout_seconds or (300 if node.node_type == NodeType.APP else 3600)
                remaining = timeout - elapsed
                if remaining > max_timeout:
                    max_timeout = remaining
        return max_timeout

    async def execute_workflow(self):
        """
        Execute workflow using topological sorting with concurrent execution
        After any node fails, wait for remaining running nodes to timeout before workflow fails
        """
        logger.info(f"Starting workflow execution for instance {self.instance_id}")

        # 鍚姩鐩戞帶
        await self._start_monitoring()

        try:
            # 1. Check for cycle
            cycle = self.detect_cycle()
            if cycle:
                error_msg = f"Cycle detected in workflow: {' -> '.join(cycle)}"
                logger.error(error_msg)
                self.instance.status = WorkflowStatus.UNREADY
                self.instance.message = error_msg
                self.db.commit()
                raise ValueError(error_msg)

            # 2. Build in-degree map
            in_degree = self.get_in_degree()

            # 3. Find starting nodes (in-degree = 0)
            ready = [node for node in self.nodes if in_degree[node.node_id] == 0]

            if not ready:
                logger.warning("No starting nodes found (all nodes have dependencies)")

            # 4. Execution loop
            self.instance.status = WorkflowStatus.UNREADY
            self.db.commit()

            workflow_failed = False
            failed_node_id = None

            while ready:
                logger.info(f"Starting {len(ready)} ready nodes: {[n.node_id for n in ready]}")

                # Start all ready nodes concurrently
                start_tasks = [self.start_node(node) for node in ready]
                results = await asyncio.gather(*start_tasks, return_exceptions=True)

                for node, result in zip(ready, results):
                    if isinstance(result, Exception):
                        logger.error(f"Node {node.node_id} failed to start: {result}")
                        node.status = NodeStatus.FAILED
                        node.message = str(result)
                        self.db.commit()

                # Wait for at least one node to complete before proceeding
                await self._wait_for_progress()

                # Sync status from K8S
                await self.sync_all_nodes_status()

                # Check for workflow completion
                if self._is_workflow_complete():
                    break

                # Check if any node has failed
                if self._has_workflow_failed():
                    workflow_failed = True
                    # Find the first failed node
                    for node in self.nodes:
                        if node.status == NodeStatus.FAILED:
                            failed_node_id = node.node_id
                            break
                    logger.warning(f"Node {failed_node_id} failed, waiting for remaining nodes to timeout...")
                    # Wait for remaining running nodes to timeout
                    await self._wait_for_remaining_timeout()
                    break

                # Find new ready nodes
                new_ready = []
                for node in self.nodes:
                    if node.status == NodeStatus.PENDING:
                        deps = self.dependency_graph.get(node.node_id, [])
                        all_deps_done = all(
                            self.node_map[dep_id].status in self.COMPLETED_STATUSES
                            for dep_id in deps
                        )
                        if all_deps_done:
                            new_ready.append(node)

                ready = new_ready

            # Final status update
            if self._is_workflow_complete():
                self.instance.status = WorkflowStatus.READY
                self.instance.finished_at = datetime.utcnow()
                self.instance.message = "All nodes completed successfully"
                logger.info(f"Workflow {self.instance_id} completed successfully")
            elif workflow_failed or self._has_workflow_failed():
                self.instance.status = WorkflowStatus.UNREADY
                self.instance.finished_at = datetime.utcnow()
                self.instance.message = f"Workflow failed: node {failed_node_id} failed"
                logger.error(f"Workflow {self.instance_id} failed")

            self.db.commit()

        finally:
            # 鍋滄鐩戞帶
            await self._stop_monitoring()

    async def _wait_for_progress(self, timeout: float = 30.0):
        """
        Wait for at least one running node to complete (or timeout)
        """
        start_time = asyncio.get_event_loop().time()

        while True:
            # Check if any node completed
            completed = any(
                node.status in self.COMPLETED_STATUSES or node.status in self.FAILED_STATUSES
                for node in self.nodes
                if node.status == NodeStatus.RUNNING
            )

            if completed:
                return

            # Check timeout
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout:
                logger.debug("Wait for progress timeout, checking again...")
                return

            # Small delay before next check
            await asyncio.sleep(2)

            # Sync status
            await self.sync_all_nodes_status()

    async def _wait_for_remaining_timeout(self):
        """
        Wait for all remaining running nodes to complete or timeout
        This is called after a node failure to allow other nodes to finish or timeout
        """
        logger.info("Waiting for remaining nodes to complete or timeout...")

        while True:
            # Check if all running nodes are done
            running_nodes = [node for node in self.nodes if node.status == NodeStatus.RUNNING]
            if not running_nodes:
                logger.info("All remaining nodes have completed")
                break

            # Check if any node is still running
            any_running = any(
                node.status == NodeStatus.RUNNING
                for node in self.nodes
            )
            if not any_running:
                break

            # Sync status to detect any new completions or timeouts
            await self.sync_all_nodes_status()

            # Check if there are still running nodes
            still_running = [node for node in self.nodes if node.status == NodeStatus.RUNNING]
            if not still_running:
                break

            # Wait a bit before next check
            await asyncio.sleep(5)

        # Final sync
        await self.sync_all_nodes_status()

    def _is_workflow_complete(self) -> bool:
        """Check if all nodes are completed (succeeded)"""
        return all(
            node.status in self.COMPLETED_STATUSES
            for node in self.nodes
        )

    def _has_workflow_failed(self) -> bool:
        """Check if any node has failed"""
        return any(
            node.status in self.FAILED_STATUSES
            for node in self.nodes
        )

    def get_node_outputs(self, node_id: str) -> Dict[str, Any]:
        """
        Get output from a node (service name, PVC names, etc.)
        """
        node = self.node_map.get(node_id)
        if not node:
            return {}

        outputs = {
            "node_id": node_id,
            "node_type": node.node_type,
            "status": node.status,
            "k8s_resource_name": node.k8s_resource_name,
            "service_name": node.service_name,
        }

        # Add PVC names from shared mount
        pvc_names = []
        for mount in node.shared_pvc_mounts or []:
            pvc_name = mount.get("pvc_name")
            if pvc_name and pvc_name not in pvc_names:
                pvc_names.append(pvc_name)

        # Add from dependency mount
        for mount in node.dependency_volume_mounts or []:
            pvc_name = mount.get("source_pvc_name")
            if pvc_name and pvc_name not in pvc_names:
                pvc_names.append(pvc_name)

        outputs["pvc_names"] = pvc_names

        return outputs

    # ============ 鐩戞帶鐩稿叧鏂规硶 ============

    async def _start_monitoring(self):
        """Start workflow status monitoring."""
        try:
            # 鏋勫缓鑺傜偣淇℃伅鍒楄〃
            nodes_info = [
                {
                    "node_id": node.node_id,
                    "node_type": "app" if node.node_type == NodeType.APP else "job",
                    "k8s_resource_name": node.k8s_resource_name,
                    "timeout_seconds": node.timeout_seconds
                }
                for node in self.nodes
            ]

            result = await self.status_client.start_monitoring(
                instance_id=self.instance_id,
                project_id=self.instance.project_id,
                nodes=nodes_info,
                poll_interval=10
            )

            if result.get("success"):
                self._monitoring_started = True
                logger.info(f"宸插惎鍔ㄧ洃鎺? instance_id={self.instance_id}")
            else:
                logger.warning(f"鍚姩鐩戞帶澶辫触: {result.get('error')}")

        except Exception as e:
            logger.warning(f"鍚姩鐩戞帶寮傚父: {e}")

    async def _stop_monitoring(self):
        """Stop workflow status monitoring."""
        if not self._monitoring_started:
            return

        try:
            success = await self.status_client.stop_monitoring(self.instance_id)
            if success:
                logger.info(f"宸插仠姝㈢洃鎺? instance_id={self.instance_id}")
            self._monitoring_started = False

        except Exception as e:
            logger.warning(f"鍋滄鐩戞帶寮傚父: {e}")

    async def _sync_node_status_to_service(self, node: WorkflowNodeInstance):
        """Push a single node status update to the workflow-status service."""
        try:
            await self.status_client.sync_node_status(
                node_id=node.node_id,
                project_id=self.instance.project_id,
                instance_id=self.instance_id,
                node_type="app" if node.node_type == NodeType.APP else "job",
                k8s_resource_name=node.k8s_resource_name,
                timeout_seconds=node.timeout_seconds
            )
        except Exception as e:
            logger.warning(f"鍚屾鑺傜偣鐘舵€佸け璐? {e}")
