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
from app.services.k8s import K8SClient

logger = logging.getLogger(__name__)


class WorkflowEngine:
    """
    Workflow execution engine with topological sorting and concurrent execution
    """

    # Node status that indicate completion
    COMPLETED_STATUSES = {NodeStatus.SUCCEEDED, NodeStatus.STOPPED}
    FAILED_STATUSES = {NodeStatus.FAILED}

    def __init__(self, instance_id: str, db: Session, k8s_client: K8SClient):
        self.instance_id = instance_id
        self.db = db
        self.k8s_client = k8s_client
        self.instance: Optional[WorkflowInstance] = None
        self.nodes: List[WorkflowNodeInstance] = []
        self.node_map: Dict[str, WorkflowNodeInstance] = {}
        self.dependency_graph: Dict[str, List[str]] = {}  # node_id -> [dependency_node_ids]
        self.reverse_graph: Dict[str, List[str]] = {}  # node_id -> [downstream_node_ids]

    async def initialize(self):
        """Initialize the engine by loading instance and nodes"""
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
                    f"with {len(self.nodes)} nodes")

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

    def detect_cycles(self) -> Optional[List[str]]:
        """
        Detect cycles in the dependency graph using DFS
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
        For Job: status must be SUCCEEDED
        For Deployment: we consider it ready when running (health check will handle the rest)
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
                # Deployment must be running (ready check done by K8S)
                if dep_node.status != NodeStatus.RUNNING and dep_node.status != NodeStatus.SUCCEEDED:
                    return False

        return True

    async def sync_node_status_from_k8s(self, node: WorkflowNodeInstance):
        """
        Sync node status from K8S to database
        """
        if not node.k8s_resource_name:
            return

        try:
            if node.node_type == NodeType.APP:
                status = self.k8s_client.get_deployment_status(
                    self.instance.project_id, node.k8s_resource_name
                )
                if status:
                    # Deployment is ready when available_replicas == replicas
                    if status.get("ready_replicas", 0) >= status.get("replicas", 0):
                        if node.status != NodeStatus.RUNNING:
                            node.status = NodeStatus.RUNNING
                            node.message = "Deployment is ready"
                    else:
                        # Still pending (deployment exists but not ready)
                        if node.status == NodeStatus.PENDING:
                            node.message = "Waiting for deployment to be ready..."
            else:
                status = self.k8s_client.get_job_status(
                    self.instance.project_id, node.k8s_resource_name
                )
                if status:
                    k8s_status = status.get("status", "")
                    if k8s_status == "Succeeded":
                        if node.status != NodeStatus.SUCCEEDED:
                            node.status = NodeStatus.SUCCEEDED
                            node.finished_at = datetime.utcnow()
                            node.message = "Job completed successfully"
                    elif k8s_status == "Failed":
                        if node.status != NodeStatus.FAILED:
                            node.status = NodeStatus.FAILED
                            node.finished_at = datetime.utcnow()
                            node.message = f"Job failed: {status.get('failed', 0)} failures"

            self.db.commit()

        except Exception as e:
            logger.error(f"Error syncing node {node.node_id} status: {e}")

    async def sync_all_nodes_status(self):
        """Sync all nodes status from K8S"""
        for node in self.nodes:
            if node.status in [NodeStatus.RUNNING, NodeStatus.PENDING]:
                await self.sync_node_status_from_k8s(node)

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
        Resolve environment variables for a single container
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
        # Skip here as global_dep_env_vars already contains all the resolved dependencies

        # 3. Global input env_vars (from node instance configuration, includes resolved source_node_id)
        for dep_env in global_dep_env_vars:
            # Check if this env var is not already defined at container level
            if not any(e["name"] == dep_env["name"] for e in env_vars):
                env_vars.append(dep_env)

        return env_vars

    def _resolve_container_volume_mounts(self, container: Dict[str, Any], node: WorkflowNodeInstance,
                                          global_mounts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Resolve volume mounts for a single container
        Combines container fixed mounts with dependency mounts from node instance
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
        # Skip here as global_mounts already contains all the resolved dependencies.

        # 3. Global volume mounts (from node instance configuration, includes resolved dependency sources)
        for mount in global_mounts:
            # Convert format from K8S format to internal format
            if mount.get("pvcName") and mount.get("mountPath"):
                if not any(m["mount_path"] == mount["mountPath"] for m in mounts):
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
            elif hasattr(container_resources, 'requests') or hasattr(container_resources, 'limits'):
                result = {}
                if hasattr(container_resources, 'requests') and container_resources.requests:
                    result["requests"] = container_resources.requests
                if hasattr(container_resources, 'limits') and container_resources.limits:
                    result["limits"] = container_resources.limits
                return result if result else None

        # If node-level resources exist, convert to K8S format if needed
        if node_resources:
            if isinstance(node_resources, dict):
                return node_resources
            # Handle ResourceRequirements object
            elif hasattr(node_resources, 'requests') or hasattr(node_resources, 'limits'):
                result = {}
                if hasattr(node_resources, 'requests') and node_resources.requests:
                    result["requests"] = node_resources.requests
                if hasattr(node_resources, 'limits') and node_resources.limits:
                    result["limits"] = node_resources.limits
                return result if result else None

        return None

    def _build_containers_config(self, node: WorkflowNodeInstance, template: Any) -> List[Dict[str, Any]]:
        """
        Build complete container configurations for K8S
        Returns list of container configs ready for K8S
        Supports inheriting resource requirements from task templates with node-level overrides
        """
        # Resolve global dependency env_vars and mounts (for backward compatibility)
        global_dep_env_vars = self._resolve_global_input_env_vars(node, template)
        global_mounts = self._resolve_global_input_volume_mounts(node, template)

        # Build container configs
        k8s_containers = []
        template_containers = template.containers or []

        for container in template_containers:
            # Resolve env vars and mounts for this container
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
        Resolve node-level input volume mounts (specifies source_node_id)
        """
        mounts = []

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
                    mounts.append({
                        "pvcName": source_pvc,
                        "mountPath": mount_path,
                        "subPath": dep_mount.get("sub_path"),
                        "readOnly": dep_mount.get("read_only", True)
                    })

        return mounts

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
        Supports multi-container deployments and jobs
        """
        from datetime import datetime

        if node.status != NodeStatus.PENDING:
            logger.info(f"Node {node.node_id} is not pending, skipping")
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
            # Build container configurations
            containers = self._build_containers_config(node, template)

            # Generate K8S resource name
            k8s_name = f"wf-{self.instance.id[:8]}-{node.node_id[:8]}"
            node.k8s_resource_name = k8s_name

            if node.node_type == NodeType.APP:
                node.k8s_resource_type = "Deployment"

                # Create service if template has service_port defined and create_service is True
                service_port = []
                if template.service_port and getattr(template, 'create_service', True):
                    # Use custom service_name if provided, otherwise use k8s_name
                    service_name = template.service_name if template.service_name else k8s_name
                    node.service_name = service_name
                    service_port = [{
                        "name": p.get("name", f"port-{p['port']}"),
                        "port": p["port"],
                        "targetPort": p.get("target_port", p["port"]),
                        "protocol": p.get("protocol", "TCP")
                    } for p in template.service_port]

                    # Get service_type, default to ClusterIP
                    service_type = getattr(template, 'service_type', 'ClusterIP') or 'ClusterIP'

                    success, error = self.k8s_client.create_service(
                        project_id=self.instance.project_id,
                        name=service_name,
                        selector={"app": k8s_name},
                        ports=service_port,
                        service_type=service_type
                    )
                    if not success:
                        raise RuntimeError(f"Failed to create service: {error}")

                # Build ports for deployment from template-level service_ports
                ports = [{
                    "name": p.get("name", f"port-{p['port']}"),
                    "containerPort": p.get("target_port", p["port"]),
                    "protocol": p.get("protocol", "TCP")
                } for p in (template.service_ports or [])]

                # Create deployment with multiple containers
                success, error = self.k8s_client.create_deployment(
                    project_id=self.instance.project_id,
                    name=k8s_name,
                    containers=containers,
                    ports=ports if ports else None,
                    replicas=template.replicas if hasattr(template, 'replicas') else 1
                )

                if not success:
                    raise RuntimeError(f"Failed to create deployment: {error}")

            else:  # JOB
                node.k8s_resource_type = "Job"

                # Create job with multiple containers
                success, error = self.k8s_client.create_job(
                    project_id=self.instance.project_id,
                    name=k8s_name,
                    containers=containers,
                    ttl_seconds_after_finished=template.ttl_seconds_after_finished if hasattr(template, 'ttl_seconds_after_finished') else 3600,
                    backoff_limit=template.backoff_limit if hasattr(template, 'backoff_limit') else 3
                )

                if not success:
                    raise RuntimeError(f"Failed to create job: {error}")

            node.status = NodeStatus.RUNNING
            node.started_at = datetime.utcnow()
            node.message = "Node started successfully"
            self.db.commit()

            logger.info(f"Started node {node.node_id} ({k8s_name}) with {len(containers)} containers")
            return True

        except Exception as e:
            logger.error(f"Failed to start node {node.node_id}: {e}")
            node.status = NodeStatus.FAILED
            node.message = str(e)
            node.finished_at = datetime.utcnow()
            self.db.commit()
            return False

    async def execute_workflow(self):
        """
        Execute workflow using topological sorting with concurrent execution
        """
        logger.info(f"Starting workflow execution for instance {self.instance_id}")

        # 1. Check for cycles
        cycle = self.detect_cycles()
        if cycle:
            error_msg = f"Cycle detected in workflow: {' -> '.join(cycle)}"
            logger.error(error_msg)
            self.instance.status = WorkflowStatus.FAILED
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
        self.instance.status = WorkflowStatus.RUNNING
        self.db.commit()

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

            # Check for workflow completion or failure
            if self._is_workflow_complete():
                break

            if self._has_workflow_failed():
                self.instance.status = WorkflowStatus.FAILED
                self.db.commit()
                logger.error(f"Workflow {self.instance_id} failed")
                return

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
            self.instance.status = WorkflowStatus.SUCCEEDED
            self.instance.finished_at = datetime.utcnow()
            self.instance.message = "All nodes completed successfully"
            logger.info(f"Workflow {self.instance_id} completed successfully")
        elif self._has_workflow_failed():
            self.instance.status = WorkflowStatus.FAILED
            self.instance.finished_at = datetime.utcnow()
            logger.error(f"Workflow {self.instance_id} failed")

        self.db.commit()

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
        Get outputs from a node (service name, PVC names, etc.)
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

        # Add PVC names from shared mounts
        pvc_names = []
        for mount in node.shared_pvc_mounts or []:
            pvc_name = mount.get("pvc_name")
            if pvc_name and pvc_name not in pvc_names:
                pvc_names.append(pvc_name)

        # Add from dependency mounts
        for mount in node.dependency_volume_mounts or []:
            pvc_name = mount.get("source_pvc_name")
            if pvc_name and pvc_name not in pvc_names:
                pvc_names.append(pvc_name)

        outputs["pvc_names"] = pvc_names

        return outputs
