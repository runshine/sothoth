"""
Code-Server任务函数
"""
import time
import secrets
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from config import Config
from database import SessionLocal
from models import Project, CodeServer
from utils.errors import CodeServerError
from managers.kubernetes_manager import KubernetesManager

logger = logging.getLogger(__name__)

def create_code_server_task(project_id: str, user_id: int, password: str = None,
                           cpu_limit: str = "1000m", memory_limit: str = "1024Mi"):
    """创建Code-Server的实际逻辑（使用已有的PVC）"""
    logger.info(f"开始创建Code-Server: project_id={project_id}")

    db = SessionLocal()
    try:
        # 获取项目
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise CodeServerError(
                message="项目不存在",
                details={"project_id": project_id},
                status_code=404
            )

        # 检查项目状态是否为就绪
        if project.status != Config.PROJECT_STATUS_READY:
            raise CodeServerError(
                message=f"项目状态为 {project.status}，无法创建Code-Server。请等待项目初始化完成。",
                details={
                    "project_id": project_id,
                    "project_status": project.status,
                    "required_status": Config.PROJECT_STATUS_READY
                },
                status_code=400
            )

        # 检查项目是否有可用的PVC
        if not project.pvc_name or project.pvc_status != "ready":
            raise CodeServerError(
                message="项目PVC不可用，请先确保PVC已创建并准备就绪",
                details={
                    "project_id": project_id,
                    "pvc_name": project.pvc_name,
                    "pvc_status": project.pvc_status
                },
                status_code=400
            )

        # 检查是否已存在Code-Server
        existing = db.query(CodeServer).filter(CodeServer.project_id == project_id).first()
        if existing and existing.status in ["creating", "running"]:
            raise CodeServerError(
                message="Code-Server已存在",
                details={
                    "project_id": project_id,
                    "existing_status": existing.status
                },
                status_code=400
            )

        # 初始化K8S管理器
        k8s = KubernetesManager(validate_connection=False)
        if not k8s.available:
            raise CodeServerError(
                message="Kubernetes功能不可用",
                details={"project_id": project_id},
                status_code=503
            )

        # 生成密码（如果未提供）
        if not password:
            password = secrets.token_urlsafe(12)

        # 步骤1: 检查Deployment是否已经存在
        deploy_name = k8s.generate_resource_name(project_id, "deploy")
        deployment_exists = False
        deployment_replicas = 0

        try:
            # 尝试获取Deployment信息
            deployment = k8s.apps_v1.read_namespaced_deployment(
                name=deploy_name, namespace=k8s.namespace
            )
            deployment_exists = True
            deployment_replicas = deployment.spec.replicas if deployment.spec.replicas is not None else 0
            logger.info(f"Deployment已存在: {deploy_name}, 副本数: {deployment_replicas}")
        except k8s.ApiException as e:
            if e.status == 404:
                logger.info(f"Deployment不存在: {deploy_name}")
                deployment_exists = False
            else:
                # 其他API错误，继续按正常流程处理
                logger.warning(f"获取Deployment状态失败: {e}")
                deployment_exists = False
        except Exception as e:
            logger.warning(f"检查Deployment状态时发生异常: {e}")
            deployment_exists = False

        # 步骤2: 根据Deployment状态决定执行流程
        if deployment_exists and deployment_replicas == 0:
            # 情况1: Deployment存在但副本数为0，直接调整副本数为1
            logger.info(f"Deployment存在但副本数为0，直接调整为1: {deploy_name}")

            # 创建或更新Code-Server记录
            if not existing:
                code_server = CodeServer(
                    id=f"cs-{project_id[:12]}",
                    project_id=project_id,
                    user_id=user_id,
                    status="running",
                    password=password,
                    cpu_limit=cpu_limit,
                    memory_limit=memory_limit,
                    deployment_name=deploy_name,
                    started_at=datetime.now(timezone.utc)
                )
                db.add(code_server)
            else:
                code_server = existing
                code_server.status = "running"
                code_server.password = password or code_server.password
                code_server.cpu_limit = cpu_limit or code_server.cpu_limit
                code_server.memory_limit = memory_limit or code_server.memory_limit
                code_server.started_at = datetime.now(timezone.utc)
                code_server.stopped_at = None

            db.commit()

            # 调整副本数
            try:
                deployment.spec.replicas = 1
                k8s.apps_v1.replace_namespaced_deployment(
                    name=deploy_name, namespace=k8s.namespace, body=deployment
                )
                logger.info(f"Deployment副本数已调整为1: {deploy_name}")
            except k8s.ApiException as e:
                logger.error(f"调整Deployment副本数失败: {e}")
                raise CodeServerError(
                    message="调整Deployment副本数失败",
                    details={
                        "project_id": project_id,
                        "deployment_name": deploy_name,
                        "error": str(e),
                        "status": e.status,
                        "reason": e.reason
                    },
                    status_code=500
                )

            # 获取Service信息（如果存在）
            svc_name = k8s.generate_resource_name(project_id, "svc")
            try:
                service = k8s.core_v1.read_namespaced_service(
                    name=svc_name, namespace=k8s.namespace
                )
                code_server.service_name = service.metadata.name
                code_server.service_port = service.spec.ports[0].port if service.spec.ports else None
                code_server.service_ip = service.spec.cluster_ip

                # 构建访问URL
                if service.spec.type == "LoadBalancer":
                    # 等待LoadBalancer IP分配
                    for i in range(10):
                        time.sleep(3)
                        try:
                            svc = k8s.core_v1.read_namespaced_service(
                                name=svc_name, namespace=k8s.namespace
                            )
                            if svc.status.load_balancer.ingress:
                                ingress = svc.status.load_balancer.ingress[0]
                                if ingress.ip:
                                    code_server.service_ip = ingress.ip
                                    code_server.access_url = f"http://{ingress.ip}:{code_server.service_port}"
                                    break
                                elif ingress.hostname:
                                    code_server.access_url = f"https://{ingress.hostname}:{code_server.service_port}"
                                    break
                        except:
                            continue

                elif service.spec.type == "NodePort":
                    if service.spec.ports and service.spec.ports[0].node_port:
                        node_port = service.spec.ports[0].node_port
                        # 获取节点IP
                        try:
                            nodes = k8s.core_v1.list_node()
                            if nodes.items:
                                node = nodes.items[0]
                                for addr in node.status.addresses:
                                    if addr.type == "ExternalIP":
                                        code_server.service_ip = addr.address
                                        code_server.access_url = f"http://{addr.address}:{node_port}"
                                        break
                                    elif addr.type == "InternalIP":
                                        code_server.service_ip = addr.address
                                        code_server.access_url = f"http://{addr.address}:{node_port}"
                                        break
                        except:
                            code_server.access_url = f"NodePort: {node_port}"

                elif service.spec.type == "ClusterIP":
                    code_server.access_url = f"https://{svc_name}.{k8s.namespace}.svc.cluster.local:{code_server.service_port}"

                logger.info(f"获取Service信息: {svc_name}, 访问URL: {code_server.access_url}")
            except k8s.ApiException as e:
                if e.status == 404:
                    logger.warning(f"Service不存在: {svc_name}")
                else:
                    logger.warning(f"获取Service信息失败: {e}")
            except Exception as e:
                logger.warning(f"获取Service信息时发生异常: {e}")

            # 获取Pod信息
            logger.info("等待Deployment就绪...")
            for i in range(30):
                time.sleep(3)
                try:
                    deploy_status = k8s.get_deployment_status(project_id)
                    if "error" not in deploy_status and deploy_status.get("ready_replicas", 0) is not None and deploy_status.get("ready_replicas", 0) >= 1:
                        # 获取Pod信息
                        pods = k8s.core_v1.list_namespaced_pod(
                            namespace=k8s.namespace,
                            label_selector=f"app=code-server,project-id={project_id}"
                        )
                        if pods.items:
                            pod = pods.items[0]
                            code_server.pod_name = pod.metadata.name
                            code_server.pod_status = pod.status.phase
                        break
                    else:
                        logger.info(f"等待Deployment就绪 ({i+1}/30): {deploy_status.get('ready_replicas', 0)}个就绪副本")
                except Exception as e:
                    logger.warning(f"检查Deployment状态失败: {e}")
                    continue

            db.commit()

            result = {
                "success": True,
                "project_id": project_id,
                "project_name": project.name,
                "access_url": code_server.access_url,
                "password": password,
                "deployment": deploy_name,
                "service": code_server.service_name,
                "pvc": project.pvc_name,
                "status": "running",
                "operation": "scaled_up",  # 标记操作为扩容
                "message": "Deployment已存在但副本数为0，已调整为1并启动"
            }

            logger.info(f"Code-Server启动成功（通过扩容）: {result}")
            return result

        else:
            # 情况2: Deployment不存在或副本数不为0，执行正常创建流程
            logger.info(f"执行正常Code-Server创建流程: {deploy_name}")

            # 创建或更新Code-Server记录
            if not existing:
                code_server = CodeServer(
                    id=f"cs-{project_id[:12]}",
                    project_id=project_id,
                    user_id=user_id,
                    status="creating",
                    password=password,
                    cpu_limit=cpu_limit,
                    memory_limit=memory_limit
                )
                db.add(code_server)
            else:
                code_server = existing
                code_server.status = "creating"
                code_server.password = password or code_server.password
                code_server.cpu_limit = cpu_limit or code_server.cpu_limit
                code_server.memory_limit = memory_limit or code_server.memory_limit

            db.commit()

            # 如果Deployment存在但副本数不为0，先删除旧的Deployment
            if deployment_exists and deployment_replicas > 0:
                logger.info(f"Deployment已存在且副本数为{deployment_replicas}，先删除旧的Deployment")
                try:
                    k8s.apps_v1.delete_namespaced_deployment(
                        name=deploy_name, namespace=k8s.namespace
                    )
                    # 等待删除完成
                    for i in range(10):
                        time.sleep(2)
                        try:
                            k8s.apps_v1.read_namespaced_deployment(
                                name=deploy_name, namespace=k8s.namespace
                            )
                        except k8s.ApiException as e:
                            if e.status == 404:
                                logger.info(f"Deployment删除成功: {deploy_name}")
                                break
                        except:
                            continue
                except k8s.ApiException as e:
                    if e.status != 404:
                        logger.error(f"删除旧的Deployment失败: {e}")
                        raise CodeServerError(
                            message="删除旧的Deployment失败",
                            details={
                                "project_id": project_id,
                                "deployment_name": deploy_name,
                                "error": str(e)
                            },
                            status_code=500
                        )

            # 执行正常创建流程
            deploy_name = k8s.create_deployment(project_id, password, project.pvc_name, cpu_limit, memory_limit)
            code_server.deployment_name = deploy_name
            db.commit()

            # 创建Service
            service_info = k8s.create_service(project_id)
            code_server.service_name = service_info["name"]
            code_server.service_port = service_info.get("port")
            code_server.service_ip = service_info.get("ip")
            code_server.access_url = service_info.get("url")
            db.commit()

            # 创建Ingress（可选）
            try:
                host = k8s.create_ingress(project_id)
                if host:
                    code_server.access_url = f"https://{host}"
                    db.commit()
            except Exception as e:
                logger.warning(f"创建Ingress失败: {e}")
                # Ingress创建失败不是致命错误

            # 等待Deployment就绪
            logger.info("等待Deployment就绪...")
            for i in range(60):
                time.sleep(5)
                try:
                    deploy_status = k8s.get_deployment_status(project_id)
                    if "error" not in deploy_status and deploy_status.get("ready_replicas", 0) is not None and deploy_status.get("ready_replicas", 0) >= 1:
                        # 获取Pod信息
                        pods = k8s.core_v1.list_namespaced_pod(
                            namespace=k8s.namespace,
                            label_selector=f"app=code-server,project-id={project_id}"
                        )
                        if pods.items:
                            pod = pods.items[0]
                            code_server.pod_name = pod.metadata.name
                            code_server.pod_status = pod.status.phase
                        break
                    else:
                        logger.info(f"等待Deployment就绪 ({i+1}/60): {deploy_status.get('ready_replicas', 0)}个就绪副本")
                except Exception as e:
                    logger.warning(f"检查Deployment状态失败: {e}")
                    continue

            code_server.status = "running"
            code_server.started_at = datetime.now(timezone.utc)
            db.commit()

            result = {
                "success": True,
                "project_id": project_id,
                "project_name": project.name,
                "access_url": code_server.access_url,
                "password": password,
                "deployment": deploy_name,
                "service": service_info["name"],
                "pvc": project.pvc_name,
                "status": "running",
                "operation": "created",  # 标记操作为新建
                "message": "Code-Server创建成功"
            }

            logger.info(f"Code-Server创建成功: {result}")
            return result

    except Exception as e:
        logger.error(f"创建Code-Server失败: {e}")

        # 更新状态为错误
        try:
            if 'code_server' in locals():
                code_server.status = "error"
                db.commit()
        except:
            pass

        # 如果异常已经是CodeServerError，直接抛出
        if isinstance(e, CodeServerError):
            raise
        # 否则包装为CodeServerError
        raise CodeServerError(
            message="创建Code-Server失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()


def start_code_server_task(project_id: str):
    """启动Code-Server的实际逻辑"""
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"启动Code-Server: project_id={project_id}")

    db = SessionLocal()
    try:
        # 获取Code-Server
        code_server = db.query(CodeServer).filter(CodeServer.project_id == project_id).first()
        if not code_server:
            raise CodeServerError(
                message="Code-Server不存在",
                details={"project_id": project_id},
                status_code=404
            )

        # 获取项目并检查状态
        project = db.query(Project).filter(Project.id == project_id).first()
        if project and project.status != Config.PROJECT_STATUS_READY:
            raise CodeServerError(
                message=f"项目状态为 {project.status}，无法启动Code-Server。请等待项目初始化完成。",
                details={
                    "project_id": project_id,
                    "project_status": project.status,
                    "required_status": Config.PROJECT_STATUS_READY
                },
                status_code=400
            )

        # 初始化K8S管理器
        k8s = KubernetesManager(validate_connection=False)
        if not k8s.available:
            raise CodeServerError(
                message="Kubernetes功能不可用",
                details={"project_id": project_id},
                status_code=503
            )

        # 检查Deployment是否存在
        try:
            deploy_status = k8s.get_deployment_status(project_id)
            if "error" in deploy_status:
                # Deployment不存在，需要重新创建
                logger.info(f"Deployment不存在，重新创建: {project_id}")
                return create_code_server_task(
                    project_id,
                    code_server.user_id,
                    code_server.password,
                    code_server.cpu_limit,
                    code_server.memory_limit
                )
        except CodeServerError:
            # Deployment不存在，重新创建
            logger.info(f"Deployment不存在，重新创建: {project_id}")
            return create_code_server_task(
                project_id,
                code_server.user_id,
                code_server.password,
                code_server.cpu_limit,
                code_server.memory_limit
            )

        # 启动Deployment（设置副本数为1）
        k8s.scale_deployment(project_id, 1)

        code_server.status = "running"
        code_server.started_at = datetime.now(timezone.utc)
        code_server.stopped_at = None
        db.commit()

        # 等待启动完成
        for i in range(30):
            time.sleep(2)
            try:
                deploy_status = k8s.get_deployment_status(project_id)
                if "error" not in deploy_status and deploy_status.get("ready_replicas", 0) >= 1:
                    break
            except:
                continue

        result = {
            "success": True,
            "project_id": project_id,
            "project_name": project.name if project else "未知项目",
            "status": "running",
            "message": "Code-Server启动成功"
        }

        logger.info(f"Code-Server启动成功: {result}")
        return result

    except Exception as e:
        logger.error(f"启动Code-Server失败: {e}")

        # 如果异常已经是CodeServerError，直接抛出
        if isinstance(e, CodeServerError):
            raise
        # 否则包装为CodeServerError
        raise CodeServerError(
            message="启动Code-Server失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()

def stop_code_server_task(project_id: str):
    """停止Code-Server的实际逻辑"""
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"停止Code-Server: project_id={project_id}")

    db = SessionLocal()
    try:
        # 获取Code-Server
        code_server = db.query(CodeServer).filter(CodeServer.project_id == project_id).first()
        if not code_server:
            raise CodeServerError(
                message="Code-Server不存在",
                details={"project_id": project_id},
                status_code=404
            )

        project = db.query(Project).filter(Project.id == project_id).first()

        # 初始化K8S管理器
        k8s = KubernetesManager(validate_connection=False)
        if not k8s.available:
            raise CodeServerError(
                message="Kubernetes功能不可用",
                details={"project_id": project_id},
                status_code=503
            )

        # 停止Deployment（设置副本数为0）
        k8s.scale_deployment(project_id, 0)

        code_server.status = "stopped"
        code_server.stopped_at = datetime.now(timezone.utc)
        db.commit()

        result = {
            "success": True,
            "project_id": project_id,
            "project_name": project.name if project else "未知项目",
            "status": "stopped",
            "message": "Code-Server停止成功"
        }

        logger.info(f"Code-Server停止成功: {result}")
        return result

    except Exception as e:
        logger.error(f"停止Code-Server失败: {e}")

        # 如果异常已经是CodeServerError，直接抛出
        if isinstance(e, CodeServerError):
            raise
        # 否则包装为CodeServerError
        raise CodeServerError(
            message="停止Code-Server失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()

def delete_code_server_task(project_id: str):
    """删除Code-Server的实际逻辑（只删除运行时资源，保留PVC）"""
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"删除Code-Server: project_id={project_id}")

    db = SessionLocal()
    try:
        # 获取Code-Server
        code_server = db.query(CodeServer).filter(CodeServer.project_id == project_id).first()
        if not code_server:
            raise CodeServerError(
                message="Code-Server不存在",
                details={"project_id": project_id},
                status_code=404
            )

        project = db.query(Project).filter(Project.id == project_id).first()

        code_server.status = "deleting"
        db.commit()

        # 初始化K8S管理器
        k8s = KubernetesManager(validate_connection=False)
        if k8s.available:
            try:
                # 只删除运行时资源，保留PVC
                results = k8s.delete_runtime_resources(project_id)
                logger.info(f"删除Kubernetes运行时资源成功: {results}")
            except CodeServerError as e:
                # 即使删除资源失败，也要删除数据库记录
                logger.error(f"删除Kubernetes运行时资源失败: {e.message}")
                results = {"errors": e.details}
        else:
            results = {"error": "Kubernetes客户端不可用"}

        # 删除数据库记录
        db.delete(code_server)
        db.commit()

        result = {
            "success": True,
            "project_id": project_id,
            "project_name": project.name if project else "未知项目",
            "deleted_resources": results,
            "pvc_preserved": True,
            "message": "Code-Server删除成功，PVC已保留"
        }

        logger.info(f"Code-Server删除成功: {result}")
        return result

    except Exception as e:
        logger.error(f"删除Code-Server失败: {e}")

        # 如果异常已经是CodeServerError，直接抛出
        if isinstance(e, CodeServerError):
            raise
        # 否则包装为CodeServerError
        raise CodeServerError(
            message="删除Code-Server失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()

def restart_code_server_task(project_id: str):
    """重启Code-Server的实际逻辑"""
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"重启Code-Server: project_id={project_id}")

    # 先停止
    try:
        stop_result = stop_code_server_task(project_id)
    except CodeServerError as e:
        # 如果停止失败，尝试继续重启
        logger.warning(f"停止Code-Server失败，尝试继续重启: {e.message}")

    # 等待一段时间
    time.sleep(5)

    # 再启动
    start_result = start_code_server_task(project_id)
    return start_result

def update_code_server_task(project_id: str, cpu_limit: str = None, memory_limit: str = None):
    """更新Code-Server配置的实际逻辑"""
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"更新Code-Server配置: project_id={project_id}")

    db = SessionLocal()
    try:
        # 获取Code-Server
        code_server = db.query(CodeServer).filter(CodeServer.project_id == project_id).first()
        if not code_server:
            raise CodeServerError(
                message="Code-Server不存在",
                details={"project_id": project_id},
                status_code=404
            )

        # 获取项目并检查状态
        project = db.query(Project).filter(Project.id == project_id).first()
        if project and project.status != Config.PROJECT_STATUS_READY:
            raise CodeServerError(
                message=f"项目状态为 {project.status}，无法更新Code-Server配置。请等待项目初始化完成。",
                details={
                    "project_id": project_id,
                    "project_status": project.status,
                    "required_status": Config.PROJECT_STATUS_READY
                },
                status_code=400
            )

        # 初始化K8S管理器
        k8s = KubernetesManager(validate_connection=False)
        if not k8s.available:
            raise CodeServerError(
                message="Kubernetes功能不可用",
                details={"project_id": project_id},
                status_code=503
            )

        # 获取当前Deployment
        deploy_name = k8s.generate_resource_name(project_id, "deploy")

        try:
            deployment = k8s.apps_v1.read_namespaced_deployment(
                name=deploy_name, namespace=k8s.namespace
            )

            # 更新资源限制
            if cpu_limit or memory_limit:
                containers = deployment.spec.template.spec.containers
                for container in containers:
                    if container.name == "code-server":
                        if cpu_limit:
                            container.resources.limits["cpu"] = cpu_limit
                            container.resources.requests["cpu"] = f"{int(cpu_limit.replace('m', ''))//2}m" if cpu_limit.endswith('m') else "500m"
                            code_server.cpu_limit = cpu_limit

                        if memory_limit:
                            container.resources.limits["memory"] = memory_limit
                            container.resources.requests["memory"] = f"{int(memory_limit.replace('Mi', ''))//2}Mi" if memory_limit.endswith('Mi') else "512Mi"
                            code_server.memory_limit = memory_limit

                # 更新Deployment
                k8s.apps_v1.replace_namespaced_deployment(
                    name=deploy_name, namespace=k8s.namespace, body=deployment
                )

                db.commit()

                result = {
                    "success": True,
                    "project_id": project_id,
                    "project_name": project.name if project else "未知项目",
                    "cpu_limit": cpu_limit or code_server.cpu_limit,
                    "memory_limit": memory_limit or code_server.memory_limit,
                    "message": "Code-Server配置更新成功"
                }

                logger.info(f"Code-Server配置更新成功: {result}")
                return result
            else:
                raise CodeServerError(
                    message="未提供更新参数",
                    details={"project_id": project_id},
                    status_code=400
                )

        except k8s.ApiException as e:
            logger.error(f"更新Code-Server配置失败: {e}")
            raise CodeServerError(
                message="更新Code-Server配置失败",
                details={
                    "project_id": project_id,
                    "deployment_name": deploy_name,
                    "error": str(e)
                },
                status_code=500
            )

    except Exception as e:
        logger.error(f"更新Code-Server配置失败: {e}")

        # 如果异常已经是CodeServerError，直接抛出
        if isinstance(e, CodeServerError):
            raise
        # 否则包装为CodeServerError
        raise CodeServerError(
            message="更新Code-Server配置失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()