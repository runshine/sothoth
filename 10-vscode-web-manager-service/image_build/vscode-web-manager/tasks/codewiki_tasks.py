"""
CodeWiki任务函数
"""
import time
import secrets
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from config import Config
from database import SessionLocal
from models import Project, CodeWiki
from utils.errors import CodeServerError
from managers.kubernetes_manager import KubernetesManager

logger = logging.getLogger(__name__)

def create_codewiki_task(project_id: str, user_id: int, api_key: str = None,
                          cpu_limit: str = "1000m", memory_limit: str = "2048Mi"):
    """创建CodeWiki服务的实际逻辑（使用已有的PVC）"""
    logger.info(f"开始创建CodeWiki: project_id={project_id}")

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
                message=f"项目状态为 {project.status}，无法创建CodeWiki。请等待项目初始化完成。",
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

        # 检查是否已存在CodeWiki
        existing = db.query(CodeWiki).filter(CodeWiki.project_id == project_id).first()
        if existing and existing.status in ["creating", "running"]:
            raise CodeServerError(
                message="CodeWiki已存在",
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

        # 生成API密钥（如果未提供）
        if not api_key:
            api_key = secrets.token_urlsafe(32)

        # 步骤1: 检查Deployment是否已经存在
        deploy_name = k8s.generate_resource_name(project_id, "wiki-deploy")
        deployment_exists = False
        deployment_replica = 0

        try:
            deployment = k8s.apps_v1.read_namespaced_deployment(
                name=deploy_name, namespace=k8s.namespace
            )
            deployment_exists = True
            # 使用getattr安全获取replica属性
            deployment_replica = getattr(deployment.status, 'replica', None)
            if deployment_replica is None:
                deployment_replica = getattr(deployment.status, 'replicas', 0)
            deployment_replica = deployment_replica if deployment_replica is not None else 0
            logger.info(f"Deployment已存在: {deploy_name}, 副本数: {deployment_replica}")
        except k8s.ApiException as e:
            if e.status == 404:
                logger.info(f"Deployment不存在: {deploy_name}")
                deployment_exists = False
            else:
                logger.warning(f"获取Deployment状态失败: {e}")
                deployment_exists = False
        except Exception as e:
            logger.warning(f"检查Deployment状态时发生异常: {e}")
            deployment_exists = False

        # 步骤2: 根据Deployment状态决定执行流程
        if deployment_exists and deployment_replica == 0:
            # 情况1: Deployment存在但副本数为0，直接调整副本数为1
            logger.info(f"Deployment存在但副本数为0，直接调整为1: {deploy_name}")

            # 创建或更新CodeWiki记录
            if not existing:
                code_wiki = CodeWiki(
                    id=f"wiki-{project_id[:12]}",
                    project_id=project_id,
                    user_id=user_id,
                    status="running",
                    api_key=api_key,
                    cpu_limit=cpu_limit,
                    memory_limit=memory_limit,
                    deployment_name=deploy_name,
                    started_at=datetime.now(timezone.utc)
                )
                db.add(code_wiki)
            else:
                code_wiki = existing
                code_wiki.status = "running"
                code_wiki.api_key = api_key or code_wiki.api_key
                code_wiki.cpu_limit = cpu_limit or code_wiki.cpu_limit
                code_wiki.memory_limit = memory_limit or code_wiki.memory_limit
                code_wiki.started_at = datetime.now(timezone.utc)
                code_wiki.stopped_at = None

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
                        "error": str(e)
                    },
                    status_code=500
                )

            # 获取Service信息
            svc_name = k8s.generate_resource_name(project_id, "wiki-svc")
            try:
                service = k8s.core_v1.read_namespaced_service(
                    name=svc_name, namespace=k8s.namespace
                )
                code_wiki.service_name = service.metadata.name
                code_wiki.service_port = service.spec.ports[0].port if service.spec.ports else None
                code_wiki.service_ip = service.spec.cluster_ip

                # 构建访问URL
                if service.spec.type == "ClusterIP":
                    code_wiki.access_url = f"http://{svc_name}.{k8s.namespace}.svc.cluster.local:{code_wiki.service_port}/codewiki"
                else:
                    code_wiki.access_url = f"{service.spec.type}://{svc_name}:{code_wiki.service_port}/codewiki"

                logger.info(f"获取Service信息: {svc_name}, 访问URL: {code_wiki.access_url}")
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
                    deploy_status = k8s.get_codewiki_deployment_status(project_id)
                    if "error" not in deploy_status and deploy_status.get("ready_replica", 0) is not None and deploy_status.get("ready_replica", 0) >= 1:
                        pods = k8s.core_v1.list_namespaced_pod(
                            namespace=k8s.namespace,
                            label_selector=f"app=codewiki,project-id={project_id}"
                        )
                        if pods.items:
                            pod = pods.items[0]
                            code_wiki.pod_name = pod.metadata.name
                            code_wiki.pod_status = pod.status.phase
                        break
                    else:
                        logger.info(f"等待Deployment就绪 ({i+1}/30)")
                except Exception as e:
                    logger.warning(f"检查Deployment状态失败: {e}")
                    continue

            db.commit()

            result = {
                "success": True,
                "project_id": project_id,
                "project_name": project.name,
                "access_url": code_wiki.access_url,
                "api_key": api_key,
                "deployment": deploy_name,
                "service": code_wiki.service_name,
                "pvc": project.pvc_name,
                "status": "running",
                "operation": "scaled_up",
                "message": "CodeWiki已存在但副本数为0，已调整为1并启动"
            }

            logger.info(f"CodeWiki启动成功（通过扩容）: {result}")
            return result

        else:
            # 情况2: Deployment不存在或副本数不为0，执行正常创建流程
            logger.info(f"执行正常CodeWiki创建流程: {deploy_name}")

            # 创建或更新CodeWiki记录
            if not existing:
                code_wiki = CodeWiki(
                    id=f"wiki-{project_id[:12]}",
                    project_id=project_id,
                    user_id=user_id,
                    status="creating",
                    api_key=api_key,
                    cpu_limit=cpu_limit,
                    memory_limit=memory_limit
                )
                db.add(code_wiki)
            else:
                code_wiki = existing
                code_wiki.status = "creating"
                code_wiki.api_key = api_key or code_wiki.api_key
                code_wiki.cpu_limit = cpu_limit or code_wiki.cpu_limit
                code_wiki.memory_limit = memory_limit or code_wiki.memory_limit

            db.commit()

            # 如果Deployment存在但副本数不为0，先删除旧的Deployment
            if deployment_exists and deployment_replica > 0:
                logger.info(f"Deployment已存在且副本数为{deployment_replica}，先删除旧的Deployment")
                try:
                    k8s.apps_v1.delete_namespaced_deployment(
                        name=deploy_name, namespace=k8s.namespace
                    )
                    for i in range(10):
                        time.sleep(2)
                        try:
                            k8s.appa_v1.read_namespaced_deployment(
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
            deploy_name = k8s.create_codewiki_deployment(project_id, project.pvc_name, api_key, cpu_limit, memory_limit)
            code_wiki.deployment_name = deploy_name
            db.commit()

            # 创建Service
            service_info = k8s.create_codewiki_service(project_id)
            code_wiki.service_name = service_info["name"]
            code_wiki.service_port = service_info.get("port")
            code_wiki.service_ip = service_info.get("cluster_ip")
            code_wiki.access_url = service_info.get("url")
            db.commit()

            # 等待Deployment就绪
            logger.info("等待Deployment就绪...")
            for i in range(60):
                time.sleep(5)
                try:
                    deploy_status = k8s.get_codewiki_deployment_status(project_id)
                    if "error" not in deploy_status and deploy_status.get("ready_replica", 0) is not None and deploy_status.get("ready_replica", 0) >= 1:
                        pods = k8s.core_v1.list_namespaced_pod(
                            namespace=k8s.namespace,
                            label_selector=f"app=codewiki,project-id={project_id}"
                        )
                        if pods.items:
                            pod = pods.items[0]
                            code_wiki.pod_name = pod.metadata.name
                            code_wiki.pod_status = pod.status.phase
                        break
                    else:
                        logger.info(f"等待Deployment就绪 ({i+1}/60)")
                except Exception as e:
                    logger.warning(f"检查Deployment状态失败: {e}")
                    continue

            code_wiki.status = "running"
            code_wiki.started_at = datetime.now(timezone.utc)
            db.commit()

            result = {
                "success": True,
                "project_id": project_id,
                "project_name": project.name,
                "access_url": code_wiki.access_url,
                "api_key": api_key,
                "deployment": deploy_name,
                "service": service_info["name"],
                "pvc": project.pvc_name,
                "status": "running",
                "operation": "created",
                "message": "CodeWiki创建成功"
            }

            logger.info(f"CodeWiki创建成功: {result}")
            return result

    except Exception as e:
        logger.error(f"创建CodeWiki失败: {e}")

        try:
            if 'code_wiki' in locals():
                code_wiki.status = "error"
                db.commit()
        except:
            pass

        if isinstance(e, CodeServerError):
            raise
        raise CodeServerError(
            message="创建CodeWiki失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()
        logger.info("CodeWiki创建任务结束")


def start_codewiki_task(project_id: str):
    """启动CodeWiki的实际逻辑"""
    logger.info(f"启动CodeWiki: project_id={project_id}")

    db = SessionLocal()
    try:
        # 获取CodeWiki
        code_wiki = db.query(CodeWiki).filter(CodeWiki.project_id == project_id).first()
        if not code_wiki:
            raise CodeServerError(
                message="CodeWiki不存在",
                details={"project_id": project_id},
                status_code=404
            )

        project = db.query(Project).filter(Project.id == project_id).first()
        if project and project.status != Config.PROJECT_STATUS_READY:
            raise CodeServerError(
                message=f"项目状态为 {project.status}，无法启动CodeWiki。请等待项目初始化完成。",
                details={
                    "project_id": project_id,
                    "project_status": project.status,
                    "required_status": Config.PROJECT_STATUS_READY
                },
                status_code=400
            )

        k8s = KubernetesManager(validate_connection=False)
        if not k8s.available:
            raise CodeServerError(
                message="Kubernetes功能不可用",
                details={"project_id": project_id},
                status_code=503
            )

        # 检查Deployment是否存在
        try:
            deploy_status = k8s.get_codewiki_deployment_status(project_id)
            if "error" in deploy_status:
                logger.info(f"Deployment不存在，重新创建: {project_id}")
                return create_codewiki_task(
                    project_id,
                    code_wiki.user_id,
                    code_wiki.api_key,
                    code_wiki.cpu_limit,
                    code_wiki.memory_limit
                )
        except CodeServerError:
            logger.info(f"Deployment不存在，重新创建: {project_id}")
            return create_codewiki_task(
                project_id,
                code_wiki.user_id,
                code_wiki.api_key,
                code_wiki.cpu_limit,
                code_wiki.memory_limit
            )

        # 启动Deployment
        k8s.scale_codewiki_deployment(project_id, 1)

        code_wiki.status = "running"
        code_wiki.started_at = datetime.now(timezone.utc)
        code_wiki.stopped_at = None
        db.commit()

        # 等待启动完成
        for i in range(30):
            time.sleep(2)
            try:
                deploy_status = k8s.get_codewiki_deployment_status(project_id)
                if "error" not in deploy_status and deploy_status.get("ready_replica", 0) >= 1:
                    break
            except:
                continue

        result = {
            "success": True,
            "project_id": project_id,
            "project_name": project.name if project else "未知项目",
            "status": "running",
            "message": "CodeWiki启动成功"
        }

        logger.info(f"CodeWiki启动成功: {result}")
        return result

    except Exception as e:
        logger.error(f"启动CodeWiki失败: {e}")
        if isinstance(e, CodeServerError):
            raise
        raise CodeServerError(
            message="启动CodeWiki失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()


def stop_codewiki_task(project_id: str):
    """停止CodeWiki的实际逻辑"""
    logger.info(f"停止CodeWiki: project_id={project_id}")

    db = SessionLocal()
    try:
        code_wiki = db.query(CodeWiki).filter(CodeWiki.project_id == project_id).first()
        if not code_wiki:
            raise CodeServerError(
                message="CodeWiki不存在",
                details={"project_id": project_id},
                status_code=404
            )

        project = db.query(Project).filter(Project.id == project_id).first()

        k8s = KubernetesManager(validate_connection=False)
        if not k8s.available:
            raise CodeServerError(
                message="Kubernetes功能不可用",
                details={"project_id": project_id},
                status_code=503
            )

        # 停止Deployment
        k8s.scale_codewiki_deployment(project_id, 0)

        code_wiki.status = "stopped"
        code_wiki.stopped_at = datetime.now(timezone.utc)
        db.commit()

        result = {
            "success": True,
            "project_id": project_id,
            "project_name": project.name if project else "未知项目",
            "status": "stopped",
            "message": "CodeWiki停止成功"
        }

        logger.info(f"CodeWiki停止成功: {result}")
        return result

    except Exception as e:
        logger.error(f"停止CodeWiki失败: {e}")
        if isinstance(e, CodeServerError):
            raise
        raise CodeServerError(
            message="停止CodeWiki失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()


def delete_codewiki_task(project_id: str):
    """删除CodeWiki的实际逻辑（只删除运行时资源，保留PVC）"""
    logger.info(f"删除CodeWiki: project_id={project_id}")

    db = SessionLocal()
    try:
        code_wiki = db.query(CodeWiki).filter(CodeWiki.project_id == project_id).first()
        if not code_wiki:
            raise CodeServerError(
                message="CodeWiki不存在",
                details={"project_id": project_id},
                status_code=404
            )

        project = db.query(Project).filter(Project.id == project_id).first()

        code_wiki.status = "deleting"
        db.commit()

        k8s = KubernetesManager(validate_connection=False)
        if k8s.available:
            try:
                results = k8s.delete_codewiki_runtime_resources(project_id)
                logger.info(f"删除Kubernetes运行时资源成功: {results}")
            except CodeServerError as e:
                logger.error(f"删除Kubernetes运行时资源失败: {e.message}")
                results = {"errors": e.details}
        else:
            results = {"error": "Kubernetes客户端不可用"}

        # 删除数据库记录
        db.delete(code_wiki)
        db.commit()

        result = {
            "success": True,
            "project_id": project_id,
            "project_name": project.name if project else "未知项目",
            "deleted_resource": results,
            "pvc_preserved": True,
            "message": "CodeWiki删除成功，PVC已保留"
        }

        logger.info(f"CodeWiki删除成功: {result}")
        return result

    except Exception as e:
        logger.error(f"删除CodeWiki失败: {e}")
        if isinstance(e, CodeServerError):
            raise
        raise CodeServerError(
            message="删除CodeWiki失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()


def restart_codewiki_task(project_id: str):
    """重启CodeWiki的实际逻辑"""
    logger.info(f"重启CodeWiki: project_id={project_id}")

    try:
        stop_result = stop_codewiki_task(project_id)
    except CodeServerError as e:
        logger.warning(f"停止CodeWiki失败，尝试继续重启: {e.message}")

    time.sleep(5)

    start_result = start_codewiki_task(project_id)
    return start_result