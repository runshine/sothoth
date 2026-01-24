"""
Code-Server管理API路由
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Body, BackgroundTasks, Query
from kubernetes.client import ApiException
from sqlalchemy.orm import Session
from sqlalchemy.exc import NoResultFound  # 添加这行

from config import Config
from database import get_db, SessionLocal  # 添加 SessionLocal
from models import CodeServer, Project
from schemas.models import CodeServerCreate, CodeServerUpdate
from utils.auth_utils import get_current_user
from api.dependencies import K8SManagerDep, TaskManagerDep
from tasks.code_server_tasks import (
    create_code_server_task,
    start_code_server_task,
    stop_code_server_task,
    delete_code_server_task,
    restart_code_server_task,
    update_code_server_task
)

router = APIRouter()

@router.post("/projects/{project_id}/code-server")
async def create_code_server(
    project_id: str,
    background_tasks: BackgroundTasks,
    config_data: CodeServerCreate = Body(...),
    user = Depends(get_current_user),
    db: Session = Depends(get_db),
    k8s_manager = K8SManagerDep,
    task_manager = TaskManagerDep
):
    """创建Code-Server（使用已有的PVC）"""
    # 检查项目
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    # 检查项目状态是否为就绪
    if project.status != Config.PROJECT_STATUS_READY:
        raise HTTPException(
            status_code=400,
            detail=f"项目状态为 {project.status}，无法创建Code-Server。请等待项目初始化完成。"
        )

    # 检查项目PVC状态
    if not project.pvc_name or project.pvc_status != "ready":
        raise HTTPException(
            status_code=400,
            detail=f"项目PVC不可用，状态: {project.pvc_status}，请先创建PVC"
        )

    # 检查是否已存在Code-Server
    existing = db.query(CodeServer).filter(CodeServer.project_id == project_id).first()
    if existing and existing.status in ["creating", "running"]:
        raise HTTPException(
            status_code=400,
            detail=f"Code-Server已存在，状态: {existing.status}"
        )

    # 检查K8S是否可用
    if not Config.K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，请检查K8S客户端配置"
        )

    # 检查K8S管理器是否已初始化
    if not k8s_manager or not k8s_manager.available:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes管理器不可用，请检查K8S配置"
        )

    # 提交任务
    task_id = task_manager.submit(
        "create_code_server",
        create_code_server_task,
        project_id,
        user.id,
        config_data.password,
        config_data.cpu_limit,
        config_data.memory_limit
    )

    return {
        "task_id": task_id,
        "message": "Code-Server创建任务已提交",
        "project_id": project_id,
        "project_name": project.name,
        "pvc_name": project.pvc_name
    }

@router.get("/code-servers")
async def list_code_servers(
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=1, le=100),
    status: Optional[str] = Query(None),
    user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Code-Server列表"""
    query = db.query(CodeServer).filter(CodeServer.user_id == user.id)

    if status:
        query = query.filter(CodeServer.status == status)

    total = query.count()
    servers = query.order_by(CodeServer.created_at.desc()).offset((page-1)*size).limit(size).all()

    result = []
    for cs in servers:
        project = db.query(Project).filter(Project.id == cs.project_id).first()

        result.append({
            "id": cs.id,
            "project_id": cs.project_id,
            "project_name": project.name if project else "未知项目",
            "project_status": project.status if project else None,
            "status": cs.status,
            "access_url": cs.access_url,
            "deployment": cs.deployment_name,
            "service": cs.service_name,
            "pvc": project.pvc_name if project else None,
            "pod_status": cs.pod_status,
            "cpu_limit": cs.cpu_limit,
            "memory_limit": cs.memory_limit,
            "created_at": cs.created_at,
            "started_at": cs.started_at
        })

    return {
        "total": total,
        "page": page,
        "size": size,
        "code_servers": result
    }

@router.get("/code-servers/{project_id}")
async def get_code_server(
        project_id: str,
        user=Depends(get_current_user),
        db: Session = Depends(get_db),
        k8s_manager=K8SManagerDep
):
    """获取Code-Server详情"""
    cs = db.query(CodeServer).filter(
        CodeServer.project_id == project_id,
        CodeServer.user_id == user.id
    ).first()

    if not cs:
        raise HTTPException(status_code=404, detail="Code-Server不存在")

    project = db.query(Project).filter(Project.id == project_id).first()

    # 获取K8S详细信息
    k8s_info = {}
    if k8s_manager and k8s_manager.available:
        try:
            k8s_info["deployment"] = k8s_manager.get_deployment_status(project_id)
            k8s_info["service"] = k8s_manager.get_service_info(project_id)
            if project and project.pvc_name:
                k8s_info["pvc"] = k8s_manager.get_pvc_status(project_id)
        except Exception as e:
            k8s_info["error"] = {
                "message": "获取K8S信息失败",
                "details": {"error": str(e)}
            }

    return {
        "code_server": {
            "id": cs.id,
            "project_id": cs.project_id,
            "project_name": project.name if project else "未知项目",
            "project_status": project.status if project else None,
            "status": cs.status,
            "access_url": cs.access_url,
            "password": cs.password,
            "deployment_name": cs.deployment_name,
            "service_name": cs.service_name,
            "pvc_name": project.pvc_name if project else None,
            "pod_name": cs.pod_name,
            "pod_status": cs.pod_status,
            "cpu_limit": cs.cpu_limit,
            "memory_limit": cs.memory_limit,
            "created_at": cs.created_at,
            "started_at": cs.started_at,
            "stopped_at": cs.stopped_at
        },
        "k8s_info": k8s_info
    }


@router.delete("/code-servers/{project_id}")
async def delete_code_server(
        project_id: str,
        background_tasks: BackgroundTasks,
        user=Depends(get_current_user),
        db: Session = Depends(get_db),
        task_manager=TaskManagerDep
):
    """删除Code-Server（只删除运行时资源，保留PVC）"""
    cs = db.query(CodeServer).filter(
        CodeServer.project_id == project_id,
        CodeServer.user_id == user.id
    ).first()

    if not cs:
        raise HTTPException(status_code=404, detail="Code-Server不存在")

    # 检查K8S是否可用
    if not Config.K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法删除Code-Server资源"
        )

    # 提交任务
    task_id = task_manager.submit(
        "delete_code_server",
        delete_code_server_task,
        project_id
    )

    return {
        "task_id": task_id,
        "message": "Code-Server删除任务已提交（PVC将保留）",
        "project_id": project_id
    }


@router.post("/code-servers/{project_id}/stop")
async def stop_code_server(
        project_id: str,
        background_tasks: BackgroundTasks,
        user=Depends(get_current_user),
        task_manager=TaskManagerDep
):
    """停止Code-Server"""
    # 检查Code-Server是否存在
    db = SessionLocal()
    try:
        cs = db.query(CodeServer).filter(
            CodeServer.project_id == project_id,
            CodeServer.user_id == user.id
        ).first()

        if not cs:
            raise HTTPException(status_code=404, detail="Code-Server不存在")
    finally:
        db.close()

    # 检查K8S是否可用
    if not Config.K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法停止Code-Server"
        )

    # 提交任务
    task_id = task_manager.submit(
        "stop_code_server",
        stop_code_server_task,
        project_id
    )

    return {
        "task_id": task_id,
        "message": "Code-Server停止任务已提交",
        "project_id": project_id
    }


@router.post("/code-servers/{project_id}/start")
async def start_code_server(
        project_id: str,
        background_tasks: BackgroundTasks,
        user=Depends(get_current_user),
        task_manager=TaskManagerDep
):
    """启动Code-Server"""
    # 检查Code-Server是否存在
    db = SessionLocal()
    try:
        cs = db.query(CodeServer).filter(
            CodeServer.project_id == project_id,
            CodeServer.user_id == user.id
        ).first()

        if not cs:
            raise HTTPException(status_code=404, detail="Code-Server不存在")
    finally:
        db.close()

    # 检查K8S是否可用
    if not Config.K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法启动Code-Server"
        )

    # 提交任务
    task_id = task_manager.submit(
        "start_code_server",
        start_code_server_task,
        project_id
    )

    return {
        "task_id": task_id,
        "message": "Code-Server启动任务已提交",
        "project_id": project_id
    }


@router.post("/code-servers/{project_id}/restart")
async def restart_code_server(
        project_id: str,
        background_tasks: BackgroundTasks,
        user=Depends(get_current_user),
        task_manager=TaskManagerDep
):
    """重启Code-Server"""
    # 检查Code-Server是否存在
    db = SessionLocal()
    try:
        cs = db.query(CodeServer).filter(
            CodeServer.project_id == project_id,
            CodeServer.user_id == user.id
        ).first()

        if not cs:
            raise HTTPException(status_code=404, detail="Code-Server不存在")
    finally:
        db.close()

    # 检查K8S是否可用
    if not Config.K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法重启Code-Server"
        )

    # 提交任务
    task_id = task_manager.submit(
        "restart_code_server",
        restart_code_server_task,
        project_id
    )

    return {
        "task_id": task_id,
        "message": "Code-Server重启任务已提交",
        "project_id": project_id
    }


@router.put("/code-servers/{project_id}")
async def update_code_server(
        project_id: str,
        background_tasks: BackgroundTasks,
        update_data: CodeServerUpdate = Body(...),
        user=Depends(get_current_user),
        task_manager=TaskManagerDep
):
    """更新Code-Server配置"""
    # 检查Code-Server是否存在
    db = SessionLocal()
    try:
        cs = db.query(CodeServer).filter(
            CodeServer.project_id == project_id,
            CodeServer.user_id == user.id
        ).first()

        if not cs:
            raise HTTPException(status_code=404, detail="Code-Server不存在")

        if not update_data.cpu_limit and not update_data.memory_limit:
            raise HTTPException(
                status_code=400,
                detail="请至少提供一个更新参数（cpu_limit或memory_limit）"
            )
    finally:
        db.close()

    # 检查K8S是否可用
    if not Config.K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法更新Code-Server配置"
        )

    # 提交任务
    task_id = task_manager.submit(
        "update_code_server",
        update_code_server_task,
        project_id,
        update_data.cpu_limit,
        update_data.memory_limit
    )

    return {
        "task_id": task_id,
        "message": "Code-Server配置更新任务已提交",
        "project_id": project_id
    }


@router.get("/code-servers/{project_id}/logs")
async def get_code_server_logs(
        project_id: str,
        lines: int = Query(100, ge=1, le=1000),
        user=Depends(get_current_user),
        k8s_manager=K8SManagerDep
):
    """获取Code-Server日志"""
    db = SessionLocal()
    try:
        cs = db.query(CodeServer).filter(
            CodeServer.project_id == project_id,
            CodeServer.user_id == user.id
        ).first()

        if not cs:
            raise HTTPException(status_code=404, detail="Code-Server不存在")
    finally:
        db.close()

    if not k8s_manager or not k8s_manager.available:
        raise HTTPException(status_code=503, detail="Kubernetes功能不可用")

    try:
        # 获取Pod名称
        deploy_status = k8s_manager.get_deployment_status(project_id)
        if not deploy_status.get("pods"):
            raise HTTPException(status_code=404, detail="未找到运行的Pod")

        pod_name = deploy_status["pods"][0]["name"]

        # 获取Pod日志
        log_content = k8s_manager.core_v1.read_namespaced_pod_log(
            name=pod_name,
            namespace=k8s_manager.namespace,
            container="code-server",
            tail_lines=lines
        )

        return {
            "pod_name": pod_name,
            "lines": lines,
            "logs": log_content
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"获取日志失败: {str(e)}"
        )

@router.get("/code-servers/{project_id}/deployment/logs")
async def get_deployment_logs(
        project_id: str,
        log_type: str = Query("all", description="日志类型: all, code-server, init, copy-job"),
        lines: int = Query(100, ge=1, le=5000, description="日志行数"),
        previous: bool = Query(False, description="是否获取上一次的日志（适用于已终止的容器）"),
        user = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """获取Code-Server部署相关的所有日志"""
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在或无权访问")

    # 检查Code-Server是否存在
    code_server = db.query(CodeServer).filter(
        CodeServer.project_id == project_id
    ).first()

    try:
        from managers.kubernetes_manager import KubernetesManager
        k8s_manager = KubernetesManager(validate_connection=False)
    except Exception as e:
        k8s_manager = None

    if not code_server:
        raise HTTPException(status_code=404, detail="Code-Server不存在")

    if not k8s_manager or not k8s_manager.available:
        raise HTTPException(status_code=503, detail="Kubernetes功能不可用")

    try:
        # 获取Deployment状态
        deploy_status = k8s_manager.get_deployment_status(project_id)
        logs_result = {
            "project_id": project_id,
            "project_name": project.name,
            "log_type": log_type,
            "lines": lines,
            "logs": []
        }

        # 获取Code-Server Pod日志
        if log_type in ["all", "code-server"] and deploy_status.get("pods"):
            for pod_info in deploy_status["pods"]:
                try:
                    # 获取容器日志
                    log_content = k8s_manager.core_v1.read_namespaced_pod_log(
                        name=pod_info["name"],
                        namespace=k8s_manager.namespace,
                        container="code-server",
                        tail_lines=lines,
                        previous=previous
                    )

                    logs_result["logs"].append({
                        "source": "code-server",
                        "pod": pod_info["name"],
                        "container": "code-server",
                        "content": log_content
                    })
                except ApiException as e:
                    logs_result["logs"].append({
                        "source": "code-server",
                        "pod": pod_info["name"],
                        "error": f"获取日志失败: {e.reason if e.reason else str(e)}"
                    })

        # 获取初始化容器日志
        if log_type in ["all", "init"] and deploy_status.get("pods"):
            for pod_info in deploy_status["pods"]:
                try:
                    pod = k8s_manager.core_v1.read_namespaced_pod(
                        name=pod_info["name"], namespace=k8s_manager.namespace
                    )

                    # 检查是否有初始化容器
                    if pod.spec.init_containers:
                        for init_container in pod.spec.init_containers:
                            try:
                                init_log = k8s_manager.core_v1.read_namespaced_pod_log(
                                    name=pod_info["name"],
                                    namespace=k8s_manager.namespace,
                                    container=init_container.name,
                                    tail_lines=lines,
                                    previous=previous
                                )

                                logs_result["logs"].append({
                                    "source": "init-container",
                                    "pod": pod_info["name"],
                                    "container": init_container.name,
                                    "content": init_log
                                })
                            except ApiException as e:
                                logs_result["logs"].append({
                                    "source": "init-container",
                                    "pod": pod_info["name"],
                                    "container": init_container.name,
                                    "error": f"获取日志失败: {e.reason if e.reason else str(e)}"
                                })
                except ApiException:
                    continue

        # 获取复制任务日志
        if log_type in ["all", "copy-job"]:
            try:
                # 查找复制任务相关的Pod
                copy_jobs = k8s_manager.batch_v1.list_namespaced_job(
                    namespace=k8s_manager.namespace,
                    label_selector=f"project-id={project_id},app=file-copy"
                )

                for job in copy_jobs.items:
                    # 获取Job的Pod
                    job_pods = k8s_manager.core_v1.list_namespaced_pod(
                        namespace=k8s_manager.namespace,
                        label_selector=f"job-name={job.metadata.name}"
                    )

                    for pod in job_pods.items:
                        try:
                            copy_log = k8s_manager.core_v1.read_namespaced_pod_log(
                                name=pod.metadata.name,
                                namespace=k8s_manager.namespace,
                                container="copy",
                                tail_lines=lines,
                                previous=previous
                            )

                            logs_result["logs"].append({
                                "source": "copy-job",
                                "job": job.metadata.name,
                                "pod": pod.metadata.name,
                                "container": "copy",
                                "content": copy_log
                            })
                        except ApiException as e:
                            logs_result["logs"].append({
                                "source": "copy-job",
                                "job": job.metadata.name,
                                "pod": pod.metadata.name,
                                "error": f"获取日志失败: {e.reason if e.reason else str(e)}"
                            })
            except ApiException as e:
                logs_result["logs"].append({
                    "source": "copy-job",
                    "error": f"查找复制任务失败: {e.reason if e.reason else str(e)}"
                })

        return logs_result

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"获取部署日志失败: {str(e)}"
        )