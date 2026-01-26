"""
CodeWiki管理API路由
"""
import httpx
from typing import Optional, List, Dict, Any, Union
from fastapi import APIRouter, Depends, HTTPException, Body, BackgroundTasks, Query, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from kubernetes.client import ApiException
from sqlalchemy.orm import Session
from sqlalchemy.exc import NoResultFound

from config import Config
from database import get_db, SessionLocal
from models import CodeWiki, Project
from schemas.model import CodeWikiCreate, CodeWikiUpdate
from utils.auth_utils import get_current_user
from api.dependencies import K8SManagerDep, TaskManagerDep
from tasks.codewiki_tasks import (
    create_codewiki_task,
    start_codewiki_task,
    stop_codewiki_task,
    delete_codewiki_task,
    restart_codewiki_task
)

router = APIRouter()


@router.post("/projects/{project_id}/codewiki")
async def create_codewiki(
    project_id: str,
    background_tasks: BackgroundTasks,
    config_data: CodeWikiCreate = Body(...),
    user = Depends(get_current_user),
    db: Session = Depends(get_db),
    k8s_manager = K8SManagerDep,
    task_manager = TaskManagerDep
):
    """创建CodeWiki（使用已有的PVC）"""
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
            detail=f"项目状态为 {project.status}，无法创建CodeWiki。请等待项目初始化完成。"
        )

    # 检查项目PVC状态
    if not project.pvc_name or project.pvc_status != "ready":
        raise HTTPException(
            status_code=400,
            detail=f"项目PVC不可用，状态: {project.pvc_status}，请先创建PVC"
        )

    # 检查是否已存在CodeWiki
    existing = db.query(CodeWiki).filter(CodeWiki.project_id == project_id).first()
    if existing and existing.status in ["creating", "running"]:
        raise HTTPException(
            status_code=400,
            detail=f"CodeWiki已存在，状态: {existing.status}"
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
        "create_codewiki",
        create_codewiki_task,
        project_id,
        user.id,
        config_data.api_key,
        config_data.cpu_limit,
        config_data.memory_limit
    )

    return {
        "task_id": task_id,
        "message": "CodeWiki创建任务已提交",
        "project_id": project_id,
        "project_name": project.name,
        "pvc_name": project.pvc_name
    }


@router.get("/codewikis")
async def list_codewikis(
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=1, le=100),
    status: Optional[str] = Query(None),
    user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取CodeWiki列表"""
    query = db.query(CodeWiki).filter(CodeWiki.user_id == user.id)

    if status:
        query = query.filter(CodeWiki.status == status)

    total = query.count()
    wikis = query.order_by(CodeWiki.created_at.desc()).offset((page-1)*size).limit(size).all()

    result = []
    for wiki in wikis:
        project = db.query(Project).filter(Project.id == wiki.project_id).first()

        result.append({
            "id": wiki.id,
            "project_id": wiki.project_id,
            "project_name": project.name if project else "未知项目",
            "project_status": project.status if project else None,
            "status": wiki.status,
            "access_url": wiki.access_url,
            "deployment": wiki.deployment_name,
            "service": wiki.service_name,
            "pvc": project.pvc_name if project else None,
            "pod_status": wiki.pod_status,
            "cpu_limit": wiki.cpu_limit,
            "memory_limit": wiki.memory_limit,
            "api_key": wiki.api_key,
            "created_at": wiki.created_at,
            "started_at": wiki.started_at
        })

    return {
        "total": total,
        "page": page,
        "size": size,
        "codewikis": result
    }


@router.get("/codewikis/{project_id}")
async def get_codewiki(
    project_id: str,
    user = Depends(get_current_user),
    db: Session = Depends(get_db),
    k8s_manager = K8SManagerDep
):
    """获取CodeWiki详情"""
    wiki = db.query(CodeWiki).filter(
        CodeWiki.project_id == project_id,
        CodeWiki.user_id == user.id
    ).first()

    if not wiki:
        raise HTTPException(status_code=404, detail="CodeWiki不存在")

    project = db.query(Project).filter(Project.id == project_id).first()

    # 获取K8S详细信息
    k8s_info = {}
    if k8s_manager and k8s_manager.available:
        try:
            k8s_info["deployment"] = k8s_manager.get_codewiki_deployment_status(project_id)
            k8s_info["service"] = k8s_manager.get_codewiki_service_info(project_id)
            if project and project.pvc_name:
                k8s_info["pvc"] = k8s_manager.get_pvc_status(project_id)
        except Exception as e:
            k8s_info["error"] = {
                "message": "获取K8S信息失败",
                "details": {"error": str(e)}
            }

    return {
        "code_wiki": {
            "id": wiki.id,
            "project_id": wiki.project_id,
            "project_name": project.name if project else "未知项目",
            "project_status": project.status if project else None,
            "status": wiki.status,
            "access_url": wiki.access_url,
            "api_key": wiki.api_key,
            "deployment_name": wiki.deployment_name,
            "service_name": wiki.service_name,
            "pvc_name": project.pvc_name if project else None,
            "pod_name": wiki.pod_name,
            "pod_status": wiki.pod_status,
            "cpu_limit": wiki.cpu_limit,
            "memory_limit": wiki.memory_limit,
            "created_at": wiki.created_at,
            "started_at": wiki.started_at,
            "stopped_at": wiki.stopped_at
        },
        "k8s_info": k8s_info
    }


@router.delete("/codewikis/{project_id}")
async def delete_codewiki(
    project_id: str,
    background_tasks: BackgroundTasks,
    user = Depends(get_current_user),
    db: Session = Depends(get_db),
    task_manager = TaskManagerDep
):
    """删除CodeWiki（只删除运行时资源，保留PVC）"""
    wiki = db.query(CodeWiki).filter(
        CodeWiki.project_id == project_id,
        CodeWiki.user_id == user.id
    ).first()

    if not wiki:
        raise HTTPException(status_code=404, detail="CodeWiki不存在")

    # 检查K8S是否可用
    if not Config.K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法删除CodeWiki资源"
        )

    # 提交任务
    task_id = task_manager.submit(
        "delete_codewiki",
        delete_codewiki_task,
        project_id
    )

    return {
        "task_id": task_id,
        "message": "CodeWiki删除任务已提交（PVC将保留）",
        "project_id": project_id
    }


@router.post("/codewikis/{project_id}/stop")
async def stop_codewiki(
    project_id: str,
    background_tasks: BackgroundTasks,
    user = Depends(get_current_user),
    task_manager = TaskManagerDep
):
    """停止CodeWiki"""
    db = SessionLocal()
    try:
        wiki = db.query(CodeWiki).filter(
            CodeWiki.project_id == project_id,
            CodeWiki.user_id == user.id
        ).first()

        if not wiki:
            raise HTTPException(status_code=404, detail="CodeWiki不存在")
    finally:
        db.close()

    if not Config.K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法停止CodeWiki"
        )

    task_id = task_manager.submit(
        "stop_codewiki",
        stop_codewiki_task,
        project_id
    )

    return {
        "task_id": task_id,
        "message": "CodeWiki停止任务已提交",
        "project_id": project_id
    }


@router.post("/codewikis/{project_id}/start")
async def start_codewiki(
    project_id: str,
    background_tasks: BackgroundTasks,
    user = Depends(get_current_user),
    task_manager = TaskManagerDep
):
    """启动CodeWiki"""
    db = SessionLocal()
    try:
        wiki = db.query(CodeWiki).filter(
            CodeWiki.project_id == project_id,
            CodeWiki.user_id == user.id
        ).first()

        if not wiki:
            raise HTTPException(status_code=404, detail="CodeWiki不存在")
    finally:
        db.close()

    if not Config.K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法启动CodeWiki"
        )

    task_id = task_manager.submit(
        "start_codewiki",
        start_codewiki_task,
        project_id
    )

    return {
        "task_id": task_id,
        "message": "CodeWiki启动任务已提交",
        "project_id": project_id
    }


@router.post("/codewikis/{project_id}/restart")
async def restart_codewiki(
    project_id: str,
    background_tasks: BackgroundTasks,
    user = Depends(get_current_user),
    task_manager = TaskManagerDep
):
    """重启CodeWiki"""
    db = SessionLocal()
    try:
        wiki = db.query(CodeWiki).filter(
            CodeWiki.project_id == project_id,
            CodeWiki.user_id == user.id
        ).first()

        if not wiki:
            raise HTTPException(status_code=404, detail="CodeWiki不存在")
    finally:
        db.close()

    if not Config.K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法重启CodeWiki"
        )

    task_id = task_manager.submit(
        "restart_codewiki",
        restart_codewiki_task,
        project_id
    )

    return {
        "task_id": task_id,
        "message": "CodeWiki重启任务已提交",
        "project_id": project_id
    }


@router.get("/codewikis/{project_id}/logs")
async def get_codewiki_logs(
    project_id: str,
    lines: int = Query(100, ge=1, le=1000),
    user = Depends(get_current_user),
    k8s_manager = K8SManagerDep
):
    """获取CodeWiki日志"""
    db = SessionLocal()
    try:
        wiki = db.query(CodeWiki).filter(
            CodeWiki.project_id == project_id,
            CodeWiki.user_id == user.id
        ).first()

        if not wiki:
            raise HTTPException(status_code=404, detail="CodeWiki不存在")
    finally:
        db.close()

    if not k8s_manager or not k8s_manager.available:
        raise HTTPException(status_code=503, detail="Kubernetes功能不可用")

    try:
        deploy_status = k8s_manager.get_codewiki_deployment_status(project_id)
        if not deploy_status.get("pods"):
            raise HTTPException(status_code=404, detail="未找到运行的Pod")

        pod_name = deploy_status["pods"][0]["name"]

        log_content = k8s_manager.core_v1.read_namespaced_pod_log(
            name=pod_name,
            namespace=k8s_manager.namespace,
            container="codewiki",
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


@router.put("/codewikis/{project_id}")
async def update_codewiki(
    project_id: str,
    background_tasks: BackgroundTasks,
    update_data: CodeWikiUpdate = Body(...),
    user = Depends(get_current_user),
    task_manager = TaskManagerDep
):
    """更新CodeWiki配置（重新初始化）"""
    db = SessionLocal()
    try:
        wiki = db.query(CodeWiki).filter(
            CodeWiki.project_id == project_id,
            CodeWiki.user_id == user.id
        ).first()

        if not wiki:
            raise HTTPException(status_code=404, detail="CodeWiki不存在")

        if not update_data.api_key and not update_data.cpu_limit and not update_data.memory_limit:
            raise HTTPException(
                status_code=400,
                detail="请至少提供一个更新参数（api_key、cpu_limit或memory_limit）"
            )
    finally:
        db.close()

    if not Config.K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法更新CodeWiki配置"
        )

    # 先删除旧的，再创建新的（重新初始化）
    task_id = task_manager.submit(
        "delete_codewiki",
        delete_codewiki_task,
        project_id
    )

    return {
        "task_id": task_id,
        "message": "CodeWiki重新初始化任务已提交",
        "project_id": project_id
    }


def get_codewiki_internal_url(project_id: str, db: Session, k8s_manager) -> str:
    """获取CodeWiki内部服务URL"""
    wiki = db.query(CodeWiki).filter(CodeWiki.project_id == project_id).first()
    if not wiki or not wiki.service_name:
        return None

    # 使用ClusterIP内部地址
    return f"http://{wiki.service_name}.{k8s_manager.namespace}.svc.cluster.local:{wiki.service_port or 8080}"


@router.get("/codewikis/{project_id}/tasks")
async def list_codewiki_tasks(
    project_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    user = Depends(get_current_user),
    db: Session = Depends(get_db),
    k8s_manager = K8SManagerDep
):
    """获取CodeWiki任务列表（代理转发到后端服务）"""
    wiki = db.query(CodeWiki).filter(
        CodeWiki.project_id == project_id,
        CodeWiki.user_id == user.id
    ).first()

    if not wiki:
        raise HTTPException(status_code=404, detail="CodeWiki不存在")

    if wiki.status != "running":
        raise HTTPException(status_code=400, detail="CodeWiki未在运行中")

    internal_url = get_codewiki_internal_url(project_id, db, k8s_manager)
    if not internal_url:
        raise HTTPException(status_code=500, detail="无法获取CodeWiki服务地址")

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{internal_url}/codewiki/tasks",
                params={"skip": skip, "limit": limit}
            )
            if response.status_code == 200:
                return response.json()
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"获取任务列表失败: {response.text}"
                )
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"请求CodeWiki服务失败: {str(e)}")


@router.post("/codewikis/{project_id}/tasks")
async def create_codewiki_task_proxy(
    project_id: str,
    task_request: Dict[str, Any] = Body(...),
    user = Depends(get_current_user),
    db: Session = Depends(get_db),
    k8s_manager = K8SManagerDep
):
    """创建CodeWiki任务（代理转发到后端服务）"""
    wiki = db.query(CodeWiki).filter(
        CodeWiki.project_id == project_id,
        CodeWiki.user_id == user.id
    ).first()

    if not wiki:
        raise HTTPException(status_code=404, detail="CodeWiki不存在")

    if wiki.status != "running":
        raise HTTPException(status_code=400, detail="CodeWiki未在运行中")

    internal_url = get_codewiki_internal_url(project_id, db, k8s_manager)
    if not internal_url:
        raise HTTPException(status_code=500, detail="无法获取CodeWiki服务地址")

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{internal_url}/codewiki/tasks",
                json=task_request
            )
            if response.status_code in [200, 201]:
                return response.json()
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"创建任务失败: {response.text}"
                )
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"请求CodeWiki服务失败: {str(e)}")


@router.get("/codewikis/{project_id}/tasks/{task_id}")
async def get_codewiki_task(
    project_id: str,
    task_id: str,
    user = Depends(get_current_user),
    db: Session = Depends(get_db),
    k8s_manager = K8SManagerDep
):
    """获取CodeWiki任务详情（代理转发到后端服务）"""
    wiki = db.query(CodeWiki).filter(
        CodeWiki.project_id == project_id,
        CodeWiki.user_id == user.id
    ).first()

    if not wiki:
        raise HTTPException(status_code=404, detail="CodeWiki不存在")

    if wiki.status != "running":
        raise HTTPException(status_code=400, detail="CodeWiki未在运行中")

    internal_url = get_codewiki_internal_url(project_id, db, k8s_manager)
    if not internal_url:
        raise HTTPException(status_code=500, detail="无法获取CodeWiki服务地址")

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{internal_url}/codewiki/tasks/{task_id}")
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                raise HTTPException(status_code=404, detail="任务不存在")
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"获取任务失败: {response.text}"
                )
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"请求CodeWiki服务失败: {str(e)}")


@router.delete("/codewikis/{project_id}/tasks/{task_id}")
async def delete_codewiki_task_proxy(
    project_id: str,
    task_id: str,
    user = Depends(get_current_user),
    db: Session = Depends(get_db),
    k8s_manager = K8SManagerDep
):
    """删除CodeWiki任务（代理转发到后端服务）"""
    wiki = db.query(CodeWiki).filter(
        CodeWiki.project_id == project_id,
        CodeWiki.user_id == user.id
    ).first()

    if not wiki:
        raise HTTPException(status_code=404, detail="CodeWiki不存在")

    if wiki.status != "running":
        raise HTTPException(status_code=400, detail="CodeWiki未在运行中")

    internal_url = get_codewiki_internal_url(project_id, db, k8s_manager)
    if not internal_url:
        raise HTTPException(status_code=500, detail="无法获取CodeWiki服务地址")

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.delete(f"{internal_url}/codewiki/tasks/{task_id}")
            if response.status_code in [200, 202]:
                return response.json()
            elif response.status_code == 404:
                raise HTTPException(status_code=404, detail="任务不存在")
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"删除任务失败: {response.text}"
                )
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"请求CodeWiki服务失败: {str(e)}")


@router.get("/codewikis/{project_id}/tasks/{task_id}/logs")
async def get_codewiki_task_logs(
    project_id: str,
    task_id: str,
    lines: int = Query(1000, ge=1, le=10000),
    user = Depends(get_current_user),
    db: Session = Depends(get_db),
    k8s_manager = K8SManagerDep
):
    """获取CodeWiki任务日志（代理转发到后端服务）"""
    wiki = db.query(CodeWiki).filter(
        CodeWiki.project_id == project_id,
        CodeWiki.user_id == user.id
    ).first()

    if not wiki:
        raise HTTPException(status_code=404, detail="CodeWiki不存在")

    if wiki.status != "running":
        raise HTTPException(status_code=400, detail="CodeWiki未在运行中")

    internal_url = get_codewiki_internal_url(project_id, db, k8s_manager)
    if not internal_url:
        raise HTTPException(status_code=500, detail="无法获取CodeWiki服务地址")

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{internal_url}/codewiki/tasks/{task_id}/logs",
                params={"lines": lines}
            )
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                raise HTTPException(status_code=404, detail="日志不存在")
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"获取日志失败: {response.text}"
                )
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"请求CodeWiki服务失败: {str(e)}")


@router.post("/codewikis/{project_id}/tasks/{task_id}/stop")
async def stop_codewiki_task_proxy(
    project_id: str,
    task_id: str,
    user = Depends(get_current_user),
    db: Session = Depends(get_db),
    k8s_manager = K8SManagerDep
):
    """停止CodeWiki任务（代理转发到后端服务）"""
    wiki = db.query(CodeWiki).filter(
        CodeWiki.project_id == project_id,
        CodeWiki.user_id == user.id
    ).first()

    if not wiki:
        raise HTTPException(status_code=404, detail="CodeWiki不存在")

    if wiki.status != "running":
        raise HTTPException(status_code=400, detail="CodeWiki未在运行中")

    internal_url = get_codewiki_internal_url(project_id, db, k8s_manager)
    if not internal_url:
        raise HTTPException(status_code=500, detail="无法获取CodeWiki服务地址")

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(f"{internal_url}/codewiki/tasks/{task_id}/stop")
            if response.status_code in [200, 202]:
                return response.json()
            elif response.status_code == 404:
                raise HTTPException(status_code=404, detail="任务不存在")
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"停止任务失败: {response.text}"
                )
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"请求CodeWiki服务失败: {str(e)}")