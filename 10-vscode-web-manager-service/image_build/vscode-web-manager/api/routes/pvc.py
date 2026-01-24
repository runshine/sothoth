"""
PVC管理API路由
"""
import os  # 添加这行
from fastapi import APIRouter, Depends, HTTPException, Form
from sqlalchemy.orm import Session

from config import Config
from database import get_db
from models import Project, CodeServer
from schemas.models import RecreatePVCRequest
from utils.auth_utils import get_current_user
from api.dependencies import K8SManagerDep, TaskManagerDep
from tasks.pvc_tasks import create_project_pvc_task, recreate_project_pvc_task

router = APIRouter()

@router.post("/projects/{project_id}/pvc/create")
async def create_project_pvc(
    project_id: str,
    storage_size: str = Form(Config.K8S_DEFAULT_STORAGE_SIZE),
    user = Depends(get_current_user),
    db: Session = Depends(get_db),
    task_manager = TaskManagerDep
):
    """为项目创建PVC并拷贝文件"""
    # 检查项目权限
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
            detail=f"项目状态为 {project.status}，无法创建PVC。请等待项目初始化完成。"
        )

    # 检查项目是否有源码
    if not project.extract_path or not os.path.exists(project.extract_path):
        raise HTTPException(status_code=400, detail="项目源码不存在，无法创建PVC")

    # 检查是否已有PVC
    if project.pvc_name and project.pvc_status == "ready":
        raise HTTPException(
            status_code=400,
            detail=f"PVC已存在: {project.pvc_name}"
        )

    # 检查K8S是否可用
    if not Config.K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法创建PVC"
        )

    # 提交任务
    task_id = task_manager.submit(
        "create_project_pvc",
        create_project_pvc_task,
        project_id,
        storage_size
    )

    return {
        "task_id": task_id,
        "message": "PVC创建任务已提交",
        "project_id": project_id,
        "project_name": project.name,
        "storage_size": storage_size
    }

@router.post("/projects/{project_id}/pvc/recreate")
async def recreate_project_pvc(
    project_id: str,
    request: RecreatePVCRequest,
    user = Depends(get_current_user),
    db: Session = Depends(get_db),
    task_manager = TaskManagerDep
):
    """重建项目PVC（删除旧的，创建新的，重新拷贝文件）"""
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    # 检查项目状态是否为就绪
    if project.status != Config.PROJECT_STATUS_READY and project.status != Config.PROJECT_STATUS_ERROR:
        raise HTTPException(
            status_code=400,
            detail=f"项目状态为 {project.status}，无法重建PVC。请等待项目初始化完成。"
        )

    # 检查项目是否有源码
    if not project.extract_path or not os.path.exists(project.extract_path):
        raise HTTPException(status_code=400, detail="项目源码不存在，无法重建PVC")

    # 检查K8S是否可用
    if not Config.K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法重建PVC"
        )

    # 提交任务
    task_id = task_manager.submit(
        "recreate_project_pvc",
        recreate_project_pvc_task,
        project_id,
        request.storage_size
    )

    return {
        "task_id": task_id,
        "message": "PVC重建任务已提交",
        "project_id": project_id,
        "project_name": project.name,
        "storage_size": request.storage_size or project.pvc_size
    }

@router.get("/projects/{project_id}/pvc/status")
async def get_project_pvc_status(
    project_id: str,
    user = Depends(get_current_user),
    db: Session = Depends(get_db),
    k8s_manager = K8SManagerDep
):
    """获取项目PVC状态"""
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    if not project.pvc_name:
        raise HTTPException(status_code=404, detail="项目未创建PVC")

    if not k8s_manager or not k8s_manager.available:
        raise HTTPException(status_code=503, detail="Kubernetes功能不可用")

    try:
        pvc_info = k8s_manager.get_pvc_status(project_id)

        return {
            "project_id": project_id,
            "project_name": project.name,
            "pvc_name": project.pvc_name,
            "pvc_status": project.pvc_status,
            "pvc_size": project.pvc_size,
            "file_synced": project.file_synced,
            "k8s_pvc_info": pvc_info
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"获取PVC状态失败: {str(e)}"
        )

@router.delete("/projects/{project_id}/pvc")
async def delete_project_pvc(
    project_id: str,
    user = Depends(get_current_user),
    db: Session = Depends(get_db),
    k8s_manager = K8SManagerDep
):
    """删除项目PVC"""
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    if not project.pvc_name:
        raise HTTPException(status_code=404, detail="项目未创建PVC")

    # 检查是否有运行的Code-Server
    code_server = db.query(CodeServer).filter(CodeServer.project_id == project_id).first()
    if code_server and code_server.status in ["creating", "running"]:
        raise HTTPException(
            status_code=400,
            detail="有运行的Code-Server，请先停止或删除Code-Server"
        )

    # 检查K8S是否可用
    if not Config.K8S_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes功能不可用，无法删除PVC"
        )

    if not k8s_manager or not k8s_manager.available:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes管理器不可用，无法删除PVC"
        )

    try:
        # 同步删除PVC
        k8s_manager.delete_pvc(project_id)

        # 更新数据库
        project.pvc_name = None
        project.pvc_status = "pending"
        project.file_synced = False
        db.commit()

        return {
            "success": True,
            "project_id": project_id,
            "project_name": project.name,
            "message": "PVC删除成功"
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"删除PVC失败: {str(e)}"
        )