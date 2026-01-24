"""
项目管理API路由
"""
import os
import shutil
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query
from fastapi.responses import JSONResponse
from kubernetes.client import ApiException
from sqlalchemy.orm import Session
from sqlalchemy import func

from config import Config
from database import get_db
from models import Project, ProjectFile, ProjectTaskLog, CodeServer
from utils.auth_utils import get_current_user
from utils.file_utils import FileUtils
from api.dependencies import TaskManagerDep  # 修正导入
from tasks.project_tasks import initialize_project_task
from tasks.project_tasks import delete_project_task  # 添加这行

router = APIRouter()

@router.post("/projects/upload")
async def upload_project(
    file: UploadFile = File(...),
    project_name: str = Form(...),
    description: Optional[str] = Form(None),
    storage_size: str = Form(Config.K8S_DEFAULT_STORAGE_SIZE),
    create_pvc: bool = Form(True, description="是否立即创建PVC"),
    user = Depends(get_current_user),
    db: Session = Depends(get_db),
    task_manager = TaskManagerDep  # 使用依赖注入
):
    """上传项目（异步初始化）"""
    # 检查文件类型
    if not FileUtils.allowed_file(file.filename):
        raise HTTPException(
            status_code=400,
            detail=f"不支持的文件类型，支持的类型: {', '.join(Config.ALLOWED_EXTENSIONS)}"
        )

    # 创建临时文件
    temp_path = os.path.join(Config.UPLOAD_DIR, f"temp_{user.id}_{file.filename}")

    try:
        # 保存文件
        file_size = 0
        with open(temp_path, "wb") as f:
            while True:
                chunk = await file.read(8192)
                if not chunk:
                    break
                file_size += len(chunk)
                if file_size > Config.MAX_FILE_SIZE:
                    os.remove(temp_path)
                    raise HTTPException(
                        status_code=400,
                        detail=f"文件大小超过限制 ({Config.MAX_FILE_SIZE // (1024*1024)}MB)"
                    )
                f.write(chunk)

        # 计算MD5
        file_md5 = FileUtils.calculate_md5(temp_path)

        # 生成项目ID（使用新的生成方式）
        project_id = FileUtils.generate_project_id(project_name, file_md5)

        # 检查是否已存在
        existing = db.query(Project).filter(Project.id == project_id).first()
        if existing:
            os.remove(temp_path)
            return JSONResponse(
                status_code=200,
                content={
                    "project_id": project_id,
                    "message": "项目已存在",
                    "existing": True
                }
            )

        # 保存原始文件
        ext = file.filename.rsplit('.', 1)[1].lower()
        archive_path = os.path.join(Config.ARCHIVE_DIR, f"{project_id}.{ext}")
        shutil.move(temp_path, archive_path)

        # 创建项目记录，状态为pending
        project = Project(
            id=project_id,
            name=project_name,
            description=description,
            original_filename=file.filename,
            archive_path=archive_path,
            extract_path=None,  # 初始化任务会设置
            archive_size=file_size,
            file_count=0,  # 初始化任务会设置
            total_size=0,  # 初始化任务会设置
            user_id=user.id,
            status=Config.PROJECT_STATUS_PENDING,  # 初始状态
            pvc_status="pending",
            pvc_size=storage_size
        )
        db.add(project)
        db.commit()

        # 提交异步初始化任务
        task_id = task_manager.submit(
            "initialize_project",
            initialize_project_task,
            project_id,
            archive_path,
            storage_size,
            create_pvc
        )

        return {
            "project_id": project_id,
            "name": project_name,
            "status": Config.PROJECT_STATUS_PENDING,
            "task_id": task_id,
            "message": "项目上传成功，正在异步初始化...",
            "create_pvc": create_pvc
        }

    except Exception as e:
        # 清理临时文件
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass

        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"上传项目失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/projects")
async def list_projects(
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=1, le=100),
    search: Optional[str] = None,
    status: Optional[str] = Query(None, description="项目状态过滤"),
    user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取项目列表"""
    query = db.query(Project).filter(Project.user_id == user.id)

    if search:
        search_pattern = f"%{search}%"
        # 搜索项目名或文件名
        file_project_ids = db.query(ProjectFile).filter(
            ProjectFile.file_name.like(search_pattern)
        ).distinct().subquery()

        query = query.filter(
            (Project.name.like(search_pattern)) |
            (Project.id.in_(file_project_ids))
        )

    if status:
        query = query.filter(Project.status == status)

    total = query.count()
    projects = query.order_by(Project.created_at.desc()).offset((page-1)*size).limit(size).all()

    result = []
    for project in projects:
        code_server = db.query(CodeServer).filter(CodeServer.project_id == project.id).first()

        result.append({
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "status": project.status,
            "file_count": project.file_count,
            "total_size": project.total_size,
            "pvc_name": project.pvc_name,
            "pvc_status": project.pvc_status,
            "file_synced": project.file_synced,
            "created_at": project.created_at,
            "initialized_at": project.initialized_at,
            "code_server_status": code_server.status if code_server else None
        })

    return {
        "total": total,
        "page": page,
        "size": size,
        "projects": result
    }

@router.get("/projects/{project_id}")
async def get_project(
    project_id: str,
    user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取项目详情"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    # 获取文件列表（如果项目已初始化）
    files = []
    if project.status == Config.PROJECT_STATUS_READY:
        files = db.query(ProjectFile).filter(ProjectFile.project_id == project_id).all()

    # 获取Code-Server信息
    code_server = db.query(CodeServer).filter(CodeServer.project_id == project_id).first()

    # 获取PVC信息（如果K8S可用）
    pvc_info = None
    try:
        from managers.kubernetes_manager import KubernetesManager
        k8s_manager = KubernetesManager(validate_connection=False)
        if k8s_manager.available and project.pvc_name:
            try:
                pvc_info = k8s_manager.get_pvc_status(project_id)
            except:
                pvc_info = {"error": "无法获取PVC状态"}
    except:
        pvc_info = {"error": "Kubernetes管理器不可用"}

    return {
        "project": {
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "status": project.status,
            "original_filename": project.original_filename,
            "file_count": project.file_count,
            "total_size": project.total_size,
            "archive_size": project.archive_size,
            "pvc_name": project.pvc_name,
            "pvc_status": project.pvc_status,
            "pvc_size": project.pvc_size,
            "file_synced": project.file_synced,
            "init_log_path": project.init_log_path,
            "init_error": project.init_error,
            "created_at": project.created_at,
            "initialized_at": project.initialized_at
        },
        "files": [
            {
                "path": f.file_path,
                "name": f.file_name,
                "size": f.file_size,
                "type": f.file_type
            }
            for f in files
        ] if files else [],
        "code_server": {
            "status": code_server.status if code_server else None,
            "access_url": code_server.access_url if code_server else None,
            "deployment": code_server.deployment_name if code_server else None,
            "created_at": code_server.created_at if code_server else None
        } if code_server else None,
        "pvc_info": pvc_info
    }


@router.delete("/projects/{project_id}")
async def delete_project(
    project_id: str,
    user = Depends(get_current_user),
    db: Session = Depends(get_db),
    task_manager = TaskManagerDep  # 使用依赖注入
):
    """删除项目（异步删除所有相关资源）"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    # 提交异步删除任务
    task_id = task_manager.submit(
        "delete_project",
        delete_project_task,  # 从 tasks.project_tasks 导入
        project_id,
        user.id
    )

    return {
        "task_id": task_id,
        "message": "项目删除任务已提交",
        "project_id": project_id,
        "project_name": project.name
    }

@router.get("/projects/{project_id}/status")
async def get_project_status(
        project_id: str,
        user = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """获取项目状态"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    # 获取最近的任务日志
    task_log = db.query(ProjectTaskLog).filter(
        ProjectTaskLog.project_id == project_id
    ).order_by(ProjectTaskLog.created_at.desc()).first()

    return {
        "project_id": project_id,
        "name": project.name,
        "status": project.status,
        "pvc_status": project.pvc_status,
        "file_synced": project.file_synced,
        "init_log_path": project.init_log_path,
        "init_error": project.init_error,
        "created_at": project.created_at,
        "initialized_at": project.initialized_at,
        "last_task": {
            "task_type": task_log.task_type if task_log else None,
            "status": task_log.status if task_log else None,
            "created_at": task_log.created_at if task_log else None,
            "completed_at": task_log.completed_at if task_log else None
        } if task_log else None
    }

@router.get("/projects/{project_id}/init-logs")
async def get_project_init_logs(
        project_id: str,
        lines: int = Query(100, ge=1, le=5000, description="日志行数"),
        user = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """获取项目初始化日志"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    if not project.init_log_path or not os.path.exists(project.init_log_path):
        raise HTTPException(status_code=404, detail="初始化日志不存在")

    try:
        # 读取日志文件
        with open(project.init_log_path, 'r', encoding='utf-8') as f:
            all_lines = f.readlines()
            if lines <= 0:
                log_content = "".join(all_lines)
            else:
                log_content = "".join(all_lines[-lines:])

        return {
            "project_id": project_id,
            "project_name": project.name,
            "status": project.status,
            "log_path": project.init_log_path,
            "lines": len(all_lines),
            "log_content": log_content
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"读取日志文件失败: {str(e)}")

@router.get("/projects/{project_id}/task-logs")
async def get_project_task_logs(
        project_id: str,
        task_type: Optional[str] = Query(None, description="任务类型过滤"),
        limit: int = Query(10, ge=1, le=100, description="返回数量"),
        user = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """获取项目任务日志列表"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    query = db.query(ProjectTaskLog).filter(ProjectTaskLog.project_id == project_id)

    if task_type:
        query = query.filter(ProjectTaskLog.task_type == task_type)

    task_logs = query.order_by(ProjectTaskLog.created_at.desc()).limit(limit).all()

    result = []
    for log in task_logs:
        log_content = None
        if log.log_path and os.path.exists(log.log_path):
            try:
                with open(log.log_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    log_content = "".join(lines[-50:])  # 最后50行
            except:
                log_content = "读取日志文件失败"

        result.append({
            "id": log.id,
            "task_type": log.task_type,
            "task_id": log.task_id,
            "status": log.status,
            "log_path": log.log_path,
            "error_message": log.error_message,
            "created_at": log.created_at,
            "completed_at": log.completed_at,
            "log_preview": log_content
        })

    return {
        "project_id": project_id,
        "project_name": project.name,
        "total": len(task_logs),
        "task_logs": result
    }


