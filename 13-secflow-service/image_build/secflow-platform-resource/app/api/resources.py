"""API routes for resource management."""

import os
import uuid
import asyncio
import base64
import aiofiles
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Header, Query, UploadFile, File, Form, Request
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session

from app.models.database import (
    get_db, Resource, AsyncTaskLog, Project,
    ResourceType, TaskStatus, TaskType, ResourceUploadStatus
)
from app.schemas import (
    ResourceUploadResponse,
    ResourceResponse, ResourceListResponse, ResourceDeleteResponse,
    TaskResponse, TaskListResponse, TaskLogResponse,
    PVCListResponse, PVCInfoResponse,
    OutputPVCCreateRequest, OutputPVCCreateResponse, OutputPVCDeleteResponse,
    ManualPVCCreateRequest, ManualPVCCreateResponse,
    PvcBrowserRootResponse, PvcBrowserChildrenResponse, PvcBrowserFileResponse, PvcBrowserUploadResponse,
    OutputPVCBrowserCreateDirectoryRequest, OutputPVCBrowserRenameRequest, OutputPVCBrowserMoveRequest,
    TokenPayload
)
from app.services.auth import get_auth_service
from app.services.project import get_project_service
from app.services.k8s import get_k8s_service
from app.services.pvc_browser import get_pvc_browser_service
from app.tasks.manager import get_task_manager
from app.tasks.worker import create_upload_extract_task, create_delete_resource_task
from app.main import get_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/resource", tags=["resources"])


@router.get("")
@router.get("/")
async def resource_service_info():
    """
    资源管理服务信息。
    """
    return {
        "service": "secflow-resource-management",
        "version": "2.2.0",
        "description": "项目管理五类资源（文档、软件、代码、其他、输出PVC）的异步上传和解压服务",
        "endpoints": {
            "upload": "POST /api/resource/resources/upload",
            "resources": "GET /api/resource/resources",
            "resource_detail": "GET /api/resource/resources/{id}",
            "download_file": "GET /api/resource/resources/{uuid}/file",
            "delete_resource": "DELETE /api/resource/resources/{id}",
            "tasks": "GET /api/resource/tasks",
            "task_detail": "GET /api/resource/tasks/{task_id}",
            "task_logs": "GET /api/resource/tasks/{task_id}/logs",
            "delete_task": "DELETE /api/resource/tasks/{task_id}",
            "pvcs": "GET /api/resource/pvcs",
            "create_output_pvc": "POST /api/resource/output-pvc",
            "get_output_pvc": "GET /api/resource/output-pvc/{resource_id}",
            "delete_output_pvc": "DELETE /api/resource/output-pvc/{resource_id}"
        },
        "resource_types": ["document", "software", "code", "other", "output_pvc"]
    }



async def get_current_user(
    authorization: Optional[str] = Header(None, alias="Authorization")
) -> tuple[TokenPayload, str]:
    """获取并验证当前用户。"""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    token = authorization.replace("Bearer ", "")

    auth_service = get_auth_service()
    user = await auth_service.validate_token(token)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return user, token


async def validate_project_access(
    project_id: str,
    token: str
) -> tuple[bool, Optional[dict]]:
    """验证用户对项目的访问权限（调用secflow_project服务）。"""
    project_service = get_project_service()
    has_access, project = await project_service.validate_project_access(
        project_id=project_id,
        token=token
    )

    if not has_access:
        return False, None

    return True, project


def get_upload_dir() -> str:
    """获取上传目录。"""
    config = get_config()
    app_config = config.get("app", {})
    return app_config.get("upload_dir", "/data/uploads")


def _resolve_output_pvc_resource(db: Session, resource_id: int) -> Resource:
    resource = db.query(Resource).filter(
        Resource.id == resource_id,
        Resource.resource_type == ResourceType.OUTPUT_PVC
    ).first()
    if not resource:
        raise HTTPException(status_code=404, detail="Output PVC resource not found")
    return resource


def _resolve_pvc_resource(db: Session, resource_id: int) -> Resource:
    resource = db.query(Resource).filter(Resource.id == resource_id).first()
    if not resource:
        raise HTTPException(status_code=404, detail="PVC resource not found")
    if not resource.pvc_name:
        raise HTTPException(status_code=409, detail="Resource is missing pvc_name")
    return resource


def _resolve_resource_project_id(resource: Resource) -> str:
    pvc_namespace = resource.pvc_namespace
    if pvc_namespace and pvc_namespace.startswith("secflow-"):
        return pvc_namespace.replace("secflow-", "", 1)
    if resource.projects:
        return resource.projects[0].id
    raise HTTPException(status_code=500, detail="Cannot determine project for PVC")


# ============ 资源上传接口（文件上传模式） ============

@router.post("/resources/upload", response_model=ResourceUploadResponse)
async def upload_resource(
    file: UploadFile = File(...),
    name: str = Form(..., description="资源名称"),
    resource_type: ResourceType = Form(..., description="资源类型"),
    project_ids: str = Form(..., description="项目ID列表，逗号分隔"),
    pvc_size: int = Form(10, ge=1, le=500, description="PVC大小，默认10Gi"),
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    上传资源文件（异步任务）。

    - 文件上传到临时目录，服务充当静态文件服务器供K8S Job下载
    - 创建异步任务：创建PVC -> 创建Job -> Job从本服务下载并解压到PVC
    - 每次上传创建独立的PVC
    - 返回任务ID供查询进度
    """
    current_user, token = user_and_token

    # 解析项目ID列表
    project_id_list = [pid.strip() for pid in project_ids.split(",") if pid.strip()]
    if not project_id_list:
        raise HTTPException(status_code=400, detail="At least one project_id is required")

    # 验证所有项目访问权限
    for project_id in project_id_list:
        has_access, _ = await validate_project_access(project_id, token)
        if not has_access:
            raise HTTPException(
                status_code=403,
                detail=f"No permission to access project {project_id}"
            )

    try:
        # 生成资源UUID（也作为文件名）
        resource_uuid = str(uuid.uuid4())

        # 构建 archive_url（供K8S Job下载使用）
        config = get_config()
        app_config = config.get("app", {})
        download_base_url = app_config.get("download_base_url", "http://localhost:10002")
        archive_url = f"{download_base_url}/api/resource/uploads/{resource_uuid}"

        # 保存文件到上传目录
        upload_dir = get_upload_dir()
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, resource_uuid)

        # 读取文件内容并保存
        content = await file.read()
        async with aiofiles.open(file_path, "wb") as f:
            await f.write(content)

        # 获取原始文件名和大小
        original_file_name = file.filename or "archive"
        file_size = len(content)

        # 推断文件格式
        original_file_format = None
        if original_file_name.endswith(".zip"):
            original_file_format = "zip"
        elif original_file_name.endswith(".tar.gz") or original_file_name.endswith(".tgz"):
            original_file_format = "tar.gz"
        elif original_file_name.endswith(".tar"):
            original_file_format = "tar"
        elif original_file_name.endswith(".gz"):
            original_file_format = "gz"

        # 创建异步任务
        task_id = await create_upload_extract_task(
            resource_uuid=resource_uuid,
            project_id=project_id_list[0],  # 使用第一个项目作为主项目
            project_ids=project_id_list,  # 关联所有项目
            resource_name=name,
            resource_type=resource_type.value if hasattr(resource_type, 'value') else resource_type,
            archive_url=archive_url,  # K8S Job 下载地址
            original_file_name=original_file_name,
            original_file_size=file_size,
            original_file_md5=None,
            original_file_format=original_file_format,
            pvc_size=pvc_size
        )

        return ResourceUploadResponse(
            task_id=task_id,
            resource_uuid=resource_uuid,
            message="Resource upload task created successfully"
        )

    except Exception as e:
        logger.error(f"Failed to create upload task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/uploads/{resource_uuid}")
async def download_upload_file(
    resource_uuid: str,
):
    """
    下载上传的原始文件（供K8S Job使用，无需认证）。

    - 直接从上传目录提供文件
    """
    upload_dir = get_upload_dir()
    file_path = os.path.join(upload_dir, resource_uuid)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(
        path=file_path,
        filename=resource_uuid,
        media_type="application/octet-stream"
    )


@router.get("/resources/{resource_uuid}/file")
async def download_resource_file(
    resource_uuid: str,
    token: Optional[str] = Query(None, description="Token URL参数（可选，优先于Header）"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    """
    下载资源文件（供前端或其他服务使用）。

    - 从本服务下载已上传的文件
    - 支持通过URL参数或Authorization Header传递token
    """
    # 优先使用URL参数的token，否则使用Header的token
    actual_token = token
    if not actual_token and authorization:
        actual_token = authorization.replace("Bearer ", "")

    if not actual_token:
        raise HTTPException(status_code=401, detail="Missing token in URL parameter or Authorization header")

    # 验证token
    auth_service = get_auth_service()
    current_user = await auth_service.validate_token(actual_token)

    if not current_user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    from app.models import database
    from app.models.database import Resource

    # 查找资源记录
    session = database.SessionLocal()
    try:
        resource = session.query(Resource).filter(
            Resource.resource_uuid == resource_uuid
        ).first()

        if not resource:
            raise HTTPException(status_code=404, detail="Resource not found")

        # 验证项目访问权限
        if resource.projects:
            has_access, _ = await validate_project_access(resource.projects[0].id, actual_token)
            if not has_access:
                raise HTTPException(status_code=403, detail="No permission to access this project")

        # 返回文件
        upload_dir = get_upload_dir()
        file_path = os.path.join(upload_dir, resource_uuid)

        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="File not found on disk")

        return FileResponse(
            path=file_path,
            filename=resource.original_file_name,
            media_type="application/octet-stream"
        )
    finally:
        session.close()


# ============ 资源查询接口 ============

@router.get("/resources", response_model=ResourceListResponse)
async def list_resource(
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    project_id: str = Query(..., description="项目ID"),
    resource_type: Optional[ResourceType] = Query(None, description="资源类型筛选"),
    upload_status: Optional[str] = Query(None, description="上传状态筛选"),
    db: Session = Depends(get_db)
):
    """
    查询资源列表。

    - 根据项目ID获取资源列表
    - 支持资源类型和状态筛选
    """
    current_user, token = user_and_token

    # 验证项目访问权限
    has_access, _ = await validate_project_access(project_id, token)
    if not has_access:
        raise HTTPException(status_code=403, detail="No permission to access this project")

    # 查询关联到该项目的资源
    query = db.query(Resource).join(
        Resource.projects
    ).filter(Project.id == project_id)

    if resource_type:
        query = query.filter(Resource.resource_type == resource_type)

    if upload_status:
        query = query.filter(Resource.upload_status == upload_status)

    resources = query.order_by(Resource.created_at.desc()).all()

    # 转换为响应格式
    resource_responses = []
    for r in resources:
        resource_responses.append(ResourceResponse(
            id=r.id,
            resource_uuid=r.resource_uuid,
            name=r.name,
            description=r.description,
            resource_type=r.resource_type,
            original_file_name=r.original_file_name,
            original_file_size=r.original_file_size,
            original_file_md5=r.original_file_md5,
            original_file_format=r.original_file_format,
            upload_status=r.upload_status.value if hasattr(r.upload_status, 'value') else r.upload_status,
            upload_message=r.upload_message,
            pvc_name=r.pvc_name,
            pvc_namespace=r.pvc_namespace,
            pvc_size=r.pvc_size,
            extract_path=r.extract_path,
            project_ids=[p.id for p in r.projects],
            resource_metadata=r.resource_metadata,
            created_by=r.created_by,
            created_at=r.created_at,
            updated_at=r.updated_at
        ))

    return ResourceListResponse(resources=resource_responses, total=len(resources))


@router.get("/resources/{resource_id}", response_model=ResourceResponse)
async def get_resource(
    resource_id: int,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取资源详情。"""
    resource = db.query(Resource).filter(Resource.id == resource_id).first()

    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")

    current_user, token = user_and_token

    # 验证项目访问权限（检查第一个关联项目）
    if resource.projects:
        has_access, _ = await validate_project_access(resource.projects[0].id, token)
        if not has_access:
            raise HTTPException(status_code=403, detail="No permission to access this project")

    return ResourceResponse(
        id=resource.id,
        resource_uuid=resource.resource_uuid,
        name=resource.name,
        description=resource.description,
        resource_type=resource.resource_type,
        original_file_name=resource.original_file_name,
        original_file_size=resource.original_file_size,
        original_file_md5=resource.original_file_md5,
        original_file_format=resource.original_file_format,
        upload_status=resource.upload_status.value if hasattr(resource.upload_status, 'value') else resource.upload_status,
        upload_message=resource.upload_message,
        pvc_name=resource.pvc_name,
        pvc_namespace=resource.pvc_namespace,
        pvc_size=resource.pvc_size,
        extract_path=resource.extract_path,
        project_ids=[p.id for p in resource.projects],
        resource_metadata=resource.resource_metadata,
        created_by=resource.created_by,
        created_at=resource.created_at,
        updated_at=resource.updated_at
    )


@router.delete("/resources/{resource_id}")
async def delete_resource(
    resource_id: int,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    删除资源（异步任务模式）。

    - 先检查关联的PVC是否被使用，如果被使用则不允许删除
    - 立即返回，创建异步删除任务在后台执行
    - 通过任务API查询删除进度
    """
    from app.tasks.worker import create_delete_resource_task

    resource = db.query(Resource).filter(Resource.id == resource_id).first()

    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")

    current_user, token = user_and_token

    # 验证项目访问权限
    if resource.projects:
        has_access, _ = await validate_project_access(resource.projects[0].id, token)
        if not has_access:
            raise HTTPException(status_code=403, detail="No permission to access this project")

    try:
        # 获取K8S服务
        k8s_service = get_k8s_service()

        # 确定项目ID和PVC信息
        project_id = None
        pvc_name = None
        pvc_namespace = None

        if resource.pvc_name:
            # 使用资源记录中存储的pvc_namespace来确定项目
            pvc_namespace = resource.pvc_namespace
            if pvc_namespace and pvc_namespace.startswith("secflow-"):
                project_id = pvc_namespace.replace("secflow-", "", 1)
            elif resource.projects:
                project_id = resource.projects[0].id

            if project_id:
                logger.info(f"Checking PVC {resource.pvc_name} in namespace {pvc_namespace} for deletion")
                in_use, message = k8s_service.check_pvc_in_use(project_id, resource.pvc_name)
                if in_use:
                    raise HTTPException(
                        status_code=409,
                        detail=f"Resource cannot be deleted: associated PVC is in use. {message}"
                    )
                pvc_name = resource.pvc_name
            else:
                logger.warning(f"Cannot determine project_id for PVC {resource.pvc_name}")

        # 检查是否已有正在运行的删除任务
        task_manager = get_task_manager()
        existing_tasks, _ = await task_manager.list_tasks(
            project_id=project_id or resource.projects[0].id if resource.projects else None,
            task_type=TaskType.DELETE,
            status=TaskStatus.RUNNING
        )
        for existing_task in existing_tasks:
            if existing_task.input_params and existing_task.input_params.get("resource_id") == resource_id:
                return {
                    "message": f"Delete task already exists for resource {resource_id}",
                    "task_id": existing_task.task_id,
                    "status": "already_pending"
                }

        # 创建异步删除任务
        task_id = await create_delete_resource_task(
            resource_id=resource_id,
            resource_uuid=resource.resource_uuid,
            resource_name=resource.name,
            project_id=project_id or (resource.projects[0].id if resource.projects else "unknown"),
            pvc_name=pvc_name,
            pvc_namespace=pvc_namespace,
            upload_file_uuid=resource.resource_uuid
        )

        return {
            "message": f"Delete task created for resource {resource_id}",
            "task_id": task_id,
            "status": "pending"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create delete task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============ 任务接口 ============

@router.get("/tasks/{task_id}", response_model=TaskResponse)
async def get_task(
    task_id: str,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取任务详情。"""
    task = db.query(AsyncTaskLog).filter(AsyncTaskLog.task_id == task_id).first()

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    current_user, token = user_and_token

    # 验证项目访问权限
    if task.project_id:
        has_access, _ = await validate_project_access(task.project_id, token)
        if not has_access:
            raise HTTPException(status_code=403, detail="No permission to access this task")

    return TaskResponse(
        task_id=task.task_id,
        task_uuid=task.task_uuid,
        resource_id=task.resource_id,
        project_id=task.project_id,
        task_type=task.task_type,
        status=task.status,
        progress=task.progress,
        message=task.message,
        error_message=task.error_message,
        input_params=task.input_params,
        result=task.result,
        created_k8s_resources=task.created_k8s_resources,
        started_at=task.started_at,
        finished_at=task.finished_at,
        created_at=task.created_at,
        updated_at=task.updated_at
    )


@router.get("/tasks/{task_id}/logs", response_model=TaskLogResponse)
async def get_task_logs(
    task_id: str,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取任务日志。"""
    task = db.query(AsyncTaskLog).filter(AsyncTaskLog.task_id == task_id).first()

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    current_user, token = user_and_token

    # 验证项目访问权限
    if task.project_id:
        has_access, _ = await validate_project_access(task.project_id, token)
        if not has_access:
            raise HTTPException(status_code=403, detail="No permission to access this task")

    task_manager = get_task_manager()
    logs = await task_manager.get_task_logs(task_id)

    return TaskLogResponse(task_id=task_id, logs=logs)


@router.get("/tasks", response_model=TaskListResponse)
async def list_tasks(
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    project_id: str = Query(..., description="项目ID"),
    task_type: Optional[TaskType] = Query(None, description="任务类型筛选"),
    status: Optional[TaskStatus] = Query(None, description="状态筛选"),
    db: Session = Depends(get_db)
):
    """查询任务列表。"""
    current_user, token = user_and_token

    # 验证项目访问权限
    has_access, _ = await validate_project_access(project_id, token)
    if not has_access:
        raise HTTPException(status_code=403, detail="No permission to access this project")

    task_manager = get_task_manager()
    tasks, total = await task_manager.list_tasks(
        project_id=project_id,
        task_type=task_type,
        status=status
    )

    return TaskListResponse(tasks=tasks, total=total)


@router.delete("/tasks/{task_id}")
async def delete_task(
    task_id: str,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
):
    """
    删除任务记录。

    - 如果任务正在运行，会取消任务
    - 清理任务日志
    """
    task_manager = get_task_manager()
    success = await task_manager.delete_task(task_id)

    if not success:
        raise HTTPException(status_code=404, detail="Task not found")

    return {"message": f"Task {task_id} deleted successfully"}


# ============ PVC接口 ============

@router.get("/pvcs/statistics")
async def get_pvc_statistics(
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    project_id: Optional[str] = Query(None, description="项目ID（可选，不传则查询全部）")
):
    """
    获取PVC统计信息。

    - 传入project_id：返回指定项目的PVC统计
    - 不传project_id：返回所有SecFlow项目的PVC统计
    - 包括：PVC总数、总存储容量、各状态数量、涉及的项目数
    """
    k8s_service = get_k8s_service()
    stats = k8s_service.get_pvc_statistics(project_id)

    return {
        "total_pvcs": stats["total_pvcs"],
        "total_storage_gi": stats["total_storage_gi"],
        "status_counts": stats["status_counts"],
        "namespaces_count": stats["namespaces_count"]
    }


@router.get("/pvcs", response_model=PVCListResponse)
async def list_pvcs(
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    project_id: str = Query(..., description="项目ID"),
    db: Session = Depends(get_db)
):
    """
    查询项目的PVC列表。

    - 返回项目中所有关联的PVC
    - 包含PVC对应的资源信息（如果有）
    """
    current_user, token = user_and_token

    # 验证项目访问权限
    has_access, _ = await validate_project_access(project_id, token)
    if not has_access:
        raise HTTPException(status_code=403, detail="No permission to access this project")

    k8s_service = get_k8s_service()
    pvcs = k8s_service.list_pvcs(project_id)

    # 查询该项目下所有资源，建立 pvc_name -> resource 的映射
    project_record = db.query(Project).filter(Project.id == project_id).first()
    pvc_to_resource = {}
    if project_record:
        for resource in project_record.resources:
            if resource.pvc_name:
                pvc_to_resource[resource.pvc_name] = resource

    result = []
    for pvc in pvcs:
        pvc_name = (pvc.get("name") or "").strip()
        if not pvc_name:
            continue
        resource = pvc_to_resource.get(pvc_name)
        namespace = (pvc.get("namespace") or k8s_service.get_project_namespace(project_id)).strip() or k8s_service.get_project_namespace(project_id)
        capacity = str(pvc.get("capacity") or "0Gi").strip() or "0Gi"
        status = str(pvc.get("status") or "Unknown").strip() or "Unknown"
        storage_class = str(pvc.get("storage_class") or "n/a").strip() or "n/a"

        result.append(PVCInfoResponse(
            pvc_name=pvc_name,
            namespace=namespace,
            capacity=capacity,
            status=status,
            storage_class=storage_class,
            resource_id=resource.id if resource else None,
            resource_name=resource.name if resource else None,
            resource_type=resource.resource_type.value if resource else None
        ))

    return PVCListResponse(pvcs=result, total=len(result))


# ============ OutputPVC接口 ============

@router.post("/output-pvc", response_model=OutputPVCCreateResponse, status_code=201)
async def create_output_pvc(
    request: OutputPVCCreateRequest,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    创建输出PVC资源。

    - 只需要指定PVC名称和大小
    - 自动创建K8S PVC
    - 创建资源记录关联到项目
    - 返回资源ID和PVC信息
    """
    current_user, token = user_and_token

    # 验证项目访问权限
    has_access, project = await validate_project_access(request.project_id, token)
    if not has_access:
        raise HTTPException(status_code=403, detail="No permission to access this project")

    k8s_service = get_k8s_service()

    # 从配置中获取 storage_class
    config = get_config()
    storage_class = config.get("k8s", {}).get("storage_class_name") or k8s_service.storage_class_name
    logger.info(
        "Creating output PVC with storageClassName=%s (project_id=%s)",
        storage_class,
        request.project_id,
    )

    # 生成资源UUID
    resource_uuid = str(uuid.uuid4())

    # 生成PVC名称
    pvc_name = k8s_service.get_pvc_name(resource_uuid)
    namespace = k8s_service.get_project_namespace(request.project_id)

    # 创建PVC
    created_pvc = k8s_service.create_pvc(
        project_id=request.project_id,
        pvc_name=pvc_name,
        size=request.pvc_size,
        storage_class=storage_class
    )

    if not created_pvc:
        raise HTTPException(status_code=500, detail="Failed to create PVC")

    # 获取或创建项目记录
    project_record = db.query(Project).filter(Project.id == request.project_id).first()
    if not project_record:
        # 从project服务获取项目信息并创建本地记录
        project_service = get_project_service()
        project_info = await project_service.get_project_info(request.project_id, token)
        project_record = Project(
            id=request.project_id,
            name=project_info.get("name", request.project_id),
            description=project_info.get("description"),
            owner_id=project_info.get("owner_id", str(current_user.id)),
            owner_name=project_info.get("owner_name"),
            k8s_namespace=namespace,
            status="active"
        )
        db.add(project_record)

    # 创建资源记录
    resource = Resource(
        resource_uuid=resource_uuid,
        name=request.name,
        description=request.description,
        resource_type=ResourceType.OUTPUT_PVC,
        original_file_name="output_pvc",  # OUTPUT_PVC没有原始文件
        original_file_size=0,
        original_file_format=None,
        upload_status=ResourceUploadStatus.COMPLETED,  # PVC直接创建完成
        upload_message="PVC created successfully",
        pvc_name=pvc_name,
        pvc_namespace=namespace,
        pvc_size=f"{request.pvc_size}Gi",
        extract_path="/",  # 根目录
        created_by=str(current_user.id)
    )
    resource.projects.append(project_record)
    db.add(resource)
    db.commit()
    db.refresh(resource)

    return OutputPVCCreateResponse(
        resource_id=resource.id,
        resource_uuid=resource_uuid,
        pvc_name=pvc_name,
        namespace=namespace,
        capacity=f"{request.pvc_size}Gi",
        message=f"Output PVC '{request.name}' created successfully"
    )


@router.delete("/output-pvc/{resource_id}")
async def delete_output_pvc(
    resource_id: int,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    删除输出PVC资源（异步任务模式）。

    - 检查PVC是否被使用（被Pod挂载或Job使用）
    - 如果被使用，禁止删除并返回409错误
    - 如果未被使用，创建异步删除任务在后台执行
    - 通过任务API查询删除进度
    """
    resource = _resolve_output_pvc_resource(db, resource_id)

    current_user, token = user_and_token

    # 验证项目访问权限
    if resource.projects:
        has_access, _ = await validate_project_access(resource.projects[0].id, token)
        if not has_access:
            raise HTTPException(status_code=403, detail="No permission to access this project")

    # 确定项目ID
    pvc_namespace = resource.pvc_namespace
    project_id = _resolve_resource_project_id(resource)

    k8s_service = get_k8s_service()
    get_pvc_browser_service().cleanup_browser_pod(project_id)

    # 检查PVC是否被使用
    if resource.pvc_name:
        in_use, message = k8s_service.check_pvc_in_use(project_id, resource.pvc_name)
        if in_use:
            raise HTTPException(
                status_code=409,
                detail=f"Cannot delete output PVC: {message}"
            )

    # 检查是否已有正在运行的删除任务
    task_manager = get_task_manager()
    existing_tasks, _ = await task_manager.list_tasks(
        project_id=project_id,
        task_type=TaskType.DELETE,
        status=TaskStatus.RUNNING
    )
    for existing_task in existing_tasks:
        if existing_task.input_params and existing_task.input_params.get("resource_id") == resource_id:
            return {
                "message": f"Delete task already exists for output PVC resource {resource_id}",
                "task_id": existing_task.task_id,
                "status": "already_pending"
            }

    # 创建异步删除任务
    task_id = await create_delete_resource_task(
        resource_id=resource_id,
        resource_uuid=resource.resource_uuid,
        resource_name=resource.name,
        project_id=project_id,
        pvc_name=resource.pvc_name,
        pvc_namespace=pvc_namespace,
        upload_file_uuid=None  # OUTPUT_PVC 没有上传文件
    )

    return {
        "message": f"Delete task created for output PVC resource {resource_id}",
        "task_id": task_id,
        "status": "pending"
    }


@router.get("/output-pvc/{resource_id}")
async def get_output_pvc(
    resource_id: int,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    获取输出PVC资源详情。

    - 返回PVC详细信息
    - 包含PVC使用状态
    """
    resource = _resolve_output_pvc_resource(db, resource_id)

    current_user, token = user_and_token

    # 验证项目访问权限
    if resource.projects:
        has_access, _ = await validate_project_access(resource.projects[0].id, token)
        if not has_access:
            raise HTTPException(status_code=403, detail="No permission to access this project")

    k8s_service = get_k8s_service()

    # 确定项目ID
    pvc_namespace = resource.pvc_namespace
    project_id = _resolve_resource_project_id(resource)

    # 获取PVC状态
    pvc_status = None
    in_use = False
    use_message = ""
    if project_id and resource.pvc_name:
        pvc_status = k8s_service.get_pvc_status(project_id, resource.pvc_name)
        in_use, use_message = k8s_service.check_pvc_in_use(project_id, resource.pvc_name)

    return {
        "id": resource.id,
        "resource_uuid": resource.resource_uuid,
        "name": resource.name,
        "description": resource.description,
        "resource_type": resource.resource_type.value if hasattr(resource.resource_type, 'value') else resource.resource_type,
        "pvc_name": resource.pvc_name,
        "pvc_namespace": resource.pvc_namespace,
        "pvc_size": resource.pvc_size,
        "status": resource.upload_status.value if hasattr(resource.upload_status, 'value') else resource.upload_status,
        "project_ids": [p.id for p in resource.projects],
        "pvc_k8s_status": pvc_status,
        "in_use": in_use,
        "use_message": use_message,
        "created_at": resource.created_at,
        "updated_at": resource.updated_at
    }


async def _load_output_pvc_with_access(
    resource_id: int,
    user_and_token: tuple[TokenPayload, str],
    db: Session,
) -> tuple[Resource, str, str]:
    resource = _resolve_output_pvc_resource(db, resource_id)
    current_user, token = user_and_token
    if resource.projects:
        has_access, _ = await validate_project_access(resource.projects[0].id, token)
        if not has_access:
            raise HTTPException(status_code=403, detail="No permission to access this project")
    project_id = _resolve_resource_project_id(resource)
    if not resource.pvc_name:
        raise HTTPException(status_code=409, detail="Output PVC is missing pvc_name")
    return resource, project_id, token


async def _load_pvc_resource_with_access(
    resource_id: int,
    user_and_token: tuple[TokenPayload, str],
    db: Session,
) -> tuple[Resource, str, str]:
    resource = _resolve_pvc_resource(db, resource_id)
    current_user, token = user_and_token
    if resource.projects:
        has_access, _ = await validate_project_access(resource.projects[0].id, token)
        if not has_access:
            raise HTTPException(status_code=403, detail="No permission to access this project")
    project_id = _resolve_resource_project_id(resource)
    return resource, project_id, token


@router.post("/resources/pvc-manual", response_model=ManualPVCCreateResponse, status_code=201)
async def create_manual_pvc_resource(
    request: ManualPVCCreateRequest,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    手动创建PVC资源（支持所有资源类型）。
    """
    current_user, token = user_and_token

    has_access, _ = await validate_project_access(request.project_id, token)
    if not has_access:
        raise HTTPException(status_code=403, detail="No permission to access this project")

    k8s_service = get_k8s_service()
    config = get_config()
    storage_class = config.get("k8s", {}).get("storage_class_name") or k8s_service.storage_class_name
    resource_uuid = str(uuid.uuid4())
    pvc_name = k8s_service.get_pvc_name(resource_uuid)
    namespace = k8s_service.get_project_namespace(request.project_id)

    created_pvc = k8s_service.create_pvc(
        project_id=request.project_id,
        pvc_name=pvc_name,
        size=request.pvc_size,
        storage_class=storage_class
    )
    if not created_pvc:
        raise HTTPException(status_code=500, detail="Failed to create PVC")

    project_record = db.query(Project).filter(Project.id == request.project_id).first()
    if not project_record:
        project_service = get_project_service()
        project_info = await project_service.get_project_info(request.project_id, token)
        project_record = Project(
            id=request.project_id,
            name=project_info.get("name", request.project_id),
            description=project_info.get("description"),
            owner_id=project_info.get("owner_id", str(current_user.id)),
            owner_name=project_info.get("owner_name"),
            k8s_namespace=namespace,
            status="active"
        )
        db.add(project_record)

    resource = Resource(
        resource_uuid=resource_uuid,
        name=request.name,
        description=request.description,
        resource_type=request.resource_type,
        original_file_name="manual_pvc",
        original_file_size=0,
        original_file_format=None,
        upload_status=ResourceUploadStatus.COMPLETED,
        upload_message="Manual PVC created successfully",
        pvc_name=pvc_name,
        pvc_namespace=namespace,
        pvc_size=f"{request.pvc_size}Gi",
        extract_path="/",
        created_by=str(current_user.id)
    )
    resource.projects.append(project_record)
    db.add(resource)
    db.commit()
    db.refresh(resource)

    return ManualPVCCreateResponse(
        resource_id=resource.id,
        resource_uuid=resource_uuid,
        resource_type=request.resource_type,
        pvc_name=pvc_name,
        namespace=namespace,
        capacity=f"{request.pvc_size}Gi",
        message=f"Manual PVC '{request.name}' created successfully"
    )


@router.get("/resources/{resource_id}/pvc-detail")
async def get_resource_pvc_detail(
    resource_id: int,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    resource, project_id, _ = await _load_pvc_resource_with_access(resource_id, user_and_token, db)
    k8s_service = get_k8s_service()
    pvc_status = k8s_service.get_pvc_status(project_id, resource.pvc_name)
    in_use, use_message = k8s_service.check_pvc_in_use(project_id, resource.pvc_name)
    return {
        "id": resource.id,
        "resource_uuid": resource.resource_uuid,
        "name": resource.name,
        "description": resource.description,
        "resource_type": resource.resource_type.value if hasattr(resource.resource_type, 'value') else resource.resource_type,
        "pvc_name": resource.pvc_name,
        "pvc_namespace": resource.pvc_namespace,
        "pvc_size": resource.pvc_size,
        "status": resource.upload_status.value if hasattr(resource.upload_status, 'value') else resource.upload_status,
        "project_ids": [p.id for p in resource.projects],
        "pvc_k8s_status": pvc_status,
        "in_use": in_use,
        "use_message": use_message,
        "created_at": resource.created_at,
        "updated_at": resource.updated_at
    }


@router.get("/resources/{resource_id}/browser/root", response_model=PvcBrowserRootResponse)
async def get_resource_pvc_browser_root(
    resource_id: int,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_pvc_resource_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    payload = browser.list_root(project_id, resource.pvc_name, resource.id)
    payload["pvc_name"] = resource.pvc_name
    return PvcBrowserRootResponse(**payload)


@router.get("/resources/{resource_id}/browser/tree", response_model=PvcBrowserRootResponse)
async def get_resource_pvc_browser_tree(
    resource_id: int,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_pvc_resource_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    payload = browser.list_tree(project_id, resource.pvc_name, resource.id)
    payload["pvc_name"] = resource.pvc_name
    return PvcBrowserRootResponse(**payload)


@router.get("/resources/{resource_id}/browser/children", response_model=PvcBrowserChildrenResponse)
async def get_resource_pvc_browser_children(
    resource_id: int,
    path: str = Query("/", description="目录路径"),
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_pvc_resource_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    payload = browser.list_children(project_id, resource.pvc_name, resource.id, path)
    payload["pvc_name"] = resource.pvc_name
    return PvcBrowserChildrenResponse(**payload)


@router.get("/resources/{resource_id}/browser/file", response_model=PvcBrowserFileResponse)
async def get_resource_pvc_browser_file(
    resource_id: int,
    path: str = Query(..., description="文件路径"),
    max_bytes: int = Query(1048576, ge=0, le=10485760, description="预览最大字节数"),
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_pvc_resource_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    payload = browser.read_file(project_id, resource.pvc_name, path, max_bytes=max_bytes)
    return PvcBrowserFileResponse(**payload)


@router.get("/resources/{resource_id}/browser/download")
async def download_resource_pvc_browser_file(
    resource_id: int,
    path: str = Query(..., description="文件路径"),
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_pvc_resource_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    payload = browser.read_file(project_id, resource.pvc_name, path, max_bytes=0)
    raw = base64.b64decode(payload.get("base64") or "")
    media_type = payload.get("content_type") or "application/octet-stream"
    filename = payload.get("filename") or "download.bin"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(iter([raw]), media_type=media_type, headers=headers)


@router.post("/resources/{resource_id}/browser/upload", response_model=PvcBrowserUploadResponse)
async def upload_resource_pvc_browser_file(
    resource_id: int,
    path: str = Form("/", description="目标目录路径"),
    file: UploadFile = File(...),
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_pvc_resource_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    payload = await browser.upload_file(project_id, resource.pvc_name, path, file)
    return PvcBrowserUploadResponse(**payload)


@router.post("/resources/{resource_id}/browser/directories")
async def create_resource_pvc_browser_directory(
    resource_id: int,
    request: OutputPVCBrowserCreateDirectoryRequest,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_pvc_resource_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    return browser.create_directory(project_id, resource.pvc_name, request.path, request.name)


@router.post("/resources/{resource_id}/browser/rename")
async def rename_resource_pvc_browser_node(
    resource_id: int,
    request: OutputPVCBrowserRenameRequest,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_pvc_resource_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    return browser.rename_node(project_id, resource.pvc_name, request.path, request.target_name)


@router.post("/resources/{resource_id}/browser/move")
async def move_resource_pvc_browser_node(
    resource_id: int,
    request: OutputPVCBrowserMoveRequest,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_pvc_resource_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    return browser.move_node(project_id, resource.pvc_name, request.path, request.target_path)


@router.delete("/resources/{resource_id}/browser/node")
async def delete_resource_pvc_browser_node(
    resource_id: int,
    path: str = Query(..., description="要删除的节点路径"),
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_pvc_resource_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    return browser.delete_node(project_id, resource.pvc_name, path)


@router.get("/output-pvc/{resource_id}/browser/root", response_model=PvcBrowserRootResponse)
async def get_output_pvc_browser_root(
    resource_id: int,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_output_pvc_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    payload = browser.list_root(project_id, resource.pvc_name, resource.id)
    payload["pvc_name"] = resource.pvc_name
    return PvcBrowserRootResponse(**payload)


@router.get("/output-pvc/{resource_id}/browser/tree", response_model=PvcBrowserRootResponse)
async def get_output_pvc_browser_tree(
    resource_id: int,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_output_pvc_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    payload = browser.list_tree(project_id, resource.pvc_name, resource.id)
    payload["pvc_name"] = resource.pvc_name
    return PvcBrowserRootResponse(**payload)


@router.get("/output-pvc/{resource_id}/browser/children", response_model=PvcBrowserChildrenResponse)
async def get_output_pvc_browser_children(
    resource_id: int,
    path: str = Query("/", description="目录路径"),
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_output_pvc_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    payload = browser.list_children(project_id, resource.pvc_name, resource.id, path)
    payload["pvc_name"] = resource.pvc_name
    return PvcBrowserChildrenResponse(**payload)


@router.get("/output-pvc/{resource_id}/browser/file", response_model=PvcBrowserFileResponse)
async def get_output_pvc_browser_file(
    resource_id: int,
    path: str = Query(..., description="文件路径"),
    max_bytes: int = Query(1048576, ge=0, le=10485760, description="预览最大字节数"),
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_output_pvc_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    payload = browser.read_file(project_id, resource.pvc_name, path, max_bytes=max_bytes)
    return PvcBrowserFileResponse(**payload)


@router.get("/output-pvc/{resource_id}/browser/download")
async def download_output_pvc_browser_file(
    resource_id: int,
    path: str = Query(..., description="文件路径"),
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_output_pvc_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    payload = browser.read_file(project_id, resource.pvc_name, path, max_bytes=0)
    raw = base64.b64decode(payload.get("base64") or "")
    media_type = payload.get("content_type") or "application/octet-stream"
    filename = payload.get("filename") or "download.bin"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(iter([raw]), media_type=media_type, headers=headers)


@router.post("/output-pvc/{resource_id}/browser/upload", response_model=PvcBrowserUploadResponse)
async def upload_output_pvc_browser_file(
    resource_id: int,
    path: str = Form("/", description="目标目录路径"),
    file: UploadFile = File(...),
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_output_pvc_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    payload = await browser.upload_file(project_id, resource.pvc_name, path, file)
    return PvcBrowserUploadResponse(**payload)


@router.post("/output-pvc/{resource_id}/browser/directories")
async def create_output_pvc_browser_directory(
    resource_id: int,
    request: OutputPVCBrowserCreateDirectoryRequest,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_output_pvc_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    return browser.create_directory(project_id, resource.pvc_name, request.path, request.name)


@router.post("/output-pvc/{resource_id}/browser/rename")
async def rename_output_pvc_browser_node(
    resource_id: int,
    request: OutputPVCBrowserRenameRequest,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_output_pvc_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    return browser.rename_node(project_id, resource.pvc_name, request.path, request.target_name)


@router.post("/output-pvc/{resource_id}/browser/move")
async def move_output_pvc_browser_node(
    resource_id: int,
    request: OutputPVCBrowserMoveRequest,
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_output_pvc_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    return browser.move_node(project_id, resource.pvc_name, request.path, request.target_path)


@router.delete("/output-pvc/{resource_id}/browser/node")
async def delete_output_pvc_browser_node(
    resource_id: int,
    path: str = Query(..., description="要删除的节点路径"),
    user_and_token: tuple[TokenPayload, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource, project_id, _ = await _load_output_pvc_with_access(resource_id, user_and_token, db)
    browser = get_pvc_browser_service()
    return browser.delete_node(project_id, resource.pvc_name, path)
