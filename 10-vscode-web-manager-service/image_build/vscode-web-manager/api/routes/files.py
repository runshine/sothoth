"""
文件下载API路由
"""
import os
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session

from config import Config
from database import get_db
from models import Project
from schemas.models import DownloadRequest, MultiDownloadRequest
from utils.auth_utils import get_current_user
from utils.file_utils import FileUtils

router = APIRouter()

@router.get("/projects/{project_id}/download")
async def download_file(
    project_id: str,
    file_path: str = Query(..., description="项目内相对文件路径"),
    user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    下载项目中的单个文件
    """
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在或无权访问")

    # 检查项目状态是否为就绪
    if project.status != Config.PROJECT_STATUS_READY:
        raise HTTPException(
            status_code=400,
            detail=f"项目状态为 {project.status}，无法下载文件。请等待项目初始化完成。"
        )

    # 检查项目解压路径是否存在
    if not project.extract_path or not os.path.exists(project.extract_path):
        raise HTTPException(status_code=404, detail="项目文件不存在")

    # 下载文件
    temp_path = FileUtils.download_file(project.extract_path, file_path, user.id)

    if not temp_path:
        raise HTTPException(status_code=404, detail="文件不存在或无法下载")

    # 获取文件名
    filename = os.path.basename(file_path)

    # 返回文件
    return FileResponse(
        path=temp_path,
        filename=filename,
        media_type="application/octet-stream"
    )

@router.get("/projects/{project_id}/download/dir")
async def download_directory(
    project_id: str,
    dir_path: str = Query(..., description="项目内相对目录路径"),
    user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    下载项目中的目录（打包为zip）
    """
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在或无权访问")

    # 检查项目状态是否为就绪
    if project.status != Config.PROJECT_STATUS_READY:
        raise HTTPException(
            status_code=400,
            detail=f"项目状态为 {project.status}，无法下载目录。请等待项目初始化完成。"
        )

    # 检查项目解压路径是否存在
    if not project.extract_path or not os.path.exists(project.extract_path):
        raise HTTPException(status_code=404, detail="项目文件不存在")

    # 下载目录（打包为zip）
    temp_path = FileUtils.download_directory(project.extract_path, dir_path, user.id)

    if not temp_path:
        raise HTTPException(status_code=404, detail="目录不存在或无法下载")

    # 获取目录名
    dir_name = os.path.basename(dir_path) or "root"
    filename = f"{dir_name}.zip"

    # 返回文件
    return FileResponse(
        path=temp_path,
        filename=filename,
        media_type="application/zip"
    )

@router.post("/projects/{project_id}/download/multiple")
async def download_multiple_files(
    project_id: str,
    download_request: MultiDownloadRequest,
    user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    下载项目中的多个文件（打包为zip）
    """
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在或无权访问")

    # 检查项目状态是否为就绪
    if project.status != Config.PROJECT_STATUS_READY:
        raise HTTPException(
            status_code=400,
            detail=f"项目状态为 {project.status}，无法下载文件。请等待项目初始化完成。"
        )

    # 检查项目解压路径是否存在
    if not project.extract_path or not os.path.exists(project.extract_path):
        raise HTTPException(status_code=404, detail="项目文件不存在")

    # 检查文件路径列表是否为空
    if not download_request.file_paths:
        raise HTTPException(status_code=400, detail="文件路径列表不能为空")

    # 下载多个文件（打包为zip）
    temp_path = FileUtils.download_project_files(
        project.extract_path,
        download_request.file_paths,
        user.id
    )

    if not temp_path:
        raise HTTPException(status_code=404, detail="文件不存在或无法下载")

    # 返回文件
    return FileResponse(
        path=temp_path,
        filename="selected_files.zip",
        media_type="application/zip"
    )

@router.get("/projects/{project_id}/download/stream")
async def download_file_stream(
    project_id: str,
    file_path: str = Query(..., description="项目内相对文件路径"),
    user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    流式下载项目中的文件（适用于大文件）
    """
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在或无权访问")

    # 检查项目状态是否为就绪
    if project.status != Config.PROJECT_STATUS_READY:
        raise HTTPException(
            status_code=400,
            detail=f"项目状态为 {project.status}，无法下载文件。请等待项目初始化完成。"
        )

    # 检查项目解压路径是否存在
    if not project.extract_path or not os.path.exists(project.extract_path):
        raise HTTPException(status_code=404, detail="项目文件不存在")

    # 检查路径安全性
    if not FileUtils.is_safe_path(project.extract_path, file_path):
        raise HTTPException(status_code=400, detail="文件路径不安全")

    # 构建完整文件路径
    full_path = os.path.join(project.extract_path, file_path)

    # 检查文件是否存在
    if not os.path.exists(full_path) or not os.path.isfile(full_path):
        raise HTTPException(status_code=404, detail="文件不存在")

    # 检查文件大小
    file_size = os.path.getsize(full_path)
    if file_size > Config.MAX_DOWNLOAD_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"文件太大，最大支持 {Config.MAX_DOWNLOAD_SIZE // (1024*1024)}MB"
        )

    # 获取文件名
    filename = os.path.basename(file_path)

    # 流式返回文件
    def file_generator():
        with open(full_path, "rb") as f:
            while chunk := f.read(8192):
                yield chunk

    return StreamingResponse(
        file_generator(),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Length": str(file_size)
        }
    )

@router.get("/projects/{project_id}/download/archive")
async def download_project_archive(
    project_id: str,
    user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    下载整个项目的原始压缩包
    """
    # 检查项目权限
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="项目不存在或无权访问")

    # 检查原始压缩包是否存在
    if not project.archive_path or not os.path.exists(project.archive_path):
        raise HTTPException(status_code=404, detail="项目压缩包不存在")

    # 获取原始文件名
    original_filename = project.original_filename
    if not original_filename:
        original_filename = f"{project.name}.zip"

    # 返回文件
    return FileResponse(
        path=project.archive_path,
        filename=original_filename,
        media_type="application/octet-stream"
    )

@router.get("/projects/{project_id}/download/archive-token")
async def download_project_archive_with_token(
    project_id: str,
    token: str = Query(..., description="下载令牌"),
    db: Session = Depends(get_db)
):
    """
    通过令牌下载项目压缩包（无需用户认证）
    """
    # 验证令牌
    if token != Config.ARCHIVE_DOWNLOAD_TOKEN:
        raise HTTPException(
            status_code=403,
            detail="无效的下载令牌"
        )

    # 获取项目
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    # 检查原始压缩包是否存在
    if not project.archive_path or not os.path.exists(project.archive_path):
        raise HTTPException(status_code=404, detail="项目压缩包不存在")

    # 获取原始文件名
    original_filename = project.original_filename
    if not original_filename:
        original_filename = f"{project.name}.zip"

    # 返回文件
    return FileResponse(
        path=project.archive_path,
        filename=original_filename,
        media_type="application/octet-stream"
    )