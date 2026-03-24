"""Fileserver API routes."""

import hashlib
import logging
import os
import tempfile
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, File, Form, Header, Query, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import ConflictError, ForbiddenError, NotFoundError, UnauthorizedError, ValidationError
from app.model import FileDirectory, FileSubproject, ManagedFile, get_db
from app.schemas import (
    DirectoryCreate,
    DirectoryResponse,
    DirectoryTreeItem,
    DirectoryTreeResponse,
    FileListResponse,
    FileMoveRequest,
    FileRenameRequest,
    FileResponse as ManagedFileResponse,
    SubprojectCreate,
    SubprojectListResponse,
    SubprojectResponse,
    SubprojectUpdate,
    SuccessResponse,
    TokenUser,
)
from app.service.auth import AuthServiceError, TokenInvalidError, get_auth_service
from app.service.project import ProjectServiceError, get_project_service


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/fileserver", tags=["fileserver"])


@router.get("/health")
async def health_check():
    return {"status": "ok", "service": "secflow-platform-fileserver"}


@router.get("/ready")
async def ready_check():
    return {"status": "ready"}


def sanitize_name(name: str) -> str:
    value = (name or "").strip()
    if not value:
        raise ValidationError("名称不能为空")
    if "/" in value or "\\" in value:
        raise ValidationError("名称不能包含路径分隔符")
    if value in {".", ".."}:
        raise ValidationError("名称不合法")
    return value


async def get_current_user(authorization: Optional[str] = Header(None)) -> TokenUser:
    if not authorization:
        raise UnauthorizedError("缺少Authorization头")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedError("Authorization格式错误，应为 Bearer <token>")

    token = parts[1]
    try:
        user = await get_auth_service().validate_token_async(token)
        return TokenUser(**user)
    except TokenInvalidError:
        raise UnauthorizedError("Token无效或已过期")
    except AuthServiceError as exc:
        raise UnauthorizedError(str(exc))


async def verify_project_access(project_id: str, authorization: Optional[str]) -> dict:
    if not authorization:
        raise UnauthorizedError("缺少Authorization头")
    parts = authorization.split()
    token = parts[1] if len(parts) == 2 else None
    if not token:
        raise UnauthorizedError("Authorization格式错误")
    try:
        project = await get_project_service().get_project(token, project_id)
    except ProjectServiceError as exc:
        raise ForbiddenError(str(exc))
    if not project:
        raise ForbiddenError(f"无权访问项目: {project_id}")
    return project


def require_subproject(db: Session, project_id: str, subproject_id: int) -> FileSubproject:
    subproject = db.query(FileSubproject).filter(
        FileSubproject.id == subproject_id,
        FileSubproject.project_id == project_id,
    ).first()
    if not subproject:
        raise NotFoundError("子项目", str(subproject_id))
    return subproject


def require_directory(
    db: Session,
    project_id: str,
    subproject_id: int,
    directory_id: Optional[int],
) -> Optional[FileDirectory]:
    if directory_id is None:
        return None
    directory = db.query(FileDirectory).filter(
        FileDirectory.id == directory_id,
        FileDirectory.project_id == project_id,
        FileDirectory.subproject_id == subproject_id,
    ).first()
    if not directory:
        raise NotFoundError("目录", str(directory_id))
    return directory


def require_file(db: Session, file_id: int) -> ManagedFile:
    file_record = db.query(ManagedFile).filter(ManagedFile.id == file_id).first()
    if not file_record:
        raise NotFoundError("文件", str(file_id))
    return file_record


def build_directory_path(parent: Optional[FileDirectory], name: str) -> str:
    if parent is None:
        return f"/{name}"
    return f"{parent.path_key.rstrip('/')}/{name}"


def build_directory_tree(directories: List[FileDirectory]) -> List[DirectoryTreeItem]:
    nodes: Dict[int, DirectoryTreeItem] = {}
    roots: List[DirectoryTreeItem] = []
    for directory in directories:
        nodes[directory.id] = DirectoryTreeItem(
            id=directory.id,
            name=directory.name,
            path_key=directory.path_key,
            parent_id=directory.parent_id,
            children=[],
        )
    for directory in directories:
        node = nodes[directory.id]
        if directory.parent_id and directory.parent_id in nodes:
            nodes[directory.parent_id].children.append(node)
        else:
            roots.append(node)
    return roots


def storage_relative_path(project_id: str, subproject_id: int, sha256: str, file_id: int, filename: str) -> str:
    safe_filename = filename.replace("/", "_").replace("\\", "_")
    return os.path.join(
        "files",
        project_id,
        str(subproject_id),
        sha256[:2],
        sha256[:4],
        f"{file_id}_{safe_filename}",
    )


def absolute_storage_path(storage_key: str) -> str:
    return os.path.join(get_config().storage.root_dir, storage_key)


async def persist_upload(upload: UploadFile, destination_dir: str) -> tuple[str, str, int]:
    sha256 = hashlib.sha256()
    total_size = 0
    fd, temp_path = tempfile.mkstemp(prefix="upload_", suffix=".part", dir=destination_dir)
    os.close(fd)
    try:
        with open(temp_path, "wb") as temp_file:
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                sha256.update(chunk)
                total_size += len(chunk)
                temp_file.write(chunk)
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise
    finally:
        await upload.close()
    return temp_path, sha256.hexdigest(), total_size


@router.post("/subprojects", response_model=SubprojectResponse)
async def create_subproject(
    payload: SubprojectCreate,
    current_user: TokenUser = Depends(get_current_user),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(payload.project_id, authorization)
    subproject = FileSubproject(
        project_id=payload.project_id,
        name=sanitize_name(payload.name),
        description=payload.description,
        created_by=str(current_user.id),
    )
    db.add(subproject)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ConflictError(f"子项目名称已存在: {payload.name}")
    db.refresh(subproject)
    return subproject


@router.get("/subprojects", response_model=SubprojectListResponse)
async def list_subprojects(
    project_id: str = Query(...),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(project_id, authorization)
    items = db.query(FileSubproject).filter(FileSubproject.project_id == project_id).order_by(FileSubproject.id.desc()).all()
    return SubprojectListResponse(total=len(items), items=items)


@router.get("/subprojects/{subproject_id}", response_model=SubprojectResponse)
async def get_subproject(
    subproject_id: int,
    project_id: str = Query(...),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(project_id, authorization)
    return require_subproject(db, project_id, subproject_id)


@router.put("/subprojects/{subproject_id}", response_model=SubprojectResponse)
async def update_subproject(
    subproject_id: int,
    payload: SubprojectUpdate,
    project_id: str = Query(...),
    current_user: TokenUser = Depends(get_current_user),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(project_id, authorization)
    subproject = require_subproject(db, project_id, subproject_id)
    if payload.name is not None:
        subproject.name = sanitize_name(payload.name)
    if payload.description is not None:
        subproject.description = payload.description
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ConflictError(f"子项目名称已存在: {payload.name}")
    db.refresh(subproject)
    return subproject


@router.delete("/subprojects/{subproject_id}", response_model=SuccessResponse)
async def delete_subproject(
    subproject_id: int,
    project_id: str = Query(...),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(project_id, authorization)
    subproject = require_subproject(db, project_id, subproject_id)
    file_count = db.query(ManagedFile).filter(ManagedFile.subproject_id == subproject_id).count()
    dir_count = db.query(FileDirectory).filter(FileDirectory.subproject_id == subproject_id).count()
    if file_count > 0 or dir_count > 0:
        raise ConflictError("子项目下仍存在目录或文件，无法删除")
    db.delete(subproject)
    db.commit()
    return SuccessResponse(message="子项目删除成功")


@router.post("/directories", response_model=DirectoryResponse)
async def create_directory(
    payload: DirectoryCreate,
    current_user: TokenUser = Depends(get_current_user),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(payload.project_id, authorization)
    require_subproject(db, payload.project_id, payload.subproject_id)
    parent = require_directory(db, payload.project_id, payload.subproject_id, payload.parent_id)
    directory_name = sanitize_name(payload.name)
    directory = FileDirectory(
        project_id=payload.project_id,
        subproject_id=payload.subproject_id,
        parent_id=payload.parent_id,
        name=directory_name,
        path_key=build_directory_path(parent, directory_name),
        created_by=str(current_user.id),
    )
    db.add(directory)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ConflictError(f"同级目录下名称已存在: {payload.name}")
    db.refresh(directory)
    return directory


@router.get("/directories/tree", response_model=DirectoryTreeResponse)
async def get_directory_tree(
    project_id: str = Query(...),
    subproject_id: int = Query(...),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(project_id, authorization)
    require_subproject(db, project_id, subproject_id)
    directories = db.query(FileDirectory).filter(
        FileDirectory.project_id == project_id,
        FileDirectory.subproject_id == subproject_id,
    ).order_by(FileDirectory.path_key.asc()).all()
    items = build_directory_tree(directories)
    return DirectoryTreeResponse(total=len(directories), items=items)


@router.post("/files/upload", response_model=ManagedFileResponse)
async def upload_file(
    project_id: str = Form(...),
    subproject_id: int = Form(...),
    directory_id: Optional[int] = Form(None),
    file: UploadFile = File(...),
    current_user: TokenUser = Depends(get_current_user),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(project_id, authorization)
    require_subproject(db, project_id, subproject_id)
    require_directory(db, project_id, subproject_id, directory_id)
    filename = sanitize_name(file.filename or "unnamed")

    config = get_config()
    temp_path, sha256, total_size = await persist_upload(file, config.storage.temp_dir)

    existing = db.query(ManagedFile).filter(
        ManagedFile.project_id == project_id,
        ManagedFile.subproject_id == subproject_id,
        ManagedFile.directory_id == directory_id,
        ManagedFile.filename == filename,
    ).first()
    if existing:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise ConflictError(f"目录下已存在同名文件: {filename}")

    file_record = ManagedFile(
        project_id=project_id,
        subproject_id=subproject_id,
        directory_id=directory_id,
        filename=filename,
        original_filename=filename,
        content_type=file.content_type,
        size=total_size,
        sha256=sha256,
        storage_key="pending",
        created_by=str(current_user.id),
    )
    db.add(file_record)
    db.flush()

    storage_key = storage_relative_path(project_id, subproject_id, sha256, file_record.id, filename)
    target_path = absolute_storage_path(storage_key)
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    os.replace(temp_path, target_path)

    file_record.storage_key = storage_key
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        if os.path.exists(target_path):
            os.remove(target_path)
        raise ConflictError(f"目录下已存在同名文件: {filename}")
    db.refresh(file_record)
    return file_record


@router.get("/files", response_model=FileListResponse)
async def list_files(
    project_id: str = Query(...),
    subproject_id: int = Query(...),
    directory_id: Optional[int] = Query(None),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(project_id, authorization)
    require_subproject(db, project_id, subproject_id)
    require_directory(db, project_id, subproject_id, directory_id)
    query = db.query(ManagedFile).filter(
        ManagedFile.project_id == project_id,
        ManagedFile.subproject_id == subproject_id,
    )
    if directory_id is None:
        query = query.filter(ManagedFile.directory_id.is_(None))
    else:
        query = query.filter(ManagedFile.directory_id == directory_id)
    items = query.order_by(ManagedFile.id.desc()).all()
    return FileListResponse(total=len(items), items=items)


@router.get("/files/{file_id}", response_model=ManagedFileResponse)
async def get_file_detail(
    file_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    file_record = require_file(db, file_id)
    await verify_project_access(file_record.project_id, authorization)
    return file_record


@router.get("/files/{file_id}/download")
async def download_file(
    file_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    file_record = require_file(db, file_id)
    await verify_project_access(file_record.project_id, authorization)
    file_path = absolute_storage_path(file_record.storage_key)
    if not os.path.exists(file_path):
        raise NotFoundError("物理文件", file_record.storage_key)
    return FileResponse(path=file_path, filename=file_record.filename, media_type=file_record.content_type or "application/octet-stream")


@router.post("/files/{file_id}/rename", response_model=ManagedFileResponse)
async def rename_file(
    file_id: int,
    payload: FileRenameRequest,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    file_record = require_file(db, file_id)
    await verify_project_access(file_record.project_id, authorization)
    new_name = sanitize_name(payload.filename)
    existing = db.query(ManagedFile).filter(
        ManagedFile.subproject_id == file_record.subproject_id,
        ManagedFile.directory_id == file_record.directory_id,
        ManagedFile.filename == new_name,
        ManagedFile.id != file_record.id,
    ).first()
    if existing:
        raise ConflictError(f"目录下已存在同名文件: {new_name}")

    old_path = absolute_storage_path(file_record.storage_key)
    new_storage_key = storage_relative_path(file_record.project_id, file_record.subproject_id, file_record.sha256, file_record.id, new_name)
    new_path = absolute_storage_path(new_storage_key)
    os.makedirs(os.path.dirname(new_path), exist_ok=True)
    if os.path.exists(old_path):
        os.replace(old_path, new_path)
    file_record.filename = new_name
    file_record.storage_key = new_storage_key
    db.commit()
    db.refresh(file_record)
    return file_record


@router.post("/files/{file_id}/move", response_model=ManagedFileResponse)
async def move_file(
    file_id: int,
    payload: FileMoveRequest,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    file_record = require_file(db, file_id)
    await verify_project_access(file_record.project_id, authorization)
    target_directory = require_directory(db, file_record.project_id, file_record.subproject_id, payload.target_directory_id)
    existing = db.query(ManagedFile).filter(
        ManagedFile.subproject_id == file_record.subproject_id,
        ManagedFile.directory_id == payload.target_directory_id,
        ManagedFile.filename == file_record.filename,
        ManagedFile.id != file_record.id,
    ).first()
    if existing:
        raise ConflictError(f"目标目录下已存在同名文件: {file_record.filename}")
    file_record.directory_id = target_directory.id if target_directory else None
    db.commit()
    db.refresh(file_record)
    return file_record


@router.delete("/files/{file_id}", response_model=SuccessResponse)
async def delete_file(
    file_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    file_record = require_file(db, file_id)
    await verify_project_access(file_record.project_id, authorization)
    file_path = absolute_storage_path(file_record.storage_key)
    db.delete(file_record)
    db.commit()
    if os.path.exists(file_path):
        os.remove(file_path)
    return SuccessResponse(message="文件删除成功")
