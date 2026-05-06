"""Fileserver API routes."""

from datetime import datetime, timezone
import hashlib
import logging
import mimetypes
import os
import posixpath
import shutil
import tempfile
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, File, Form, Header, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_config, get_data_nfs_base_path, get_data_nfs_server, get_data_pvc_name
from app.exception import ConflictError, ForbiddenError, NotFoundError, UnauthorizedError, ValidationError
from app.model import FileDirectory, FileSubproject, ManagedFile, get_db
from app.schemas import (
    DirectoryChildrenResponse,
    DirectoryCreate,
    DirectoryMoveRequest,
    DirectoryRenameRequest,
    DirectoryResponse,
    ExplorerBreadcrumbItem,
    ExplorerNode,
    ExplorerRootResponse,
    FilePreviewResponse,
    DirectoryTreeItem,
    DirectoryTreeResponse,
    FileListResponse,
    FileMoveRequest,
    FileRenameRequest,
    FileResponse as ManagedFileResponse,
    ProjectPathChildrenResponse,
    ProjectPathDirectoryCreate,
    ProjectPathDirectoryEntry,
    ProjectPathFileEntry,
    ProjectPathMkdirsRequest,
    ProjectPathOperationResponse,
    ProjectFilesystemBreadcrumbItem,
    ProjectFilesystemChildrenResponse,
    ProjectFilesystemDirectoryCreate,
    ProjectFilesystemEntry,
    ProjectFilesystemMoveRequest,
    ProjectFilesystemRenameRequest,
    ProjectFilesystemRootResponse,
    StoragePVCResponse,
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
SPECIAL_VULN_SUBPROJECT_NAME = "__vuln_cases__"


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


@router.get("/storage/pvc", response_model=StoragePVCResponse)
async def get_storage_pvc(
    current_user: TokenUser = Depends(get_current_user),
):
    return StoragePVCResponse(
        mount_path=get_config().storage.root_dir,
        pvc_name=get_data_pvc_name(),
        nfs_server=get_data_nfs_server(),
        nfs_base_path=get_data_nfs_base_path(),
    )


@router.get("/explorer/root", response_model=ExplorerRootResponse)
async def get_explorer_root(
    project_id: str = Query(...),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(project_id, authorization)
    subprojects = db.query(FileSubproject).filter(
        FileSubproject.project_id == project_id,
    ).order_by(FileSubproject.id.asc()).all()
    items: List[ExplorerNode] = []
    for subproject in subprojects:
        directories = db.query(FileDirectory).filter(
            FileDirectory.project_id == project_id,
            FileDirectory.subproject_id == subproject.id,
        ).order_by(FileDirectory.path_key.asc()).all()
        files = db.query(ManagedFile).filter(
            ManagedFile.project_id == project_id,
            ManagedFile.subproject_id == subproject.id,
        ).order_by(ManagedFile.filename.asc()).all()
        items.append(build_subproject_root_node(subproject, directories, files))
    return ExplorerRootResponse(
        project_id=project_id,
        root_name=project_id,
        total=len(items),
        items=items,
    )


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


def ensure_special_subproject(
    db: Session,
    project_id: str,
    *,
    name: str = SPECIAL_VULN_SUBPROJECT_NAME,
    created_by: str = "system",
) -> FileSubproject:
    subproject = db.query(FileSubproject).filter(
        FileSubproject.project_id == project_id,
        FileSubproject.name == name,
    ).first()
    if subproject:
        return subproject

    subproject = FileSubproject(
        project_id=project_id,
        name=name,
        description="漏洞疑点专用文件区",
        created_by=created_by,
    )
    db.add(subproject)
    db.flush()
    return subproject


def normalize_special_project_path(path: str) -> tuple[str, str, str]:
    relative_no_lead, normalized = normalize_sync_path(path)
    prefix = f"/{SPECIAL_VULN_SUBPROJECT_NAME}"
    if normalized != prefix and not normalized.startswith(prefix + "/"):
        raise ValidationError(f"路径必须位于 {prefix} 之下")
    special_relative = normalized[len(prefix):] or "/"
    return relative_no_lead, normalized, special_relative


def build_project_relative_directory_path(directory: Optional[FileDirectory]) -> str:
    if directory is None:
        return f"/{SPECIAL_VULN_SUBPROJECT_NAME}"
    return f"/{SPECIAL_VULN_SUBPROJECT_NAME}{directory.path_key}"


def build_project_relative_file_path(file_record: ManagedFile, directory: Optional[FileDirectory]) -> str:
    base = build_project_relative_directory_path(directory)
    if base == f"/{SPECIAL_VULN_SUBPROJECT_NAME}":
        return f"{base}/{file_record.filename}"
    return f"{base.rstrip('/')}/{file_record.filename}"


def split_special_relative_path(special_relative: str) -> list[str]:
    if special_relative in {"", "/"}:
        return []
    return [part for part in special_relative.strip("/").split("/") if part]


def ensure_directory_chain_by_parts(
    db: Session,
    project_id: str,
    subproject: FileSubproject,
    parts: list[str],
    *,
    created_by: str,
) -> Optional[FileDirectory]:
    parent: Optional[FileDirectory] = None
    current_path = ""
    for name in parts:
        current_path = f"{current_path}/{name}" if current_path else f"/{name}"
        directory = db.query(FileDirectory).filter(
            FileDirectory.project_id == project_id,
            FileDirectory.subproject_id == subproject.id,
            FileDirectory.path_key == current_path,
        ).first()
        if directory is None:
            directory = FileDirectory(
                project_id=project_id,
                subproject_id=subproject.id,
                parent_id=parent.id if parent else None,
                name=name,
                path_key=current_path,
                created_by=created_by,
            )
            db.add(directory)
            db.flush()
        parent = directory
    return parent


def lookup_directory_by_special_path(
    db: Session,
    project_id: str,
    subproject: FileSubproject,
    special_relative: str,
) -> Optional[FileDirectory]:
    parts = split_special_relative_path(special_relative)
    if not parts:
        return None
    return db.query(FileDirectory).filter(
        FileDirectory.project_id == project_id,
        FileDirectory.subproject_id == subproject.id,
        FileDirectory.path_key == f"/{'/'.join(parts)}",
    ).first()


def resolve_special_parent_and_filename(
    db: Session,
    project_id: str,
    subproject: FileSubproject,
    normalized_path: str,
    *,
    create_dirs: bool,
    created_by: str,
) -> tuple[Optional[FileDirectory], str]:
    _, _, special_relative = normalize_special_project_path(normalized_path)
    parts = split_special_relative_path(special_relative)
    if len(parts) < 2:
        raise ValidationError("文件路径至少需要包含 case_uuid 和文件名")
    parent_parts = parts[:-1]
    filename = sanitize_name(parts[-1])
    parent_dir = (
        ensure_directory_chain_by_parts(db, project_id, subproject, parent_parts, created_by=created_by)
        if create_dirs
        else lookup_directory_by_special_path(db, project_id, subproject, "/" + "/".join(parent_parts))
    )
    if parent_dir is None:
        raise NotFoundError("目录", "/" + "/".join(parent_parts))
    return parent_dir, filename


def remove_empty_special_parents(project_id: str, subproject_id: int, directory: Optional[FileDirectory]) -> None:
    current = directory
    root = sync_subproject_root(project_id, subproject_id)
    while current is not None:
        if (current.path_key or "").count("/") <= 1:
            break
        has_dirs = len(current.children)
        has_files = len(current.files)
        if has_dirs or has_files:
            break
        current_path = get_directory_storage_path(project_id, subproject_id, current)
        parent = current.parent
        if os.path.isdir(current_path):
            shutil.rmtree(current_path, ignore_errors=True)
            remove_empty_parents(current_path, root)
        current = parent


def to_project_path_directory_entry(directory: FileDirectory) -> ProjectPathDirectoryEntry:
    return ProjectPathDirectoryEntry(
        id=directory.id,
        name=directory.name,
        path=build_project_relative_directory_path(directory),
        created_at=directory.created_at,
        updated_at=directory.updated_at,
    )


def to_project_path_file_entry(file_record: ManagedFile, directory: Optional[FileDirectory]) -> ProjectPathFileEntry:
    return ProjectPathFileEntry(
        id=file_record.id,
        filename=file_record.filename,
        original_filename=file_record.original_filename,
        path=build_project_relative_file_path(file_record, directory),
        content_type=file_record.content_type,
        size=file_record.size,
        sha256=file_record.sha256,
        storage_key=file_record.storage_key,
        created_at=file_record.created_at,
        updated_at=file_record.updated_at,
    )


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


def guess_content_type(filename: str, current_type: Optional[str]) -> str:
    if current_type:
        return current_type
    guessed, _ = mimetypes.guess_type(filename)
    return guessed or "application/octet-stream"


def get_directory_storage_path(project_id: str, subproject_id: int, directory: Optional[FileDirectory]) -> str:
    base = sync_subproject_root(project_id, subproject_id)
    relative = normalize_directory_path(directory)
    return os.path.join(base, relative) if relative else base


def build_breadcrumbs(
    project_id: str,
    subproject: FileSubproject,
    directory: Optional[FileDirectory],
) -> List[ExplorerBreadcrumbItem]:
    breadcrumbs = [
        ExplorerBreadcrumbItem(node_type="project", id=f"project:{project_id}", name=project_id),
        ExplorerBreadcrumbItem(
            node_type="subproject",
            id=f"subproject:{subproject.id}",
            name=subproject.name,
            subproject_id=subproject.id,
        ),
    ]
    if directory is None:
        return breadcrumbs

    chain: List[FileDirectory] = []
    current = directory
    while current is not None:
        chain.append(current)
        current = current.parent
    for item in reversed(chain):
        breadcrumbs.append(
            ExplorerBreadcrumbItem(
                node_type="directory",
                id=f"directory:{item.id}",
                name=item.name,
                subproject_id=item.subproject_id,
                directory_id=item.id,
            )
        )
    return breadcrumbs


def directory_to_explorer_node(directory: FileDirectory) -> ExplorerNode:
    return ExplorerNode(
        node_type="directory",
        id=f"directory:{directory.id}",
        name=directory.name,
        project_id=directory.project_id,
        subproject_id=directory.subproject_id,
        directory_id=directory.id,
        parent_directory_id=directory.parent_id,
        path_key=directory.path_key,
        updated_at=directory.updated_at,
        has_children=True,
    )


def file_to_explorer_node(file_record: ManagedFile) -> ExplorerNode:
    return ExplorerNode(
        node_type="file",
        id=f"file:{file_record.id}",
        name=file_record.filename,
        project_id=file_record.project_id,
        subproject_id=file_record.subproject_id,
        directory_id=file_record.directory_id,
        file_id=file_record.id,
        parent_directory_id=file_record.directory_id,
        path_key=file_record.storage_key,
        content_type=file_record.content_type,
        size=file_record.size,
        updated_at=file_record.updated_at,
        has_children=False,
    )


def build_subproject_root_node(
    subproject: FileSubproject,
    directories: List[FileDirectory],
    files: List[ManagedFile],
) -> ExplorerNode:
    child_nodes = [directory_to_explorer_node(item) for item in directories if item.parent_id is None]
    child_nodes.extend(file_to_explorer_node(item) for item in files if item.directory_id is None)
    child_nodes.sort(key=lambda item: (0 if item.node_type != "file" else 1, item.name.lower()))
    return ExplorerNode(
        node_type="subproject",
        id=f"subproject:{subproject.id}",
        name=subproject.name,
        project_id=subproject.project_id,
        subproject_id=subproject.id,
        path_key=f"/{subproject.id}",
        updated_at=subproject.updated_at,
        special_badge="SUBPROJECT",
        has_children=bool(child_nodes),
        children=child_nodes,
    )


def ensure_no_descendant_move(directory: FileDirectory, target_parent: Optional[FileDirectory]):
    if target_parent is None:
        return
    if target_parent.id == directory.id:
        raise ConflictError("目录不能移动到自身下")
    source_prefix = f"{directory.path_key.rstrip('/')}/"
    if (target_parent.path_key or "").startswith(source_prefix):
        raise ConflictError("目录不能移动到自己的子目录下")


def update_directory_subtree_paths(db: Session, root_directory: FileDirectory):
    directories = db.query(FileDirectory).filter(
        FileDirectory.subproject_id == root_directory.subproject_id,
    ).all()
    by_parent: Dict[Optional[int], List[FileDirectory]] = {}
    for item in directories:
        by_parent.setdefault(item.parent_id, []).append(item)

    def walk(node: FileDirectory, parent_path: Optional[str]):
        node.path_key = f"/{node.name}" if not parent_path else f"{parent_path.rstrip('/')}/{node.name}"
        for child in by_parent.get(node.id, []):
            walk(child, node.path_key)

    walk(root_directory, root_directory.parent.path_key if root_directory.parent else None)


def refresh_file_storage_keys(db: Session, subproject_id: int):
    files = db.query(ManagedFile).filter(ManagedFile.subproject_id == subproject_id).all()
    for item in files:
        item.storage_key = storage_relative_path(item.project_id, item.subproject_id, item.directory, item.filename)


def remove_empty_parents(path: str, stop_path: str):
    current = os.path.dirname(path)
    stop = os.path.abspath(stop_path)
    while os.path.abspath(current).startswith(stop) and os.path.abspath(current) != stop:
        try:
            os.rmdir(current)
        except OSError:
            break
        current = os.path.dirname(current)


def delete_subproject_contents(db: Session, project_id: str, subproject_id: int):
    directories = db.query(FileDirectory).filter(
        FileDirectory.project_id == project_id,
        FileDirectory.subproject_id == subproject_id,
    ).all()
    directory_ids = [item.id for item in directories]
    if directory_ids:
        db.query(ManagedFile).filter(
            ManagedFile.project_id == project_id,
            ManagedFile.subproject_id == subproject_id,
            ManagedFile.directory_id.in_(directory_ids),
        ).delete(synchronize_session=False)
        db.query(FileDirectory).filter(
            FileDirectory.id.in_(directory_ids),
        ).delete(synchronize_session=False)

    db.query(ManagedFile).filter(
        ManagedFile.project_id == project_id,
        ManagedFile.subproject_id == subproject_id,
        ManagedFile.directory_id.is_(None),
    ).delete(synchronize_session=False)


def preview_mode_for_file(file_record: ManagedFile) -> str:
    content_type = guess_content_type(file_record.filename, file_record.content_type)
    if content_type.startswith("text/"):
        return "text"
    if content_type in {"application/json", "application/xml", "application/javascript"}:
        return "text"
    if content_type.startswith("image/"):
        return "image"
    if content_type == "application/pdf":
        return "pdf"
    if content_type.startswith("audio/"):
        return "audio"
    if content_type.startswith("video/"):
        return "video"
    extension = file_record.filename.rsplit(".", 1)[-1].lower() if "." in file_record.filename else ""
    if extension in {"yml", "yaml", "md", "log", "csv", "sql", "sh", "py", "java", "go", "ts", "js", "tsx", "jsx", "xml"}:
        return "text"
    return "binary"


def normalize_directory_path(directory: Optional[FileDirectory]) -> str:
    if directory is None or not directory.path_key:
        return ""
    return directory.path_key.strip("/")


def storage_relative_path(
    project_id: str,
    subproject_id: int,
    directory: Optional[FileDirectory],
    filename: str,
) -> str:
    parts = ["files", project_id, str(subproject_id)]
    directory_path = normalize_directory_path(directory)
    if directory_path:
        parts.extend(part for part in directory_path.split("/") if part)
    parts.append(filename.replace("/", "_").replace("\\", "_"))
    return os.path.join(*parts)


def absolute_storage_path(storage_key: str) -> str:
    return os.path.join(get_config().storage.root_dir, storage_key)


def sync_subproject_root(project_id: str, subproject_id: Any) -> str:
    normalized_subproject = normalize_sync_subproject_id(subproject_id)
    return os.path.join(get_config().storage.root_dir, "files", project_id, normalized_subproject)


def normalize_sync_subproject_id(subproject_id: Any) -> str:
    text = str(subproject_id or "").strip()
    if not text:
        raise ValidationError("subproject_id不能为空")
    if text in {".", ".."}:
        raise ValidationError("subproject_id非法")
    if "/" in text or "\\" in text:
        raise ValidationError("subproject_id不能包含路径分隔符")
    return text


def normalize_sync_path(path: str) -> tuple[str, str]:
    raw = (path or "").strip()
    if not raw:
        raise ValidationError("同步路径不能为空")
    normalized = posixpath.normpath(raw)
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    if normalized == "/":
        return "", "/"
    if normalized.startswith("/../") or normalized == "/..":
        raise ValidationError("同步路径不能越权")
    return normalized.lstrip("/"), normalized


def sync_target_path(project_id: str, subproject_id: Any, relative_path: str) -> str:
    relative_no_lead, _ = normalize_sync_path(relative_path)
    return os.path.join(sync_subproject_root(project_id, subproject_id), relative_no_lead)


def project_files_root(project_id: str) -> str:
    root = os.path.join(get_config().storage.root_dir, "files", project_id)
    os.makedirs(root, exist_ok=True)
    return root


def normalize_project_filesystem_path(path: str) -> tuple[str, str]:
    raw = (path or "").strip() or "/"
    normalized = posixpath.normpath(raw)
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    if normalized.startswith("/../") or normalized == "/..":
        raise ValidationError("项目路径不能越权")
    if normalized == "//":
        normalized = "/"
    return normalized.lstrip("/"), normalized


def project_filesystem_target_path(project_id: str, path: str) -> tuple[str, str]:
    relative_no_lead, normalized = normalize_project_filesystem_path(path)
    root = os.path.abspath(project_files_root(project_id))
    target_path = os.path.abspath(os.path.join(root, relative_no_lead))
    if os.path.commonpath([target_path, root]) != root:
        raise ValidationError("项目路径不能越权")
    return target_path, normalized


def ensure_project_realpath_inside_root(project_id: str, target_path: str) -> str:
    root = os.path.realpath(project_files_root(project_id))
    resolved = os.path.realpath(target_path)
    if os.path.commonpath([resolved, root]) != root:
        raise ForbiddenError("项目路径超出允许范围")
    return resolved


def path_parent(path: str) -> str:
    _, normalized = normalize_project_filesystem_path(path)
    if normalized == "/":
        return "/"
    parent = posixpath.dirname(normalized.rstrip("/")) or "/"
    return parent if parent.startswith("/") else f"/{parent}"


def path_basename(path: str) -> str:
    _, normalized = normalize_project_filesystem_path(path)
    if normalized == "/":
        return "/"
    return posixpath.basename(normalized.rstrip("/"))


def is_root_level_directory(path: str) -> bool:
    _, normalized = normalize_project_filesystem_path(path)
    parts = [item for item in normalized.strip("/").split("/") if item]
    return len(parts) == 1


def infer_preview_mode_by_filename(filename: str, content_type: Optional[str]) -> str:
    guessed = guess_content_type(filename, content_type)
    if guessed.startswith("text/"):
        return "text"
    if guessed in {"application/json", "application/xml", "application/javascript"}:
        return "text"
    if guessed.startswith("image/"):
        return "image"
    if guessed == "application/pdf":
        return "pdf"
    if guessed.startswith("audio/"):
        return "audio"
    if guessed.startswith("video/"):
        return "video"
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if extension in {"yml", "yaml", "md", "log", "csv", "sql", "sh", "py", "java", "go", "ts", "js", "tsx", "jsx", "xml", "json", "txt"}:
        return "text"
    return "binary"


def safe_dir_has_children(path: str) -> bool:
    try:
        with os.scandir(path) as iterator:
            for _ in iterator:
                return True
    except OSError:
        return False
    return False


def to_project_filesystem_entry(parent_path: str, entry: os.DirEntry[str], *, root_level: bool) -> ProjectFilesystemEntry:
    child_path = "/" + entry.name if parent_path == "/" else f"{parent_path.rstrip('/')}/{entry.name}"
    node_type = "file"
    has_children = False
    content_type: Optional[str] = None
    size: Optional[int] = None
    special_badge: Optional[str] = None

    try:
        stat_result = entry.stat(follow_symlinks=False)
    except OSError:
        stat_result = None

    if entry.is_dir(follow_symlinks=False):
        node_type = "subproject" if root_level else "directory"
        has_children = safe_dir_has_children(entry.path)
        if root_level:
            special_badge = "SUBPROJECT"
    else:
        content_type = guess_content_type(entry.name, None)
        size = stat_result.st_size if stat_result else None

    updated_at = (
        datetime.fromtimestamp(stat_result.st_mtime, tz=timezone.utc)
        if stat_result is not None
        else None
    )
    return ProjectFilesystemEntry(
        node_type=node_type,
        name=entry.name,
        path=child_path,
        content_type=content_type,
        size=size,
        updated_at=updated_at,
        has_children=has_children,
        special_badge=special_badge,
    )


def list_project_filesystem_entries(project_id: str, path: str) -> tuple[str, str, list[ProjectFilesystemEntry], list[ProjectFilesystemEntry]]:
    target_path, normalized = project_filesystem_target_path(project_id, path)
    if not os.path.exists(target_path):
        raise NotFoundError("项目目录", normalized)
    if not os.path.isdir(target_path):
        raise ValidationError("当前路径不是目录")
    ensure_project_realpath_inside_root(project_id, target_path)

    directories: list[ProjectFilesystemEntry] = []
    files: list[ProjectFilesystemEntry] = []
    with os.scandir(target_path) as iterator:
        for entry in iterator:
            item = to_project_filesystem_entry(normalized, entry, root_level=(normalized == "/"))
            if item.node_type in {"subproject", "directory"}:
                directories.append(item)
            else:
                files.append(item)

    directories.sort(key=lambda item: item.name.lower())
    files.sort(key=lambda item: item.name.lower())
    current_name = project_id if normalized == "/" else path_basename(normalized)
    return target_path, current_name, directories, files


def build_project_filesystem_breadcrumbs(project_id: str, path: str) -> list[ProjectFilesystemBreadcrumbItem]:
    _, normalized = normalize_project_filesystem_path(path)
    breadcrumbs = [ProjectFilesystemBreadcrumbItem(node_type="project", name=project_id, path="/")]
    if normalized == "/":
        return breadcrumbs
    parts = [item for item in normalized.strip("/").split("/") if item]
    current = ""
    for index, part in enumerate(parts):
        current = f"{current}/{part}" if current else f"/{part}"
        breadcrumbs.append(
            ProjectFilesystemBreadcrumbItem(
                node_type="subproject" if index == 0 else "directory",
                name=part,
                path=current,
            )
        )
    return breadcrumbs


def load_project_filesystem_entry(project_id: str, path: str) -> ProjectFilesystemEntry:
    target_path, normalized = project_filesystem_target_path(project_id, path)
    if not os.path.lexists(target_path):
        raise NotFoundError("项目文件", normalized)
    ensure_project_realpath_inside_root(project_id, path_parent(normalized) == "/" and target_path or os.path.dirname(target_path))
    stat_result = os.lstat(target_path)
    is_directory = os.path.isdir(target_path) and not os.path.islink(target_path)
    node_type = "subproject" if is_directory and is_root_level_directory(normalized) else ("directory" if is_directory else "file")
    return ProjectFilesystemEntry(
        node_type=node_type,
        name=path_basename(normalized),
        path=normalized,
        content_type=None if is_directory else guess_content_type(path_basename(normalized), None),
        size=None if is_directory else stat_result.st_size,
        updated_at=datetime.fromtimestamp(stat_result.st_mtime, tz=timezone.utc),
        has_children=safe_dir_has_children(target_path) if is_directory else False,
        special_badge="SUBPROJECT" if node_type == "subproject" else None,
    )


def compute_existing_sync_meta(target_path: str) -> dict[str, Any]:
    if not os.path.lexists(target_path):
        return {"exists": False}
    if os.path.islink(target_path):
        return {
            "exists": True,
            "entry_type": "symlink",
            "symlink_target": os.readlink(target_path),
            "size": 0,
            "sha256": "",
        }
    if os.path.isdir(target_path):
        return {
            "exists": True,
            "entry_type": "directory",
            "size": 0,
            "sha256": "",
        }
    sha256 = hashlib.sha256()
    total = 0
    with open(target_path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            sha256.update(chunk)
            total += len(chunk)
    return {
        "exists": True,
        "entry_type": "file",
        "size": total,
        "sha256": sha256.hexdigest(),
    }


def build_sync_headers(meta: dict[str, Any]) -> dict[str, str]:
    if not meta.get("exists"):
        return {
            "X-Sync-Exists": "false",
        }
    headers = {
        "X-Sync-Exists": "true",
        "X-Sync-Entry-Type": str(meta.get("entry_type") or ""),
        "X-Sync-Size": str(meta.get("size") or 0),
        "X-Sync-Sha256": str(meta.get("sha256") or ""),
    }
    if meta.get("symlink_target") is not None:
        headers["X-Sync-Symlink-Target"] = str(meta.get("symlink_target") or "")
    return headers


async def persist_sync_stream(request: Request, destination_path: str) -> tuple[str, str, int]:
    sha256 = hashlib.sha256()
    total_size = 0
    parent_dir = os.path.dirname(destination_path)
    os.makedirs(parent_dir, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix="sync_", suffix=".part", dir=parent_dir)
    os.close(fd)
    try:
        with open(temp_path, "wb") as temp_file:
            async for chunk in request.stream():
                if not chunk:
                    continue
                sha256.update(chunk)
                total_size += len(chunk)
                temp_file.write(chunk)
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise
    return temp_path, sha256.hexdigest(), total_size


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


@router.head("/sync/root/{project_id}/{subproject_id}/object")
async def sync_head_object(project_id: str, subproject_id: str, path: str = Query(...)):
    target_path = sync_target_path(project_id, subproject_id, path)
    meta = compute_existing_sync_meta(target_path)
    return Response(status_code=200 if meta.get("exists") else 404, headers=build_sync_headers(meta))


@router.get("/sync/root/{project_id}/{subproject_id}/object/meta")
async def sync_object_meta(project_id: str, subproject_id: str, path: str = Query(...)):
    target_path = sync_target_path(project_id, subproject_id, path)
    meta = compute_existing_sync_meta(target_path)
    if not meta.get("exists"):
        raise NotFoundError("同步对象", path)
    return {
        "path": normalize_sync_path(path)[1],
        **meta,
    }


@router.post("/sync/root/{project_id}/{subproject_id}/mkdirs")
async def sync_mkdirs(project_id: str, subproject_id: str, payload: dict[str, list[str]] = Body(...)):
    paths = payload.get("paths") or []
    created: list[str] = []
    for item in paths:
        relative_no_lead, normalized = normalize_sync_path(item)
        target_dir = os.path.join(sync_subproject_root(project_id, subproject_id), relative_no_lead)
        os.makedirs(target_dir, exist_ok=True)
        created.append(normalized)
    return {"ok": True, "created": created}


@router.put("/sync/root/{project_id}/{subproject_id}/object")
async def sync_put_object(
    project_id: str,
    subproject_id: str,
    request: Request,
    path: str = Query(...),
    size: int = Query(0),
    sha256: str = Query(""),
):
    normalized_relative_no_lead, normalized_relative = normalize_sync_path(path)
    target_path = os.path.join(sync_subproject_root(project_id, subproject_id), normalized_relative_no_lead)
    os.makedirs(os.path.dirname(target_path), exist_ok=True)

    entry_type = (request.headers.get("X-Sync-Entry-Type") or "file").strip().lower()
    existing = compute_existing_sync_meta(target_path)

    if entry_type == "symlink":
        symlink_target = request.headers.get("X-Sync-Symlink-Target", "")
        if existing.get("exists") and existing.get("entry_type") == "symlink" and existing.get("symlink_target") == symlink_target:
            return {
                "path": normalized_relative,
                "entry_type": "symlink",
                "status": "skipped",
                "size": 0,
                "sha256": "",
                "symlink_target": symlink_target,
            }
        if os.path.lexists(target_path):
            if os.path.isdir(target_path) and not os.path.islink(target_path):
                raise ConflictError(f"目标路径已存在目录，无法覆盖: {normalized_relative}")
            os.remove(target_path)
        os.symlink(symlink_target, target_path)
        return {
            "path": normalized_relative,
            "entry_type": "symlink",
            "status": "uploaded",
            "size": 0,
            "sha256": "",
            "symlink_target": symlink_target,
        }

    if existing.get("exists") and existing.get("entry_type") == "file":
        existing_size = int(existing.get("size") or 0)
        existing_sha256 = str(existing.get("sha256") or "")
        if existing_size == size and existing_sha256 and sha256 and existing_sha256 == sha256:
            return {
                "path": normalized_relative,
                "entry_type": "file",
                "status": "skipped",
                "size": existing_size,
                "sha256": existing_sha256,
            }

    temp_path, computed_sha256, computed_size = await persist_sync_stream(request, target_path)
    if size and computed_size != size:
        os.remove(temp_path)
        raise ValidationError("上传文件大小不匹配", {"expected_size": size, "actual_size": computed_size})
    if sha256 and computed_sha256 != sha256:
        os.remove(temp_path)
        raise ValidationError("上传文件摘要不匹配", {"expected_sha256": sha256, "actual_sha256": computed_sha256})
    os.replace(temp_path, target_path)
    return {
        "path": normalized_relative,
        "entry_type": "file",
        "status": "uploaded",
        "size": computed_size,
        "sha256": computed_sha256,
    }


@router.get("/project-filesystem/root", response_model=ProjectFilesystemRootResponse)
async def get_project_filesystem_root(
    project_id: str = Query(...),
    authorization: Optional[str] = Header(None),
):
    await verify_project_access(project_id, authorization)
    project_files_root(project_id)
    _, _, directories, files = list_project_filesystem_entries(project_id, "/")
    return ProjectFilesystemRootResponse(
        project_id=project_id,
        root_name=project_id,
        total=len(directories) + len(files),
        items=[*directories, *files],
    )


@router.get("/project-filesystem/children", response_model=ProjectFilesystemChildrenResponse)
async def get_project_filesystem_children(
    project_id: str = Query(...),
    path: str = Query("/"),
    authorization: Optional[str] = Header(None),
):
    await verify_project_access(project_id, authorization)
    project_files_root(project_id)
    _, current_name, directories, files = list_project_filesystem_entries(project_id, path)
    _, normalized = normalize_project_filesystem_path(path)
    return ProjectFilesystemChildrenResponse(
        project_id=project_id,
        current_path=normalized,
        current_name=current_name,
        breadcrumbs=build_project_filesystem_breadcrumbs(project_id, normalized),
        directories=directories,
        files=files,
    )


@router.post("/project-filesystem/directories", response_model=ProjectFilesystemEntry)
async def create_project_filesystem_directory(
    payload: ProjectFilesystemDirectoryCreate,
    current_user: TokenUser = Depends(get_current_user),
    authorization: Optional[str] = Header(None),
):
    await verify_project_access(payload.project_id, authorization)
    target_path, normalized = project_filesystem_target_path(payload.project_id, payload.path)
    if normalized == "/":
        raise ValidationError("不能直接创建项目根目录")
    parent_path = path_parent(normalized)
    parent_target_path, _ = project_filesystem_target_path(payload.project_id, parent_path)
    if not os.path.isdir(parent_target_path):
        raise NotFoundError("父目录", parent_path)
    ensure_project_realpath_inside_root(payload.project_id, parent_target_path)
    directory_name = sanitize_name(path_basename(normalized))
    final_target_path = os.path.join(parent_target_path, directory_name)
    if os.path.lexists(final_target_path):
        raise ConflictError(f"目录已存在: {normalized}")
    os.mkdir(final_target_path)
    return load_project_filesystem_entry(payload.project_id, normalized)


@router.post("/project-filesystem/files/upload", response_model=ProjectFilesystemEntry)
async def upload_project_filesystem_file(
    project_id: str = Form(...),
    path: str = Form("/"),
    overwrite: bool = Form(False),
    file: UploadFile = File(...),
    current_user: TokenUser = Depends(get_current_user),
    authorization: Optional[str] = Header(None),
):
    del current_user
    await verify_project_access(project_id, authorization)
    target_directory_path, normalized_directory = project_filesystem_target_path(project_id, path)
    if not os.path.isdir(target_directory_path):
        raise NotFoundError("目录", normalized_directory)
    ensure_project_realpath_inside_root(project_id, target_directory_path)
    filename = sanitize_name(file.filename or "upload.bin")
    destination_path = os.path.join(target_directory_path, filename)
    if os.path.lexists(destination_path):
        if os.path.isdir(destination_path):
            raise ConflictError(f"目标路径已存在目录，无法覆盖: {filename}")
        if not overwrite:
            raise ConflictError(f"目录下已存在同名文件: {filename}")

    config = get_config()
    temp_path, _, _ = await persist_upload(file, config.storage.temp_dir)
    os.makedirs(os.path.dirname(destination_path), exist_ok=True)
    os.replace(temp_path, destination_path)
    file_path = "/" + filename if normalized_directory == "/" else f"{normalized_directory.rstrip('/')}/{filename}"
    return load_project_filesystem_entry(project_id, file_path)


@router.post("/project-filesystem/rename", response_model=ProjectFilesystemEntry)
async def rename_project_filesystem_node(
    payload: ProjectFilesystemRenameRequest,
    current_user: TokenUser = Depends(get_current_user),
    authorization: Optional[str] = Header(None),
):
    del current_user
    await verify_project_access(payload.project_id, authorization)
    source_path, normalized_source = project_filesystem_target_path(payload.project_id, payload.path)
    if normalized_source == "/":
        raise ValidationError("不能重命名项目根目录")
    if not os.path.lexists(source_path):
        raise NotFoundError("项目文件", normalized_source)
    parent_path = path_parent(normalized_source)
    parent_target_path, _ = project_filesystem_target_path(payload.project_id, parent_path)
    ensure_project_realpath_inside_root(payload.project_id, parent_target_path)
    new_name = sanitize_name(payload.name)
    target_normalized = "/" + new_name if parent_path == "/" else f"{parent_path.rstrip('/')}/{new_name}"
    target_path, _ = project_filesystem_target_path(payload.project_id, target_normalized)
    if os.path.lexists(target_path):
        raise ConflictError(f"目标已存在: {target_normalized}")
    os.replace(source_path, target_path)
    return load_project_filesystem_entry(payload.project_id, target_normalized)


@router.post("/project-filesystem/move", response_model=ProjectFilesystemEntry)
async def move_project_filesystem_node(
    payload: ProjectFilesystemMoveRequest,
    current_user: TokenUser = Depends(get_current_user),
    authorization: Optional[str] = Header(None),
):
    del current_user
    await verify_project_access(payload.project_id, authorization)
    source_path, normalized_source = project_filesystem_target_path(payload.project_id, payload.source_path)
    target_directory_path, normalized_target_directory = project_filesystem_target_path(payload.project_id, payload.target_directory_path)
    if normalized_source == "/":
        raise ValidationError("不能移动项目根目录")
    if not os.path.lexists(source_path):
        raise NotFoundError("项目文件", normalized_source)
    if not os.path.isdir(target_directory_path):
        raise NotFoundError("目录", normalized_target_directory)
    ensure_project_realpath_inside_root(payload.project_id, target_directory_path)
    if os.path.isdir(source_path) and not os.path.islink(source_path) and is_root_level_directory(normalized_source):
        raise ValidationError("一级子项目目录不支持拖拽移动")
    source_name = path_basename(normalized_source)
    target_normalized = "/" + source_name if normalized_target_directory == "/" else f"{normalized_target_directory.rstrip('/')}/{source_name}"
    target_path, _ = project_filesystem_target_path(payload.project_id, target_normalized)
    if os.path.lexists(target_path):
        raise ConflictError(f"目标已存在: {target_normalized}")
    if os.path.isdir(source_path) and not os.path.islink(source_path):
        source_real = ensure_project_realpath_inside_root(payload.project_id, source_path)
        target_real_parent = ensure_project_realpath_inside_root(payload.project_id, target_directory_path)
        if os.path.commonpath([target_real_parent, source_real]) == source_real:
            raise ConflictError("目录不能移动到自己的子目录下")
    os.replace(source_path, target_path)
    return load_project_filesystem_entry(payload.project_id, target_normalized)


@router.delete("/project-filesystem", response_model=SuccessResponse)
async def delete_project_filesystem_node(
    project_id: str = Query(...),
    path: str = Query(...),
    recursive: bool = Query(True),
    authorization: Optional[str] = Header(None),
):
    await verify_project_access(project_id, authorization)
    target_path, normalized = project_filesystem_target_path(project_id, path)
    if normalized == "/":
        raise ValidationError("不能删除项目根目录")
    if not os.path.lexists(target_path):
        raise NotFoundError("项目文件", normalized)
    parent_target = os.path.dirname(target_path) or project_files_root(project_id)
    ensure_project_realpath_inside_root(project_id, parent_target)
    if os.path.isdir(target_path) and not os.path.islink(target_path):
        if recursive:
            shutil.rmtree(target_path, ignore_errors=True)
        else:
            os.rmdir(target_path)
    else:
        os.remove(target_path)
    return SuccessResponse(message="删除成功")


@router.get("/project-filesystem/preview")
async def preview_project_filesystem_file(
    project_id: str = Query(...),
    path: str = Query(...),
    authorization: Optional[str] = Header(None),
):
    await verify_project_access(project_id, authorization)
    target_path, normalized = project_filesystem_target_path(project_id, path)
    if not os.path.lexists(target_path):
        raise NotFoundError("项目文件", normalized)
    if os.path.isdir(target_path) and not os.path.islink(target_path):
        raise ValidationError("目录不支持预览")
    resolved = ensure_project_realpath_inside_root(project_id, target_path)
    filename = path_basename(normalized)
    media_type = guess_content_type(filename, None)
    return FileResponse(
        path=resolved,
        filename=filename,
        media_type=media_type,
        headers={
            "Content-Disposition": f'inline; filename="{filename}"',
            "X-Preview-Mode": infer_preview_mode_by_filename(filename, media_type),
        },
    )


@router.get("/project-filesystem/download")
async def download_project_filesystem_file(
    project_id: str = Query(...),
    path: str = Query(...),
    authorization: Optional[str] = Header(None),
):
    await verify_project_access(project_id, authorization)
    target_path, normalized = project_filesystem_target_path(project_id, path)
    if not os.path.lexists(target_path):
        raise NotFoundError("项目文件", normalized)
    if os.path.isdir(target_path) and not os.path.islink(target_path):
        raise ValidationError("目录不支持下载")
    resolved = ensure_project_realpath_inside_root(project_id, target_path)
    filename = path_basename(normalized)
    media_type = guess_content_type(filename, None)
    return FileResponse(path=resolved, filename=filename, media_type=media_type or "application/octet-stream")


@router.get("/vuln/project-path/children", response_model=ProjectPathChildrenResponse)
async def get_vuln_project_path_children(
    project_id: str = Query(...),
    path: str = Query(...),
    current_user: TokenUser = Depends(get_current_user),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(project_id, authorization)
    subproject = ensure_special_subproject(db, project_id, created_by=str(current_user.id))
    _, normalized, special_relative = normalize_special_project_path(path)
    parts = split_special_relative_path(special_relative)
    current_directory = ensure_directory_chain_by_parts(
        db,
        project_id,
        subproject,
        parts,
        created_by=str(current_user.id),
    ) if parts else None
    db.commit()

    if current_directory is None:
        directories = db.query(FileDirectory).filter(
            FileDirectory.project_id == project_id,
            FileDirectory.subproject_id == subproject.id,
            FileDirectory.parent_id.is_(None),
        ).order_by(FileDirectory.name.asc()).all()
        files = db.query(ManagedFile).filter(
            ManagedFile.project_id == project_id,
            ManagedFile.subproject_id == subproject.id,
            ManagedFile.directory_id.is_(None),
        ).order_by(ManagedFile.filename.asc()).all()
    else:
        directories = db.query(FileDirectory).filter(
            FileDirectory.project_id == project_id,
            FileDirectory.subproject_id == subproject.id,
            FileDirectory.parent_id == current_directory.id,
        ).order_by(FileDirectory.name.asc()).all()
        files = db.query(ManagedFile).filter(
            ManagedFile.project_id == project_id,
            ManagedFile.subproject_id == subproject.id,
            ManagedFile.directory_id == current_directory.id,
        ).order_by(ManagedFile.filename.asc()).all()

    case_uuid = parts[0] if parts else None
    root_path = f"/{SPECIAL_VULN_SUBPROJECT_NAME}/{case_uuid}" if case_uuid else f"/{SPECIAL_VULN_SUBPROJECT_NAME}"
    root_name = case_uuid or SPECIAL_VULN_SUBPROJECT_NAME
    return ProjectPathChildrenResponse(
        project_id=project_id,
        current_path=normalized,
        current_name=parts[-1] if parts else SPECIAL_VULN_SUBPROJECT_NAME,
        root_path=root_path,
        root_name=root_name,
        special_subproject_name=SPECIAL_VULN_SUBPROJECT_NAME,
        special_subproject_id=subproject.id,
        case_uuid=case_uuid,
        directories=[to_project_path_directory_entry(item) for item in directories],
        files=[to_project_path_file_entry(item, item.directory) for item in files],
    )


@router.post("/vuln/project-path/directories", response_model=ProjectPathDirectoryEntry)
async def create_vuln_project_path_directory(
    payload: ProjectPathDirectoryCreate,
    current_user: TokenUser = Depends(get_current_user),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(payload.project_id, authorization)
    subproject = ensure_special_subproject(db, payload.project_id, created_by=str(current_user.id))
    _, _, special_relative = normalize_special_project_path(payload.path)
    parts = split_special_relative_path(special_relative)
    if not parts:
        raise ValidationError("不能直接创建特殊子项目根目录")
    directory = ensure_directory_chain_by_parts(
        db,
        payload.project_id,
        subproject,
        parts,
        created_by=str(current_user.id),
    )
    db.commit()
    assert directory is not None
    db.refresh(directory)
    return to_project_path_directory_entry(directory)


@router.post("/vuln/project-path/mkdirs", response_model=ProjectPathOperationResponse)
async def create_vuln_project_path_directories(
    payload: ProjectPathMkdirsRequest,
    current_user: TokenUser = Depends(get_current_user),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(payload.project_id, authorization)
    subproject = ensure_special_subproject(db, payload.project_id, created_by=str(current_user.id))
    last_path = f"/{SPECIAL_VULN_SUBPROJECT_NAME}"
    for item in payload.paths:
        _, normalized, special_relative = normalize_special_project_path(item)
        parts = split_special_relative_path(special_relative)
        if not parts:
            continue
        ensure_directory_chain_by_parts(
            db,
            payload.project_id,
            subproject,
            parts,
            created_by=str(current_user.id),
        )
        last_path = normalized
    db.commit()
    return ProjectPathOperationResponse(path=last_path, entry_type="directory", message="目录创建成功")


@router.post("/vuln/project-path/files/upload", response_model=ProjectPathFileEntry)
async def upload_vuln_project_path_file(
    project_id: str = Form(...),
    path: str = Form(...),
    file: UploadFile = File(...),
    current_user: TokenUser = Depends(get_current_user),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(project_id, authorization)
    subproject = ensure_special_subproject(db, project_id, created_by=str(current_user.id))
    normalized_relative_path = normalize_sync_path(path)[1]
    parent_dir, filename = resolve_special_parent_and_filename(
        db,
        project_id,
        subproject,
        normalized_relative_path,
        create_dirs=True,
        created_by=str(current_user.id),
    )

    config = get_config()
    temp_path, sha256, total_size = await persist_upload(file, config.storage.temp_dir)
    existing = db.query(ManagedFile).filter(
        ManagedFile.project_id == project_id,
        ManagedFile.subproject_id == subproject.id,
        ManagedFile.directory_id == (parent_dir.id if parent_dir else None),
        ManagedFile.filename == filename,
    ).first()
    if existing:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise ConflictError(f"目录下已存在同名文件: {filename}")

    file_record = ManagedFile(
        project_id=project_id,
        subproject_id=subproject.id,
        directory_id=parent_dir.id if parent_dir else None,
        filename=filename,
        original_filename=file.filename or filename,
        content_type=guess_content_type(filename, file.content_type),
        size=total_size,
        sha256=sha256,
        storage_key="pending",
        created_by=str(current_user.id),
    )
    db.add(file_record)
    db.flush()
    storage_key = storage_relative_path(project_id, subproject.id, parent_dir, filename)
    target_path = absolute_storage_path(storage_key)
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    os.replace(temp_path, target_path)
    file_record.storage_key = storage_key
    db.commit()
    db.refresh(file_record)
    return to_project_path_file_entry(file_record, parent_dir)


@router.delete("/vuln/project-path/object", response_model=ProjectPathOperationResponse)
async def delete_vuln_project_path_object(
    project_id: str = Query(...),
    path: str = Query(...),
    recursive: bool = Query(True),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(project_id, authorization)
    subproject = ensure_special_subproject(db, project_id)
    _, normalized, special_relative = normalize_special_project_path(path)
    parts = split_special_relative_path(special_relative)
    if not parts:
        raise ValidationError("不能删除特殊子项目根目录")

    filename = parts[-1]
    parent_dir = lookup_directory_by_special_path(
        db,
        project_id,
        subproject,
        "/" + "/".join(parts[:-1]),
    ) if len(parts) > 1 else None
    file_record = db.query(ManagedFile).filter(
        ManagedFile.project_id == project_id,
        ManagedFile.subproject_id == subproject.id,
        ManagedFile.directory_id == (parent_dir.id if parent_dir else None),
        ManagedFile.filename == filename,
    ).first()
    if file_record:
        file_path = absolute_storage_path(file_record.storage_key)
        db.delete(file_record)
        db.commit()
        if os.path.exists(file_path):
            os.remove(file_path)
        remove_empty_special_parents(project_id, subproject.id, parent_dir)
        return ProjectPathOperationResponse(path=normalized, entry_type="file", message="文件删除成功")

    directory = lookup_directory_by_special_path(db, project_id, subproject, special_relative)
    if directory is None:
        raise NotFoundError("对象", normalized)

    descendant_dirs = db.query(FileDirectory).filter(
        FileDirectory.project_id == project_id,
        FileDirectory.subproject_id == subproject.id,
        FileDirectory.path_key.startswith(directory.path_key.rstrip("/") + "/"),
    ).all()
    descendant_ids = [directory.id] + [item.id for item in descendant_dirs]
    file_count = db.query(ManagedFile).filter(ManagedFile.directory_id.in_(descendant_ids)).count()
    if (descendant_dirs or file_count > 0) and not recursive:
        raise ConflictError("目录下仍存在子目录或文件，无法删除")

    target_path = get_directory_storage_path(project_id, subproject.id, directory)
    if descendant_ids:
        db.query(ManagedFile).filter(ManagedFile.directory_id.in_(descendant_ids)).delete(synchronize_session=False)
        db.query(FileDirectory).filter(FileDirectory.id.in_(descendant_ids[1:])).delete(synchronize_session=False)
    parent = directory.parent
    db.delete(directory)
    db.commit()
    if os.path.isdir(target_path):
        shutil.rmtree(target_path, ignore_errors=True)
        remove_empty_parents(target_path, sync_subproject_root(project_id, subproject.id))
    remove_empty_special_parents(project_id, subproject.id, parent)
    return ProjectPathOperationResponse(path=normalized, entry_type="directory", message="目录删除成功")


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


@router.get("/subprojects/{subproject_id}/children", response_model=DirectoryChildrenResponse)
async def get_subproject_children(
    subproject_id: int,
    project_id: str = Query(...),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(project_id, authorization)
    subproject = require_subproject(db, project_id, subproject_id)
    directories = db.query(FileDirectory).filter(
        FileDirectory.project_id == project_id,
        FileDirectory.subproject_id == subproject_id,
        FileDirectory.parent_id.is_(None),
    ).order_by(FileDirectory.name.asc()).all()
    files = db.query(ManagedFile).filter(
        ManagedFile.project_id == project_id,
        ManagedFile.subproject_id == subproject_id,
        ManagedFile.directory_id.is_(None),
    ).order_by(ManagedFile.filename.asc()).all()
    return DirectoryChildrenResponse(
        project_id=project_id,
        subproject_id=subproject_id,
        directory_id=None,
        current_name=subproject.name,
        current_path="/",
        breadcrumbs=build_breadcrumbs(project_id, subproject, None),
        directories=directories,
        files=files,
    )


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
    recursive: bool = Query(False),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(project_id, authorization)
    subproject = require_subproject(db, project_id, subproject_id)
    file_count = db.query(ManagedFile).filter(ManagedFile.subproject_id == subproject_id).count()
    dir_count = db.query(FileDirectory).filter(FileDirectory.subproject_id == subproject_id).count()
    if (file_count > 0 or dir_count > 0) and not recursive:
        raise ConflictError("子项目下仍存在目录或文件，无法删除")
    subproject_root = sync_subproject_root(project_id, subproject_id)
    if recursive:
        delete_subproject_contents(db, project_id, subproject_id)
    db.delete(subproject)
    db.commit()
    if recursive and os.path.isdir(subproject_root):
        import shutil

        shutil.rmtree(subproject_root, ignore_errors=True)
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


@router.get("/directories/{directory_id}/children", response_model=DirectoryChildrenResponse)
async def get_directory_children(
    directory_id: int,
    project_id: str = Query(...),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(project_id, authorization)
    directory = db.query(FileDirectory).filter(
        FileDirectory.id == directory_id,
        FileDirectory.project_id == project_id,
    ).first()
    if not directory:
        raise NotFoundError("目录", str(directory_id))
    subproject = require_subproject(db, project_id, directory.subproject_id)
    directories = db.query(FileDirectory).filter(
        FileDirectory.project_id == project_id,
        FileDirectory.subproject_id == directory.subproject_id,
        FileDirectory.parent_id == directory.id,
    ).order_by(FileDirectory.name.asc()).all()
    files = db.query(ManagedFile).filter(
        ManagedFile.project_id == project_id,
        ManagedFile.subproject_id == directory.subproject_id,
        ManagedFile.directory_id == directory.id,
    ).order_by(ManagedFile.filename.asc()).all()
    return DirectoryChildrenResponse(
        project_id=project_id,
        subproject_id=subproject.id,
        directory_id=directory.id,
        current_name=directory.name,
        current_path=directory.path_key,
        breadcrumbs=build_breadcrumbs(project_id, subproject, directory),
        directories=directories,
        files=files,
    )


@router.post("/directories/{directory_id}/rename", response_model=DirectoryResponse)
async def rename_directory(
    directory_id: int,
    payload: DirectoryRenameRequest,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    directory = db.query(FileDirectory).filter(FileDirectory.id == directory_id).first()
    if not directory:
        raise NotFoundError("目录", str(directory_id))
    await verify_project_access(directory.project_id, authorization)
    new_name = sanitize_name(payload.name)
    existing = db.query(FileDirectory).filter(
        FileDirectory.subproject_id == directory.subproject_id,
        FileDirectory.parent_id == directory.parent_id,
        FileDirectory.name == new_name,
        FileDirectory.id != directory.id,
    ).first()
    if existing:
        raise ConflictError(f"同级目录下名称已存在: {new_name}")

    old_path = get_directory_storage_path(directory.project_id, directory.subproject_id, directory)
    directory.name = new_name
    update_directory_subtree_paths(db, directory)
    refresh_file_storage_keys(db, directory.subproject_id)
    new_path = get_directory_storage_path(directory.project_id, directory.subproject_id, directory)
    if old_path != new_path and os.path.exists(old_path):
        os.makedirs(os.path.dirname(new_path), exist_ok=True)
        os.replace(old_path, new_path)
        remove_empty_parents(old_path, sync_subproject_root(directory.project_id, directory.subproject_id))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ConflictError(f"同级目录下名称已存在: {new_name}")
    db.refresh(directory)
    return directory


@router.post("/directories/{directory_id}/move", response_model=DirectoryResponse)
async def move_directory(
    directory_id: int,
    payload: DirectoryMoveRequest,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    directory = db.query(FileDirectory).filter(FileDirectory.id == directory_id).first()
    if not directory:
        raise NotFoundError("目录", str(directory_id))
    await verify_project_access(directory.project_id, authorization)
    target_parent = require_directory(db, directory.project_id, directory.subproject_id, payload.target_parent_id)
    ensure_no_descendant_move(directory, target_parent)
    existing = db.query(FileDirectory).filter(
        FileDirectory.subproject_id == directory.subproject_id,
        FileDirectory.parent_id == payload.target_parent_id,
        FileDirectory.name == directory.name,
        FileDirectory.id != directory.id,
    ).first()
    if existing:
        raise ConflictError(f"目标目录下已存在同名目录: {directory.name}")

    old_path = get_directory_storage_path(directory.project_id, directory.subproject_id, directory)
    directory.parent_id = target_parent.id if target_parent else None
    directory.parent = target_parent
    update_directory_subtree_paths(db, directory)
    refresh_file_storage_keys(db, directory.subproject_id)
    new_path = get_directory_storage_path(directory.project_id, directory.subproject_id, directory)
    if old_path != new_path and os.path.exists(old_path):
        os.makedirs(os.path.dirname(new_path), exist_ok=True)
        os.replace(old_path, new_path)
        remove_empty_parents(old_path, sync_subproject_root(directory.project_id, directory.subproject_id))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ConflictError(f"目标目录下已存在同名目录: {directory.name}")
    db.refresh(directory)
    return directory


@router.delete("/directories/{directory_id}", response_model=SuccessResponse)
async def delete_directory(
    directory_id: int,
    project_id: str = Query(...),
    recursive: bool = Query(False),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    await verify_project_access(project_id, authorization)
    directory = db.query(FileDirectory).filter(
        FileDirectory.id == directory_id,
        FileDirectory.project_id == project_id,
    ).first()
    if not directory:
        raise NotFoundError("目录", str(directory_id))
    descendant_dirs = db.query(FileDirectory).filter(
        FileDirectory.project_id == project_id,
        FileDirectory.subproject_id == directory.subproject_id,
        FileDirectory.path_key.startswith(directory.path_key.rstrip("/") + "/"),
    ).all()
    descendant_ids = [directory.id] + [item.id for item in descendant_dirs]
    child_dir_count = len(descendant_dirs)
    file_count = db.query(ManagedFile).filter(ManagedFile.directory_id.in_(descendant_ids)).count()
    if (child_dir_count > 0 or file_count > 0) and not recursive:
        raise ConflictError("目录下仍存在子目录或文件，无法删除")
    target_path = get_directory_storage_path(project_id, directory.subproject_id, directory)
    if descendant_ids:
        db.query(ManagedFile).filter(ManagedFile.directory_id.in_(descendant_ids)).delete(synchronize_session=False)
        db.query(FileDirectory).filter(FileDirectory.id.in_(descendant_ids[1:])).delete(synchronize_session=False)
    db.delete(directory)
    db.commit()
    if recursive and os.path.isdir(target_path):
        import shutil

        shutil.rmtree(target_path, ignore_errors=True)
        remove_empty_parents(target_path, sync_subproject_root(project_id, directory.subproject_id))
    return SuccessResponse(message="目录删除成功")


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
    directory = require_directory(db, project_id, subproject_id, directory_id)
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
        original_filename=file.filename or filename,
        content_type=guess_content_type(filename, file.content_type),
        size=total_size,
        sha256=sha256,
        storage_key="pending",
        created_by=str(current_user.id),
    )
    db.add(file_record)
    db.flush()

    storage_key = storage_relative_path(project_id, subproject_id, directory, filename)
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


@router.get("/files/{file_id}/preview")
async def preview_file(
    file_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    file_record = require_file(db, file_id)
    await verify_project_access(file_record.project_id, authorization)
    file_path = absolute_storage_path(file_record.storage_key)
    if not os.path.exists(file_path):
        raise NotFoundError("物理文件", file_record.storage_key)
    media_type = guess_content_type(file_record.filename, file_record.content_type)
    return FileResponse(
        path=file_path,
        filename=file_record.filename,
        media_type=media_type,
        headers={
            "Content-Disposition": f'inline; filename="{file_record.filename}"',
            "X-Preview-Mode": preview_mode_for_file(file_record),
        },
    )


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
    directory = require_directory(db, file_record.project_id, file_record.subproject_id, file_record.directory_id)
    new_storage_key = storage_relative_path(file_record.project_id, file_record.subproject_id, directory, new_name)
    new_path = absolute_storage_path(new_storage_key)
    os.makedirs(os.path.dirname(new_path), exist_ok=True)
    if os.path.exists(old_path):
        os.replace(old_path, new_path)
    file_record.filename = new_name
    file_record.content_type = guess_content_type(new_name, file_record.content_type)
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
    old_path = absolute_storage_path(file_record.storage_key)
    new_storage_key = storage_relative_path(
        file_record.project_id,
        file_record.subproject_id,
        target_directory,
        file_record.filename,
    )
    new_path = absolute_storage_path(new_storage_key)
    os.makedirs(os.path.dirname(new_path), exist_ok=True)
    if os.path.exists(old_path):
        os.replace(old_path, new_path)
    file_record.directory_id = target_directory.id if target_directory else None
    file_record.storage_key = new_storage_key
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
