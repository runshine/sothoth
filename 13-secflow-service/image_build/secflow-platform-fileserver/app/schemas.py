"""Pydantic schemas."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class SuccessResponse(BaseModel):
    message: str


class StoragePVCResponse(BaseModel):
    mount_path: str
    pvc_name: Optional[str]


class TokenUser(BaseModel):
    id: int | str
    username: Optional[str] = None
    is_active: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    role: List[str] = Field(default_factory=list)


class SubprojectCreate(BaseModel):
    project_id: str = Field(..., min_length=1, max_length=32)
    name: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = None


class SubprojectUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = None


class SubprojectResponse(BaseModel):
    id: int
    project_id: str
    name: str
    description: Optional[str]
    created_by: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class SubprojectListResponse(BaseModel):
    total: int
    items: List[SubprojectResponse]


class DirectoryCreate(BaseModel):
    project_id: str = Field(..., min_length=1, max_length=32)
    subproject_id: int
    parent_id: Optional[int] = None
    name: str = Field(..., min_length=1, max_length=255)


class DirectoryResponse(BaseModel):
    id: int
    project_id: str
    subproject_id: int
    parent_id: Optional[int]
    name: str
    path_key: str
    created_by: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class DirectoryTreeItem(BaseModel):
    id: int
    name: str
    path_key: str
    parent_id: Optional[int]
    children: List["DirectoryTreeItem"] = Field(default_factory=list)


if hasattr(DirectoryTreeItem, "model_rebuild"):
    DirectoryTreeItem.model_rebuild()
else:
    DirectoryTreeItem.update_forward_refs()


class DirectoryTreeResponse(BaseModel):
    total: int
    items: List[DirectoryTreeItem]


class DirectoryRenameRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)


class DirectoryMoveRequest(BaseModel):
    target_parent_id: Optional[int] = None


class FileResponse(BaseModel):
    id: int
    project_id: str
    subproject_id: int
    directory_id: Optional[int]
    filename: str
    original_filename: str
    content_type: Optional[str]
    size: int
    sha256: str
    storage_key: str
    created_by: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class FileListResponse(BaseModel):
    total: int
    items: List[FileResponse]


class FileRenameRequest(BaseModel):
    filename: str = Field(..., min_length=1, max_length=255)


class FileMoveRequest(BaseModel):
    target_directory_id: Optional[int] = None


class ExplorerBreadcrumbItem(BaseModel):
    node_type: str
    id: str
    name: str
    subproject_id: Optional[int] = None
    directory_id: Optional[int] = None


class ExplorerNode(BaseModel):
    node_type: str
    id: str
    name: str
    project_id: str
    subproject_id: Optional[int] = None
    directory_id: Optional[int] = None
    file_id: Optional[int] = None
    parent_directory_id: Optional[int] = None
    path_key: Optional[str] = None
    content_type: Optional[str] = None
    size: Optional[int] = None
    updated_at: Optional[datetime] = None
    special_badge: Optional[str] = None
    has_children: bool = False
    children: List["ExplorerNode"] = Field(default_factory=list)


if hasattr(ExplorerNode, "model_rebuild"):
    ExplorerNode.model_rebuild()
else:
    ExplorerNode.update_forward_refs()


class ExplorerRootResponse(BaseModel):
    project_id: str
    root_name: str
    total: int
    items: List[ExplorerNode]


class DirectoryChildrenResponse(BaseModel):
    project_id: str
    subproject_id: int
    directory_id: Optional[int] = None
    current_name: str
    current_path: str
    breadcrumbs: List[ExplorerBreadcrumbItem]
    directories: List[DirectoryResponse]
    files: List[FileResponse]


class FilePreviewResponse(BaseModel):
    file_id: int
    filename: str
    content_type: Optional[str]
    preview_mode: str
    preview_url: str
    download_url: str
