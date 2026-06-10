"""Pydantic schemas."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class SuccessResponse(BaseModel):
    message: str
    request_id: Optional[str] = None
    queue_class: Optional[str] = None


class StoragePVCResponse(BaseModel):
    mount_path: str
    pvc_name: Optional[str]
    nfs_server: Optional[str] = None
    nfs_base_path: Optional[str] = None


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
    request_id: Optional[str] = None
    queue_class: Optional[str] = None

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
    request_id: Optional[str] = None
    queue_class: Optional[str] = None

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


class ProjectPathDirectoryCreate(BaseModel):
    project_id: str = Field(..., min_length=1, max_length=32)
    path: str = Field(..., min_length=1, max_length=1024)


class ProjectPathMkdirsRequest(BaseModel):
    project_id: str = Field(..., min_length=1, max_length=32)
    paths: List[str] = Field(default_factory=list)


class ProjectPathDirectoryEntry(BaseModel):
    id: int
    name: str
    path: str
    created_at: datetime
    updated_at: datetime
    request_id: Optional[str] = None
    queue_class: Optional[str] = None


class ProjectPathFileEntry(BaseModel):
    id: int
    filename: str
    original_filename: str
    path: str
    content_type: Optional[str]
    size: int
    sha256: str
    storage_key: str
    created_at: datetime
    updated_at: datetime
    request_id: Optional[str] = None
    queue_class: Optional[str] = None


class ProjectPathChildrenResponse(BaseModel):
    project_id: str
    current_path: str
    current_name: str
    root_path: str
    root_name: str
    special_subproject_name: str
    special_subproject_id: int
    case_uuid: Optional[str] = None
    directories: List[ProjectPathDirectoryEntry]
    files: List[ProjectPathFileEntry]


class ProjectPathOperationResponse(BaseModel):
    ok: bool = True
    path: str
    entry_type: str
    message: Optional[str] = None
    request_id: Optional[str] = None
    queue_class: Optional[str] = None


class ProjectFilesystemBreadcrumbItem(BaseModel):
    node_type: str
    name: str
    path: str


class ProjectFilesystemEntry(BaseModel):
    node_type: str
    name: str
    path: str
    content_type: Optional[str] = None
    size: Optional[int] = None
    updated_at: Optional[datetime] = None
    has_children: bool = False
    special_badge: Optional[str] = None
    request_id: Optional[str] = None
    queue_class: Optional[str] = None


class ProjectFilesystemRootResponse(BaseModel):
    project_id: str
    root_name: str
    total: int
    items: List[ProjectFilesystemEntry]


class ProjectFilesystemChildrenResponse(BaseModel):
    project_id: str
    current_path: str
    current_name: str
    breadcrumbs: List[ProjectFilesystemBreadcrumbItem]
    directories: List[ProjectFilesystemEntry]
    files: List[ProjectFilesystemEntry]


class ProjectFilesystemDirectoryCreate(BaseModel):
    project_id: str = Field(..., min_length=1, max_length=32)
    path: str = Field(..., min_length=1, max_length=1024)


class ProjectFilesystemRenameRequest(BaseModel):
    project_id: str = Field(..., min_length=1, max_length=32)
    path: str = Field(..., min_length=1, max_length=1024)
    name: str = Field(..., min_length=1, max_length=255)


class ProjectFilesystemMoveRequest(BaseModel):
    project_id: str = Field(..., min_length=1, max_length=32)
    source_path: str = Field(..., min_length=1, max_length=1024)
    target_directory_path: str = Field(..., min_length=1, max_length=1024)


class TaskSubmitResponse(BaseModel):
    task_id: str
    status: str
    accepted_at: datetime
    request_id: Optional[str] = None
    queue_class: Optional[str] = None


class TaskStatusResponse(BaseModel):
    task_id: str
    task_type: Optional[str] = None
    project_id: Optional[str] = None
    status: str
    progress: float
    accepted_at: datetime
    finished_at: Optional[datetime] = None
    result: Optional[dict] = None
    error: Optional[str] = None


class ArchiveTaskCreateRequest(BaseModel):
    project_id: str = Field(..., min_length=1, max_length=32)
    items: List[str] = Field(default_factory=list)
    archive_name: Optional[str] = Field(None, min_length=1, max_length=255)


class ProjectInputUploadBatchSummary(BaseModel):
    batch_id: str
    status: str
    mode: str
    keep_original: bool
    submitted_file_count: int
    processed_file_count: int
    processed_size_bytes: int
    error_summary: Optional[str] = None
    created_at: datetime
    finished_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ProjectInputUploadRecordResponse(BaseModel):
    upload_id: str
    project_id: str
    input_type: str
    status: str
    keep_original: bool
    source_archive_count: int
    stored_file_count: int
    stored_total_size_bytes: int
    target_path: str
    last_error: Optional[str] = None
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    finished_at: Optional[datetime] = None
    latest_batch: Optional[ProjectInputUploadBatchSummary] = None
    batch_count: int = 0


class ProjectInputUploadListResponse(BaseModel):
    total: int
    items: List[ProjectInputUploadRecordResponse]
    page: int = 1
    page_size: int = 50


class ProjectInputUploadStatsResponse(BaseModel):
    project_id: str
    input_type: str
    total_uploads: int
    processing_uploads: int
    succeeded_uploads: int
    partial_failed_uploads: int
    failed_uploads: int
    stored_file_count: int
    stored_total_size_bytes: int


class ProjectInputUploadOverviewResponse(BaseModel):
    project_id: str
    categories: List[ProjectInputUploadStatsResponse]


class ProjectInputUploadAcceptedResponse(BaseModel):
    upload_id: str
    batch_id: str
    status: str
    accepted_at: datetime
    request_id: Optional[str] = None
    queue_class: Optional[str] = None


class ProjectInputUploadDeleteRequest(BaseModel):
    project_id: str = Field(..., min_length=1, max_length=32)
    input_type: str = Field(..., min_length=1, max_length=32)
    upload_ids: List[str] = Field(default_factory=list)


class ProjectInputUploadDeleteFailedItem(BaseModel):
    upload_id: str
    message: str


class ProjectInputUploadDeleteResponse(BaseModel):
    deleted_ids: List[str] = Field(default_factory=list)
    failed_items: List[ProjectInputUploadDeleteFailedItem] = Field(default_factory=list)


class ProjectInputUploadDetailResponse(ProjectInputUploadRecordResponse):
    batches: List[ProjectInputUploadBatchSummary] = Field(default_factory=list)


class ProjectInputUploadBrowseEntry(BaseModel):
    name: str
    relative_path: str
    absolute_path: str
    node_type: str
    size: Optional[int] = None
    updated_at: Optional[datetime] = None
    has_children: bool = False
    content_type: Optional[str] = None


class ProjectInputUploadBrowseResponse(BaseModel):
    project_id: str
    upload_id: str
    input_type: str
    target_path: str
    current_relative_path: str
    current_absolute_path: str
    root_relative_path: str
    root_absolute_path: str
    current_name: str
    breadcrumbs: List[ProjectFilesystemBreadcrumbItem] = Field(default_factory=list)
    directories: List[ProjectInputUploadBrowseEntry] = Field(default_factory=list)
    files: List[ProjectInputUploadBrowseEntry] = Field(default_factory=list)


class ProjectInputUploadResolveResponse(BaseModel):
    project_id: str
    upload_id: str
    input_type: str
    target_path: str
    relative_path: str
    absolute_path: str
    node_type: str
    name: str
    size: Optional[int] = None
    updated_at: Optional[datetime] = None
    content_type: Optional[str] = None
