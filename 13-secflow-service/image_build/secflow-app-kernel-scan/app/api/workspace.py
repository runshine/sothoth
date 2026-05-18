from __future__ import annotations

import mimetypes
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

router = APIRouter()

WORKSPACE_ROOT = Path("/workspace")

MAX_PREVIEW_SIZE = 2 * 1024 * 1024  # 2 MB


class FileEntry(BaseModel):
    name: str = Field(..., description="文件或目录名")
    path: str = Field(..., description="容器内绝对路径（/workspace 开头）")
    is_dir: bool = Field(..., description="是否为目录")
    size: int | None = Field(None, description="文件大小（字节），目录为 null")


class BrowseResponse(BaseModel):
    path: str = Field(..., description="当前浏览的绝对路径（/workspace 开头）")
    parent: str | None = Field(None, description="父目录绝对路径，处于 /workspace 根时为 null")
    items: list[FileEntry] = Field(default_factory=list, description="目录内容列表")


@router.get(
    "/workspace/browse",
    response_model=BrowseResponse,
    summary="浏览 workspace 目录",
    description=(
        "列出容器内 `/workspace` 下指定目录的文件和子目录，供前端文件浏览器使用。"
        "`path` 为容器内绝对路径，必须以 `/workspace` 开头；不传则默认为 `/workspace`。"
    ),
)
def browse_workspace(
    path: str = Query(
        "/workspace",
        description="容器内绝对路径，必须为 `/workspace` 或 `/workspace/...`；不传则默认为 `/workspace`",
    ),
):
    if not path:
        path = str(WORKSPACE_ROOT)

    requested = Path(path)
    if not requested.is_absolute():
        raise HTTPException(400, f"path must be an absolute path starting with {WORKSPACE_ROOT}")

    resolved = requested.resolve()
    try:
        resolved.relative_to(WORKSPACE_ROOT)
    except ValueError:
        raise HTTPException(403, f"access denied: path must be under {WORKSPACE_ROOT}")

    if not resolved.exists():
        raise HTTPException(404, f"path not found: {path}")

    if not resolved.is_dir():
        raise HTTPException(400, "path is not a directory")

    resolved_str = str(resolved)
    parent: str | None
    if resolved == WORKSPACE_ROOT:
        parent = None
    else:
        parent = str(resolved.parent)

    items: list[FileEntry] = []
    try:
        for entry in sorted(resolved.iterdir(), key=lambda e: (not e.is_dir(), e.name)):
            items.append(FileEntry(
                name=entry.name,
                path=str(entry),
                is_dir=entry.is_dir(),
                size=entry.stat().st_size if entry.is_file() else None,
            ))
    except PermissionError:
        raise HTTPException(403, "permission denied")

    return BrowseResponse(path=resolved_str, parent=parent, items=items)


class FileReadResponse(BaseModel):
    path: str = Field(..., description="容器内绝对路径")
    name: str = Field(..., description="文件名")
    size: int = Field(..., description="文件字节数")
    content_type: str = Field(..., description="MIME 类型推断")
    content: str = Field(..., description="文件文本内容（UTF-8 解码）")


@router.get(
    "/workspace/read",
    response_model=FileReadResponse,
    summary="读取文件内容",
    description=(
        "读取 `/workspace` 下指定文件的文本内容，用于前端预览 `.md`、`.txt`、`.json`、`.log` 等文本文件。"
        "文件大小上限 2 MB，超出返回 413。传 `?raw=true` 可直接返回 `text/plain` 原文。"
    ),
)
def read_file(
    path: str = Query(..., description="容器内绝对路径，必须以 `/workspace` 开头，指向一个文件"),
    raw: bool = Query(False, description="为 true 时直接返回 text/plain 原文，不包裹 JSON"),
):
    if not path:
        raise HTTPException(400, "path is required")

    requested = Path(path)
    if not requested.is_absolute():
        raise HTTPException(400, f"path must be an absolute path starting with {WORKSPACE_ROOT}")

    resolved = requested.resolve()
    try:
        resolved.relative_to(WORKSPACE_ROOT)
    except ValueError:
        raise HTTPException(403, f"access denied: path must be under {WORKSPACE_ROOT}")

    if not resolved.exists():
        raise HTTPException(404, f"file not found: {path}")

    if not resolved.is_file():
        raise HTTPException(400, "path is not a file")

    size = resolved.stat().st_size
    if size > MAX_PREVIEW_SIZE:
        raise HTTPException(413, f"file too large for preview: {size} bytes (max {MAX_PREVIEW_SIZE})")

    try:
        content = resolved.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        raise HTTPException(403, "permission denied")
    except OSError as exc:
        raise HTTPException(500, f"failed to read file: {exc}")

    if raw:
        return PlainTextResponse(content, media_type="text/plain; charset=utf-8")

    mime, _ = mimetypes.guess_type(resolved.name)
    content_type = mime or "text/plain"

    return FileReadResponse(
        path=str(resolved),
        name=resolved.name,
        size=size,
        content_type=content_type,
        content=content,
    )
