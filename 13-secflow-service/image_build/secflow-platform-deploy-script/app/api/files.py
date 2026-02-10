"""
文件管理API路由模块
"""

import os
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Header, Query, Body, UploadFile, File
from fastapi.responses import StreamingResponse, PlainTextResponse, JSONResponse
import aiofiles
from aiofiles import os as aio_os

from app.config import get_config
from app.exception import NotFoundError, ValidationError, UnauthorizedError
from app.service.auth import get_auth_service, TokenInvalidError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/deploy-script", tags=["DeployScript"])


def get_file_root() -> Path:
    """获取文件根目录"""
    config = get_config()
    return Path(config.file_root)


def validate_path(file_root: Path, path: str) -> Path:
    """
    验证并规范化路径，防止路径遍历攻击

    Args:
        file_root: 根目录
        path: 请求路径

    Returns:
        规范化后的绝对路径

    Raises:
        ValidationError: 路径无效
    """
    # 移除开头的/
    clean_path = path.lstrip("/")

    # 拼接根目录
    full_path = file_root / clean_path

    # 规范化路径（解析 .. 和符号链接）
    resolved_path = full_path.resolve()

    # 确保路径在根目录内（防止路径遍历）
    if not str(resolved_path).startswith(str(file_root.resolve())):
        raise ValidationError("无效的路径")

    return resolved_path


async def get_current_user(
    authorization: Optional[str] = Header(None)
) -> dict:
    """
    获取当前用户（认证）

    Args:
        authorization: Authorization header

    Returns:
        用户信息

    Raises:
        UnauthorizedError: 未授权
    """
    if not authorization:
        raise UnauthorizedError("缺少Authorization头")

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedError("Authorization格式错误，应为: Bearer <token>")

    token = parts[1]

    try:
        auth_service = get_auth_service()
        user = await auth_service.validate_token_async(token)
        return user
    except TokenInvalidError:
        raise UnauthorizedError("Token无效或已过期")


# ============ 健康检查 ============

@router.get("/health")
async def health_check():
    """健康检查接口"""
    return {"status": "ok", "service": "secflow-deploy-script-service"}


@router.get("/ready")
async def ready_check():
    """就绪检查接口"""
    file_root = get_file_root()
    if not file_root.exists():
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "reason": "file_root not exists"}
        )
    return {"status": "ready"}


# ============ 文件列表 ============

@router.get("/files{path:path}")
async def list_directory(
    path: str = "",
    current_user: Optional[dict] = Depends(get_current_user)
):
    """
    列出目录内容

    支持可选认证：无token时可访问，返回有限信息；有token时返回完整信息

    Args:
        path: 目录路径，相对于根目录

    Returns:
        目录下的文件和子目录列表
    """
    file_root = get_file_root()
    dir_path = validate_path(file_root, path)

    if not dir_path.exists():
        raise NotFoundError("目录", path or "/")

    if not dir_path.is_dir():
        raise ValidationError("这不是一个目录")

    # 读取目录内容
    items = []
    for item in dir_path.iterdir():
        stat = item.stat()
        item_info = {
            "name": item.name,
            "path": "/" + str(item.relative_to(file_root)),
            "is_dir": item.is_dir(),
            "size": stat.st_size if not item.is_dir() else 0,
            "modified_at": stat.st_mtime,
        }
        items.append(item_info)

    # 按目录在前、文件名在后排序
    items.sort(key=lambda x: (not x["is_dir"], x["name"]))

    return {
        "path": "/" + str(dir_path.relative_to(file_root)) if dir_path != file_root else "/",
        "total": len(items),
        "items": items,
    }


# ============ 查看文件内容 ============

@router.get("/files{path:path}/content")
async def read_file(
    path: str = "",
    current_user: Optional[dict] = Depends(get_current_user)
):
    """
    查看文件内容

    支持可选认证

    Args:
        path: 文件路径，相对于根目录

    Returns:
        文件内容（文本或二进制）
    """
    file_root = get_file_root()
    file_path = validate_path(file_root, path)

    if not file_path.exists():
        raise NotFoundError("文件", path)

    if file_path.is_dir():
        raise ValidationError("这是目录，请使用列出目录接口")

    # 判断是否为文本文件
    text_extensions = {'.txt', '.sh', '.py', '.yaml', '.yml', '.json', '.xml', '.md', '.html', '.css', '.js'}
    is_text = file_path.suffix.lower() in text_extension

    if is_text:
        # 返回文本内容
        async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = await f.read()
        return PlainTextResponse(
            content=content,
            media_type="text/plain; charset=utf-8"
        )
    else:
        # 返回二进制流
        async with aiofiles.open(file_path, 'rb') as f:
            content = await f.read()

        return StreamingResponse(
            iter([content]),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{file_path.name}"'}
        )


# ============ 下载文件 ============

@router.get("/file{path:path}/download")
async def download_file(
    path: str = "",
    current_user: Optional[dict] = Depends(get_current_user)
):
    """
    下载文件（公开接口，无需认证）

    Args:
        path: 文件路径，相对于根目录

    Returns:
        文件下载流
    """
    file_root = get_file_root()
    file_path = validate_path(file_root, path)

    if not file_path.exists():
        raise NotFoundError("文件", path)

    if file_path.is_dir():
        raise ValidationError("不能下载目录")

    # 读取文件并返回
    async with aiofiles.open(file_path, 'rb') as f:
        content = await f.read()

    return StreamingResponse(
        iter([content]),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{file_path.name}"'}
    )


# ============ 上传文件 ============

@router.post("/file{path:path}")
async def upload_file(
    path: str = "",
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """
    上传文件（需要认证）

    Args:
        path: 目标路径，相对于根目录
        file: 上传的文件

    Returns:
        上传结果
    """
    file_root = get_file_root()
    target_path = validate_path(file_root, path)

    # 如果目标不存在，尝试创建
    if not target_path.parent.exists():
        target_path.parent.mkdir(parents=True, exist_ok=True)

    # 写入文件
    content = await file.read()
    async with aiofiles.open(target_path, 'wb') as f:
        await f.write(content)

    logger.info(f"用户 {current_user.get('id')} 上传文件: {target_path}")

    return {
        "message": "文件上传成功",
        "path": "/" + str(target_path.relative_to(file_root)),
        "filename": target_path.name,
        "size": len(content),
    }


# ============ 编辑文件 ============

@router.put("/file{path:path}")
async def edit_file(
    path: str = "",
    content: str = Body(..., description="文件内容"),
    current_user: dict = Depends(get_current_user)
):
    """
    编辑文件（需要认证）

    Args:
        path: 文件路径，相对于根目录
        content: 新文件内容

    Returns:
        编辑结果
    """
    file_root = get_file_root()
    file_path = validate_path(file_root, path)

    if not file_path.exists():
        raise NotFoundError("文件", path)

    if file_path.is_dir():
        raise ValidationError("不能编辑目录")

    # 写入新内容
    async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
        await f.write(content)

    logger.info(f"用户 {current_user.get('id')} 编辑文件: {file_path}")

    return {
        "message": "文件编辑成功",
        "path": "/" + str(file_path.relative_to(file_root)),
    }


# ============ 删除文件/目录 ============

@router.delete("/file{path:path}")
async def delete_file(
    path: str = "",
    current_user: dict = Depends(get_current_user)
):
    """
    删除文件或目录（需要认证）

    Args:
        path: 路径，相对于根目录

    Returns:
        删除结果
    """
    file_root = get_file_root()
    target_path = validate_path(file_root, path)

    if not target_path.exists():
        raise NotFoundError("资源", path)

    # 递归删除目录或单个文件
    if target_path.is_dir():
        import shutil
        shutil.rmtree(target_path)
        logger.info(f"用户 {current_user.get('id')} 删除目录: {target_path}")
    else:
        target_path.unlink()
        logger.info(f"用户 {current_user.get('id')} 删除文件: {target_path}")

    return {
        "message": "删除成功",
        "path": "/" + str(target_path.relative_to(file_root)),
    }


# ============ 创建目录 ============

@router.post("/directory{path:path}")
async def create_directory(
    path: str = "",
    current_user: dict = Depends(get_current_user)
):
    """
    创建目录（需要认证）

    Args:
        path: 目录路径，相对于根目录

    Returns:
        创建结果
    """
    file_root = get_file_root()
    dir_path = validate_path(file_root, path)

    if dir_path.exists():
        raise ValidationError(f"目录已存在: {path}")

    # 创建目录
    dir_path.mkdir(parents=True, exist_ok=True)

    logger.info(f"用户 {current_user.get('id')} 创建目录: {dir_path}")

    return {
        "message": "目录创建成功",
        "path": "/" + str(dir_path.relative_to(file_root)),
    }


# ============ 重命名 ============

@router.post("/file{path:path}/rename")
async def rename_file(
    path: str = "",
    new_name: str = Body(..., description="新名称"),
    current_user: dict = Depends(get_current_user)
):
    """
    重命名文件或目录（需要认证）

    Args:
        path: 原始路径，相对于根目录
        new_name: 新名称

    Returns:
        重命名结果
    """
    if not new_name or new_name.strip() == "":
        raise ValidationError("新名称不能为空")

    # 验证新名称不包含路径
    if "/" in new_name or "\\" in new_name:
        raise ValidationError("新名称不能包含路径分隔符")

    file_root = get_file_root()
    old_path = validate_path(file_root, path)

    if not old_path.exists():
        raise NotFoundError("资源", path)

    # 新路径
    new_path = old_path.parent / new_name
    new_path = validate_path(file_root, "/" + str(new_path.relative_to(file_root))

    # 执行重命名
    old_path.rename(new_path)

    logger.info(f"用户 {current_user.get('id')} 重命名: {old_path} -> {new_path}")

    return {
        "message": "重命名成功",
        "old_path": "/" + str(old_path.relative_to(file_root)),
        "new_path": "/" + str(new_path.relative_to(file_root)),
    }


# ============ 批量上传 ============

@router.post("/files{path:path}/batch")
async def batch_upload(
    path: str = "",
    files: list[UploadFile] = File(...),
    current_user: dict = Depends(get_current_user)
):
    """
    批量上传文件（需要认证）

    Args:
        path: 目标目录路径，相对于根目录
        files: 上传的文件列表

    Returns:
        上传结果列表
    """
    file_root = get_file_root()
    target_dir = validate_path(file_root, path)

    # 确保目标目录存在
    if not target_dir.exists():
        target_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for file in files:
        target_path = target_dir / file.filename

        content = await file.read()
        async with aiofiles.open(target_path, 'wb') as f:
            await f.write(content)

        results.append({
            "filename": file.filename,
            "path": "/" + str(target_path.relative_to(file_root)),
            "size": len(content),
        })

    logger.info(f"用户 {current_user.get('id')} 批量上传 {len(files)} 个文件到: {target_dir}")

    return {
        "message": f"成功上传 {len(files)} 个文件",
        "total": len(results),
        "results": results,
    }