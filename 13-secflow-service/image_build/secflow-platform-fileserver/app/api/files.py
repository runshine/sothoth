"""Fileserver API routes."""

from datetime import datetime, timezone
import asyncio
import hashlib
import logging
import mimetypes
import os
import posixpath
import shutil
import tempfile
import zipfile
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, File, Form, Header, Query, Request, Response, UploadFile, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.concurrency import get_queue_class, get_queue_controller, get_request_id
from app.config import get_config, get_data_nfs_base_path, get_data_nfs_server, get_data_pvc_name
from app.exception import ConflictError, ForbiddenError, NotFoundError, UnauthorizedError, ValidationError
from app.model import FileDirectory, FileSubproject, ManagedFile, get_db, get_db_session
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
    ArchiveTaskCreateRequest,
    TaskStatusResponse,
    TaskSubmitResponse,
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
from app.service.watch_service import (
    build_byte_delta,
    build_line_delta,
    encode_bytes,
    get_watch_limiter,
    maybe_create_observer,
    stat_file,
    utc_now_iso,
)
from app.task_manager import get_task_manager


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/fileserver", tags=["fileserver"])
SPECIAL_VULN_SUBPROJECT_NAME = "__vuln_cases__"
ARCHIVE_TASK_TYPE = "archive_download"
ARCHIVE_TASK_RETENTION_SECONDS = 3600
ARCHIVE_TASK_SUBDIR = ".archive_tasks"


async def run_in_queue(queue_class: str, coro):
    return await get_queue_controller().run(queue_class, coro)


def with_trace(payload: dict) -> dict:
    payload["request_id"] = get_request_id()
    payload["queue_class"] = get_queue_class()
    return payload


async def run_io(func, *args, **kwargs):
    return await asyncio.to_thread(func, *args, **kwargs)


async def _safe_ws_send_json(websocket: WebSocket, payload: dict[str, Any]) -> bool:
    try:
        await websocket.send_json(payload)
        return True
    except (WebSocketDisconnect, RuntimeError):
        return False
    except Exception as exc:
        logger.info("watch websocket send aborted: %s", exc)
        return False


@router.get("/health")
async def health_check():
    return {"status": "ok", "service": "secflow-platform-fileserver"}


@router.get("/ready")
async def ready_check():
    return {"status": "ready"}


@router.get("/metrics/queue")
async def queue_metrics():
    return {
        "request_id": get_request_id(),
        "queues": get_queue_controller().snapshot(),
        "websocket": get_watch_limiter().snapshot(),
    }


@router.websocket("/ws/watch")
async def watch_file_ws(websocket: WebSocket):
    cfg = get_config().websocket
    if not cfg.enabled:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="websocket disabled")
        return

    request_id = get_request_id() or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    project_id = websocket.query_params.get("project_id", "").strip()
    raw_path = websocket.query_params.get("path", "").strip()
    path_mode = websocket.query_params.get("path_mode", "project_filesystem").strip()
    read_mode = websocket.query_params.get("read_mode", "line").strip().lower()
    start_from = websocket.query_params.get("start_from", "head").strip().lower()
    token_qs = websocket.query_params.get("token", "").strip()
    auth_hdr = websocket.headers.get("authorization", "").strip()
    bearer_token = ""
    if auth_hdr.lower().startswith("bearer "):
        bearer_token = auth_hdr.split(" ", 1)[1].strip()
    if not bearer_token:
        bearer_token = token_qs

    await websocket.accept()

    if not project_id or not raw_path:
        await websocket.send_json({"type": "error", "request_id": request_id, "message": "project_id/path 必填", "ts": utc_now_iso()})
        await websocket.close(code=1008)
        return
    if read_mode not in {"line", "byte"}:
        await websocket.send_json({"type": "error", "request_id": request_id, "message": "read_mode 仅支持 line/byte", "ts": utc_now_iso()})
        await websocket.close(code=1008)
        return
    if start_from not in {"head", "tail"}:
        await websocket.send_json({"type": "error", "request_id": request_id, "message": "start_from 仅支持 head/tail", "ts": utc_now_iso()})
        await websocket.close(code=1008)
        return
    if not bearer_token:
        await get_watch_limiter().inc_auth_failures()
        await websocket.send_json({"type": "error", "request_id": request_id, "message": "缺少token", "ts": utc_now_iso()})
        await websocket.close(code=1008)
        return

    try:
        await verify_project_access_by_token(project_id, bearer_token)
        target_path, normalized_path = resolve_ws_target_path(path_mode, project_id, raw_path)
    except Exception as exc:
        await get_watch_limiter().inc_auth_failures()
        await websocket.send_json({"type": "error", "request_id": request_id, "message": str(exc), "ts": utc_now_iso()})
        await websocket.close(code=1008)
        return

    limiter = get_watch_limiter()
    if not await limiter.acquire(project_id):
        await websocket.send_json({"type": "error", "request_id": request_id, "message": "连接数超限", "ts": utc_now_iso()})
        await websocket.close(code=1013)
        return

    max_buffer = max(4096, cfg.max_buffer_bytes)
    poll_interval = max(0.1, cfg.poll_interval_ms / 1000.0)
    heartbeat_seconds = max(2, cfg.heartbeat_seconds)
    auth_recheck_seconds = max(10, cfg.auth_recheck_seconds)
    start_line = int(websocket.query_params.get("start_line", "0") or "0")
    start_byte = int(websocket.query_params.get("start_byte", "0") or "0")
    observer_queue: asyncio.Queue = asyncio.Queue()
    observer = maybe_create_observer(target_path, observer_queue)

    try:
        initial = stat_file(target_path)
        byte_offset = start_byte if read_mode == "byte" else 0
        line_offset = start_line if read_mode == "line" else 0
        if start_from == "tail" and initial.exists:
            if read_mode == "byte":
                byte_offset = initial.size
            else:
                try:
                    _, line_offset, _ = await build_line_delta(target_path, 0)
                except UnicodeDecodeError:
                    line_offset = 0
        if not await _safe_ws_send_json(websocket, {
            "type": "snapshot",
            "request_id": request_id,
            "project_id": project_id,
            "path": normalized_path,
            "path_mode": path_mode,
            "read_mode": read_mode,
            "exists": initial.exists,
            "start_line": line_offset if read_mode == "line" else None,
            "start_byte": byte_offset if read_mode == "byte" else None,
            "queue_class": "STREAM",
            "ts": utc_now_iso(),
        }):
            return

        async def _session_loop():
            nonlocal read_mode, line_offset, byte_offset, initial
            last_stat = initial
            last_heartbeat = asyncio.get_running_loop().time()
            last_auth_check = asyncio.get_running_loop().time()
            while True:
                now = asyncio.get_running_loop().time()
                try:
                    msg = await asyncio.wait_for(websocket.receive_json(), timeout=poll_interval)
                    action = (msg.get("action") or "").strip().lower()
                    if action in {"unsubscribe", "close"}:
                        await _safe_ws_send_json(websocket, {"type": "file_event", "event": "closed", "request_id": request_id, "project_id": project_id, "path": normalized_path, "ts": utc_now_iso()})
                        break
                    if action == "seek":
                        if read_mode == "line":
                            line_offset = int(msg.get("line", 0) or 0)
                        else:
                            byte_offset = int(msg.get("byte", 0) or 0)
                    elif action == "switch_mode":
                        next_mode = (msg.get("read_mode") or "").strip().lower()
                        if next_mode in {"line", "byte"} and next_mode != read_mode:
                            read_mode = next_mode
                            if read_mode == "line":
                                line_offset = int(msg.get("line", 0) or 0)
                            else:
                                byte_offset = int(msg.get("byte", 0) or 0)
                    elif action == "ack":
                        pass
                except asyncio.TimeoutError:
                    pass
                except WebSocketDisconnect:
                    break

                current = stat_file(target_path)
                fs_event = None
                if not last_stat.exists and current.exists:
                    fs_event = "created"
                elif last_stat.exists and not current.exists:
                    fs_event = "deleted"
                elif current.exists and last_stat.exists:
                    if current.inode != last_stat.inode:
                        fs_event = "renamed"
                    elif current.size < last_stat.size:
                        fs_event = "truncated"
                    elif current.mode != last_stat.mode:
                        fs_event = "permission_changed"
                    elif current.mtime != last_stat.mtime and current.size == last_stat.size:
                        fs_event = "metadata_changed"

                if fs_event:
                    await limiter.inc_events()
                    if not await _safe_ws_send_json(websocket, {
                        "type": "file_event",
                        "event": fs_event,
                        "request_id": request_id,
                        "project_id": project_id,
                        "path": normalized_path,
                        "size": current.size if current.exists else 0,
                        "mtime": current.mtime if current.exists else 0,
                        "inode": current.inode if current.exists else 0,
                        "ts": utc_now_iso(),
                    }):
                        break
                    if fs_event == "deleted":
                        break
                    if fs_event == "truncated":
                        line_offset = 0
                        byte_offset = 0

                if current.exists and current.size > (byte_offset if read_mode == "byte" else 0):
                    if read_mode == "line":
                        try:
                            from_line, to_line, lines = await build_line_delta(target_path, line_offset)
                        except UnicodeDecodeError:
                            if not await _safe_ws_send_json(websocket, {"type": "error", "request_id": request_id, "project_id": project_id, "path": normalized_path, "message": "文件非UTF-8文本，line模式不可用", "ts": utc_now_iso()}):
                                break
                            lines = []
                            from_line = line_offset
                            to_line = line_offset
                        if lines:
                            await limiter.inc_events()
                            if not await _safe_ws_send_json(websocket, {
                                "type": "delta",
                                "read_mode": "line",
                                "from_line": from_line,
                                "to_line": to_line,
                                "lines": lines,
                                "request_id": request_id,
                                "project_id": project_id,
                                "path": normalized_path,
                                "ts": utc_now_iso(),
                            }):
                                break
                            line_offset = to_line
                    else:
                        from_byte, to_byte, chunk = await build_byte_delta(target_path, byte_offset, max_buffer)
                        if chunk:
                            await limiter.inc_events()
                            await limiter.inc_bytes(len(chunk))
                            if not await _safe_ws_send_json(websocket, {
                                "type": "delta",
                                "read_mode": "byte",
                                "from_byte": from_byte,
                                "to_byte": to_byte,
                                "encoding": "base64",
                                "content_base64": encode_bytes(chunk),
                                "request_id": request_id,
                                "project_id": project_id,
                                "path": normalized_path,
                                "ts": utc_now_iso(),
                            }):
                                break
                            byte_offset = to_byte

                # consume watchdog hints (not mandatory for logic correctness)
                while not observer_queue.empty():
                    _ = observer_queue.get_nowait()

                if now - last_heartbeat >= heartbeat_seconds:
                    if not await _safe_ws_send_json(websocket, {
                        "type": "heartbeat",
                        "request_id": request_id,
                        "project_id": project_id,
                        "path": normalized_path,
                        "read_mode": read_mode,
                        "line_offset": line_offset if read_mode == "line" else None,
                        "byte_offset": byte_offset if read_mode == "byte" else None,
                        "ts": utc_now_iso(),
                    }):
                        break
                    last_heartbeat = now

                if now - last_auth_check >= auth_recheck_seconds:
                    try:
                        await verify_project_access_by_token(project_id, bearer_token)
                    except Exception as exc:
                        await limiter.inc_auth_failures()
                        await _safe_ws_send_json(websocket, {"type": "error", "request_id": request_id, "project_id": project_id, "path": normalized_path, "message": f"鉴权失效: {exc}", "ts": utc_now_iso()})
                        break
                    last_auth_check = now

                last_stat = current

        await run_in_queue("STREAM", _session_loop())
    finally:
        if observer is not None:
            observer.stop()
            observer.join(timeout=1)
        await limiter.release(project_id)


@router.post("/tasks/delete-tree", response_model=TaskSubmitResponse)
async def submit_delete_tree_task(
    project_id: str = Body(..., embed=True),
    path: str = Body(..., embed=True),
    authorization: Optional[str] = Header(None),
):
    await verify_project_access(project_id, authorization)

    async def _runner():
        target_path, normalized = project_filesystem_target_path(project_id, path)
        if normalized == "/":
            raise ValidationError("不能删除项目根目录")
        if not await run_io(os.path.isdir, target_path):
            raise ValidationError("仅支持目录删除任务")
        await run_io(shutil.rmtree, target_path, True)
        return {"project_id": project_id, "path": normalized, "entry_type": "directory"}

    task = await get_task_manager().submit(_runner)
    return TaskSubmitResponse(
        task_id=task.task_id,
        status=task.status,
        accepted_at=task.accepted_at,
        request_id=get_request_id(),
        queue_class=get_queue_class(),
    )


@router.post("/tasks/move-tree", response_model=TaskSubmitResponse)
async def submit_move_tree_task(
    project_id: str = Body(..., embed=True),
    source_path: str = Body(..., embed=True),
    target_directory_path: str = Body(..., embed=True),
    authorization: Optional[str] = Header(None),
):
    await verify_project_access(project_id, authorization)

    async def _runner():
        source_abs, normalized_source = project_filesystem_target_path(project_id, source_path)
        target_abs, normalized_target = project_filesystem_target_path(project_id, target_directory_path)
        if normalized_source == "/":
            raise ValidationError("不能移动项目根目录")
        if not await run_io(os.path.lexists, source_abs):
            raise NotFoundError("项目文件", normalized_source)
        if not await run_io(os.path.isdir, target_abs):
            raise NotFoundError("目录", normalized_target)
        source_name = path_basename(normalized_source)
        final_normalized = "/" + source_name if normalized_target == "/" else f"{normalized_target.rstrip('/')}/{source_name}"
        final_abs, _ = project_filesystem_target_path(project_id, final_normalized)
        if await run_io(os.path.lexists, final_abs):
            raise ConflictError(f"目标已存在: {final_normalized}")
        await run_io(os.replace, source_abs, final_abs)
        return {"project_id": project_id, "source_path": normalized_source, "target_path": final_normalized}

    task = await get_task_manager().submit(_runner)
    return TaskSubmitResponse(
        task_id=task.task_id,
        status=task.status,
        accepted_at=task.accepted_at,
        request_id=get_request_id(),
        queue_class=get_queue_class(),
    )


@router.post("/project-filesystem/archive-tasks", response_model=TaskSubmitResponse)
async def submit_project_filesystem_archive_task(
    payload: ArchiveTaskCreateRequest,
    authorization: Optional[str] = Header(None),
):
    await verify_project_access(payload.project_id, authorization)
    if not payload.items:
        raise ValidationError("items 不能为空")
    entries, dedup_items = collect_project_fs_archive_entries(payload.project_id, payload.items)
    archive_filename = ensure_archive_name(payload.archive_name)

    async def _runner():
        async def _inner():
            archive_dir = archive_workspace_root()
            archive_path = os.path.join(archive_dir, f"{datetime.now(timezone.utc).strftime('%Y%m%d')}-{os.urandom(4).hex()}-{archive_filename}")
            file_count, archive_size = await run_io(build_archive_file, archive_path, entries)
            expires_at = datetime.now(timezone.utc).timestamp() + ARCHIVE_TASK_RETENTION_SECONDS
            return {
                "project_id": payload.project_id,
                "mode": "project_filesystem",
                "items": dedup_items,
                "archive_name": archive_filename,
                "download_path": archive_path,
                "archive_size": archive_size,
                "file_count": file_count,
                "expires_at": datetime.fromtimestamp(expires_at, timezone.utc).isoformat(),
            }
        return await run_in_queue("IO_HEAVY", _inner())

    task = await get_task_manager().submit(_runner, task_type=ARCHIVE_TASK_TYPE, project_id=payload.project_id)
    return TaskSubmitResponse(
        task_id=task.task_id,
        status=task.status,
        accepted_at=task.accepted_at,
        request_id=get_request_id(),
        queue_class="IO_HEAVY",
    )


@router.post("/vuln/project-path/archive-tasks", response_model=TaskSubmitResponse)
async def submit_vuln_project_path_archive_task(
    payload: ArchiveTaskCreateRequest,
    authorization: Optional[str] = Header(None),
):
    await verify_project_access(payload.project_id, authorization)
    if not payload.items:
        raise ValidationError("items 不能为空")
    entries, dedup_items = collect_vuln_archive_entries(payload.project_id, payload.items)
    archive_filename = ensure_archive_name(payload.archive_name)

    async def _runner():
        async def _inner():
            archive_dir = archive_workspace_root()
            archive_path = os.path.join(archive_dir, f"{datetime.now(timezone.utc).strftime('%Y%m%d')}-{os.urandom(4).hex()}-{archive_filename}")
            file_count, archive_size = await run_io(build_archive_file, archive_path, entries)
            expires_at = datetime.now(timezone.utc).timestamp() + ARCHIVE_TASK_RETENTION_SECONDS
            return {
                "project_id": payload.project_id,
                "mode": "vuln_project_path",
                "items": dedup_items,
                "archive_name": archive_filename,
                "download_path": archive_path,
                "archive_size": archive_size,
                "file_count": file_count,
                "expires_at": datetime.fromtimestamp(expires_at, timezone.utc).isoformat(),
            }
        return await run_in_queue("IO_HEAVY", _inner())

    task = await get_task_manager().submit(_runner, task_type=ARCHIVE_TASK_TYPE, project_id=payload.project_id)
    return TaskSubmitResponse(
        task_id=task.task_id,
        status=task.status,
        accepted_at=task.accepted_at,
        request_id=get_request_id(),
        queue_class="IO_HEAVY",
    )


@router.get("/archive-tasks", response_model=List[TaskStatusResponse])
async def list_archive_tasks(
    project_id: str = Query(...),
    limit: int = Query(100, ge=1, le=1000),
    authorization: Optional[str] = Header(None),
):
    await verify_project_access(project_id, authorization)
    tasks = await get_task_manager().list(task_type=ARCHIVE_TASK_TYPE, project_id=project_id)
    items = tasks[:limit]
    return [
        TaskStatusResponse(
            task_id=task.task_id,
            task_type=task.task_type,
            project_id=task.project_id,
            status=task.status,
            progress=task.progress,
            accepted_at=task.accepted_at,
            finished_at=task.finished_at,
            result=task.result,
            error=task.error,
        )
        for task in items
    ]


@router.get("/archive-tasks/{task_id}/download")
async def download_archive_task_file(
    task_id: str,
    authorization: Optional[str] = Header(None),
):
    task = await get_task_manager().get(task_id)
    if task is None:
        raise NotFoundError("任务", task_id)
    if task.task_type != ARCHIVE_TASK_TYPE:
        raise ValidationError("仅支持下载 archive_download 类型任务")
    if not task.project_id:
        raise ValidationError("任务缺少 project_id")
    await verify_project_access(task.project_id, authorization)
    if task.status != "succeeded" or not task.result:
        raise ConflictError("任务未完成，暂不可下载")
    download_path = str(task.result.get("download_path") or "")
    if not download_path or not os.path.exists(download_path):
        raise NotFoundError("归档文件", task_id)
    expires_at = str(task.result.get("expires_at") or "")
    if expires_at:
        try:
            expiry = datetime.fromisoformat(expires_at)
            if datetime.now(timezone.utc) > expiry:
                raise ConflictError("归档文件已过期，请重新发起打包")
        except ValueError:
            pass
    filename = str(task.result.get("archive_name") or f"{task_id}.zip")
    return FileResponse(
        path=download_path,
        filename=filename,
        media_type="application/zip",
        headers={"X-Queue-Class": "STREAM"},
    )


@router.get("/tasks/{task_id}", response_model=TaskStatusResponse)
async def get_task_status(task_id: str, authorization: Optional[str] = Header(None)):
    del authorization
    task = await get_task_manager().get(task_id)
    if task is None:
        raise NotFoundError("任务", task_id)
    return TaskStatusResponse(
        task_id=task.task_id,
        task_type=task.task_type,
        project_id=task.project_id,
        status=task.status,
        progress=task.progress,
        accepted_at=task.accepted_at,
        finished_at=task.finished_at,
        result=task.result,
        error=task.error,
    )


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


async def verify_project_access_by_token(project_id: str, token: str) -> dict:
    try:
        project = await get_project_service().get_project(token, project_id)
    except ProjectServiceError as exc:
        raise ForbiddenError(str(exc))
    if not project:
        raise ForbiddenError(f"无权访问项目: {project_id}")
    return project


def resolve_ws_target_path(path_mode: str, project_id: str, path: str) -> tuple[str, str]:
    mode = (path_mode or "").strip().lower()
    if mode == "project_filesystem":
        return project_filesystem_target_path(project_id, path)
    if mode == "vuln_project_path":
        _, normalized, special_relative = normalize_special_project_path(path)
        parts = split_special_relative_path(special_relative)
        if len(parts) < 2:
            raise ValidationError("vuln_project_path 文件路径至少包含 case_uuid 和文件名")
        directory_relative = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
        filename = parts[-1]
        db = get_db_session()
        try:
            subproject = db.query(FileSubproject).filter(
                FileSubproject.project_id == project_id,
                FileSubproject.name == SPECIAL_VULN_SUBPROJECT_NAME,
            ).first()
            if subproject is None:
                raise NotFoundError("疑点文件子项目", SPECIAL_VULN_SUBPROJECT_NAME)
            directory = lookup_directory_by_special_path(db, project_id, subproject, directory_relative)
            if directory is None:
                raise NotFoundError("目录", directory_relative)
            file_record = db.query(ManagedFile).filter(
                ManagedFile.project_id == project_id,
                ManagedFile.subproject_id == subproject.id,
                ManagedFile.directory_id == directory.id,
                ManagedFile.filename == filename,
            ).first()
            if file_record is None:
                raise NotFoundError("文件", normalized)
            return absolute_storage_path(file_record.storage_key), normalized
        finally:
            db.close()
    raise ValidationError("path_mode仅支持 project_filesystem 或 vuln_project_path")


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


def normalize_project_filesystem_path(path: str, project_id: Optional[str] = None) -> tuple[str, str]:
    raw = (path or "").strip() or "/"
    if project_id and raw.startswith("/"):
        project_root = os.path.abspath(project_files_root(project_id))
        files_root = os.path.abspath(os.path.join(get_config().storage.root_dir, "files"))
        raw_abs = os.path.abspath(raw)
        try:
            if os.path.commonpath([raw_abs, project_root]) == project_root:
                relative = os.path.relpath(raw_abs, project_root)
                raw = "/" if relative == "." else "/" + relative.replace(os.sep, "/")
            elif os.path.commonpath([raw_abs, files_root]) == files_root:
                raise ValidationError("项目路径不能越权")
        except ValueError:
            pass
    normalized = posixpath.normpath(raw)
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    if normalized.startswith("/../") or normalized == "/..":
        raise ValidationError("项目路径不能越权")
    if normalized == "//":
        normalized = "/"
    return normalized.lstrip("/"), normalized


def project_filesystem_target_path(project_id: str, path: str) -> tuple[str, str]:
    relative_no_lead, normalized = normalize_project_filesystem_path(path, project_id)
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


def ensure_archive_name(name: Optional[str]) -> str:
    if not name:
        return f"secflow-archive-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.zip"
    safe = sanitize_name(name).replace(" ", "_")
    return safe if safe.lower().endswith(".zip") else f"{safe}.zip"


def archive_workspace_root() -> str:
    base = os.path.join(get_config().storage.root_dir, ARCHIVE_TASK_SUBDIR)
    os.makedirs(base, exist_ok=True)
    return base


def collect_project_fs_archive_entries(project_id: str, items: list[str]) -> tuple[list[dict[str, str]], list[str]]:
    normalized_items: list[str] = []
    for item in items:
        _, normalized = normalize_project_filesystem_path(item, project_id)
        if normalized == "/":
            raise ValidationError("不允许打包项目根目录")
        normalized_items.append(normalized)

    dedup = sorted(set(normalized_items))
    entries: list[dict[str, str]] = []
    for normalized in dedup:
        target_path, _ = project_filesystem_target_path(project_id, normalized)
        if not os.path.lexists(target_path):
            raise NotFoundError("项目文件", normalized)
        arc_base = normalized.lstrip("/")
        if os.path.isdir(target_path) and not os.path.islink(target_path):
            entries.append({"kind": "dir", "src": target_path, "arc": arc_base})
        else:
            entries.append({"kind": "file", "src": target_path, "arc": arc_base})
    return entries, dedup


def collect_vuln_archive_entries(project_id: str, items: list[str]) -> tuple[list[dict[str, str]], list[str]]:
    db = get_db_session()
    try:
        subproject = ensure_special_subproject(db, project_id)
        normalized_items: list[str] = []
        for item in items:
            _, normalized, _ = normalize_special_project_path(item)
            if normalized == f"/{SPECIAL_VULN_SUBPROJECT_NAME}":
                raise ValidationError("不允许打包疑点文件根目录")
            normalized_items.append(normalized)

        dedup = sorted(set(normalized_items))
        entries: list[dict[str, str]] = []
        for normalized in dedup:
            _, _, special_relative = normalize_special_project_path(normalized)
            parts = split_special_relative_path(special_relative)
            if not parts:
                raise ValidationError("无效疑点路径")

            filename = parts[-1]
            parent_dir = lookup_directory_by_special_path(
                db, project_id, subproject, "/" + "/".join(parts[:-1])
            ) if len(parts) > 1 else None

            file_record = db.query(ManagedFile).filter(
                ManagedFile.project_id == project_id,
                ManagedFile.subproject_id == subproject.id,
                ManagedFile.directory_id == (parent_dir.id if parent_dir else None),
                ManagedFile.filename == filename,
            ).first()
            arc_base = normalized.lstrip("/")
            if file_record is not None:
                entries.append({"kind": "file", "src": absolute_storage_path(file_record.storage_key), "arc": arc_base})
                continue

            directory = lookup_directory_by_special_path(db, project_id, subproject, special_relative)
            if directory is None:
                raise NotFoundError("对象", normalized)
            target_path = get_directory_storage_path(project_id, subproject.id, directory)
            entries.append({"kind": "dir", "src": target_path, "arc": arc_base})
        return entries, dedup
    finally:
        db.close()


def build_archive_file(archive_path: str, entries: list[dict[str, str]]) -> tuple[int, int]:
    os.makedirs(os.path.dirname(archive_path), exist_ok=True)
    count = 0
    with zipfile.ZipFile(archive_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for entry in entries:
            source = entry["src"]
            arc = entry["arc"].strip("/")
            if not arc:
                continue
            kind = entry["kind"]
            if kind == "file":
                if not os.path.lexists(source):
                    continue
                zf.write(source, arcname=arc)
                count += 1
                continue

            # directory
            if os.path.isdir(source):
                has_children = False
                for root, dirs, files in os.walk(source):
                    rel = os.path.relpath(root, source)
                    rel_norm = "" if rel == "." else rel.replace("\\", "/")
                    dir_arc = arc if not rel_norm else f"{arc}/{rel_norm}"
                    if not files and not dirs:
                        zf.writestr(f"{dir_arc.rstrip('/')}/", b"")
                    for filename in files:
                        has_children = True
                        file_src = os.path.join(root, filename)
                        file_arc = f"{dir_arc.rstrip('/')}/{filename}" if dir_arc else filename
                        zf.write(file_src, arcname=file_arc)
                        count += 1
                if not has_children and not os.path.isdir(source):
                    zf.writestr(f"{arc.rstrip('/')}/", b"")
            else:
                zf.writestr(f"{arc.rstrip('/')}/", b"")
    size = os.path.getsize(archive_path) if os.path.exists(archive_path) else 0
    return count, size


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
    _, normalized = normalize_project_filesystem_path(path, project_id)
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
    await run_io(os.makedirs, parent_dir, 0o777, True)
    fd, temp_path = await run_io(tempfile.mkstemp, ".part", "sync_", parent_dir)
    os.close(fd)
    def _truncate(path: str):
        with open(path, "wb"):
            pass
    def _append_chunk(path: str, chunk: bytes):
        with open(path, "ab") as temp_file:
            temp_file.write(chunk)
    try:
        await run_io(_truncate, temp_path)
        async for chunk in request.stream():
            if not chunk:
                continue
            sha256.update(chunk)
            total_size += len(chunk)
            await run_io(_append_chunk, temp_path, chunk)
    except Exception:
        if await run_io(os.path.exists, temp_path):
            await run_io(os.remove, temp_path)
        raise
    return temp_path, sha256.hexdigest(), total_size


async def persist_upload(upload: UploadFile, destination_dir: str) -> tuple[str, str, int]:
    sha256 = hashlib.sha256()
    total_size = 0
    await run_io(os.makedirs, destination_dir, 0o777, True)
    fd, temp_path = await run_io(tempfile.mkstemp, ".part", "upload_", destination_dir)
    os.close(fd)
    def _truncate(path: str):
        with open(path, "wb"):
            pass
    def _append_chunk(path: str, chunk: bytes):
        with open(path, "ab") as temp_file:
            temp_file.write(chunk)
    try:
        await run_io(_truncate, temp_path)
        while True:
            chunk = await upload.read(1024 * 1024)
            if not chunk:
                break
            sha256.update(chunk)
            total_size += len(chunk)
            await run_io(_append_chunk, temp_path, chunk)
    except Exception:
        if await run_io(os.path.exists, temp_path):
            await run_io(os.remove, temp_path)
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
    _, normalized = normalize_project_filesystem_path(path, project_id)
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

    async def _op():
        await verify_project_access(project_id, authorization)
        target_directory_path, normalized_directory = project_filesystem_target_path(project_id, path)
        if not await run_io(os.path.isdir, target_directory_path):
            raise NotFoundError("目录", normalized_directory)
        ensure_project_realpath_inside_root(project_id, target_directory_path)
        filename = sanitize_name(file.filename or "upload.bin")
        destination_path = os.path.join(target_directory_path, filename)
        if await run_io(os.path.lexists, destination_path):
            if await run_io(os.path.isdir, destination_path):
                raise ConflictError(f"目标路径已存在目录，无法覆盖: {filename}")
            if not overwrite:
                raise ConflictError(f"目录下已存在同名文件: {filename}")

        config = get_config()
        temp_path, _, _ = await persist_upload(file, config.storage.temp_dir)
        await run_io(os.makedirs, os.path.dirname(destination_path), 0o777, True)
        await run_io(os.replace, temp_path, destination_path)
        file_path = "/" + filename if normalized_directory == "/" else f"{normalized_directory.rstrip('/')}/{filename}"
        return load_project_filesystem_entry(project_id, file_path)

    result = await run_in_queue("IO_HEAVY", _op())
    return with_trace(result.model_dump())


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
    async def _op():
        await verify_project_access(project_id, authorization)
        target_path, normalized = project_filesystem_target_path(project_id, path)
        if normalized == "/":
            raise ValidationError("不能删除项目根目录")
        if not await run_io(os.path.lexists, target_path):
            raise NotFoundError("项目文件", normalized)
        parent_target = os.path.dirname(target_path) or project_files_root(project_id)
        ensure_project_realpath_inside_root(project_id, parent_target)
        if await run_io(os.path.isdir, target_path) and not await run_io(os.path.islink, target_path):
            if recursive:
                await run_io(shutil.rmtree, target_path, True)
            else:
                await run_io(os.rmdir, target_path)
        else:
            await run_io(os.remove, target_path)
        return SuccessResponse(message="删除成功")

    result = await run_in_queue("IO_HEAVY", _op())
    return SuccessResponse(**with_trace(result.model_dump()))


@router.get("/project-filesystem/preview")
async def preview_project_filesystem_file(
    project_id: str = Query(...),
    path: str = Query(...),
    authorization: Optional[str] = Header(None),
):
    async def _op():
        await verify_project_access(project_id, authorization)
        target_path, normalized = project_filesystem_target_path(project_id, path)
        if not await run_io(os.path.lexists, target_path):
            raise NotFoundError("项目文件", normalized)
        if await run_io(os.path.isdir, target_path) and not await run_io(os.path.islink, target_path):
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
                "X-Queue-Class": "STREAM",
            },
        )

    return await run_in_queue("STREAM", _op())


@router.get("/project-filesystem/download")
async def download_project_filesystem_file(
    project_id: str = Query(...),
    path: str = Query(...),
    authorization: Optional[str] = Header(None),
):
    async def _op():
        await verify_project_access(project_id, authorization)
        target_path, normalized = project_filesystem_target_path(project_id, path)
        if not await run_io(os.path.lexists, target_path):
            raise NotFoundError("项目文件", normalized)
        if await run_io(os.path.isdir, target_path) and not await run_io(os.path.islink, target_path):
            raise ValidationError("目录不支持下载")
        resolved = ensure_project_realpath_inside_root(project_id, target_path)
        filename = path_basename(normalized)
        media_type = guess_content_type(filename, None)
        return FileResponse(
            path=resolved,
            filename=filename,
            media_type=media_type or "application/octet-stream",
            headers={"X-Queue-Class": "STREAM"},
        )

    return await run_in_queue("STREAM", _op())


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
    async def _op():
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
            if await run_io(os.path.exists, temp_path):
                await run_io(os.remove, temp_path)
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
        await run_io(os.makedirs, os.path.dirname(target_path), 0o777, True)
        await run_io(os.replace, temp_path, target_path)
        file_record.storage_key = storage_key
        db.commit()
        db.refresh(file_record)
        return to_project_path_file_entry(file_record, parent_dir)

    result = await run_in_queue("IO_HEAVY", _op())
    return with_trace(result.model_dump())


@router.delete("/vuln/project-path/object", response_model=ProjectPathOperationResponse)
async def delete_vuln_project_path_object(
    project_id: str = Query(...),
    path: str = Query(...),
    recursive: bool = Query(True),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    async def _op():
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
            if await run_io(os.path.exists, file_path):
                await run_io(os.remove, file_path)
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
        if await run_io(os.path.isdir, target_path):
            await run_io(shutil.rmtree, target_path, True)
            remove_empty_parents(target_path, sync_subproject_root(project_id, subproject.id))
        remove_empty_special_parents(project_id, subproject.id, parent)
        return ProjectPathOperationResponse(path=normalized, entry_type="directory", message="目录删除成功")

    result = await run_in_queue("IO_HEAVY", _op())
    return ProjectPathOperationResponse(**with_trace(result.model_dump()))


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
    async def _op():
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
            if await run_io(os.path.exists, temp_path):
                await run_io(os.remove, temp_path)
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
        await run_io(os.makedirs, os.path.dirname(target_path), 0o777, True)
        await run_io(os.replace, temp_path, target_path)

        file_record.storage_key = storage_key
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            if await run_io(os.path.exists, target_path):
                await run_io(os.remove, target_path)
            raise ConflictError(f"目录下已存在同名文件: {filename}")
        db.refresh(file_record)
        return file_record

    result = await run_in_queue("IO_HEAVY", _op())
    return with_trace(ManagedFileResponse.model_validate(result).model_dump())


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
    async def _op():
        file_record = require_file(db, file_id)
        await verify_project_access(file_record.project_id, authorization)
        file_path = absolute_storage_path(file_record.storage_key)
        db.delete(file_record)
        db.commit()
        if await run_io(os.path.exists, file_path):
            await run_io(os.remove, file_path)
        return SuccessResponse(message="文件删除成功")

    result = await run_in_queue("IO_HEAVY", _op())
    return SuccessResponse(**with_trace(result.model_dump()))
