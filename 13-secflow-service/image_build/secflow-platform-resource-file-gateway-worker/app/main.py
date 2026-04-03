"""secflow-platform-resource-file-gateway-worker."""

import base64
import binascii
import gzip
import mimetypes
import os
import shutil
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Optional

import uvicorn
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

ROOT_PATH = Path(os.environ.get("PVC_MOUNT_PATH", "/data/pvc")).resolve()
INTERNAL_TOKEN = os.environ.get("FILE_GATEWAY_INTERNAL_TOKEN", "")
MAX_UPLOAD_BYTES = int(os.environ.get("FILE_GATEWAY_MAX_UPLOAD_BYTES", str(1024 * 1024 * 1024)))

app = FastAPI(title="secflow-platform-resource-file-gateway-worker", version="1.0.0")


class CreateDirectoryRequest(BaseModel):
    path: str = "/"
    name: str


class RenameNodeRequest(BaseModel):
    path: str
    target_name: str


class MoveNodeRequest(BaseModel):
    path: str
    target_path: str


def _ensure_token(x_internal_token: Optional[str] = Header(None, alias="X-Internal-Token")) -> None:
    if INTERNAL_TOKEN and x_internal_token != INTERNAL_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid internal token")


def _normalize_path(value: Optional[str]) -> str:
    raw = (value or "/").strip()
    if not raw:
        return "/"
    if not raw.startswith("/"):
        raw = f"/{raw}"
    normalized = PurePosixPath(raw)
    parts = []
    for part in normalized.parts:
        if part in ("", "/"):
            continue
        if part in (".", ".."):
            raise HTTPException(status_code=400, detail="Invalid path")
        parts.append(part)
    return "/" + "/".join(parts) if parts else "/"


def _validate_name(value: str, label: str = "name") -> str:
    name = (value or "").strip()
    if not name or "/" in name or name in {".", ".."}:
        raise HTTPException(status_code=400, detail=f"Invalid {label}")
    return name


def _resolve_target(path_value: Optional[str]) -> tuple[str, Path]:
    normalized = _normalize_path(path_value)
    relative = normalized.lstrip("/")
    target = (ROOT_PATH / relative).resolve()
    if target != ROOT_PATH and ROOT_PATH not in target.parents:
        raise HTTPException(status_code=400, detail="Path escapes PVC root")
    if target.is_symlink():
        raise HTTPException(status_code=400, detail="Symbolic links are not supported")
    return normalized, target


def _node_payload(path_obj: Path, normalized: str) -> dict:
    stat = path_obj.stat()
    node_type = "directory" if path_obj.is_dir() else "file"
    content_type = None if node_type == "directory" else mimetypes.guess_type(path_obj.name)[0]
    has_children = False
    if node_type == "directory":
        try:
            has_children = any(not child.is_symlink() for child in path_obj.iterdir())
        except Exception:
            has_children = False
    return {
        "path": normalized,
        "name": path_obj.name or "/",
        "node_type": node_type,
        "size": None if node_type == "directory" else stat.st_size,
        "updated_at": int(stat.st_mtime),
        "content_type": content_type,
        "has_children": has_children,
    }


def _iter_entries(path_obj: Path):
    with os.scandir(path_obj) as iterator:
        entries = [entry for entry in iterator if not entry.is_symlink()]
    entries.sort(key=lambda item: (not item.is_dir(follow_symlinks=False), item.name.lower()))
    return entries


def _extract_to_directory(archive_path: Path, target_dir: Path, original_name: str) -> None:
    lower = original_name.lower()
    if lower.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(target_dir)
        return
    if lower.endswith(".tar.gz") or lower.endswith(".tgz"):
        with tarfile.open(archive_path, "r:gz") as tf:
            tf.extractall(target_dir)
        return
    if lower.endswith(".tar"):
        with tarfile.open(archive_path, "r:") as tf:
            tf.extractall(target_dir)
        return
    if lower.endswith(".gz"):
        out_name = Path(original_name[:-3] if lower.endswith(".gz") else original_name).name or "archive"
        out_path = target_dir / out_name
        with gzip.open(archive_path, "rb") as src, out_path.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        return
    raise HTTPException(status_code=400, detail="Unsupported archive format")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "root": str(ROOT_PATH)}


@app.get("/fs/children")
def list_children(path: str = Query("/"), _: None = Depends(_ensure_token)) -> dict:
    current_path, target = _resolve_target(path)
    if not target.exists():
        raise HTTPException(status_code=404, detail="Path not found")
    if not target.is_dir():
        raise HTTPException(status_code=400, detail="Path is not a directory")

    directories = []
    files = []
    for entry in _iter_entries(target):
        child_path = current_path.rstrip("/") + "/" + entry.name if current_path != "/" else "/" + entry.name
        payload = _node_payload(Path(entry.path), child_path)
        if payload["node_type"] == "directory":
            directories.append(payload)
        else:
            files.append(payload)

    breadcrumbs = [{"path": "/", "name": "/"}]
    parts = [part for part in current_path.split("/") if part]
    cursor = ""
    for part in parts:
        cursor += "/" + part
        breadcrumbs.append({"path": cursor, "name": part})

    return {
        "current_path": current_path,
        "breadcrumbs": breadcrumbs,
        "directories": directories,
        "files": files,
    }


@app.get("/fs/file")
def read_file(path: str = Query(...), max_bytes: int = Query(1048576, ge=0, le=10485760), _: None = Depends(_ensure_token)) -> dict:
    target_path, target = _resolve_target(path)
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    data = target.read_bytes()
    truncated = False
    if max_bytes and len(data) > max_bytes:
        data = data[:max_bytes]
        truncated = True

    return {
        "path": target_path,
        "filename": target.name,
        "size": target.stat().st_size,
        "content_type": mimetypes.guess_type(target.name)[0],
        "truncated": truncated,
        "base64": base64.b64encode(data).decode("ascii"),
    }


@app.get("/fs/download")
def download_file(path: str = Query(...), _: None = Depends(_ensure_token)):
    _, target = _resolve_target(path)
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(path=str(target), filename=target.name, media_type="application/octet-stream")


@app.post("/fs/upload")
async def upload_file(path: str = Form("/"), file: UploadFile = File(...), _: None = Depends(_ensure_token)) -> dict:
    directory_path, directory = _resolve_target(path)
    if not directory.exists() or not directory.is_dir():
        raise HTTPException(status_code=400, detail="Target directory not found")

    filename = _validate_name(file.filename or "upload.bin", label="filename")
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large")

    target = directory / filename
    target.write_bytes(content)
    target_path = directory_path.rstrip("/") + "/" + filename if directory_path != "/" else "/" + filename
    return {"message": "File uploaded successfully", "path": target_path, "size": len(content)}


@app.post("/fs/directories")
def create_directory(request: CreateDirectoryRequest, _: None = Depends(_ensure_token)) -> dict:
    directory_path, directory = _resolve_target(request.path)
    if not directory.exists() or not directory.is_dir():
        raise HTTPException(status_code=400, detail="Target directory not found")

    name = _validate_name(request.name)
    target = directory / name
    target.mkdir(parents=False, exist_ok=False)
    target_path = directory_path.rstrip("/") + "/" + name if directory_path != "/" else "/" + name
    return {"message": "Directory created successfully", "path": target_path}


@app.post("/fs/rename")
def rename_node(request: RenameNodeRequest, _: None = Depends(_ensure_token)) -> dict:
    source_path, source = _resolve_target(request.path)
    if not source.exists():
        raise HTTPException(status_code=404, detail="Source path not found")

    target_name = _validate_name(request.target_name, label="target_name")
    target = source.parent / target_name
    if target.exists():
        raise HTTPException(status_code=409, detail="Target already exists")

    source.rename(target)
    parent = source_path.rsplit("/", 1)[0] if "/" in source_path[1:] else "/"
    target_path = parent.rstrip("/") + "/" + target_name if parent != "/" else "/" + target_name
    return {"message": "Node renamed successfully", "path": target_path}


@app.post("/fs/move")
def move_node(request: MoveNodeRequest, _: None = Depends(_ensure_token)) -> dict:
    source_path, source = _resolve_target(request.path)
    if not source.exists():
        raise HTTPException(status_code=404, detail="Source path not found")

    target_dir_path, target_dir = _resolve_target(request.target_path)
    if not target_dir.exists() or not target_dir.is_dir():
        raise HTTPException(status_code=400, detail="Target directory not found")

    target = target_dir / source.name
    if target.exists():
        raise HTTPException(status_code=409, detail="Target already exists")

    shutil.move(str(source), str(target))
    target_path = target_dir_path.rstrip("/") + "/" + source.name if target_dir_path != "/" else "/" + source.name
    return {"message": "Node moved successfully", "path": target_path}


@app.delete("/fs/node")
def delete_node(path: str = Query(...), _: None = Depends(_ensure_token)) -> dict:
    source_path, source = _resolve_target(path)
    if source_path == "/":
        raise HTTPException(status_code=400, detail="Root directory cannot be deleted")
    if not source.exists():
        raise HTTPException(status_code=404, detail="Source path not found")

    if source.is_dir():
        shutil.rmtree(source)
    else:
        source.unlink()
    return {"message": "Node deleted successfully", "path": source_path}


@app.post("/fs/extract")
async def extract_archive(path: str = Form("/"), file: UploadFile = File(...), _: None = Depends(_ensure_token)) -> dict:
    target_path, target_dir = _resolve_target(path)
    if not target_dir.exists() or not target_dir.is_dir():
        raise HTTPException(status_code=400, detail="Target directory not found")

    original_name = _validate_name(file.filename or "archive.bin", label="filename")
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large")

    tmp_name = f".upload-{os.getpid()}-{os.urandom(6).hex()}"
    archive_path = target_dir / tmp_name
    archive_path.write_bytes(content)
    try:
        _extract_to_directory(archive_path, target_dir, original_name)
    except (zipfile.BadZipFile, tarfile.ReadError, OSError, binascii.Error, gzip.BadGzipFile) as error:
        raise HTTPException(status_code=400, detail=f"Failed to extract archive: {error}") from error
    finally:
        if archive_path.exists():
            archive_path.unlink()

    return {
        "message": "Archive extracted successfully",
        "path": target_path,
        "filename": original_name,
        "size": len(content),
    }


def main() -> None:
    host = os.environ.get("APP_HOST", "0.0.0.0")
    port = int(os.environ.get("APP_PORT", "8081"))
    uvicorn.run(app, host=host, port=port)

