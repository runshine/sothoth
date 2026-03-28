"""PVC browser service built on top of platform-k8s Pod exec."""

import base64
import json
import logging
import time
from pathlib import PurePosixPath
from typing import Any, Dict, Optional

from fastapi import HTTPException, UploadFile

from app.main import get_config
from app.services.k8s import get_k8s_service


logger = logging.getLogger(__name__)


def _normalize_browser_path(value: Optional[str]) -> str:
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


def _validate_target_name(name: str) -> str:
    value = (name or "").strip()
    if not value or "/" in value or value in {".", ".."}:
        raise HTTPException(status_code=400, detail="Invalid target name")
    return value


class PvcBrowserService:
    """Browser operations for files stored inside an output PVC."""

    def __init__(self):
        config = get_config()
        browser_config = config.get("resource_browser", {})
        self.image = browser_config.get("image", "python:3.12-alpine")
        self.image_pull_policy = browser_config.get("image_pull_policy", "IfNotPresent")
        self.mount_path = browser_config.get("mount_path", "/mnt/pvc")
        self.pod_name = browser_config.get("pod_name", "secflow-resource-browser")
        self.container_name = browser_config.get("container_name", "browser")
        self.ready_timeout = int(browser_config.get("ready_timeout", 60))
        self.exec_timeout = int(browser_config.get("exec_timeout", 30))

    def _pod_labels(self, pvc_name: str) -> Dict[str, str]:
        return {
            "app": "secflow-resource-browser",
            "managed-by": "secflow-platform-resource",
            "secflow-pvc-name": pvc_name,
        }

    def cleanup_browser_pod(self, project_id: str) -> None:
        """Remove the shared browser pod if it exists."""
        k8s = get_k8s_service()
        if k8s.delete_pod(project_id, self.pod_name):
            deadline = time.time() + 30
            while time.time() < deadline:
                if k8s.get_pod(project_id, self.pod_name) is None:
                    return
                time.sleep(1)

    def ensure_browser_pod(self, project_id: str, pvc_name: str) -> str:
        """Create or reuse a project-scoped browser pod mounted to the target PVC."""
        k8s = get_k8s_service()
        existing = k8s.get_pod(project_id, self.pod_name)
        if existing:
            labels = existing.get("label") or {}
            if labels.get("secflow-pvc-name") == pvc_name and existing.get("status") == "Running":
                return self.pod_name
            self.cleanup_browser_pod(project_id)

        manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": self.pod_name,
                "labels": self._pod_labels(pvc_name),
            },
            "spec": {
                "restartPolicy": "Always",
                "containers": [
                    {
                        "name": self.container_name,
                        "image": self.image,
                        "imagePullPolicy": self.image_pull_policy,
                        "command": ["/bin/sh", "-lc", "sleep infinity"],
                        "volumeMounts": [
                            {
                                "name": "target-pvc",
                                "mountPath": self.mount_path,
                            }
                        ],
                        "resources": {
                            "requests": {"cpu": "50m", "memory": "64Mi"},
                            "limits": {"cpu": "300m", "memory": "256Mi"},
                        },
                    }
                ],
                "volumes": [
                    {
                        "name": "target-pvc",
                        "persistentVolumeClaim": {"claimName": pvc_name},
                    }
                ],
            },
        }
        created = k8s.create_pod(project_id, manifest)
        if not created:
            raise HTTPException(status_code=500, detail="Failed to create PVC browser pod")
        if not k8s.wait_for_pod_running(project_id, self.pod_name, timeout=self.ready_timeout):
            raise HTTPException(status_code=504, detail="PVC browser pod did not become ready in time")
        return self.pod_name

    def _exec_json(
        self,
        project_id: str,
        pvc_name: str,
        script: str,
        *args: str,
        stdin: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        pod_name = self.ensure_browser_pod(project_id, pvc_name)
        result = get_k8s_service().exec_pod_command(
            project_id=project_id,
            pod_name=pod_name,
            container=self.container_name,
            command=["python", "-c", script, self.mount_path, *args],
            stdin=stdin,
            timeout=timeout or self.exec_timeout,
            tty=False,
        )
        if int(result.get("exit_code", 1)) != 0:
            raise HTTPException(
                status_code=400,
                detail=(result.get("stderr") or result.get("stdout") or "PVC browser command failed").strip(),
            )
        stdout = (result.get("stdout") or "").strip()
        if not stdout:
            return {}
        return json.loads(stdout)

    def list_root(self, project_id: str, pvc_name: str, resource_id: int) -> Dict[str, Any]:
        payload = self.list_children(project_id, pvc_name, resource_id, "/")
        return {
            "resource_id": resource_id,
            "pvc_name": pvc_name,
            "total": len(payload["directories"]) + len(payload["files"]),
            "items": payload["directories"] + payload["files"],
        }

    def list_tree(self, project_id: str, pvc_name: str, resource_id: int) -> Dict[str, Any]:
        script = _TREE_SCRIPT
        return self._exec_json(project_id, pvc_name, script, str(resource_id))

    def list_children(self, project_id: str, pvc_name: str, resource_id: int, path: str = "/") -> Dict[str, Any]:
        script = _LIST_CHILDREN_SCRIPT
        return self._exec_json(project_id, pvc_name, script, str(resource_id), _normalize_browser_path(path))

    def read_file(self, project_id: str, pvc_name: str, path: str, max_bytes: Optional[int] = None) -> Dict[str, Any]:
        script = _READ_FILE_SCRIPT
        return self._exec_json(
            project_id,
            pvc_name,
            script,
            _normalize_browser_path(path),
            str(max_bytes or 0),
            timeout=max(self.exec_timeout, 60),
        )

    async def upload_file(self, project_id: str, pvc_name: str, path: str, upload: UploadFile) -> Dict[str, Any]:
        target_dir = _normalize_browser_path(path)
        filename = _validate_target_name(upload.filename or "upload.bin")
        raw = await upload.read()
        payload = base64.b64encode(raw).decode("ascii")
        script = _UPLOAD_FILE_SCRIPT
        return self._exec_json(
            project_id,
            pvc_name,
            script,
            target_dir,
            filename,
            stdin=payload,
            timeout=max(self.exec_timeout, 120),
        )

    def create_directory(self, project_id: str, pvc_name: str, path: str, name: str) -> Dict[str, Any]:
        return self._exec_json(
            project_id,
            pvc_name,
            _CREATE_DIRECTORY_SCRIPT,
            _normalize_browser_path(path),
            _validate_target_name(name),
        )

    def rename_node(self, project_id: str, pvc_name: str, path: str, target_name: str) -> Dict[str, Any]:
        return self._exec_json(
            project_id,
            pvc_name,
            _RENAME_NODE_SCRIPT,
            _normalize_browser_path(path),
            _validate_target_name(target_name),
        )

    def move_node(self, project_id: str, pvc_name: str, path: str, target_path: str) -> Dict[str, Any]:
        return self._exec_json(
            project_id,
            pvc_name,
            _MOVE_NODE_SCRIPT,
            _normalize_browser_path(path),
            _normalize_browser_path(target_path),
        )

    def delete_node(self, project_id: str, pvc_name: str, path: str) -> Dict[str, Any]:
        normalized = _normalize_browser_path(path)
        if normalized == "/":
            raise HTTPException(status_code=400, detail="Root directory cannot be deleted")
        return self._exec_json(project_id, pvc_name, _DELETE_NODE_SCRIPT, normalized)


_COMMON_SCRIPT_HEADER = """
import base64
import json
import mimetypes
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()

def normalize(path_value: str):
    raw = (path_value or '/').strip()
    if not raw.startswith('/'):
        raw = '/' + raw
    parts = []
    for part in raw.split('/'):
        if not part or part == '.':
            continue
        if part == '..':
            raise SystemExit('Invalid path')
        parts.append(part)
    return '/' + '/'.join(parts) if parts else '/'

def resolve_target(path_value: str):
    normalized = normalize(path_value)
    relative = normalized.lstrip('/')
    target = (ROOT / relative).resolve()
    if target != ROOT and ROOT not in target.parents:
        raise SystemExit('Path escapes PVC root')
    if target.is_symlink():
        raise SystemExit('Symbolic links are not supported')
    return normalized, target

def stat_payload(path_obj: Path, normalized: str):
    st = path_obj.stat()
    node_type = 'directory' if path_obj.is_dir() else 'file'
    content_type = None if node_type == 'directory' else mimetypes.guess_type(path_obj.name)[0]
    has_children = False
    if node_type == 'directory':
        try:
            has_children = any(not child.is_symlink() for child in path_obj.iterdir())
        except Exception:
            has_children = False
    return {
        'path': normalized,
        'name': path_obj.name or '/',
        'node_type': node_type,
        'size': None if node_type == 'directory' else st.st_size,
        'updated_at': int(st.st_mtime),
        'content_type': content_type,
        'has_children': has_children,
    }
"""

_LIST_CHILDREN_SCRIPT = _COMMON_SCRIPT_HEADER + """
resource_id = int(sys.argv[2])
current_path, target = resolve_target(sys.argv[3])
if not target.exists():
    raise SystemExit('Path not found')
if not target.is_dir():
    raise SystemExit('Path is not a directory')
directories = []
files = []
with os.scandir(target) as iterator:
    entries = sorted(
        [entry for entry in iterator if not entry.is_symlink()],
        key=lambda item: (not item.is_dir(follow_symlinks=False), item.name.lower())
    )
    for entry in entries:
        child_path = current_path.rstrip('/') + '/' + entry.name if current_path != '/' else '/' + entry.name
        payload = stat_payload(Path(entry.path), child_path)
        if payload['node_type'] == 'directory':
            directories.append(payload)
        else:
            files.append(payload)
breadcrumbs = [{'path': '/', 'name': '/'}]
parts = [part for part in current_path.split('/') if part]
cursor = ''
for part in parts:
    cursor += '/' + part
    breadcrumbs.append({'path': cursor, 'name': part})
print(json.dumps({
    'resource_id': resource_id,
    'pvc_name': os.environ.get('PVC_NAME', ''),
    'current_path': current_path,
    'breadcrumbs': breadcrumbs,
    'directories': directories,
    'files': files,
}))
"""

_TREE_SCRIPT = _COMMON_SCRIPT_HEADER + """
resource_id = int(sys.argv[2])
def build_tree(path_obj: Path, normalized: str):
    node = stat_payload(path_obj, normalized)
    node['children'] = []
    if path_obj.is_dir():
        children = []
        with os.scandir(path_obj) as iterator:
            entries = sorted(
                [entry for entry in iterator if not entry.is_symlink()],
                key=lambda item: (not item.is_dir(follow_symlinks=False), item.name.lower())
            )
            for entry in entries:
                child_path = normalized.rstrip('/') + '/' + entry.name if normalized != '/' else '/' + entry.name
                child = build_tree(Path(entry.path), child_path)
                children.append(child)
        node['children'] = children
    return node
root_children = []
with os.scandir(ROOT) as iterator:
    entries = sorted(
        [entry for entry in iterator if not entry.is_symlink()],
        key=lambda item: (not item.is_dir(follow_symlinks=False), item.name.lower())
    )
    for entry in entries:
        child_path = '/' + entry.name
        root_children.append(build_tree(Path(entry.path), child_path))
print(json.dumps({
    'resource_id': resource_id,
    'pvc_name': os.environ.get('PVC_NAME', ''),
    'total': len(root_children),
    'items': root_children,
}))
"""

_READ_FILE_SCRIPT = _COMMON_SCRIPT_HEADER + """
target_path, target = resolve_target(sys.argv[2])
max_bytes = int(sys.argv[3])
if not target.exists():
    raise SystemExit('File not found')
if not target.is_file():
    raise SystemExit('Path is not a file')
data = target.read_bytes()
truncated = False
if max_bytes and len(data) > max_bytes:
    data = data[:max_bytes]
    truncated = True
print(json.dumps({
    'path': target_path,
    'filename': target.name,
    'size': target.stat().st_size,
    'content_type': mimetypes.guess_type(target.name)[0],
    'truncated': truncated,
    'base64': base64.b64encode(data).decode('ascii'),
}))
"""

_UPLOAD_FILE_SCRIPT = _COMMON_SCRIPT_HEADER + """
directory_path, directory = resolve_target(sys.argv[2])
filename = sys.argv[3]
if not directory.exists():
    raise SystemExit('Target directory not found')
if not directory.is_dir():
    raise SystemExit('Target path is not a directory')
if '/' in filename or filename in ('.', '..'):
    raise SystemExit('Invalid filename')
raw = sys.stdin.read()
data = base64.b64decode(raw.encode('ascii')) if raw else b''
target = directory / filename
target.write_bytes(data)
target_path = directory_path.rstrip('/') + '/' + filename if directory_path != '/' else '/' + filename
print(json.dumps({
    'message': 'File uploaded successfully',
    'path': target_path,
    'size': len(data),
}))
"""

_CREATE_DIRECTORY_SCRIPT = _COMMON_SCRIPT_HEADER + """
directory_path, directory = resolve_target(sys.argv[2])
name = sys.argv[3]
if not directory.exists():
    raise SystemExit('Target directory not found')
if not directory.is_dir():
    raise SystemExit('Target path is not a directory')
target = directory / name
target.mkdir(parents=False, exist_ok=False)
target_path = directory_path.rstrip('/') + '/' + name if directory_path != '/' else '/' + name
print(json.dumps({'message': 'Directory created successfully', 'path': target_path}))
"""

_RENAME_NODE_SCRIPT = _COMMON_SCRIPT_HEADER + """
source_path, source = resolve_target(sys.argv[2])
target_name = sys.argv[3]
if not source.exists():
    raise SystemExit('Source path not found')
target = source.parent / target_name
source.rename(target)
parent = source_path.rsplit('/', 1)[0] if '/' in source_path[1:] else '/'
target_path = parent.rstrip('/') + '/' + target_name if parent != '/' else '/' + target_name
print(json.dumps({'message': 'Node renamed successfully', 'path': target_path}))
"""

_MOVE_NODE_SCRIPT = _COMMON_SCRIPT_HEADER + """
source_path, source = resolve_target(sys.argv[2])
target_dir_path, target_dir = resolve_target(sys.argv[3])
if not source.exists():
    raise SystemExit('Source path not found')
if not target_dir.exists():
    raise SystemExit('Target directory not found')
if not target_dir.is_dir():
    raise SystemExit('Target path is not a directory')
target = target_dir / source.name
if target.exists():
    raise SystemExit('Target already exists')
shutil.move(str(source), str(target))
target_path = target_dir_path.rstrip('/') + '/' + source.name if target_dir_path != '/' else '/' + source.name
print(json.dumps({'message': 'Node moved successfully', 'path': target_path}))
"""

_DELETE_NODE_SCRIPT = _COMMON_SCRIPT_HEADER + """
source_path, source = resolve_target(sys.argv[2])
if not source.exists():
    raise SystemExit('Source path not found')
if source.is_dir():
    shutil.rmtree(source)
else:
    source.unlink()
print(json.dumps({'message': 'Node deleted successfully', 'path': source_path}))
"""


_service: Optional[PvcBrowserService] = None


def get_pvc_browser_service() -> PvcBrowserService:
    global _service
    if _service is None:
        _service = PvcBrowserService()
    return _service
