"""File upload service."""

import os
import hashlib
import uuid
import asyncio
import shutil
import aiohttp
import aiofiles
from pathlib import Path
from typing import Optional, Tuple
from fastapi import UploadFile


def _safe_copy2(src: str | os.PathLike[str], dst: str | os.PathLike[str], *, follow_symlinks: bool = True) -> str:
    if os.fspath(src) == os.fspath(dst):
        return "reused"
    if os.path.realpath(os.fspath(src)) == os.path.realpath(os.fspath(dst)):
        return "reused"
    shutil.copy2(src, dst, follow_symlinks=follow_symlinks)
    return "copied"


class UploadService:
    """Upload service for file operations."""

    def __init__(self, upload_dir: str, temp_dir: str):
        """
        Initialize upload service.

        Args:
            upload_dir: Upload file storage directory
            temp_dir: Temporary file directory
        """
        self.upload_dir = Path(upload_dir)
        self.temp_dir = Path(temp_dir)
        self._ensure_dirs()

    def _ensure_dirs(self):
        """Ensure directories exists."""
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    def get_project_dir(self, project_id: str) -> Path:
        """Get project upload directory."""
        return self.upload_dir / project_id

    def get_resource_dir(self, project_id: str, resource_type: str) -> Path:
        """Get resource type directory."""
        return self.get_project_dir(project_id) / resource_type

    def get_temp_dir(self, project_id: str, resource_type: str) -> Path:
        """Get temporary directory."""
        return self.temp_dir / project_id / resource_type

    async def save_upload_file(
        self,
        file: UploadFile,
        project_id: str,
        resource_type: str
    ) -> Tuple[str, str, int, str]:
        """
        Save uploaded file to temporary directory.

        Args:
            file: Uploaded file object
            project_id: Project ID
            resource_type: Resource type

        Returns:
            tuple: (file_path, file_name, file_size, MD5 hash)
        """
        resource_dir = self.get_resource_dir(project_id, resource_type)
        resource_dir.mkdir(parents=True, exist_ok=True)

        # Generate unique filename
        file_ext = Path(file.filename).suffix
        unique_name = f"{uuid.uuid4().hex[:16]}{file_ext}"
        file_path = resource_dir / unique_name

        # Read file content
        content = await file.read()
        file_size = len(content)

        # Calculate MD5
        md5_hash = hashlib.md5(content).hexdigest()

        # Write to disk
        async with aiofiles.open(str(file_path), "wb") as f:
            await f.write(content)

        return str(file_path), file.filename, file_size, md5_hash

    async def download_file(
        self,
        url: str,
        project_id: str,
        resource_type: str
    ) -> Tuple[str, str, int, str]:
        """
        Download file from URL.

        Args:
            url: Download URL
            project_id: Project ID
            resource_type: Resource type

        Returns:
            tuple: (file_path, file_name, file_size, MD5 hash)
        """
        temp_dir = self.get_temp_dir(project_id, resource_type)
        temp_dir.mkdir(parents=True, exist_ok=True)

        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status != 200:
                    raise Exception(f"Failed to download: HTTP {response.status}")

                # Extract filename from URL or Content-Disposition
                file_name = self.extract_filename(url, response)

                file_path = temp_dir / file_name

                # Download content
                content = await response.read()
                file_size = len(content)

                # Calculate MD5
                md5_hash = hashlib.md5(content).hexdigest()

                # Write to disk
                async with aiofiles.open(str(file_path), "wb") as f:
                    await f.write(content)

                return str(file_path), file_name, file_size, md5_hash

    def extract_filename(self, url: str, response) -> str:
        """Extract filename from URL or response headers."""
        # Try Content-Disposition header first
        content_disposition = response.headers.get("Content-Disposition", "")
        if "filename=" in content_disposition:
            import re
            match = re.search(r'filename="?([^"\\n]+)"?', content_disposition)
            if match:
                return match.group(1)

        # Extract from URL path
        from urllib.parse import urlparse, unquote
        path = urlparse(url).path
        file_name = unquote(Path(path).name)

        if not file_name:
            file_name = f"download_{uuid.uuid4().hex[:8]}"

        return file_name

    def save_local_file(
        self,
        source_path: str,
        project_id: str,
        resource_type: str
    ) -> Tuple[str, str, int, str]:
        """
        Save local file to storage directory.

        Args:
            source_path: Source file path
            project_id: Project ID
            resource_type: Resource type

        Returns:
            tuple: (file_path, file_name, file_size, MD5 hash)
        """
        source = Path(source_path)

        if not source.exists():
            raise FileNotFoundError(f"Source file not found: {source_path}")

        resource_dir = self.get_resource_dir(project_id, resource_type)
        resource_dir.mkdir(parents=True, exist_ok=True)

        file_path = resource_dir / source.name
        file_size = source.stat().st_size

        # Calculate MD5
        md5_hash = hashlib.md5(source.read_bytes()).hexdigest()

        # Copy file
        _safe_copy2(source, file_path)

        return str(file_path), source.name, file_size, md5_hash

    def extract_archive(self, file_path: str, extract_path: str) -> bool:
        """
        Extract archive file.

        Args:
            file_path: Archive file path
            extract_path: Extract target directory

        Returns:
            bool: Success or failure
        """
        import zipfile
        import tarfile

        path = Path(file_path)
        extract_dir = Path(extract_path)

        if not path.exists():
            return False

        extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            if file_path.endswith(".zip"):
                with zipfile.ZipFile(path, "r") as zip_ref:
                    zip_ref.extractall(extract_dir)
            elif file_path.endswith(".tar.gz") or file_path.endswith(".tgz"):
                with tarfile.open(path, "gz") as tar_ref:
                    tar_ref.extractall(extract_dir)
            elif file_path.endswith(".tar"):
                with tarfile.open(path, "r") as tar_ref:
                    tar_ref.extractall(extract_dir)
            else:
                return False

            return True

        except Exception as e:
            print(f"Failed to extract archive: {e}")
            return False

    def get_file_format(self, file_name: str) -> str:
        """Get file format/extension."""
        ext = Path(file_name).suffix.lower()
        format_map = {
            ".zip": "zip",
            ".tar.gz": "tar.gz",
            ".tar": "tar",
            ".gz": "gz",
            ".tgz": "tgz",
            ".rar": "rar",
            ".7z": "7z"
        }
        return format_map.get(ext, "unknown")

    def is_archive(self, file_name: str) -> bool:
        """Check if file is an archive that can be extracted."""
        archive_extension = {".zip", ".tar.gz", ".tar", ".tgz", ".gz", ".rar", ".7z"}
        return Path(file_name).suffix.lower() in archive_extension


# Global upload service instance
_upload_service: Optional[UploadService] = None


def get_upload_service() -> UploadService:
    """Get upload service instance."""
    global _upload_service
    if _upload_service is None:
        raise RuntimeError("Upload service not initialized")
    return _upload_service


def init_upload_service(upload_dir: str, temp_dir: str) -> UploadService:
    """Initialize upload service instance."""
    global _upload_service
    _upload_service = UploadService(upload_dir=upload_dir, temp_dir=temp_dir)
    return _upload_service
