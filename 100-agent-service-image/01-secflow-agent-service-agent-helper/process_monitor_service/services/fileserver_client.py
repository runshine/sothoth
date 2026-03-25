from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterator

import requests

from process_monitor_service.models.sync_models import SyncFileCandidate


@dataclass
class RemoteMeta:
    exists: bool
    entry_type: str | None = None
    size: int | None = None
    sha256: str | None = None
    symlink_target: str | None = None


class FileserverSyncClient:
    def __init__(self, remote_root_url: str, timeout: int = 30) -> None:
        self.remote_root_url = remote_root_url.rstrip('/')
        self.timeout = timeout

    def ensure_dirs(self, dirs: list[str]) -> None:
        if not dirs:
            return
        resp = requests.post(f'{self.remote_root_url}/mkdirs', json={'paths': sorted(set(dirs))}, timeout=self.timeout)
        resp.raise_for_status()

    def head_object(self, relative_path: str) -> RemoteMeta:
        resp = requests.head(f'{self.remote_root_url}/object', params={'path': relative_path}, timeout=self.timeout)
        if resp.status_code == 404:
            return RemoteMeta(exists=False)
        resp.raise_for_status()
        headers = resp.headers
        return RemoteMeta(
            exists=headers.get('X-Sync-Exists', 'false').lower() == 'true',
            entry_type=headers.get('X-Sync-Entry-Type'),
            size=int(headers['X-Sync-Size']) if headers.get('X-Sync-Size') else None,
            sha256=headers.get('X-Sync-Sha256'),
            symlink_target=headers.get('X-Sync-Symlink-Target'),
        )

    def upload(self, candidate: SyncFileCandidate, progress_cb=None) -> dict[str, Any]:
        if candidate.entry_type == 'symlink':
            payload = b''
            headers = {'X-Sync-Entry-Type': 'symlink', 'X-Sync-Symlink-Target': candidate.symlink_target or ''}
            resp = requests.put(
                f'{self.remote_root_url}/object',
                params={'path': candidate.relative_path, 'size': 0, 'sha256': ''},
                headers=headers,
                data=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return resp.json()

        sha256, size = self._compute_sha256(candidate.real_path)

        def generate() -> Iterator[bytes]:
            with open(candidate.real_path, 'rb') as fh:
                while True:
                    chunk = fh.read(1024 * 1024)
                    if not chunk:
                        break
                    if progress_cb:
                        progress_cb(len(chunk))
                    yield chunk

        headers = {'X-Sync-Entry-Type': 'file'}
        resp = requests.put(
            f'{self.remote_root_url}/object',
            params={'path': candidate.relative_path, 'size': size, 'sha256': sha256},
            headers=headers,
            data=generate(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        payload = resp.json()
        payload.setdefault('sha256', sha256)
        payload.setdefault('size', size)
        return payload

    @staticmethod
    def compute_sha256(path: str) -> tuple[str, int]:
        sha256 = hashlib.sha256()
        total = 0
        with open(path, 'rb') as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                sha256.update(chunk)
                total += len(chunk)
        return sha256.hexdigest(), total

    def _compute_sha256(self, path: str) -> tuple[str, int]:
        return self.compute_sha256(path)
