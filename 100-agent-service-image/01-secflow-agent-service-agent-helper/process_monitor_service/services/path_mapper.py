from __future__ import annotations

import os
from pathlib import Path

from process_monitor_service.config import settings


class HostPathMapper:
    def __init__(self) -> None:
        self.host_root = Path(settings.host_root).resolve(strict=False)
        self.host_root_text = str(self.host_root)

    def canonicalize_input_path(self, raw_path: str) -> str:
        text = str(raw_path or '').strip()
        if not text.startswith('/'):
            raise ValueError(f'invalid_host_path: {raw_path}')
        normalized = os.path.normpath(text)
        if not normalized.startswith('/'):
            normalized = '/' + normalized.lstrip('/')
        normalized = self._strip_host_root_prefix(normalized)
        # Validate path is resolvable inside host_root.
        self.to_real_path(normalized)
        return normalized

    def to_real_path(self, canonical_host_path: str) -> str:
        host_path = str(canonical_host_path or '').strip()
        if not host_path.startswith('/'):
            raise ValueError(f'invalid_host_path: {canonical_host_path}')
        joined = os.path.normpath(str(self.host_root / host_path.lstrip('/')))
        joined_abs = os.path.abspath(joined)
        root_abs = os.path.abspath(self.host_root_text)
        if os.path.commonpath([joined_abs, root_abs]) != root_abs:
            raise ValueError(f'path_escapes_host_root: {canonical_host_path}')
        return joined_abs

    def to_host_path(self, real_path: str) -> str:
        normalized = os.path.normpath(str(real_path or '').strip())
        if not normalized.startswith('/'):
            return normalized
        root_abs = os.path.abspath(self.host_root_text)
        real_abs = os.path.abspath(normalized)
        if os.path.commonpath([real_abs, root_abs]) != root_abs:
            return normalized
        rel = os.path.relpath(real_abs, root_abs)
        if rel in ('.', ''):
            return '/'
        return '/' + rel.replace('\\', '/').lstrip('/')

    def map_public_path(self, value: str) -> str:
        text = str(value or '')
        if not text:
            return text
        suffix = ''
        if text.endswith(' (deleted)'):
            suffix = ' (deleted)'
            text = text[:-10]
        if not text.startswith('/'):
            return str(value or '')
        normalized = os.path.normpath(text)
        normalized = self._strip_host_root_prefix(normalized)
        if normalized in ('', '.'):
            normalized = '/'
        if not normalized.startswith('/'):
            normalized = '/' + normalized.lstrip('/')
        return f'{normalized}{suffix}'

    def _strip_host_root_prefix(self, path: str) -> str:
        normalized = os.path.normpath(path)
        root = self.host_root_text.rstrip('/')
        if normalized == root:
            return '/'
        prefix = root + '/'
        if normalized.startswith(prefix):
            rel = normalized[len(prefix):].lstrip('/')
            return '/' + rel if rel else '/'
        return normalized

