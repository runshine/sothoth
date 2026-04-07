from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

import psutil

from process_monitor_service.config import settings
from process_monitor_service.models.sync_models import SyncFileCandidate
from process_monitor_service.services.path_mapper import HostPathMapper


class HostPathResolver:
    def __init__(self) -> None:
        self.host_root = Path(settings.host_root)
        self.proc_root = Path(settings.proc_root)
        self.mapper = HostPathMapper()

    def to_real_path(self, host_path: str) -> str:
        return self.mapper.to_real_path(host_path)

    def to_host_path(self, real_path: str) -> str:
        return self.mapper.to_host_path(real_path)

    def to_relative_path(self, host_path: str) -> str:
        return self.mapper.canonicalize_input_path(host_path)

    def validate_host_path(self, host_path: str) -> str:
        canonical = self.mapper.canonicalize_input_path(host_path)
        real_path = self.to_real_path(canonical)
        return real_path

    def canonicalize_host_path(self, host_path: str) -> str:
        return self.mapper.canonicalize_input_path(host_path)


class FileCollectorService:
    def __init__(self) -> None:
        self.resolver = HostPathResolver()

    def collect_from_paths(self, paths: list[str]) -> tuple[list[SyncFileCandidate], list[dict[str, Any]]]:
        candidates: dict[str, SyncFileCandidate] = {}
        issues: list[dict[str, Any]] = []
        for raw_path in paths:
            try:
                host_path = self.resolver.canonicalize_host_path(raw_path)
                real_path = self.resolver.validate_host_path(host_path)
            except ValueError as exc:
                issues.append({'path': str(raw_path), 'reason': str(exc), 'status': 'failed'})
                continue
            self._collect_path_recursive(host_path, real_path, candidates, issues, ref_path=host_path)
        return list(candidates.values()), issues

    def collect_from_pids(self, pids: list[int]) -> tuple[list[SyncFileCandidate], dict[str, Any], list[dict[str, Any]]]:
        candidates: dict[str, SyncFileCandidate] = {}
        pid_summary: dict[str, Any] = {}
        pid_results: list[dict[str, Any]] = []
        for pid in pids:
            summary = {
                'pid': pid,
                'status': 'pending',
                'visible_in_host_namespace': False,
                'syncable_files': 0,
                'reasons': [],
            }
            proc_dir = self.resolver.proc_root / str(pid)
            if not proc_dir.exists():
                summary['status'] = 'skipped'
                summary['reasons'].append('pid_not_found_in_host_proc')
                pid_summary[str(pid)] = summary
                pid_results.append({'pid': pid, 'status': 'skipped', 'reason': 'pid_not_found_in_host_proc'})
                continue
            summary['visible_in_host_namespace'] = True
            collected_any = False
            for source_type, items in (
                ('exe', self._collect_pid_exe(pid)),
                ('maps', self._collect_pid_maps(pid)),
                ('open_files', self._collect_pid_open_files(pid)),
            ):
                for item in items:
                    if item.get('skip_reason'):
                        summary['reasons'].append(item['skip_reason'])
                        continue
                    host_path = item['host_path']
                    real_path = item['real_path']
                    stat_info = self._stat_path(real_path)
                    if stat_info.get('skip_reason'):
                        summary['reasons'].append(stat_info['skip_reason'])
                        continue
                    collected_any = True
                    candidate = candidates.get(host_path)
                    if not candidate:
                        candidate = SyncFileCandidate(
                            host_path=host_path,
                            real_path=real_path,
                            relative_path=self.resolver.to_relative_path(host_path),
                            size=stat_info.get('size'),
                            entry_type=stat_info['entry_type'],
                            symlink_target=stat_info.get('symlink_target'),
                        )
                        candidates[host_path] = candidate
                    candidate.pid_refs.append({'pid': pid, 'source_type': source_type, 'evidence': item.get('evidence')})
            if collected_any:
                summary['status'] = 'ok'
                refs = [c for c in candidates.values() if any(ref['pid'] == pid for ref in c.pid_refs)]
                summary['syncable_files'] = len(refs)
            else:
                summary['status'] = 'skipped'
                if not summary['reasons']:
                    summary['reasons'].append('pid_has_no_syncable_host_files')
                pid_results.append({'pid': pid, 'status': 'skipped', 'reason': summary['reasons'][-1]})
            pid_summary[str(pid)] = summary
        return list(candidates.values()), pid_summary, pid_results

    def _collect_path_recursive(self, host_path: str, real_path: str, candidates: dict[str, SyncFileCandidate], issues: list[dict[str, Any]], ref_path: str) -> None:
        path_obj = Path(real_path)
        if not path_obj.exists() and not path_obj.is_symlink():
            issues.append({'path': host_path, 'reason': 'path_not_found', 'status': 'failed'})
            return
        if path_obj.is_dir() and not path_obj.is_symlink():
            for child in sorted(path_obj.iterdir(), key=lambda item: item.name):
                child_real = str(child)
                child_host = self.resolver.to_host_path(child_real)
                self._collect_path_recursive(child_host, child_real, candidates, issues, ref_path=ref_path)
            return
        stat_info = self._stat_path(real_path)
        if stat_info.get('skip_reason'):
            issues.append({'path': host_path, 'reason': stat_info['skip_reason'], 'status': 'skipped'})
            return
        candidate = candidates.get(host_path)
        if not candidate:
            candidate = SyncFileCandidate(
                host_path=host_path,
                real_path=real_path,
                relative_path=self.resolver.to_relative_path(host_path),
                size=stat_info.get('size'),
                entry_type=stat_info['entry_type'],
                symlink_target=stat_info.get('symlink_target'),
            )
            candidates[host_path] = candidate
        if ref_path not in candidate.path_refs:
            candidate.path_refs.append(ref_path)

    def _collect_pid_exe(self, pid: int) -> list[dict[str, Any]]:
        exe_link = self.resolver.proc_root / str(pid) / 'exe'
        if not exe_link.exists() and not exe_link.is_symlink():
            return [{'skip_reason': 'pid_not_visible_from_host_namespace'}]
        try:
            target = os.readlink(exe_link)
        except OSError:
            return [{'skip_reason': 'pid_exe_unreadable'}]
        return [self._build_item(target, evidence='exe')]

    def _collect_pid_maps(self, pid: int) -> list[dict[str, Any]]:
        maps_path = self.resolver.proc_root / str(pid) / 'maps'
        if not maps_path.exists():
            return []
        items: list[dict[str, Any]] = []
        try:
            with maps_path.open('r', encoding='utf-8', errors='ignore') as fh:
                for line in fh:
                    parts = line.strip().split()
                    if len(parts) < 6:
                        continue
                    path = parts[-1]
                    if not path.startswith('/'):
                        continue
                    items.append(self._build_item(path, evidence=line.strip()))
        except OSError:
            items.append({'skip_reason': 'pid_maps_unreadable'})
        return items

    def _collect_pid_open_files(self, pid: int) -> list[dict[str, Any]]:
        fd_dir = self.resolver.proc_root / str(pid) / 'fd'
        if not fd_dir.exists():
            return []
        items: list[dict[str, Any]] = []
        for fd_entry in sorted(fd_dir.iterdir(), key=lambda item: item.name):
            try:
                target = os.readlink(fd_entry)
            except OSError:
                continue
            items.append(self._build_item(target, evidence=f'fd:{fd_entry.name}'))
        try:
            proc = psutil.Process(pid)
            for open_file in proc.open_files():
                items.append(self._build_item(open_file.path, evidence='psutil.open_files'))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return items

    def _build_item(self, host_path: str, evidence: str) -> dict[str, Any]:
        if host_path.endswith(' (deleted)'):
            return {'skip_reason': 'deleted_file', 'evidence': evidence}
        if host_path.startswith(('socket:', 'pipe:', 'anon_inode:', 'memfd:')):
            return {'skip_reason': 'non_regular_fd_target', 'evidence': evidence}
        if not host_path.startswith('/'):
            return {'skip_reason': 'non_host_file', 'evidence': evidence}
        try:
            real_path = self.resolver.validate_host_path(host_path)
        except ValueError as exc:
            return {'skip_reason': str(exc), 'evidence': evidence}
        canonical_host = self.resolver.canonicalize_host_path(host_path)
        return {'host_path': canonical_host, 'real_path': real_path, 'evidence': evidence}

    def _stat_path(self, real_path: str) -> dict[str, Any]:
        path_obj = Path(real_path)
        try:
            st = path_obj.lstat()
        except FileNotFoundError:
            return {'skip_reason': 'path_not_found'}
        mode = st.st_mode
        if stat.S_ISLNK(mode):
            try:
                target = os.readlink(path_obj)
            except OSError:
                return {'skip_reason': 'symlink_unreadable'}
            return {'entry_type': 'symlink', 'size': None, 'symlink_target': target}
        if stat.S_ISREG(mode):
            return {'entry_type': 'file', 'size': st.st_size}
        if stat.S_ISDIR(mode):
            return {'skip_reason': 'directory_requires_recursive_mode'}
        return {'skip_reason': 'unsupported_file_type'}
