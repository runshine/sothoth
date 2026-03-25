from __future__ import annotations

import base64
import json
import os
import signal
import threading
import time
from pathlib import Path
from typing import Any

import psutil

from process_monitor_service.config import settings


class ProcessService:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._latest: dict[str, Any] = {'ts': 0, 'summary': {}}
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._snapshot_path = Path(settings.state_dir) / 'process_monitor_snapshot.json'
        self._proc_root = self._resolve_proc_root()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name='process-monitor-housekeeping', daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    def latest(self) -> dict[str, Any]:
        with self._lock:
            if self._latest.get('ts'):
                return dict(self._latest)
        if self._snapshot_path.exists():
            try:
                return json.loads(self._snapshot_path.read_text())
            except Exception:
                pass
        return self.snapshot()

    def snapshot(self) -> dict[str, Any]:
        current = {
            'ts': int(time.time()),
            'summary': self._collect_summary(),
        }
        with self._lock:
            self._latest = current
        self._persist(current)
        return current

    def list_processes(self, *, name: str | None = None, keyword: str | None = None) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'status', 'cmdline', 'cwd', 'exe', 'create_time']):
            try:
                info = self._basic_info(proc)
                if name and info['name'] != name:
                    continue
                if keyword:
                    haystack = f"{info['name']} {' '.join(info['cmdline'])}"
                    if keyword not in haystack:
                        continue
                items.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        items.sort(key=lambda item: item['pid'])
        return items

    def get_process_details(self, pid: int) -> dict[str, Any]:
        proc = psutil.Process(pid)
        procfs_root = self._proc_root / str(pid)
        return {
            'process': self._rich_info(proc),
            'procfs_root': str(procfs_root),
            'procfs': self._walk_procfs(procfs_root),
        }

    def send_signal(self, *, pids: list[int], signal_value: str | int | None = None, force: bool = False) -> dict[str, Any]:
        resolved_signal = self._resolve_signal(signal_value, force)
        results: list[dict[str, Any]] = []
        for pid in sorted(set(pids)):
            try:
                proc = psutil.Process(pid)
                os.kill(pid, resolved_signal)
                results.append({
                    'pid': pid,
                    'ok': True,
                    'signal': resolved_signal,
                    'name': proc.name(),
                })
            except psutil.NoSuchProcess:
                results.append({'pid': pid, 'ok': False, 'error': 'process_not_found'})
            except PermissionError as exc:
                results.append({'pid': pid, 'ok': False, 'error': f'permission_denied: {exc}'})
            except OSError as exc:
                results.append({'pid': pid, 'ok': False, 'error': str(exc)})
        return {
            'signal': resolved_signal,
            'force': force,
            'results': results,
        }

    def resolve_target_pids(
        self,
        *,
        pid: int | None = None,
        pids: list[int] | None = None,
        name: str | None = None,
        keyword: str | None = None,
    ) -> list[int]:
        resolved: set[int] = set()
        if pid is not None:
            resolved.add(int(pid))
        if pids:
            resolved.update(int(item) for item in pids)
        if name or keyword:
            for item in self.list_processes(name=name, keyword=keyword):
                resolved.add(int(item['pid']))
        return sorted(resolved)

    def _loop(self) -> None:
        while not self._stop.wait(settings.interval_sec):
            try:
                self.snapshot()
            except Exception:
                continue

    def _collect_summary(self) -> dict[str, Any]:
        total = 0
        running = 0
        sleeping = 0
        zombies = 0
        for proc in psutil.process_iter(['status']):
            try:
                total += 1
                status = proc.info.get('status')
                if status == psutil.STATUS_RUNNING:
                    running += 1
                elif status in (psutil.STATUS_SLEEPING, psutil.STATUS_DISK_SLEEP):
                    sleeping += 1
                elif status == psutil.STATUS_ZOMBIE:
                    zombies += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return {
            'total_processes': total,
            'running': running,
            'sleeping': sleeping,
            'zombie': zombies,
        }

    def _persist(self, snapshot: dict[str, Any]) -> None:
        os.makedirs(settings.state_dir, exist_ok=True)
        self._snapshot_path.write_text(json.dumps(snapshot, ensure_ascii=True, indent=2))

    def _resolve_proc_root(self) -> Path:
        configured = Path(settings.proc_root)
        if configured.exists():
            return configured
        host_proc = Path(settings.host_root) / 'proc'
        if host_proc.exists():
            return host_proc
        return Path('/proc')

    def _basic_info(self, proc: psutil.Process) -> dict[str, Any]:
        info = proc.info
        return {
            'pid': proc.pid,
            'ppid': info.get('ppid'),
            'name': info.get('name') or '',
            'username': info.get('username') or '',
            'status': info.get('status') or 'unknown',
            'cmdline': info.get('cmdline') or [],
            'cwd': info.get('cwd'),
            'exe': info.get('exe'),
            'create_time': info.get('create_time'),
        }

    def _rich_info(self, proc: psutil.Process) -> dict[str, Any]:
        with proc.oneshot():
            result = self._basic_info(proc)
            result.update({
                'uids': tuple(proc.uids()) if hasattr(proc, 'uids') else None,
                'gids': tuple(proc.gids()) if hasattr(proc, 'gids') else None,
                'terminal': proc.terminal(),
                'num_threads': proc.num_threads(),
                'threads': [thread._asdict() for thread in proc.threads()],
                'open_files': [item._asdict() for item in proc.open_files()],
                'connections': [item._asdict() for item in proc.net_connections(kind='all')],
                'memory_info': proc.memory_info()._asdict(),
                'memory_percent': proc.memory_percent(),
                'cpu_times': proc.cpu_times()._asdict(),
                'cpu_percent': proc.cpu_percent(interval=0.0),
                'io_counters': proc.io_counters()._asdict() if proc.io_counters() else None,
                'num_fds': proc.num_fds() if hasattr(proc, 'num_fds') else None,
                'environ': proc.environ(),
                'children': [child.pid for child in proc.children(recursive=True)],
            })
        return result

    def _resolve_signal(self, signal_value: str | int | None, force: bool) -> int:
        if force:
            return signal.SIGKILL
        if signal_value is None:
            return signal.SIGTERM
        if isinstance(signal_value, int):
            return signal_value
        normalized = str(signal_value).upper().strip()
        if normalized.isdigit():
            return int(normalized)
        if not normalized.startswith('SIG'):
            normalized = f'SIG{normalized}'
        if not hasattr(signal, normalized):
            raise ValueError(f'unsupported_signal: {signal_value}')
        return int(getattr(signal, normalized))

    def _walk_procfs(self, root: Path) -> dict[str, Any]:
        if not root.exists():
            raise FileNotFoundError(f'procfs_not_found: {root}')
        return self._read_path(root)

    def _read_path(self, path: Path) -> dict[str, Any]:
        try:
            stat = path.lstat()
        except FileNotFoundError:
            return {'path': str(path), 'type': 'missing'}
        mode = stat.st_mode
        if path.is_symlink():
            try:
                target = os.readlink(path)
            except OSError as exc:
                target = f'<error: {exc}>'
            return {'path': str(path), 'type': 'symlink', 'target': target}
        if path.is_dir():
            children: dict[str, Any] = {}
            try:
                for child in sorted(path.iterdir(), key=lambda item: item.name):
                    children[child.name] = self._read_path(child)
            except PermissionError as exc:
                return {'path': str(path), 'type': 'dir', 'error': str(exc)}
            return {'path': str(path), 'type': 'dir', 'children': children}
        return self._read_file(path)

    def _read_file(self, path: Path) -> dict[str, Any]:
        try:
            data = path.read_bytes()
        except PermissionError as exc:
            return {'path': str(path), 'type': 'file', 'error': str(exc)}
        except OSError as exc:
            return {'path': str(path), 'type': 'file', 'error': str(exc)}
        try:
            text = data.decode('utf-8')
            content: dict[str, Any] = {'encoding': 'utf-8', 'text': text}
        except UnicodeDecodeError:
            content = {
                'encoding': 'base64',
                'base64': base64.b64encode(data).decode('ascii'),
            }
        return {
            'path': str(path),
            'type': 'file',
            'size': len(data),
            **content,
        }
