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
from process_monitor_service.services.path_mapper import HostPathMapper


class ProcessService:
    _MAX_TEXT_BYTES = 512 * 1024
    _MAX_BINARY_BYTES = 256 * 1024
    _PROC_TEXT_ENTRIES = ('cmdline', 'status', 'maps', 'mounts', 'limits', 'io')
    _PROC_NET_ENTRIES = (
        'arp',
        'dev',
        'if_inet6',
        'igmp',
        'igmp6',
        'ipv6_route',
        'netstat',
        'packet',
        'protocols',
        'psched',
        'ptype',
        'raw',
        'raw6',
        'route',
        'snmp',
        'snmp6',
        'sockstat',
        'sockstat6',
        'tcp',
        'tcp6',
        'udp',
        'udp6',
        'unix',
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._latest: dict[str, Any] = {'ts': 0, 'summary': {}}
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._snapshot_path = Path(settings.state_dir) / 'process_monitor_snapshot.json'
        self._proc_root = self._resolve_proc_root()
        self._path_mapper = HostPathMapper()

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
        payload = {
            'pid': pid,
            'process': self._rich_info(proc),
            'procfs_root': str(procfs_root),
            'proc_entries': self._collect_proc_entries(procfs_root),
        }
        return self._normalize_paths_for_public(payload)

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
        info = getattr(proc, 'info', None)
        if info is None:
            info = {
                'ppid': self._safe_proc_value(proc, lambda current: current.ppid()),
                'name': self._safe_proc_value(proc, lambda current: current.name(), ''),
                'username': self._safe_proc_value(proc, lambda current: current.username(), ''),
                'status': self._safe_proc_value(proc, lambda current: current.status(), 'unknown'),
                'cmdline': self._safe_proc_value(proc, lambda current: current.cmdline(), []),
                'cwd': self._safe_proc_value(proc, lambda current: current.cwd()),
                'exe': self._safe_proc_value(proc, lambda current: current.exe()),
                'create_time': self._safe_proc_value(proc, lambda current: current.create_time()),
            }
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
                'uids': self._safe_proc_value(proc, lambda current: tuple(current.uids()) if hasattr(current, 'uids') else None),
                'gids': self._safe_proc_value(proc, lambda current: tuple(current.gids()) if hasattr(current, 'gids') else None),
                'terminal': self._safe_proc_value(proc, lambda current: current.terminal()),
                'num_threads': self._safe_proc_value(proc, lambda current: current.num_threads()),
                'threads': self._safe_proc_value(proc, lambda current: [thread._asdict() for thread in current.threads()], []),
                'open_files': self._safe_proc_value(proc, lambda current: [item._asdict() for item in current.open_files()], []),
                'connections': self._safe_proc_value(proc, lambda current: [item._asdict() for item in current.net_connections(kind='all')], []),
                'memory_info': self._safe_proc_value(proc, lambda current: current.memory_info()._asdict()),
                'memory_percent': self._safe_proc_value(proc, lambda current: current.memory_percent()),
                'cpu_times': self._safe_proc_value(proc, lambda current: current.cpu_times()._asdict()),
                'cpu_percent': self._safe_proc_value(proc, lambda current: current.cpu_percent(interval=0.0)),
                'io_counters': self._safe_proc_value(proc, lambda current: current.io_counters()._asdict() if current.io_counters() else None),
                'num_fds': self._safe_proc_value(proc, lambda current: current.num_fds() if hasattr(current, 'num_fds') else None),
                'environ': self._safe_proc_value(proc, lambda current: current.environ(), {}),
                'children': self._safe_proc_value(proc, lambda current: [child.pid for child in current.children(recursive=True)], []),
            })
        return result

    def _safe_proc_value(self, proc: psutil.Process, getter, default=None):
        try:
            return getter(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            return default

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

    def _collect_proc_entries(self, root: Path) -> dict[str, Any]:
        if not root.exists():
            raise FileNotFoundError(f'procfs_not_found: {root}')
        entries: dict[str, Any] = {}
        for name in self._PROC_TEXT_ENTRIES:
            entries[name] = self._read_proc_file(root / name, parse_environ=False)
        entries['environ'] = self._read_proc_file(root / 'environ', parse_environ=True)
        entries['fd'] = self._read_fd_entries(root / 'fd')
        entries['fdinfo'] = self._read_fdinfo_entries(root / 'fdinfo')
        entries['net'] = self._read_net_entries(root / 'net')
        entries['task'] = self._read_task_summary(root / 'task')
        entries['map_files'] = self._read_dir_summary(root / 'map_files')
        return entries

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

    def _read_proc_file(self, path: Path, *, parse_environ: bool = False) -> dict[str, Any]:
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            return {'path': str(path), 'type': 'missing'}
        except (PermissionError, OSError) as exc:
            return {'path': str(path), 'type': 'file', 'error': str(exc)}
        if parse_environ:
            return {
                'path': str(path),
                'type': 'file',
                'size': len(data),
                'items': self._parse_environ_bytes(data),
            }
        if len(data) > self._MAX_TEXT_BYTES:
            data = data[:self._MAX_TEXT_BYTES]
            truncated = True
        else:
            truncated = False
        try:
            text = data.decode('utf-8')
            return {
                'path': str(path),
                'type': 'file',
                'size': len(data),
                'encoding': 'utf-8',
                'text': text,
                'truncated': truncated,
            }
        except UnicodeDecodeError:
            if len(data) > self._MAX_BINARY_BYTES:
                data = data[:self._MAX_BINARY_BYTES]
                truncated = True
            return {
                'path': str(path),
                'type': 'file',
                'size': len(data),
                'encoding': 'base64',
                'base64': base64.b64encode(data).decode('ascii'),
                'truncated': truncated,
            }

    def _read_fd_entries(self, fd_dir: Path) -> dict[str, Any]:
        if not fd_dir.exists():
            return {'path': str(fd_dir), 'type': 'missing'}
        entries: dict[str, Any] = {}
        try:
            for child in sorted(fd_dir.iterdir(), key=lambda item: item.name):
                try:
                    target = os.readlink(child)
                    entries[child.name] = {'target': target}
                except OSError as exc:
                    entries[child.name] = {'error': str(exc)}
        except (PermissionError, OSError) as exc:
            return {'path': str(fd_dir), 'type': 'dir', 'error': str(exc)}
        return {'path': str(fd_dir), 'type': 'dir', 'children': entries}

    def _read_fdinfo_entries(self, fdinfo_dir: Path) -> dict[str, Any]:
        if not fdinfo_dir.exists():
            return {'path': str(fdinfo_dir), 'type': 'missing'}
        entries: dict[str, Any] = {}
        try:
            for child in sorted(fdinfo_dir.iterdir(), key=lambda item: item.name):
                entries[child.name] = self._read_proc_file(child, parse_environ=False)
        except (PermissionError, OSError) as exc:
            return {'path': str(fdinfo_dir), 'type': 'dir', 'error': str(exc)}
        return {'path': str(fdinfo_dir), 'type': 'dir', 'children': entries}

    def _read_net_entries(self, net_dir: Path) -> dict[str, Any]:
        if not net_dir.exists():
            return {'path': str(net_dir), 'type': 'missing'}
        entries: dict[str, Any] = {}
        for name in self._PROC_NET_ENTRIES:
            child = net_dir / name
            if child.exists():
                entries[name] = self._read_proc_file(child, parse_environ=False)
        return {'path': str(net_dir), 'type': 'dir', 'children': entries}

    def _read_task_summary(self, task_dir: Path) -> dict[str, Any]:
        if not task_dir.exists():
            return {'path': str(task_dir), 'type': 'missing'}
        items: list[dict[str, Any]] = []
        try:
            for child in sorted(task_dir.iterdir(), key=lambda item: item.name):
                stat_entry = self._read_proc_file(child / 'status', parse_environ=False)
                items.append({'tid': child.name, 'status': stat_entry})
        except (PermissionError, OSError) as exc:
            return {'path': str(task_dir), 'type': 'dir', 'error': str(exc)}
        return {'path': str(task_dir), 'type': 'dir', 'items': items}

    def _read_dir_summary(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            return {'path': str(path), 'type': 'missing'}
        try:
            names = [child.name for child in sorted(path.iterdir(), key=lambda item: item.name)]
        except (PermissionError, OSError) as exc:
            return {'path': str(path), 'type': 'dir', 'error': str(exc)}
        return {'path': str(path), 'type': 'dir', 'count': len(names), 'items': names}

    def _parse_environ_bytes(self, data: bytes) -> dict[str, str]:
        items: dict[str, str] = {}
        for raw in data.split(b'\x00'):
            if not raw:
                continue
            text = raw.decode('utf-8', errors='replace')
            if '=' in text:
                key, value = text.split('=', 1)
                items[key] = value
            else:
                items[text] = ''
        return items

    def _normalize_paths_for_public(self, node: Any, key_name: str = '') -> Any:
        if isinstance(node, dict):
            return {key: self._normalize_paths_for_public(value, str(key)) for key, value in node.items()}
        if isinstance(node, list):
            return [self._normalize_paths_for_public(item, key_name) for item in node]
        if isinstance(node, str):
            if key_name in {'path', 'procfs_root', 'cwd', 'exe', 'target', 'symlink_target'}:
                return self._path_mapper.map_public_path(node)
            return node
        return node
