from __future__ import annotations

import json
import os
import queue
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from process_monitor_service.config import settings
from process_monitor_service.models.sync_models import SyncEvent, SyncFileCandidate, SyncResult, SyncTask
from process_monitor_service.services.file_collectors import FileCollectorService
from process_monitor_service.services.fileserver_client import FileserverSyncClient
from process_monitor_service.services.store import JsonStateStore


class SyncTaskService:
    def __init__(self) -> None:
        os.makedirs(settings.state_dir, exist_ok=True)
        self._tasks_store = JsonStateStore(os.path.join(settings.state_dir, 'sync_tasks.json'))
        self._results_store = JsonStateStore(os.path.join(settings.state_dir, 'sync_results.json'))
        self._events_path = Path(settings.state_dir) / 'sync_events.jsonl'
        self._lock = threading.Lock()
        self._queue: queue.Queue[str] = queue.Queue()
        self._collector = FileCollectorService()
        self._tasks: dict[str, dict[str, Any]] = self._tasks_store.load({})
        self._results: dict[str, list[dict[str, Any]]] = self._results_store.load({})
        self._events_index: dict[str, list[dict[str, Any]]] = self._load_events()
        self._worker = threading.Thread(target=self._worker_loop, name='process-sync-worker', daemon=True)
        self._worker.start()

    def create_task(self, mode: str, remote_root_url: str, *, pids: list[int] | None = None, paths: list[str] | None = None, source_task_id: str | None = None, preset_results: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        task_id = uuid.uuid4().hex
        task = SyncTask(
            task_id=task_id,
            mode=mode,
            remote_root_url=remote_root_url,
            status='pending',
            created_at=time.time(),
            pids=pids or [],
            paths=paths or [],
            source_task_id=source_task_id,
        )
        with self._lock:
            self._tasks[task_id] = task.to_dict()
            self._results.setdefault(task_id, preset_results or [])
            self._persist_locked()
            self._queue.put(task_id)
            return self._tasks[task_id]

    def list_tasks(self, status: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._tasks.values())
        if status:
            items = [item for item in items if item['status'] == status]
        items.sort(key=lambda item: item['created_at'], reverse=True)
        return items

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self._lock:
            task = self._tasks.get(task_id)
            return dict(task) if task else None

    def get_progress(self, task_id: str) -> dict[str, Any] | None:
        task = self.get_task(task_id)
        if not task:
            return None
        progress = {
            'task_id': task_id,
            'status': task['status'],
            'total_files': task['total_files'],
            'completed_files': task['completed_files'],
            'failed_files': task['failed_files'],
            'skipped_files': task['skipped_files'],
            'total_bytes': task['total_bytes'],
            'uploaded_bytes': task['uploaded_bytes'],
            'speed_bps': task['speed_bps'],
            'avg_speed_bps': task['avg_speed_bps'],
        }
        return progress

    def get_results(self, task_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._results.get(task_id, []))

    def get_events(self, task_id: str, cursor: int = 0, limit: int = 200) -> dict[str, Any]:
        with self._lock:
            items = self._events_index.get(task_id, [])
            sliced = [item for item in items if item['seq'] > cursor][:limit]
        next_cursor = sliced[-1]['seq'] if sliced else cursor
        return {'cursor': cursor, 'next_cursor': next_cursor, 'items': sliced}

    def retry_task(self, task_id: str) -> dict[str, Any]:
        task = self.get_task(task_id)
        if not task:
            raise KeyError(task_id)
        failed_items = [item for item in self.get_results(task_id) if item.get('status') == 'failed']
        retry_paths = sorted({item['source_path'] for item in failed_items if item.get('source_path')})
        retry_pids = sorted({int(item['pid']) for item in failed_items if item.get('pid') is not None})
        if task['mode'] == 'pid_files':
            return self.create_task('pid_files', task['remote_root_url'], pids=retry_pids, source_task_id=task_id, preset_results=[])
        return self.create_task('path_files', task['remote_root_url'], paths=retry_paths, source_task_id=task_id, preset_results=[])

    def _worker_loop(self) -> None:
        while True:
            task_id = self._queue.get()
            try:
                self._run_task(task_id)
            except Exception as exc:
                self._set_task_failed(task_id, f'unhandled_error: {exc}')
            finally:
                self._queue.task_done()

    def _run_task(self, task_id: str) -> None:
        task = self.get_task(task_id)
        if not task:
            return
        self._update_task(task_id, status='running', started_at=time.time(), speed_bps=0.0, avg_speed_bps=0.0)
        self._append_event(task_id, 'info', 'task_started', 'sync task started', {'mode': task['mode']})
        if task['mode'] == 'pid_files':
            candidates, pid_summary, pid_results = self._collector.collect_from_pids(task['pids'])
            for item in pid_results:
                self._append_result(task_id, SyncResult(
                    item_id=f"pid:{item['pid']}",
                    source_path=None,
                    relative_path=None,
                    entry_type='pid',
                    status='failed' if item['status'] == 'failed' else 'skipped',
                    pid=item['pid'],
                    reason=item['reason'],
                    error=item.get('reason'),
                ).to_dict())
            self._update_task(task_id, pid_summary=pid_summary)
        else:
            candidates, issues = self._collector.collect_from_paths(task['paths'])
            for item in issues:
                self._append_result(task_id, SyncResult(
                    item_id=f"path:{item['path']}",
                    source_path=item['path'],
                    relative_path=item['path'],
                    entry_type='path',
                    status='failed' if item['status'] == 'failed' else 'skipped',
                    error=item['reason'],
                    reason=item['reason'],
                ).to_dict())
        if task['mode'] == 'path_files':
            pid_summary = {}
        self._upload_candidates(task_id, candidates)
        self._finalize_task(task_id)

    def _upload_candidates(self, task_id: str, candidates: list[SyncFileCandidate]) -> None:
        task = self.get_task(task_id)
        if not task:
            return
        total_bytes = sum(item.size or 0 for item in candidates if item.entry_type == 'file')
        self._update_task(task_id, total_files=len(candidates), total_bytes=total_bytes)
        client = FileserverSyncClient(task['remote_root_url'])
        dirs = [str(Path(item.relative_path).parent) for item in candidates if str(Path(item.relative_path).parent) not in ('', '.')]
        client.ensure_dirs(dirs)
        recent_bytes = 0
        recent_ts = time.time()
        for candidate in candidates:
            self._append_event(task_id, 'info', 'file_started', f'start {candidate.relative_path}', {'path': candidate.relative_path, 'entry_type': candidate.entry_type})
            try:
                meta = client.head_object(candidate.relative_path)
                if self._should_skip(candidate, meta):
                    self._append_result(task_id, SyncResult(
                        item_id=candidate.relative_path,
                        source_path=candidate.host_path,
                        relative_path=candidate.relative_path,
                        entry_type=candidate.entry_type,
                        status='skipped',
                        size=candidate.size,
                        reason='remote_same_content',
                        refs=self._refs(candidate),
                    ).to_dict())
                    self._append_event(task_id, 'info', 'file_skipped', f'skip {candidate.relative_path}', {'path': candidate.relative_path})
                    self._touch_progress(task_id, completed_inc=1, skipped_inc=1)
                    continue
                uploaded_bytes_counter = {'delta': 0}
                def on_progress(chunk_size: int) -> None:
                    uploaded_bytes_counter['delta'] += chunk_size
                    self._touch_progress(task_id, uploaded_bytes_inc=chunk_size)
                payload = client.upload(candidate, progress_cb=on_progress)
                sha256 = payload.get('sha256')
                size = self._result_size(candidate, payload)
                self._append_result(task_id, SyncResult(
                    item_id=candidate.relative_path,
                    source_path=candidate.host_path,
                    relative_path=candidate.relative_path,
                    entry_type=candidate.entry_type,
                    status='uploaded',
                    size=size,
                    sha256=sha256,
                    refs=self._refs(candidate),
                ).to_dict())
                self._append_event(task_id, 'info', 'file_uploaded', f'uploaded {candidate.relative_path}', {'path': candidate.relative_path, 'size': size})
                self._touch_progress(task_id, completed_inc=1)
            except Exception as exc:
                self._append_result(task_id, SyncResult(
                    item_id=candidate.relative_path,
                    source_path=candidate.host_path,
                    relative_path=candidate.relative_path,
                    entry_type=candidate.entry_type,
                    status='failed',
                    size=candidate.size,
                    error=str(exc),
                    refs=self._refs(candidate),
                ).to_dict())
                self._append_event(task_id, 'error', 'file_failed', f'failed {candidate.relative_path}', {'path': candidate.relative_path, 'error': str(exc)})
                self._touch_progress(task_id, completed_inc=1, failed_inc=1)
            now = time.time()
            snapshot = self.get_task(task_id)
            if snapshot and snapshot['started_at']:
                elapsed = max(now - snapshot['started_at'], 0.001)
                avg_speed = snapshot['uploaded_bytes'] / elapsed
                current_speed = (snapshot['uploaded_bytes'] - recent_bytes) / max(now - recent_ts, 0.001)
                self._update_task(task_id, avg_speed_bps=avg_speed, speed_bps=current_speed)
                recent_bytes = snapshot['uploaded_bytes']
                recent_ts = now

    def _should_skip(self, candidate: SyncFileCandidate, meta: Any) -> bool:
        if not meta.exists:
            return False
        if candidate.entry_type == 'symlink':
            return meta.entry_type == 'symlink' and meta.symlink_target == (candidate.symlink_target or '')
        if meta.entry_type != 'file':
            return False
        if meta.size != (candidate.size or 0):
            return False
        if not meta.sha256:
            return False
        sha256, _ = FileserverSyncClient.compute_sha256(candidate.real_path)
        return sha256 == meta.sha256

    def _finalize_task(self, task_id: str) -> None:
        task = self.get_task(task_id)
        if not task:
            return
        results = self.get_results(task_id)
        uploaded = sum(1 for item in results if item.get('status') == 'uploaded')
        skipped = sum(1 for item in results if item.get('status') == 'skipped')
        failed = sum(1 for item in results if item.get('status') == 'failed')
        status = 'success'
        if failed and (uploaded or skipped):
            status = 'partial_success'
        elif failed and not (uploaded or skipped):
            status = 'failed'
        elif skipped and not uploaded and task.get('mode') == 'pid_files' and task.get('total_files', 0) == 0:
            status = 'partial_success'
        self._update_task(task_id, status=status, finished_at=time.time(), failed_files=failed, skipped_files=skipped, completed_files=uploaded + skipped + failed, speed_bps=0.0)
        self._append_event(task_id, 'info', 'task_finished', 'sync task finished', {'status': status})

    def _set_task_failed(self, task_id: str, error: str) -> None:
        self._update_task(task_id, status='failed', finished_at=time.time(), last_error=error, speed_bps=0.0)
        self._append_event(task_id, 'error', 'task_failed', error, {'error': error})

    def _update_task(self, task_id: str, **updates: Any) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return
            task.update(updates)
            self._persist_locked()

    def _touch_progress(
        self,
        task_id: str,
        *,
        completed_inc: int = 0,
        failed_inc: int = 0,
        skipped_inc: int = 0,
        uploaded_bytes_inc: int = 0,
    ) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return
            task['completed_files'] = int(task.get('completed_files', 0)) + completed_inc
            task['failed_files'] = int(task.get('failed_files', 0)) + failed_inc
            task['skipped_files'] = int(task.get('skipped_files', 0)) + skipped_inc
            task['uploaded_bytes'] = int(task.get('uploaded_bytes', 0)) + uploaded_bytes_inc
            self._persist_locked()

    def _append_result(self, task_id: str, item: dict[str, Any]) -> None:
        with self._lock:
            self._results.setdefault(task_id, []).append(item)
            self._persist_locked()

    def _append_event(
        self,
        task_id: str,
        level: str,
        event_type: str,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        with self._lock:
            events = self._events_index.setdefault(task_id, [])
            seq = (events[-1]['seq'] if events else 0) + 1
            event = SyncEvent(
                seq=seq,
                ts=time.time(),
                level=level,
                type=event_type,
                message=message,
                data=data or {},
            ).to_dict()
            events.append(event)
            with self._events_path.open('a', encoding='utf-8') as fh:
                fh.write(json.dumps({'task_id': task_id, **event}, ensure_ascii=True) + '\n')

    def _refs(self, candidate: SyncFileCandidate) -> list[dict[str, Any]]:
        refs: list[dict[str, Any]] = []
        refs.extend(candidate.pid_refs)
        refs.extend({'path': item, 'source_type': 'path'} for item in candidate.path_refs)
        return refs

    def _result_size(self, candidate: SyncFileCandidate, payload: dict[str, Any]) -> int | None:
        if candidate.entry_type != 'file':
            return None
        if candidate.size is not None:
            return candidate.size
        payload_size = payload.get('size')
        if isinstance(payload_size, int):
            return payload_size
        if isinstance(payload_size, str) and payload_size.isdigit():
            return int(payload_size)
        try:
            return os.path.getsize(candidate.real_path)
        except OSError:
            return None

    def _load_events(self) -> dict[str, list[dict[str, Any]]]:
        items: dict[str, list[dict[str, Any]]] = {}
        if not self._events_path.exists():
            return items
        with self._events_path.open('r', encoding='utf-8') as fh:
            for line in fh:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                task_id = payload.pop('task_id', None)
                if not task_id:
                    continue
                items.setdefault(task_id, []).append(payload)
        return items

    def _persist_locked(self) -> None:
        self._tasks_store.save(self._tasks)
        self._results_store.save(self._results)


sync_task_service = SyncTaskService()
