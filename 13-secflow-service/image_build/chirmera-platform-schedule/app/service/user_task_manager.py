"""User task center service for chirmera-platform-schedule."""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import httpx
from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import ConflictError, NotFoundError, UpstreamError, ValidationError
from app.model import (
    ScheduleUserTask,
    ScheduleUserTaskDispatch,
    ScheduleUserTaskInputBinding,
)
from app.service.http_client import get_shared_async_client


TASK_TYPE_INPUT_TYPE: dict[str, str] = {
    "binary_firmware_e2e": "software",
    "source_scan_e2e": "code",
    "binary_module_e2e": "software",
}

TASK_TYPE_BINARY_SECURITY: dict[str, str] = {
    "binary_firmware_e2e": "binary",
    "source_scan_e2e": "source",
    "binary_module_e2e": "binary_module",
}

TASK_TYPE_DETAIL_VIEW: dict[str, str] = {
    "binary_firmware_e2e": "binary-security-detail",
    "source_scan_e2e": "source-security-detail",
    "binary_module_e2e": "binary-module-security-detail",
}


@dataclass
class ResolvedInputRecord:
    upload_id: str
    project_id: str
    input_type: str
    status: str
    keep_original: bool
    target_path: str
    latest_batch_id: Optional[str]
    display_name: str


class ProjectInputResolver:
    def __init__(self) -> None:
        self.cfg = get_config().fileserver_service

    async def list_uploads(self, project_id: str, bearer_token: str) -> dict[str, Any]:
        query = httpx.QueryParams({"project_id": project_id, "page_size": 200})
        client = await get_shared_async_client("schedule-fileserver", timeout=self.cfg.timeout)
        try:
            response = await client.get(
                f"{self.cfg.base_url.rstrip('/')}{self.cfg.project_input_uploads_path}",
                params=query,
                headers={"Authorization": f"Bearer {bearer_token}"},
            )
        except httpx.TimeoutException as exc:
            raise UpstreamError("读取任务输入列表超时") from exc
        except httpx.RequestError as exc:
            raise UpstreamError(f"读取任务输入列表失败: {exc}") from exc
        if response.status_code != 200:
            raise UpstreamError(f"任务输入服务返回异常状态码: {response.status_code}")
        return response.json()

    async def resolve_single(self, project_id: str, upload_id: str, bearer_token: str) -> ResolvedInputRecord:
        payload = await self.list_uploads(project_id, bearer_token)
        for item in payload.get("items") or []:
            if str(item.get("upload_id")) == upload_id:
                latest_batch = item.get("latest_batch") or {}
                return ResolvedInputRecord(
                    upload_id=str(item.get("upload_id")),
                    project_id=str(item.get("project_id")),
                    input_type=str(item.get("input_type") or ""),
                    status=str(item.get("status") or ""),
                    keep_original=bool(item.get("keep_original")),
                    target_path=str(item.get("target_path") or ""),
                    latest_batch_id=str(latest_batch.get("batch_id")) if latest_batch.get("batch_id") else None,
                    display_name=str(item.get("target_path") or item.get("upload_id") or ""),
                )
        raise ValidationError(f"未找到任务输入记录: {upload_id}")

    async def resolve_path(self, project_id: str, upload_id: str, relative_path: str, bearer_token: str) -> dict[str, Any]:
        client = await get_shared_async_client("schedule-fileserver", timeout=self.cfg.timeout)
        params = httpx.QueryParams({"project_id": project_id, "relative_path": relative_path})
        try:
            response = await client.get(
                f"{self.cfg.base_url.rstrip('/')}/api/fileserver/project-input/uploads/{upload_id}/resolve",
                params=params,
                headers={"Authorization": f"Bearer {bearer_token}"},
            )
        except httpx.TimeoutException as exc:
            raise UpstreamError("解析任务输入路径超时") from exc
        except httpx.RequestError as exc:
            raise UpstreamError(f"解析任务输入路径失败: {exc}") from exc
        if response.status_code != 200:
            raise UpstreamError(f"任务输入服务返回异常状态码: {response.status_code}")
        return response.json()


class AiGatewayWorkKeyClient:
    def __init__(self) -> None:
        self.cfg = get_config().aigw_service

    async def create_work_key(self, *, parent_key_id: int, task_id: str) -> dict[str, Any]:
        client = await get_shared_async_client("schedule-aigw", timeout=self.cfg.timeout)
        payload = {
            "key_name": f"work-{task_id}",
            "key_type": "work",
            "parent_key_id": parent_key_id,
            "task_id": task_id,
            "sub_task_id": task_id,
            "enabled": True,
            "description": f"schedule user task {task_id}",
        }
        try:
            response = await client.post(
                f"{self.cfg.base_url.rstrip('/')}/api/aigw/llm-keys",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
        except httpx.TimeoutException as exc:
            raise UpstreamError("申请 work key 超时") from exc
        except httpx.RequestError as exc:
            raise UpstreamError(f"申请 work key 失败: {exc}") from exc
        if response.status_code not in (200, 201):
            raise UpstreamError(f"申请 work key 失败: {response.status_code}")
        return response.json()


class BinarySecurityDispatchClient:
    def __init__(self) -> None:
        self.cfg = get_config().binary_security_service

    async def create_task(self, *, project_id: str, task_id: str, payload: dict[str, Any], bearer_token: str) -> dict[str, Any]:
        client = await get_shared_async_client("schedule-binary-security", timeout=self.cfg.timeout)
        try:
            response = await client.post(
                f"{self.cfg.base_url.rstrip('/')}/api/app/binary-security/projects/{project_id}/tasks",
                json={**payload, "task_id": task_id},
                headers={"Authorization": f"Bearer {bearer_token}", "Content-Type": "application/json"},
            )
        except httpx.TimeoutException as exc:
            raise UpstreamError("创建 binary-security 任务超时") from exc
        except httpx.RequestError as exc:
            raise UpstreamError(f"创建 binary-security 任务失败: {exc}") from exc
        if response.status_code != 200:
            raise UpstreamError(f"创建 binary-security 任务失败: {response.status_code}")
        return response.json()

    async def complete_uploads(self, *, project_id: str, task_id: str, files: list[dict[str, Any]], bearer_token: str) -> dict[str, Any]:
        client = await get_shared_async_client("schedule-binary-security", timeout=self.cfg.timeout)
        response = await client.post(
            f"{self.cfg.base_url.rstrip('/')}/api/app/binary-security/projects/{project_id}/tasks/{task_id}/uploads/complete",
            json={"files": files},
            headers={"Authorization": f"Bearer {bearer_token}", "Content-Type": "application/json"},
        )
        if response.status_code != 200:
            raise UpstreamError(f"确认 binary-security 输入失败: {response.status_code}")
        return response.json()

    async def start_task(self, *, project_id: str, task_id: str, bearer_token: str) -> dict[str, Any]:
        client = await get_shared_async_client("schedule-binary-security", timeout=self.cfg.timeout)
        response = await client.post(
            f"{self.cfg.base_url.rstrip('/')}/api/app/binary-security/projects/{project_id}/tasks/{task_id}/start",
            headers={"Authorization": f"Bearer {bearer_token}"},
        )
        if response.status_code != 200:
            raise UpstreamError(f"启动 binary-security 任务失败: {response.status_code}")
        return response.json()


class UserTaskManager:
    def __init__(self) -> None:
        self.input_resolver = ProjectInputResolver()
        self.aigw = AiGatewayWorkKeyClient()
        self.binary_security = BinarySecurityDispatchClient()

    def get_task_or_404(self, db: Session, project_id: str, task_id: str) -> ScheduleUserTask:
        task = db.query(ScheduleUserTask).filter(
            ScheduleUserTask.project_id == project_id,
            ScheduleUserTask.id == task_id,
        ).first()
        if task is None:
            raise NotFoundError("UserTask", task_id)
        return task

    def _bindings_for_task(self, db: Session, task_id: str) -> list[ScheduleUserTaskInputBinding]:
        return db.query(ScheduleUserTaskInputBinding).filter(
            ScheduleUserTaskInputBinding.user_task_id == task_id
        ).order_by(ScheduleUserTaskInputBinding.created_at.asc()).all()

    def _dispatches_for_task(self, db: Session, task_id: str) -> list[ScheduleUserTaskDispatch]:
        return db.query(ScheduleUserTaskDispatch).filter(
            ScheduleUserTaskDispatch.user_task_id == task_id
        ).order_by(ScheduleUserTaskDispatch.created_at.desc()).all()

    def _serialize_task(self, task: ScheduleUserTask, bindings: list[ScheduleUserTaskInputBinding]) -> dict[str, Any]:
        return {
            "id": task.id,
            "project_id": task.project_id,
            "task_type": task.task_type,
            "name": task.name,
            "description": task.description,
            "create_status": task.create_status,
            "dispatch_status": task.dispatch_status,
            "business_status": task.business_status,
            "input_upload_count": len(bindings),
            "inputs": [
                {
                    "input_upload_id": item.input_upload_id,
                    "input_type": item.input_type,
                    "input_label": item.input_label,
                    "target_path": item.target_path,
                    "latest_batch_id": item.latest_batch_id,
                    "keep_original": item.keep_original,
                    "selection_type": item.selection_type,
                    "relative_path": item.relative_path,
                    "relative_paths": list(item.relative_paths or []),
                    "resolved_path": item.resolved_path,
                    "display_name": item.display_name,
                }
                for item in bindings
            ],
            "task_key_ref": task.task_key_ref,
            "module_name": task.module_name,
            "active_work_key_prefix": task.active_work_key_prefix,
            "downstream_task_id": task.downstream_task_id,
            "downstream_detail_view": task.downstream_detail_view,
            "last_error": task.last_error,
            "created_by": task.created_by,
            "updated_at": task.updated_at,
            "created_at": task.created_at,
        }

    def _task_selection_type(self, task_type: str) -> str:
        if task_type == "binary_firmware_e2e":
            return "file"
        if task_type == "binary_module_e2e":
            return "file_list"
        if task_type == "source_scan_e2e":
            return "directory"
        raise ValidationError(f"不支持的任务类型: {task_type}")

    def list_tasks(self, db: Session, project_id: str) -> tuple[int, list[dict[str, Any]], dict[str, int]]:
        rows = db.query(ScheduleUserTask).filter(
            ScheduleUserTask.project_id == project_id
        ).order_by(ScheduleUserTask.created_at.desc()).all()
        stats = {
            "total": len(rows),
            "created": 0,
            "ready_for_dispatch": 0,
            "dispatching": 0,
            "running": 0,
            "success": 0,
            "failed": 0,
        }
        items: list[dict[str, Any]] = []
        for task in rows:
            bindings = self._bindings_for_task(db, task.id)
            stats[task.dispatch_status] = int(stats.get(task.dispatch_status, 0)) + 1
            items.append(self._serialize_task(task, bindings))
        return len(rows), items, stats

    async def create_task(self, db: Session, *, project_id: str, payload, actor: str, bearer_token: str) -> dict[str, Any]:
        if not payload.input_upload_ids:
            raise ValidationError("必须选择任务输入记录")
        if len(payload.input_upload_ids) != 1:
            raise ValidationError("当前版本仅支持单选一个任务输入记录")
        expected_input_type = TASK_TYPE_INPUT_TYPE.get(payload.task_type)
        if not expected_input_type:
            raise ValidationError(f"不支持的任务类型: {payload.task_type}")
        duplicate = db.query(ScheduleUserTask).filter(
            ScheduleUserTask.project_id == project_id,
            ScheduleUserTask.name == payload.name,
        ).first()
        if duplicate is not None:
            raise ConflictError(f"任务已存在: {payload.name}")
        resolved = await self.input_resolver.resolve_single(project_id, payload.input_upload_ids[0], bearer_token)
        if resolved.project_id != project_id:
            raise ValidationError("任务输入记录不属于当前项目")
        if resolved.input_type != expected_input_type:
            raise ValidationError(f"{payload.task_type} 仅允许选择 {expected_input_type} 类型输入")
        if resolved.status not in {"succeeded", "partial_failed"}:
            raise ValidationError("所选任务输入尚未准备完成")
        if payload.task_type == "binary_module_e2e" and not str(payload.module_name or "").strip():
            raise ValidationError("二进制模块任务必须填写模块名")

        selection_type = self._task_selection_type(payload.task_type)
        input_binding_payload = payload.input_binding
        if input_binding_payload is None:
            raise ValidationError("必须提供结构化 input_binding")
        binding_upload_id = str(input_binding_payload.upload_id or payload.input_upload_ids[0]).strip()
        if binding_upload_id != resolved.upload_id:
            raise ValidationError("input_binding.upload_id 与 input_upload_ids 不一致")
        requested_selection_type = str(input_binding_payload.selection_type or selection_type).strip()
        if requested_selection_type != selection_type:
            raise ValidationError("所选输入模式与任务类型不匹配")

        relative_path = str(input_binding_payload.relative_path or "").strip()
        relative_paths = [str(item or "").strip() for item in (input_binding_payload.relative_paths or []) if str(item or "").strip()]
        resolved_relative_path: Optional[str] = None
        resolved_relative_paths: list[str] = []
        resolved_path: Optional[str] = None
        display_name = resolved.display_name
        if selection_type == "file":
            if not relative_path:
                raise ValidationError("盖亚-二进制固件必须选择一个文件")
            node = await self.input_resolver.resolve_path(project_id, resolved.upload_id, relative_path, bearer_token)
            if node.get("node_type") != "file":
                raise ValidationError("盖亚-二进制固件只允许选择文件")
            resolved_relative_path = str(node.get("relative_path") or "").strip()
            resolved_relative_paths = [resolved_relative_path]
            resolved_path = str(node.get("absolute_path") or "").strip()
            display_name = str(node.get("name") or resolved_relative_path or display_name)
        elif selection_type == "file_list":
            if not relative_paths:
                raise ValidationError("盖亚-二进制模块必须至少选择一个文件")
            for item in relative_paths:
                node = await self.input_resolver.resolve_path(project_id, resolved.upload_id, item, bearer_token)
                if node.get("node_type") != "file":
                    raise ValidationError("盖亚-二进制模块只允许选择文件列表")
                resolved_relative_paths.append(str(node.get("relative_path") or "").strip())
            resolved_path = resolved.target_path
            display_name = f"{len(resolved_relative_paths)} files"
        else:
            if not relative_path:
                raise ValidationError("盖亚-源码必须显式选择一个文件夹")
            node = await self.input_resolver.resolve_path(project_id, resolved.upload_id, relative_path, bearer_token)
            if node.get("node_type") != "directory":
                raise ValidationError("盖亚-源码只允许选择文件夹")
            resolved_relative_path = str(node.get("relative_path") or "").strip()
            resolved_relative_paths = [resolved_relative_path] if resolved_relative_path else []
            resolved_path = str(node.get("absolute_path") or "").strip()
            display_name = str(node.get("name") or resolved_relative_path or display_name)

        task = ScheduleUserTask(
            project_id=project_id,
            task_type=payload.task_type,
            name=payload.name,
            description=payload.description,
            module_name=str(payload.module_name or "").strip() or None,
            create_status="created",
            dispatch_status="ready_for_dispatch",
            business_status="created",
            task_key_ref=payload.task_key_ref,
            downstream_detail_view=TASK_TYPE_DETAIL_VIEW.get(payload.task_type),
            created_by=actor,
            updated_by=actor,
        )
        db.add(task)
        db.flush()
        binding = ScheduleUserTaskInputBinding(
            user_task_id=task.id,
            project_id=project_id,
            input_upload_id=resolved.upload_id,
            input_type=resolved.input_type,
            input_label=display_name,
            target_path=resolved.target_path,
            latest_batch_id=resolved.latest_batch_id,
            keep_original=resolved.keep_original,
            selection_type=selection_type,
            relative_path=resolved_relative_path,
            relative_paths=resolved_relative_paths,
            resolved_path=resolved_path,
            display_name=display_name,
        )
        db.add(binding)
        db.commit()
        db.refresh(task)
        return self._serialize_task(task, [binding])

    async def dispatch_task(self, db: Session, *, project_id: str, task_id: str, actor: str, bearer_token: str) -> dict[str, Any]:
        task = self.get_task_or_404(db, project_id, task_id)
        bindings = self._bindings_for_task(db, task.id)
        if not bindings:
            raise ValidationError("任务缺少输入绑定，无法分发")
        task.dispatch_status = "dispatching"
        task.business_status = "dispatching"
        task.updated_by = actor
        dispatch = ScheduleUserTaskDispatch(
            user_task_id=task.id,
            project_id=project_id,
            dispatch_status="dispatching",
            task_key_ref=task.task_key_ref,
            created_by=actor,
        )
        db.add(dispatch)
        db.commit()
        db.refresh(dispatch)

        try:
            try:
                parent_key_id = int(str(task.task_key_ref).strip())
            except ValueError as exc:
                raise ValidationError("task_key_ref 必须是 AI Gateway task key ID") from exc
            work_key_result = await self.aigw.create_work_key(parent_key_id=parent_key_id, task_id=task.id)
            key_payload = work_key_result.get("key") or {}
            dispatch.work_key_id = str(key_payload.get("id") or "")
            dispatch.work_key_prefix = str(key_payload.get("key_prefix") or "")
            dispatch.work_key_secret = str(work_key_result.get("secret") or "")
            task.active_work_key_prefix = dispatch.work_key_prefix or None

            input_binding = bindings[0]
            source_path = Path(input_binding.resolved_path or input_binding.target_path)
            if not source_path.exists():
                raise ValidationError(f"任务输入路径不存在: {source_path}")
            target_root = Path(f"/data/files/{project_id}/app/secflow-app-binary-security/{task.id}/input")
            await asyncio.to_thread(target_root.mkdir, parents=True, exist_ok=True)
            copied_files: list[dict[str, Any]] = []
            selected_paths = list(input_binding.relative_paths or [])
            if input_binding.selection_type == "file_list" and selected_paths:
                for item in selected_paths:
                    child = Path(input_binding.target_path) / item
                    if not child.is_file():
                        raise ValidationError(f"选中的任务输入文件不存在: {item}")
                    destination = target_root / item
                    await asyncio.to_thread(destination.parent.mkdir, parents=True, exist_ok=True)
                    await asyncio.to_thread(shutil.copy2, child, destination)
                    copied_files.append({
                        "filename": child.name,
                        "relative_path": item,
                        "size": child.stat().st_size,
                        "metadata": {"input_upload_id": input_binding.input_upload_id},
                    })
            elif source_path.is_dir():
                for child in sorted(source_path.rglob("*")):
                    if not child.is_file():
                        continue
                    relative = child.relative_to(source_path).as_posix()
                    destination = target_root / relative
                    await asyncio.to_thread(destination.parent.mkdir, parents=True, exist_ok=True)
                    await asyncio.to_thread(shutil.copy2, child, destination)
                    copied_files.append({
                        "filename": child.name,
                        "relative_path": relative,
                        "size": child.stat().st_size,
                        "metadata": {"input_upload_id": input_binding.input_upload_id},
                    })
            else:
                destination = target_root / source_path.name
                await asyncio.to_thread(shutil.copy2, source_path, destination)
                copied_files.append({
                    "filename": source_path.name,
                    "relative_path": source_path.name,
                    "size": source_path.stat().st_size,
                    "metadata": {"input_upload_id": input_binding.input_upload_id},
                })
            if not copied_files:
                raise ValidationError("任务输入目录中没有可分发文件")

            create_payload: dict[str, Any] = {
                "task_type": TASK_TYPE_BINARY_SECURITY[task.task_type],
                "name": task.name,
                "description": task.description,
                "input_files": copied_files,
                "policy_overrides": {},
            }
            if task.task_type == "binary_module_e2e":
                create_payload["module_name"] = str(task.module_name or "").strip() or task.name or "module"
            await self.binary_security.create_task(
                project_id=project_id,
                task_id=task.id,
                payload=create_payload,
                bearer_token=bearer_token,
            )
            await self.binary_security.complete_uploads(
                project_id=project_id,
                task_id=task.id,
                files=copied_files,
                bearer_token=bearer_token,
            )
            await self.binary_security.start_task(
                project_id=project_id,
                task_id=task.id,
                bearer_token=bearer_token,
            )

            dispatch.dispatch_status = "succeeded"
            dispatch.downstream_task_id = task.id
            dispatch.downstream_detail_view = TASK_TYPE_DETAIL_VIEW.get(task.task_type)
            task.dispatch_status = "running"
            task.business_status = "running"
            task.downstream_task_id = task.id
            task.downstream_detail_view = dispatch.downstream_detail_view
            task.last_error = None
            db.commit()
        except Exception as exc:
            db.rollback()
            task = self.get_task_or_404(db, project_id, task_id)
            dispatch = db.query(ScheduleUserTaskDispatch).filter(
                ScheduleUserTaskDispatch.id == dispatch.id
            ).first()
            message = str(exc)
            task.dispatch_status = "dispatch_failed"
            task.business_status = "failed"
            task.last_error = message
            task.updated_by = actor
            if dispatch is not None:
                dispatch.dispatch_status = "failed"
                dispatch.last_error = message
            db.commit()
            raise
        return self._serialize_task(task, bindings)

    def get_task_detail(self, db: Session, project_id: str, task_id: str) -> dict[str, Any]:
        task = self.get_task_or_404(db, project_id, task_id)
        return self._serialize_task(task, self._bindings_for_task(db, task.id))

    def list_dispatches(self, db: Session, project_id: str, task_id: str) -> tuple[int, list[dict[str, Any]]]:
        self.get_task_or_404(db, project_id, task_id)
        rows = self._dispatches_for_task(db, task_id)
        return len(rows), [
            {
                "id": row.id,
                "user_task_id": row.user_task_id,
                "project_id": row.project_id,
                "dispatch_status": row.dispatch_status,
                "task_key_ref": row.task_key_ref,
                "work_key_id": row.work_key_id,
                "work_key_prefix": row.work_key_prefix,
                "downstream_task_id": row.downstream_task_id,
                "downstream_detail_view": row.downstream_detail_view,
                "last_error": row.last_error,
                "created_by": row.created_by,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }
            for row in rows
        ]


_user_task_manager: Optional[UserTaskManager] = None


def get_user_task_manager() -> UserTaskManager:
    global _user_task_manager
    if _user_task_manager is None:
        _user_task_manager = UserTaskManager()
    return _user_task_manager
