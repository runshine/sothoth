from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest


def _auth_headers():
    return {"Authorization": "Bearer test-token"}


async def _fake_validate_token(token: str):
    return {"user_id": "u1", "username": "alice", "token_type": "human"}


async def _fake_require_access(token: str, project_id: str):
    return {"id": project_id}


def _resolved_input(target_path: str = "/data/files/proj1/user_input/software/upload-001", input_type: str = "software"):
    return type("Resolved", (), {
        "upload_id": "upload-001",
        "project_id": "proj1",
        "input_type": input_type,
        "status": "succeeded",
        "keep_original": False,
        "target_path": target_path,
        "latest_batch_id": "batch-001",
        "display_name": "/user_input/software/upload-001",
    })()


def test_schedule_job_crud_and_trigger(client):
    payload = {
        "name": "job-a",
        "trigger_type": "manual",
        "target_method": "POST",
        "target_url": "http://example/api/tasks",
        "target_body_template": {"project": "{project_id}"},
        "success_status_codes": [200],
    }
    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)

        create_resp = client.post("/api/chirmera-platform-schedule/projects/proj1/jobs", json=payload, headers=_auth_headers())
        assert create_resp.status_code == 200, create_resp.text
        job = create_resp.json()
        assert job["project_id"] == "proj1"

        list_resp = client.get("/api/chirmera-platform-schedule/projects/proj1/jobs", headers=_auth_headers())
        assert list_resp.status_code == 200
        assert list_resp.json()["total"] == 1

        with patch("app.service.schedule_manager.get_shared_async_client") as client_factory:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=type("Resp", (), {"status_code": 200, "json": lambda self: {"task_id": "t-1"}, "text": ""})())
            client_factory.return_value = mock_client
            trigger_resp = client.post(
                f"/api/chirmera-platform-schedule/projects/proj1/jobs/{job['id']}/trigger",
                json={"trigger_source": "manual"},
                headers=_auth_headers(),
            )
        assert trigger_resp.status_code == 200, trigger_resp.text
        execution = trigger_resp.json()
        assert execution["status"] == "queued"
        assert execution["downstream_task_id"] is None


def test_user_task_create_requires_single_file_binding(client):
    payload = {
        "task_type": "binary_firmware_e2e",
        "name": "firmware-task-a",
        "description": "demo",
        "input_upload_ids": ["upload-001"],
        "input_binding": {
            "upload_id": "upload-001",
            "selection_type": "file",
            "relative_path": "firmware.bin",
        },
        "policy": {},
        "dispatch_policy": {},
    }
    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)
        with patch("app.service.user_task_manager.ProjectInputResolver.resolve_single", new=AsyncMock(return_value=_resolved_input())), \
             patch("app.service.user_task_manager.ProjectInputResolver.resolve_path", new=AsyncMock(return_value={
                 "relative_path": "firmware.bin",
                 "absolute_path": "/data/files/proj1/user_input/software/upload-001/firmware.bin",
                 "node_type": "file",
                 "name": "firmware.bin",
             })):
            create_resp = client.post(
                "/api/chirmera-platform-schedule/projects/proj1/user-tasks",
                json=payload,
                headers=_auth_headers(),
            )

    assert create_resp.status_code == 200, create_resp.text
    body = create_resp.json()
    assert body["project_id"] == "proj1"
    assert body["create_status"] == "created"
    assert body["dispatch_status"] == "ready_for_dispatch"
    assert body["input_upload_count"] == 1
    assert body["inputs"][0]["input_upload_id"] == "upload-001"
    assert body["inputs"][0]["selection_type"] == "file"
    assert body["inputs"][0]["relative_path"] == "firmware.bin"
    assert body["inputs"][0]["resolved_path"].endswith("firmware.bin")


def test_auto_dispatch_ready_tasks_runs_in_scheduler_loop(db_session, tmp_path):
    from app.service.user_task_manager import UserTaskManager

    source_root = tmp_path / "upload-root"
    source_root.mkdir(parents=True)
    (source_root / "firmware.bin").write_bytes(b"firmware")

    manager = UserTaskManager()
    payload = SimpleNamespace(
        task_type="binary_firmware_e2e",
        name="firmware-auto-dispatch",
        description="demo",
        module_name=None,
        input_upload_ids=["upload-001"],
        input_binding=SimpleNamespace(
            upload_id="upload-001",
            selection_type="file",
            relative_path="firmware.bin",
            relative_paths=None,
        ),
    )

    with patch("app.service.user_task_manager.ProjectInputResolver.resolve_single", new=AsyncMock(return_value=_resolved_input(str(source_root)))), \
         patch("app.service.user_task_manager.ProjectInputResolver.resolve_path", new=AsyncMock(return_value={
             "relative_path": "firmware.bin",
             "absolute_path": str(source_root / "firmware.bin"),
             "node_type": "file",
             "name": "firmware.bin",
         })), \
         patch.object(manager, "auto_dispatch_token", return_value="machine-token"), \
         patch("app.service.user_task_manager.UserTaskManager._aigw_management_token", return_value="mgmt-token"), \
         patch("app.service.user_task_manager.AiGatewayTaskKeyClient.create_task_key", new=AsyncMock(return_value={"key": {"id": "tk-dispatch-1", "key_name": "dispatch-key", "key_prefix": "tsk_dispatch", "capacity_pool_ids": [1]}, "secret": "tsk_dispatch_secret"})), \
         patch("app.service.user_task_manager.BinarySecurityDispatchClient.create_task", new=AsyncMock(return_value={"task_id": "child-1"})), \
         patch("app.service.user_task_manager.BinarySecurityDispatchClient.complete_uploads", new=AsyncMock(return_value={"ok": True})), \
         patch("app.service.user_task_manager.BinarySecurityDispatchClient.start_task", new=AsyncMock(return_value={"ok": True})):
        created = asyncio.run(manager.create_task(
            db_session,
            project_id="proj1",
            payload=payload,
            actor="alice",
            bearer_token="user-token",
        ))
        assert created["dispatch_status"] == "ready_for_dispatch"
        dispatched = asyncio.run(manager.auto_dispatch_ready_tasks(batch_size=1, actor="schedule-auto-dispatcher"))
        assert dispatched == 1
        detail = asyncio.run(manager.get_task_detail(db_session, "proj1", created["id"], "user-token"))
        assert detail["dispatch_status"] == "running"
        assert detail["business_status"] == "running"
        assert detail["root_task_key_id"] == "tk-dispatch-1"


def test_user_task_rejects_directory_for_firmware_file_mode(client):
    payload = {
        "task_type": "binary_firmware_e2e",
        "name": "firmware-task-dir",
        "description": "demo",
        "input_upload_ids": ["upload-001"],
        "input_binding": {
            "upload_id": "upload-001",
            "selection_type": "file",
            "relative_path": "firmware",
        },
        "policy": {},
        "dispatch_policy": {},
    }
    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)
        with patch("app.service.user_task_manager.ProjectInputResolver.resolve_single", new=AsyncMock(return_value=_resolved_input())), \
             patch("app.service.user_task_manager.ProjectInputResolver.resolve_path", new=AsyncMock(return_value={
                 "relative_path": "firmware",
                 "absolute_path": "/data/files/proj1/user_input/software/upload-001/firmware",
                 "node_type": "directory",
                 "name": "firmware",
             })):
            response = client.post("/api/chirmera-platform-schedule/projects/proj1/user-tasks", json=payload, headers=_auth_headers())
    assert response.status_code == 400
    assert "只允许选择文件" in response.text


def test_user_task_rejects_file_for_source_directory_mode(client):
    payload = {
        "task_type": "source_scan_e2e",
        "name": "source-task-file",
        "description": "demo",
        "input_upload_ids": ["upload-001"],
        "input_binding": {
            "upload_id": "upload-001",
            "selection_type": "directory",
            "relative_path": "src/main.c",
        },
        "policy": {},
        "dispatch_policy": {},
    }
    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)
        with patch("app.service.user_task_manager.ProjectInputResolver.resolve_single", new=AsyncMock(return_value=_resolved_input("/data/files/proj1/user_input/code/upload-001", "code"))), \
             patch("app.service.user_task_manager.ProjectInputResolver.resolve_path", new=AsyncMock(return_value={
                 "relative_path": "src/main.c",
                 "absolute_path": "/data/files/proj1/user_input/code/upload-001/src/main.c",
                 "node_type": "file",
                 "name": "main.c",
             })):
            response = client.post("/api/chirmera-platform-schedule/projects/proj1/user-tasks", json=payload, headers=_auth_headers())
    assert response.status_code == 400
    assert "只允许选择文件夹" in response.text


def test_user_task_requires_module_name_for_binary_module(client):
    payload = {
        "task_type": "binary_module_e2e",
        "name": "module-task-no-name",
        "description": "demo",
        "module_name": "   ",
        "input_upload_ids": ["upload-001"],
        "input_binding": {
            "upload_id": "upload-001",
            "selection_type": "file_list",
            "relative_paths": ["mods/a.bin"],
        },
        "policy": {},
        "dispatch_policy": {},
    }
    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)
        with patch("app.service.user_task_manager.ProjectInputResolver.resolve_single", new=AsyncMock(return_value=_resolved_input())), \
             patch("app.service.user_task_manager.ProjectInputResolver.resolve_path", new=AsyncMock(return_value={
                 "relative_path": "mods/a.bin",
                 "absolute_path": "/data/files/proj1/user_input/software/upload-001/mods/a.bin",
                 "node_type": "file",
                 "name": "a.bin",
             })):
            response = client.post("/api/chirmera-platform-schedule/projects/proj1/user-tasks", json=payload, headers=_auth_headers())
    assert response.status_code == 400
    assert "必须填写模块名" in response.text


def test_user_task_dispatch_uses_persisted_module_name_and_selected_files(client, tmp_path):
    source_root = tmp_path / "upload-root"
    (source_root / "mods").mkdir(parents=True)
    (source_root / "mods" / "a.bin").write_bytes(b"a")
    (source_root / "mods" / "b.bin").write_bytes(b"bb")
    forwarded_payloads: list[dict] = []

    payload = {
        "task_type": "binary_module_e2e",
        "name": "module-task-a",
        "description": "demo description",
        "module_name": "libcrypto",
        "input_upload_ids": ["upload-001"],
        "input_binding": {
            "upload_id": "upload-001",
            "selection_type": "file_list",
            "relative_paths": ["mods/a.bin", "mods/b.bin"],
        },
        "policy": {},
        "dispatch_policy": {},
    }

    def fake_path(value: str):
        if value.startswith("/data/files/"):
            return Path(tmp_path / "dispatch-root" / value.removeprefix("/data/files/"))
        return Path(value)

    async def fake_create_task(self, *, project_id: str, task_id: str, payload: dict, bearer_token: str):
        forwarded_payloads.append(payload)
        return {"task_id": task_id}

    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)
        with patch("app.service.user_task_manager.ProjectInputResolver.resolve_single", new=AsyncMock(return_value=_resolved_input(str(source_root)))), \
             patch("app.service.user_task_manager.ProjectInputResolver.resolve_path", new=AsyncMock(side_effect=[
                 {
                     "relative_path": "mods/a.bin",
                     "absolute_path": str(source_root / "mods" / "a.bin"),
                     "node_type": "file",
                     "name": "a.bin",
                 },
                 {
                     "relative_path": "mods/b.bin",
                     "absolute_path": str(source_root / "mods" / "b.bin"),
                     "node_type": "file",
                     "name": "b.bin",
                 },
             ])), \
             patch("app.service.user_task_manager.UserTaskManager._aigw_management_token", return_value="mgmt-token"), \
             patch("app.service.user_task_manager.AiGatewayTaskKeyClient.create_task_key", new=AsyncMock(return_value={"key": {"id": "tk-dispatch-1", "key_name": "dispatch-key", "key_prefix": "tsk_dispatch", "capacity_pool_ids": [1, 2]}, "secret": "tsk_dispatch_secret"})), \
             patch("app.service.user_task_manager.BinarySecurityDispatchClient.create_task", new=fake_create_task), \
             patch("app.service.user_task_manager.BinarySecurityDispatchClient.complete_uploads", new=AsyncMock(return_value={"ok": True})), \
             patch("app.service.user_task_manager.BinarySecurityDispatchClient.start_task", new=AsyncMock(return_value={"ok": True})), \
             patch("app.service.user_task_manager.Path", new=fake_path):
            create_resp = client.post("/api/chirmera-platform-schedule/projects/proj1/user-tasks", json=payload, headers=_auth_headers())
            assert create_resp.status_code == 200, create_resp.text
            body = create_resp.json()
            assert body["module_name"] == "libcrypto"
            assert body["inputs"][0]["selection_type"] == "file_list"
            assert body["inputs"][0]["relative_paths"] == ["mods/a.bin", "mods/b.bin"]
            task_id = body["id"]

            detail_resp = client.get(
                f"/api/chirmera-platform-schedule/projects/proj1/user-tasks/{task_id}",
                headers=_auth_headers(),
            )
            assert detail_resp.status_code == 200, detail_resp.text
            detail = detail_resp.json()
            assert detail["module_name"] == "libcrypto"
            assert detail["inputs"][0]["display_name"] == "2 files"
            assert detail["inputs"][0]["relative_paths"] == ["mods/a.bin", "mods/b.bin"]

            dispatch_resp = client.post(
                f"/api/chirmera-platform-schedule/projects/proj1/user-tasks/{task_id}/dispatch",
                json={"force": False},
                headers=_auth_headers(),
            )
            assert dispatch_resp.status_code == 200, dispatch_resp.text
            dispatch_body = dispatch_resp.json()
            assert dispatch_body["root_task_key_id"] == "tk-dispatch-1"
            assert dispatch_body["root_task_key_prefix"] == "tsk_dispatch"
            assert dispatch_body["dispatched_task_key_id"] == "tk-dispatch-1"
            assert dispatch_body["dispatched_task_key_prefix"] == "tsk_dispatch"

    assert forwarded_payloads
    assert forwarded_payloads[0]["module_name"] == "libcrypto"
    assert [item["relative_path"] for item in forwarded_payloads[0]["input_files"]] == ["mods/a.bin", "mods/b.bin"]


def test_user_task_dispatch_fails_without_capacity_pool_policy(client, tmp_path):
    source_root = tmp_path / "upload-root"
    source_root.mkdir(parents=True)
    (source_root / "firmware.bin").write_bytes(b"firmware")
    payload = {
        "task_type": "binary_firmware_e2e",
        "name": "firmware-task-policy-missing",
        "description": "demo",
        "input_upload_ids": ["upload-001"],
        "input_binding": {
            "upload_id": "upload-001",
            "selection_type": "file",
            "relative_path": "firmware.bin",
        },
        "policy": {},
        "dispatch_policy": {},
    }

    broken_config = SimpleNamespace(
        user_task_dispatch_policy=SimpleNamespace(
            binary_firmware_e2e=SimpleNamespace(
                capacity_pool_ids=[],
                root_task_key_max_concurrency=0,
                root_task_key_expires_at=None,
            ),
        ),
        aigw_service=SimpleNamespace(management_bearer_token="mgmt-token"),
        auth_service=SimpleNamespace(service_machine_token=""),
    )

    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)
        with patch("app.service.user_task_manager.ProjectInputResolver.resolve_single", new=AsyncMock(return_value=_resolved_input(str(source_root)))), \
             patch("app.service.user_task_manager.ProjectInputResolver.resolve_path", new=AsyncMock(return_value={
                 "relative_path": "firmware.bin",
                 "absolute_path": str(source_root / "firmware.bin"),
                 "node_type": "file",
                 "name": "firmware.bin",
             })), \
             patch("app.service.user_task_manager.get_config", return_value=broken_config):
            create_resp = client.post("/api/chirmera-platform-schedule/projects/proj1/user-tasks", json=payload, headers=_auth_headers())
            assert create_resp.status_code == 200, create_resp.text
            task_id = create_resp.json()["id"]
            dispatch_resp = client.post(
                f"/api/chirmera-platform-schedule/projects/proj1/user-tasks/{task_id}/dispatch",
                json={"force": False},
                headers=_auth_headers(),
            )

    assert dispatch_resp.status_code == 400
    assert "capacity_pool_ids" in dispatch_resp.text


def test_auto_dispatch_keeps_failed_task_visible_for_retry(db_session, tmp_path):
    from app.service.user_task_manager import UserTaskManager

    source_root = tmp_path / "upload-root"
    source_root.mkdir(parents=True)
    (source_root / "firmware.bin").write_bytes(b"firmware")

    manager = UserTaskManager()
    payload = SimpleNamespace(
        task_type="binary_firmware_e2e",
        name="firmware-auto-fail",
        description="demo",
        module_name=None,
        input_upload_ids=["upload-001"],
        input_binding=SimpleNamespace(
            upload_id="upload-001",
            selection_type="file",
            relative_path="firmware.bin",
            relative_paths=None,
        ),
    )

    with patch("app.service.user_task_manager.ProjectInputResolver.resolve_single", new=AsyncMock(return_value=_resolved_input(str(source_root)))), \
         patch("app.service.user_task_manager.ProjectInputResolver.resolve_path", new=AsyncMock(return_value={
             "relative_path": "firmware.bin",
             "absolute_path": str(source_root / "firmware.bin"),
             "node_type": "file",
             "name": "firmware.bin",
         })), \
         patch.object(manager, "auto_dispatch_token", return_value="machine-token"), \
         patch("app.service.user_task_manager.get_config", return_value=SimpleNamespace(
             user_task_dispatch_policy=SimpleNamespace(
                 binary_firmware_e2e=SimpleNamespace(capacity_pool_ids=[], root_task_key_max_concurrency=0, root_task_key_expires_at=None),
             ),
             aigw_service=SimpleNamespace(management_bearer_token="mgmt-token"),
             auth_service=SimpleNamespace(service_machine_token="machine-token"),
             fileserver_service=SimpleNamespace(base_url="", project_input_uploads_path="", timeout=30),
             security=SimpleNamespace(task_key_secret_master_key="test-key"),
             binary_security_service=SimpleNamespace(base_url="", timeout=30),
             ai4red_service=SimpleNamespace(base_url="", timeout=30),
             turing_app_security_service=SimpleNamespace(base_url="", timeout=30),
         )):
        created = asyncio.run(manager.create_task(
            db_session,
            project_id="proj1",
            payload=payload,
            actor="alice",
            bearer_token="user-token",
        ))
        assert created["dispatch_status"] == "ready_for_dispatch"
        with pytest.raises(Exception, match="capacity_pool_ids"):
            asyncio.run(manager.auto_dispatch_ready_tasks(batch_size=1, actor="schedule-auto-dispatcher"))
        detail = asyncio.run(manager.get_task_detail(db_session, "proj1", created["id"], "user-token"))
        assert detail["dispatch_status"] == "dispatch_failed"
        assert "capacity_pool_ids" in str(detail["last_error"] or "")


def test_ai4red_task_create_accepts_directory_binding_without_input_type_restriction(client, tmp_path):
    deliver_dir = tmp_path / "deliver-dir"
    deliver_dir.mkdir(parents=True)
    payload = {
        "task_type": "ai4red",
        "name": "ai4red-task-a",
        "description": "demo",
        "input_upload_ids": ["upload-001"],
        "input_binding": {
            "upload_id": "upload-001",
            "selection_type": "directory",
            "relative_path": "deliver-dir",
        },
        "policy": {},
        "dispatch_policy": {},
    }
    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)
        with patch("app.service.user_task_manager.ProjectInputResolver.resolve_single", new=AsyncMock(return_value=_resolved_input(str(tmp_path), "document"))), \
             patch("app.service.user_task_manager.ProjectInputResolver.resolve_path", new=AsyncMock(return_value={
                 "relative_path": "deliver-dir",
                 "absolute_path": str(deliver_dir),
                 "node_type": "directory",
                 "name": "deliver-dir",
             })):
            response = client.post("/api/chirmera-platform-schedule/projects/proj1/user-tasks", json=payload, headers=_auth_headers())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["task_type"] == "ai4red"
    assert body["downstream_detail_view"] == "ai4red-detail"
    assert body["inputs"][0]["selection_type"] == "directory"


def test_ai4red_dispatch_passes_deliver_dir_and_does_not_copy_archive(client, tmp_path):
    source_root = tmp_path / "upload-root"
    deliver_dir = source_root / "deliver-dir"
    deliver_dir.mkdir(parents=True)
    (deliver_dir / "deliverable.zip").write_bytes(b"zip-content")

    payload = {
        "task_type": "ai4red",
        "name": "ai4red-task-dispatch",
        "description": "demo",
        "input_upload_ids": ["upload-001"],
        "input_binding": {
            "upload_id": "upload-001",
            "selection_type": "directory",
            "relative_path": "deliver-dir",
        },
        "policy": {},
        "dispatch_policy": {},
    }

    captured_calls: list[dict] = []

    async def fake_create(self, *, project_id: str, task_id: str, deliver_dir: str, bearer_token: str, llm_key=None):
        captured_calls.append({
            "project_id": project_id,
            "task_id": task_id,
            "deliver_dir": deliver_dir,
            "token": bearer_token,
            "llm_key": llm_key,
        })
        return {"code": 200, "message": "success", "data": {"taskId": "ai4red-inner-1"}}

    async def fake_get(self, *, downstream_task_id: str, bearer_token: str):
        return {"code": 200, "message": "success", "data": {"taskId": downstream_task_id, "status": "EXECUTING", "errorMessage": None}}

    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)
        with patch("app.service.user_task_manager.ProjectInputResolver.resolve_single", new=AsyncMock(return_value=_resolved_input(str(source_root), "document"))), \
             patch("app.service.user_task_manager.ProjectInputResolver.resolve_path", new=AsyncMock(return_value={
                 "relative_path": "deliver-dir",
                 "absolute_path": str(deliver_dir),
                 "node_type": "directory",
                 "name": "deliver-dir",
             })), \
             patch("app.service.user_task_manager.Ai4RedDispatchClient.create_task", new=fake_create), \
             patch("app.service.user_task_manager.Ai4RedDispatchClient.get_task", new=fake_get), \
             patch("app.service.user_task_manager.get_config", return_value=SimpleNamespace(
                 ai4red_service=SimpleNamespace(base_url="http://ai4red-platform-service:12345", timeout=30),
                 user_task_dispatch_policy=SimpleNamespace(ai4red=SimpleNamespace(capacity_pool_ids=[], root_task_key_max_concurrency=0, root_task_key_expires_at=None)),
                 aigw_service=SimpleNamespace(management_bearer_token=""),
                 auth_service=SimpleNamespace(service_machine_token=""),
                 fileserver_service=SimpleNamespace(base_url="", project_input_uploads_path="", timeout=30),
                 security=SimpleNamespace(task_key_secret_master_key="test-key"),
             )):
            create_resp = client.post("/api/chirmera-platform-schedule/projects/proj1/user-tasks", json=payload, headers=_auth_headers())
            assert create_resp.status_code == 200, create_resp.text
            task_id = create_resp.json()["id"]
            dispatch_resp = client.post(
                f"/api/chirmera-platform-schedule/projects/proj1/user-tasks/{task_id}/dispatch",
                json={"force": False},
                headers=_auth_headers(),
            )

    assert dispatch_resp.status_code == 200, dispatch_resp.text
    body = dispatch_resp.json()
    assert body["downstream_task_id"] == "ai4red-inner-1"
    assert body["downstream_detail_view"] == "ai4red-detail"
    assert body["business_status"] == "running"
    assert body["downstream_status_raw"] == "EXECUTING"
    assert body["downstream_status_mapped"] == "running"
    assert captured_calls and captured_calls[0]["project_id"] == "proj1"
    assert captured_calls[0]["deliver_dir"] == str(deliver_dir)


def test_ai4apk_task_create_accepts_file_binding_without_input_type_restriction(client, tmp_path):
    apk_file = tmp_path / "sample.bin"
    apk_file.write_bytes(b"apk")
    payload = {
        "task_type": "ai4apk",
        "name": "ai4apk-task-a",
        "description": "demo",
        "input_upload_ids": ["upload-001"],
        "input_binding": {
            "upload_id": "upload-001",
            "selection_type": "file",
            "relative_path": "sample.bin",
        },
        "policy": {},
        "dispatch_policy": {},
    }
    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)
        with patch("app.service.user_task_manager.ProjectInputResolver.resolve_single", new=AsyncMock(return_value=_resolved_input(str(tmp_path), "document"))), \
             patch("app.service.user_task_manager.ProjectInputResolver.resolve_path", new=AsyncMock(return_value={
                 "relative_path": "sample.bin",
                 "absolute_path": str(apk_file),
                 "node_type": "file",
                 "name": "sample.bin",
             })):
            response = client.post("/api/chirmera-platform-schedule/projects/proj1/user-tasks", json=payload, headers=_auth_headers())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["task_type"] == "ai4apk"
    assert body["downstream_detail_view"] is None
    assert body["inputs"][0]["selection_type"] == "file"


def test_ai4apk_task_create_rejects_directory_binding(client, tmp_path):
    apk_dir = tmp_path / "apk-dir"
    apk_dir.mkdir(parents=True)
    payload = {
        "task_type": "ai4apk",
        "name": "ai4apk-task-dir",
        "description": "demo",
        "input_upload_ids": ["upload-001"],
        "input_binding": {
            "upload_id": "upload-001",
            "selection_type": "directory",
            "relative_path": "apk-dir",
        },
        "policy": {},
        "dispatch_policy": {},
    }
    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)
        with patch("app.service.user_task_manager.ProjectInputResolver.resolve_single", new=AsyncMock(return_value=_resolved_input(str(tmp_path), "other"))):
            response = client.post("/api/chirmera-platform-schedule/projects/proj1/user-tasks", json=payload, headers=_auth_headers())
    assert response.status_code == 400
    assert "输入模式与任务类型不匹配" in response.text


def test_ai4apk_dispatch_passes_file_path_without_aigw(client, tmp_path):
    apk_file = tmp_path / "sample.apk"
    apk_file.write_bytes(b"apk-content")
    payload = {
        "task_type": "ai4apk",
        "name": "ai4apk-task-dispatch",
        "description": "demo",
        "input_upload_ids": ["upload-001"],
        "input_binding": {
            "upload_id": "upload-001",
            "selection_type": "file",
            "relative_path": "sample.apk",
        },
        "policy": {},
        "dispatch_policy": {},
    }

    captured_calls: list[dict] = []

    async def fake_create(self, *, project_id: str, task_id: str, file_path: str, task_type: str = "APK"):
        captured_calls.append({
            "project_id": project_id,
            "task_id": task_id,
            "file_path": file_path,
            "task_type": task_type,
        })
        return {
            "tool_task_id": "TuringAppSecurity-ab123-1718012345678",
            "project_id": "inner-proj",
            "job_id": "job-1",
            "status": "pending",
        }

    async def fake_get(self, *, downstream_task_id: str):
        return {
            "tool_task_id": downstream_task_id,
            "status": "running",
            "progress": {"phases": {}},
            "token_usage": {"input": 1, "cache_read": 0, "output": 2, "cost": 0.01},
            "created_at": 1718012345,
            "started_at": 1718012350,
            "completed_at": None,
            "error": None,
        }

    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)
        with patch("app.service.user_task_manager.ProjectInputResolver.resolve_single", new=AsyncMock(return_value=_resolved_input(str(tmp_path), "other"))), \
             patch("app.service.user_task_manager.ProjectInputResolver.resolve_path", new=AsyncMock(return_value={
                 "relative_path": "sample.apk",
                 "absolute_path": str(apk_file),
                 "node_type": "file",
                 "name": "sample.apk",
             })), \
             patch("app.service.user_task_manager.TuringAppSecurityClient.create_task", new=fake_create), \
             patch("app.service.user_task_manager.TuringAppSecurityClient.get_task", new=fake_get), \
             patch("app.service.user_task_manager.AiGatewayTaskKeyClient.create_task_key", new=AsyncMock(side_effect=AssertionError("should not call aigw"))), \
             patch("app.service.user_task_manager.get_config", return_value=SimpleNamespace(
                 ai4red_service=SimpleNamespace(base_url="http://ai4red-platform-service:12345", timeout=30),
                 turing_app_security_service=SimpleNamespace(base_url="http://turing-app-security", timeout=30),
                 user_task_dispatch_policy=SimpleNamespace(
                     ai4red=SimpleNamespace(capacity_pool_ids=[], root_task_key_max_concurrency=0, root_task_key_expires_at=None),
                     ai4apk=SimpleNamespace(capacity_pool_ids=[], root_task_key_max_concurrency=0, root_task_key_expires_at=None),
                 ),
                 aigw_service=SimpleNamespace(management_bearer_token=""),
                 auth_service=SimpleNamespace(service_machine_token=""),
                 fileserver_service=SimpleNamespace(base_url="", project_input_uploads_path="", timeout=30),
                 security=SimpleNamespace(task_key_secret_master_key="test-key"),
             )):
            create_resp = client.post("/api/chirmera-platform-schedule/projects/proj1/user-tasks", json=payload, headers=_auth_headers())
            assert create_resp.status_code == 200, create_resp.text
            task_id = create_resp.json()["id"]
            dispatch_resp = client.post(
                f"/api/chirmera-platform-schedule/projects/proj1/user-tasks/{task_id}/dispatch",
                json={"force": False},
                headers=_auth_headers(),
            )

    assert dispatch_resp.status_code == 200, dispatch_resp.text
    body = dispatch_resp.json()
    assert body["downstream_task_id"] == "TuringAppSecurity-ab123-1718012345678"
    assert body["downstream_detail_view"] is None
    assert body["business_status"] == "running"
    assert body["downstream_status_raw"] == "running"
    assert body["downstream_status_mapped"] == "running"
    assert captured_calls and captured_calls[0]["project_id"] == "proj1"
    assert captured_calls[0]["file_path"] == str(apk_file)
    assert captured_calls[0]["task_type"] == "APK"


def test_ai4apk_dispatch_propagates_422_error_message(client, tmp_path):
    apk_file = tmp_path / "missing.apk"
    apk_file.write_bytes(b"x")
    payload = {
        "task_type": "ai4apk",
        "name": "ai4apk-task-error",
        "description": "demo",
        "input_upload_ids": ["upload-001"],
        "input_binding": {
            "upload_id": "upload-001",
            "selection_type": "file",
            "relative_path": "missing.apk",
        },
        "policy": {},
        "dispatch_policy": {},
    }

    async def fake_create(self, *, project_id: str, task_id: str, file_path: str, task_type: str = "APK"):
        raise Exception("创建 ai4apk 任务失败: 422: file not found")

    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)
        with patch("app.service.user_task_manager.ProjectInputResolver.resolve_single", new=AsyncMock(return_value=_resolved_input(str(tmp_path), "document"))), \
             patch("app.service.user_task_manager.ProjectInputResolver.resolve_path", new=AsyncMock(return_value={
                 "relative_path": "missing.apk",
                 "absolute_path": str(apk_file),
                 "node_type": "file",
                 "name": "missing.apk",
             })), \
             patch("app.service.user_task_manager.TuringAppSecurityClient.create_task", new=fake_create), \
             patch("app.service.user_task_manager.get_config", return_value=SimpleNamespace(
                 ai4red_service=SimpleNamespace(base_url="http://ai4red-platform-service:12345", timeout=30),
                 turing_app_security_service=SimpleNamespace(base_url="http://turing-app-security", timeout=30),
                 user_task_dispatch_policy=SimpleNamespace(
                     ai4red=SimpleNamespace(capacity_pool_ids=[], root_task_key_max_concurrency=0, root_task_key_expires_at=None),
                     ai4apk=SimpleNamespace(capacity_pool_ids=[], root_task_key_max_concurrency=0, root_task_key_expires_at=None),
                 ),
                 aigw_service=SimpleNamespace(management_bearer_token=""),
                 auth_service=SimpleNamespace(service_machine_token=""),
                 fileserver_service=SimpleNamespace(base_url="", project_input_uploads_path="", timeout=30),
                 security=SimpleNamespace(task_key_secret_master_key="test-key"),
             )):
            create_resp = client.post("/api/chirmera-platform-schedule/projects/proj1/user-tasks", json=payload, headers=_auth_headers())
            assert create_resp.status_code == 200, create_resp.text
            task_id = create_resp.json()["id"]
            with pytest.raises(Exception, match="422: file not found"):
                client.post(
                    f"/api/chirmera-platform-schedule/projects/proj1/user-tasks/{task_id}/dispatch",
                    json={"force": False},
                    headers=_auth_headers(),
                )
            detail_resp = client.get(
                f"/api/chirmera-platform-schedule/projects/proj1/user-tasks/{task_id}",
                headers=_auth_headers(),
            )
            assert detail_resp.status_code == 200, detail_resp.text
            detail_body = detail_resp.json()
            assert detail_body["dispatch_status"] == "dispatch_failed"
            assert detail_body["business_status"] == "failed"
            assert "422" in str(detail_body["last_error"] or "")


def test_delete_user_task_deletes_binary_security_parent_after_downstream_success(client):
    payload = {
        "task_type": "binary_firmware_e2e",
        "name": "delete-me",
        "description": "demo",
        "input_upload_ids": ["upload-001"],
        "input_binding": {
            "upload_id": "upload-001",
            "selection_type": "file",
            "relative_path": "firmware.bin",
        },
        "policy": {},
        "dispatch_policy": {},
    }
    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)
        with patch("app.service.user_task_manager.ProjectInputResolver.resolve_single", new=AsyncMock(return_value=_resolved_input())), \
             patch("app.service.user_task_manager.ProjectInputResolver.resolve_path", new=AsyncMock(return_value={
                 "relative_path": "firmware.bin",
                 "absolute_path": "/data/files/proj1/user_input/software/upload-001/firmware.bin",
                 "node_type": "file",
                 "name": "firmware.bin",
             })), \
             patch("app.service.user_task_manager.BinarySecurityDispatchClient.delete_task", new=AsyncMock(return_value=None)):
            create_resp = client.post("/api/chirmera-platform-schedule/projects/proj1/user-tasks", json=payload, headers=_auth_headers())
            task_id = create_resp.json()["id"]
            from app.model import get_db_session, ScheduleUserTask
            db = get_db_session()
            try:
                task = db.query(ScheduleUserTask).filter(ScheduleUserTask.id == task_id).first()
                task.downstream_task_id = task_id
                db.commit()
            finally:
                db.close()
            delete_resp = client.delete(f"/api/chirmera-platform-schedule/projects/proj1/user-tasks/{task_id}", headers=_auth_headers())
            assert delete_resp.status_code == 200, delete_resp.text
            body = delete_resp.json()
            assert body["deleted_count"] == 1
            assert body["failed_count"] == 0
            assert body["results"][0]["status"] == "deleted"
            detail_resp = client.get(f"/api/chirmera-platform-schedule/projects/proj1/user-tasks/{task_id}", headers=_auth_headers())
            assert detail_resp.status_code == 404


def test_delete_user_task_rejects_unsupported_ai4red(client, tmp_path):
    deliver_dir = tmp_path / "deliver-dir"
    deliver_dir.mkdir(parents=True)
    payload = {
        "task_type": "ai4red",
        "name": "ai4red-delete",
        "description": "demo",
        "input_upload_ids": ["upload-001"],
        "input_binding": {
            "upload_id": "upload-001",
            "selection_type": "directory",
            "relative_path": "deliver-dir",
        },
        "policy": {},
        "dispatch_policy": {},
    }
    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)
        with patch("app.service.user_task_manager.ProjectInputResolver.resolve_single", new=AsyncMock(return_value=_resolved_input(str(tmp_path), "document"))), \
             patch("app.service.user_task_manager.ProjectInputResolver.resolve_path", new=AsyncMock(return_value={
                 "relative_path": "deliver-dir",
                 "absolute_path": str(deliver_dir),
                 "node_type": "directory",
                 "name": "deliver-dir",
             })):
            create_resp = client.post("/api/chirmera-platform-schedule/projects/proj1/user-tasks", json=payload, headers=_auth_headers())
            task_id = create_resp.json()["id"]
            from app.model import get_db_session, ScheduleUserTask
            db = get_db_session()
            try:
                task = db.query(ScheduleUserTask).filter(ScheduleUserTask.id == task_id).first()
                task.downstream_task_id = "ai4red-task-1"
                db.commit()
            finally:
                db.close()
            bulk_resp = client.post(
                "/api/chirmera-platform-schedule/projects/proj1/user-tasks/bulk-delete",
                json={"task_ids": [task_id], "select_all_matching": False},
                headers=_auth_headers(),
            )
            assert bulk_resp.status_code == 200, bulk_resp.text
            body = bulk_resp.json()
            assert body["failed_count"] == 1
            assert body["results"][0]["status"] == "unsupported"


def test_bulk_delete_user_tasks_select_all_matching_filters_by_status(client):
    base_payload = {
        "description": "demo",
        "input_upload_ids": ["upload-001"],
        "input_binding": {
            "upload_id": "upload-001",
            "selection_type": "file",
            "relative_path": "firmware.bin",
        },
        "policy": {},
        "dispatch_policy": {},
    }
    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)
        with patch("app.service.user_task_manager.ProjectInputResolver.resolve_single", new=AsyncMock(return_value=_resolved_input())), \
             patch("app.service.user_task_manager.ProjectInputResolver.resolve_path", new=AsyncMock(return_value={
                 "relative_path": "firmware.bin",
                 "absolute_path": "/data/files/proj1/user_input/software/upload-001/firmware.bin",
                 "node_type": "file",
                 "name": "firmware.bin",
             })), \
             patch("app.service.user_task_manager.BinarySecurityDispatchClient.delete_task", new=AsyncMock(return_value=None)):
            ready_resp = client.post(
                "/api/chirmera-platform-schedule/projects/proj1/user-tasks",
                json={**base_payload, "task_type": "binary_firmware_e2e", "name": "ready-task"},
                headers=_auth_headers(),
            )
            failed_resp = client.post(
                "/api/chirmera-platform-schedule/projects/proj1/user-tasks",
                json={**base_payload, "task_type": "binary_firmware_e2e", "name": "failed-task"},
                headers=_auth_headers(),
            )
            failed_task_id = failed_resp.json()["id"]
            from app.model import get_db_session, ScheduleUserTask
            db = get_db_session()
            try:
                failed_task = db.query(ScheduleUserTask).filter(ScheduleUserTask.id == failed_task_id).first()
                failed_task.dispatch_status = "dispatch_failed"
                failed_task.business_status = "failed"
                failed_task.downstream_task_id = failed_task_id
                db.commit()
            finally:
                db.close()

            bulk_resp = client.post(
                "/api/chirmera-platform-schedule/projects/proj1/user-tasks/bulk-delete",
                json={"select_all_matching": True, "filters": {"status": "dispatch_failed"}},
                headers=_auth_headers(),
            )
            assert bulk_resp.status_code == 200, bulk_resp.text
            body = bulk_resp.json()
            assert body["total_requested"] == 1
            assert body["deleted_count"] == 1
            assert body["results"][0]["task_id"] == failed_task_id
