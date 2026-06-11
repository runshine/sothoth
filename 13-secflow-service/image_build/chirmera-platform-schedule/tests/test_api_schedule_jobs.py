from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch


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


def _task_key_payload():
    return {
        "parent_task_key_id": "tk-123",
        "parent_task_key_name": "parent-task-key",
        "parent_task_key_prefix": "tsk_parent",
        "parent_task_key_secret": "tsk_secret_value",
        "parent_task_capacity_pool_ids": [1, 2],
    }


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
        **_task_key_payload(),
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
        **_task_key_payload(),
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
        **_task_key_payload(),
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
        **_task_key_payload(),
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
        **_task_key_payload(),
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
            assert dispatch_body["dispatched_task_key_id"] == "tk-dispatch-1"
            assert dispatch_body["dispatched_task_key_prefix"] == "tsk_dispatch"

    assert forwarded_payloads
    assert forwarded_payloads[0]["module_name"] == "libcrypto"
    assert [item["relative_path"] for item in forwarded_payloads[0]["input_files"]] == ["mods/a.bin", "mods/b.bin"]
