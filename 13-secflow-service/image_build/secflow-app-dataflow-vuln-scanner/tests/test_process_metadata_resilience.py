from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import run_vuln_scan
from app.artifacts import io as artifact_io
from app.services import execution_service as execution_service_module
from app.services.execution_service import ExecutionService


def test_artifact_write_json_preserves_existing_file_when_replace_fails(tmp_path, monkeypatch):
    target = tmp_path / "process.json"
    target.write_text(json.dumps({"status": "running"}), encoding="utf-8")

    def fail_replace(_source, _target):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(artifact_io.os, "replace", fail_replace)

    with pytest.raises(OSError):
        artifact_io.write_json(target, {"status": "exited"})

    assert json.loads(target.read_text(encoding="utf-8")) == {"status": "running"}
    assert list(tmp_path.glob(".process.json.*.tmp")) == []


def test_run_timestamps_preserves_existing_file_when_replace_fails(tmp_path, monkeypatch):
    run_dir = tmp_path / "demo-run"
    timestamps = run_dir / "run" / "_meta" / "run_timestamps.json"
    timestamps.parent.mkdir(parents=True)
    timestamps.write_text(json.dumps({"status": "running"}), encoding="utf-8")

    def fail_replace(_source, _target):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(run_vuln_scan.os, "replace", fail_replace)

    with pytest.raises(OSError):
        run_vuln_scan._write_run_timestamps(run_dir, status="failed")

    assert json.loads(timestamps.read_text(encoding="utf-8")) == {"status": "running"}
    assert list(timestamps.parent.glob(".run_timestamps.json.*.tmp")) == []


def test_cli_process_metadata_write_failure_does_not_stop_child_process(
    tmp_path,
    monkeypatch,
    service_config_path,
):
    monkeypatch.delenv("SECFLOW_DATAFLOW_CLI_IN_PROCESS", raising=False)
    monkeypatch.setattr(execution_service_module.time, "sleep", lambda _seconds: None)

    class FakeProcess:
        def __init__(self):
            self.pid = 12345
            self.returncode = None
            self.poll_calls = 0
            self.terminated = False

        def poll(self):
            self.poll_calls += 1
            if self.poll_calls == 1:
                return None
            self.returncode = 0
            return 0

        def terminate(self):
            self.terminated = True
            self.returncode = -15

    fake_process = FakeProcess()
    monkeypatch.setattr(
        execution_service_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: fake_process,
    )

    service = ExecutionService()
    write_attempts: list[str] = []

    def fail_process_file_write(**kwargs):
        write_attempts.append(str(kwargs.get("status_text") or ""))
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(service, "_write_cli_process_file", fail_process_file_write)
    monkeypatch.setattr(service, "record_event", lambda *_args, **_kwargs: None)

    class FakeDb:
        def add(self, _obj):
            pass

        def commit(self):
            pass

        def expire(self, _obj):
            pass

        def rollback(self):
            pass

    execution = SimpleNamespace(
        id="exec-test",
        status="running",
        workspace_root=str(tmp_path / "run"),
        process_pid=None,
        process_host=None,
        process_status=None,
        process_started_at=None,
        process_finished_at=None,
    )
    trigger = SimpleNamespace(id="tt-test", status="running")

    exit_code = service._invoke_run_vuln_scan_cli(
        argv=["--help"],
        db=FakeDb(),
        execution=execution,
        trigger=trigger,
    )

    assert exit_code == 0
    assert write_attempts == ["running", "running", "exited"]
    assert fake_process.terminated is False
