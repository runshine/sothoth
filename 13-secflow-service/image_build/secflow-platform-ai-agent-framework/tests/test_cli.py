from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.main import cli_entry


def _write_cli_config(
    *,
    framework_root: Path,
    tmp_path: Path,
    execution_id: str,
    write_summary: bool = True,
    exit_code_on_failure: int = 1,
) -> Path:
    payload = json.loads((framework_root / "config.pi_vuln.example.json").read_text(encoding="utf-8"))

    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    workspace_root = tmp_path / "workspace"
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    task_file = input_dir / "task.md"
    task_file.write_text("# CLI Test\n\nRun via app.main CLI.\n", encoding="utf-8")

    payload["global"]["workspace_root"] = str(workspace_root)
    payload["execution"]["execution_id"] = execution_id
    payload["execution"]["runtime_mode"] = "cli_test"
    payload["execution"]["input_task"]["task_file"] = str(task_file)
    payload["execution"]["input_task"]["task_id"] = f"{execution_id}-task"
    payload["execution"]["output_dir"] = str(output_dir)
    payload["execution"]["on_completion"]["write_summary"] = write_summary
    payload["execution"]["on_completion"]["summary_file"] = str(output_dir / "execution_summary.json")
    payload["execution"]["on_completion"]["exit_code_on_failure"] = exit_code_on_failure

    config_path = tmp_path / f"{execution_id}.json"
    config_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return config_path


def _run_cli(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> int:
    monkeypatch.setattr("sys.argv", argv)
    with pytest.raises(SystemExit) as exc_info:
        cli_entry()
    assert isinstance(exc_info.value.code, int)
    return exc_info.value.code


def test_cli_run_help_outputs_expected_flags(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = _run_cli(monkeypatch, ["app.main", "run", "--help"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "--config" in captured.out
    assert "--keep-workspace" in captured.out
    assert "--clean-workspace" in captured.out


def test_cli_run_success_with_keep_workspace(
    framework_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    patch_mock_agent_runtime,
) -> None:
    config_path = _write_cli_config(
        framework_root=framework_root,
        tmp_path=tmp_path,
        execution_id="keep-run-001",
    )

    exit_code = _run_cli(
        monkeypatch,
        ["app.main", "run", "--config", str(config_path), "--keep-workspace"],
    )

    assert exit_code == 0
    assert (tmp_path / "output" / "execution_summary.json").exists()
    assert (tmp_path / "workspace").exists()
    assert list((tmp_path / "workspace").rglob("workflow_result.json"))


def test_cli_run_success_with_clean_workspace(
    framework_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    patch_mock_agent_runtime,
) -> None:
    config_path = _write_cli_config(
        framework_root=framework_root,
        tmp_path=tmp_path,
        execution_id="clean-run-001",
    )

    exit_code = _run_cli(
        monkeypatch,
        ["app.main", "run", "--config", str(config_path), "--clean-workspace"],
    )

    assert exit_code == 0
    assert (tmp_path / "output" / "execution_summary.json").exists()
    assert not (tmp_path / "workspace").exists()


def test_cli_run_invalid_config_returns_exit_code_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config_path = tmp_path / "invalid.json"
    config_path.write_text(
        json.dumps(
            {
                "version": "1.0",
                "global": {},
                "agents": [],
                "plugins": [],
                "workflows": {},
                "execution": {},
            }
        ),
        encoding="utf-8",
    )

    exit_code = _run_cli(
        monkeypatch,
        ["app.main", "run", "--config", str(config_path)],
    )
    assert exit_code == 1
    assert "pi-vuln config validation failed" in caplog.text


def test_cli_run_respects_write_summary_false(
    framework_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    patch_mock_agent_runtime,
) -> None:
    config_path = _write_cli_config(
        framework_root=framework_root,
        tmp_path=tmp_path,
        execution_id="no-summary-run-001",
        write_summary=False,
    )

    exit_code = _run_cli(
        monkeypatch,
        ["app.main", "run", "--config", str(config_path), "--keep-workspace"],
    )

    assert exit_code == 0
    assert not (tmp_path / "output" / "execution_summary.json").exists()
    assert list((tmp_path / "workspace").rglob("summary.md"))
