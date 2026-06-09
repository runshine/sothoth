"""Tests for the poc-dynamic-verify CLI."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from app.cli import main as cli_main


class TestCLISubCommands:
    def test_phase1_help(self):
        with pytest.raises(SystemExit):
            cli_main(["phase1", "--help"])

    def test_phase2_help(self):
        with pytest.raises(SystemExit):
            cli_main(["phase2", "--help"])

    def test_run_help(self):
        with pytest.raises(SystemExit):
            cli_main(["run", "--help"])

    def test_no_command(self):
        with pytest.raises(SystemExit):
            cli_main([])


class TestCLIPhase1:
    def _write_tree(self, tmp):
        (tmp / "vuln.md").write_text("# test")
        (tmp / "source").mkdir()
        (tmp / "binaries").mkdir()
        (tmp / "out").mkdir()

    @patch("app.cli._invoke_pi")
    def test_invokes_pi(self, mock_pi, tmp_path):
        mock_pi.return_value = 0
        self._write_tree(tmp_path)
        rc = cli_main([
            "phase1",
            "--vuln-report", str(tmp_path / "vuln.md"),
            "--entry-func", "main",
            "--source-dir", str(tmp_path / "source"),
            "--binary-dir", str(tmp_path / "binaries"),
            "-o", str(tmp_path / "out"),
        ])
        assert rc == 0
        mock_pi.assert_called_once()
        assert mock_pi.call_args[0][0] == "poc-phase1-binary-dependency"

    @patch("app.cli._invoke_pi")
    def test_writes_phase1_input_json(self, mock_pi, tmp_path):
        mock_pi.return_value = 0
        self._write_tree(tmp_path)
        cli_main(["phase1", "--vuln-report", str(tmp_path / "vuln.md"),
                  "--entry-func", "main", "--source-dir", str(tmp_path / "source"),
                  "--binary-dir", str(tmp_path / "binaries"), "-o", str(tmp_path / "out")])
        meta = json.loads((tmp_path / "out" / "phase1_input.json").read_text())
        assert meta["entry_function"] == "main"
        assert "source_dir" in meta
        assert "binary_dir" in meta
        assert "vuln_report" in meta
        # No dataflow_report
        assert "dataflow_report" not in meta

    def test_missing_file(self, tmp_path, capsys):
        (tmp_path / "source").mkdir()
        (tmp_path / "binaries").mkdir()
        rc = cli_main(["phase1", "--vuln-report", str(tmp_path / "nope.md"),
                       "--entry-func", "main", "--source-dir", str(tmp_path / "source"),
                       "--binary-dir", str(tmp_path / "binaries")])
        assert rc == 1


class TestCLIPhase2:
    @patch("app.cli._invoke_pi")
    def test_invokes_pi(self, mock_pi, tmp_path):
        mock_pi.return_value = 0
        (tmp_path / "dep.json").write_text("{}")
        (tmp_path / "binaries").mkdir()
        (tmp_path / "out").mkdir()
        rc = cli_main(["phase2", "--dep-map", str(tmp_path / "dep.json"),
                       "--binary-dir", str(tmp_path / "binaries"),
                       "-o", str(tmp_path / "out")])
        assert rc == 0
        assert mock_pi.call_args[0][0] == "poc-phase2-qiling-emulation"

    @patch("app.cli._invoke_pi")
    def test_passes_rootfs(self, mock_pi, tmp_path):
        mock_pi.return_value = 0
        (tmp_path / "dep.json").write_text("{}")
        (tmp_path / "binaries").mkdir()
        (tmp_path / "rootfs").mkdir()
        (tmp_path / "out").mkdir()
        cli_main(["phase2", "--dep-map", str(tmp_path / "dep.json"),
                  "--binary-dir", str(tmp_path / "binaries"),
                  "--rootfs", str(tmp_path / "rootfs"),
                  "-o", str(tmp_path / "out")])
        assert "rootfs" in mock_pi.call_args[0][1]


class TestCLIRun:
    @patch("app.cli._invoke_pi")
    def test_calls_both_phases(self, mock_pi, tmp_path):
        mock_pi.return_value = 0
        (tmp_path / "vuln.md").write_text("# test")
        (tmp_path / "source").mkdir()
        (tmp_path / "binaries").mkdir()
        (tmp_path / "out").mkdir()
        # Simulate Phase 1 output so Phase 2 validation passes
        (tmp_path / "out" / "binary_dependency_map.json").write_text("{}")
        rc = cli_main(["run", "--vuln-report", str(tmp_path / "vuln.md"),
                       "--entry-func", "main", "--source-dir", str(tmp_path / "source"),
                       "--binary-dir", str(tmp_path / "binaries"),
                       "-o", str(tmp_path / "out")])
        assert rc == 0
        assert mock_pi.call_count == 2
        calls = [c[0][0] for c in mock_pi.call_args_list]
        assert calls == ["poc-phase1-binary-dependency", "poc-phase2-qiling-emulation"]
