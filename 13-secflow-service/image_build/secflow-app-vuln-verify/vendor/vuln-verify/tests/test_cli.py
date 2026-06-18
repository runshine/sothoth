from __future__ import annotations

from pathlib import Path
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from vuln_verify.cli import main


@pytest.fixture
def mock_artifacts(tmp_path: Path) -> dict[str, Path]:
    """Create minimal directories and files for CLI validation."""
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "r.md").write_text("dummy")

    src = tmp_path / "src"
    src.mkdir()

    binary = tmp_path / "bin"
    binary.mkdir()

    threat = tmp_path / "threat.md"
    threat.write_text("## threat model")

    output = tmp_path / "output"

    return {
        "reports": reports,
        "source_root": src,
        "binary_root": binary,
        "threat": threat,
        "output": output,
    }


def _patch_all(pipeline_return=None):
    """Patch run/assemble/launch to avoid side effects."""
    patches = [
        patch("vuln_verify.cli.run", return_value=pipeline_return or MagicMock()),
        patch("vuln_verify.cli.assemble"),
        patch("vuln_verify.cli.launch"),
    ]
    return patches


# ── argument validation ───────────────────────────────────────


class TestArgumentValidation:
    def test_missing_reports_fails(self, mock_artifacts):
        code = main([
            "--reports", "/nonexistent",
            "--source-root", str(mock_artifacts["source_root"]),
            "--binary-root", str(mock_artifacts["binary_root"]),
            "--threat", str(mock_artifacts["threat"]),
            "--output", str(mock_artifacts["output"]),
        ])
        assert code == 1

    def test_missing_source_root_fails(self, mock_artifacts):
        code = main([
            "--reports", str(mock_artifacts["reports"]),
            "--source-root", "/nonexistent",
            "--binary-root", str(mock_artifacts["binary_root"]),
            "--threat", str(mock_artifacts["threat"]),
            "--output", str(mock_artifacts["output"]),
        ])
        assert code == 1

    def test_missing_binary_root_fails(self, mock_artifacts):
        code = main([
            "--reports", str(mock_artifacts["reports"]),
            "--source-root", str(mock_artifacts["source_root"]),
            "--binary-root", "/nonexistent",
            "--threat", str(mock_artifacts["threat"]),
            "--output", str(mock_artifacts["output"]),
        ])
        assert code == 1

    def test_missing_threat_fails(self, mock_artifacts):
        code = main([
            "--reports", str(mock_artifacts["reports"]),
            "--source-root", str(mock_artifacts["source_root"]),
            "--binary-root", str(mock_artifacts["binary_root"]),
            "--threat", "/nonexistent/threat.md",
            "--output", str(mock_artifacts["output"]),
        ])
        assert code == 1

    def test_missing_required_returns_one(self):
        code = main([])
        assert code == 1


# ── successful invocation ─────────────────────────────────────


class TestSuccessfulInvocation:
    def test_runs_pipeline_and_returns_zero(self, mock_artifacts):
        patches = _patch_all()
        for p in patches:
            p.start()

        try:
            code = main([
                "--reports", str(mock_artifacts["reports"]),
                "--source-root", str(mock_artifacts["source_root"]),
                "--binary-root", str(mock_artifacts["binary_root"]),
                "--threat", str(mock_artifacts["threat"]),
                "--output", str(mock_artifacts["output"]),
            ])
            assert code == 0
        finally:
            for p in patches:
                p.stop()

    def test_pipeline_order(self, mock_artifacts):
        """Verify run → assemble → launch call order."""
        call_order: list[str] = []

        def _ordered_run(*a, **kw):
            call_order.append("run")
            return MagicMock()

        def _ordered_assemble(*a, **kw):
            call_order.append("assemble")

        def _ordered_launch(*a, **kw):
            call_order.append("launch")

        with (
            patch("vuln_verify.cli.run", side_effect=_ordered_run),
            patch("vuln_verify.cli.assemble", side_effect=_ordered_assemble),
            patch("vuln_verify.cli.launch", side_effect=_ordered_launch),
        ):
            main([
                "--reports", str(mock_artifacts["reports"]),
                "--source-root", str(mock_artifacts["source_root"]),
                "--binary-root", str(mock_artifacts["binary_root"]),
                "--threat", str(mock_artifacts["threat"]),
                "--output", str(mock_artifacts["output"]),
            ])

        assert call_order == ["run", "assemble", "launch"]

    def test_model_passed_to_launch(self, mock_artifacts):
        with patch("vuln_verify.cli.run", return_value=MagicMock()), \
             patch("vuln_verify.cli.assemble"), \
             patch("vuln_verify.cli.launch") as mock_launch:
            main([
                "--reports", str(mock_artifacts["reports"]),
                "--source-root", str(mock_artifacts["source_root"]),
                "--binary-root", str(mock_artifacts["binary_root"]),
                "--threat", str(mock_artifacts["threat"]),
                "--output", str(mock_artifacts["output"]),
                "--model", "test-model:xhigh",
            ])
            mock_launch.assert_called_once()
            assert mock_launch.call_args.kwargs["model"] == "test-model:xhigh"

    def test_model_omitted_when_not_provided(self, mock_artifacts):
        with patch("vuln_verify.cli.run", return_value=MagicMock()), \
             patch("vuln_verify.cli.assemble"), \
             patch("vuln_verify.cli.launch") as mock_launch:
            main([
                "--reports", str(mock_artifacts["reports"]),
                "--source-root", str(mock_artifacts["source_root"]),
                "--binary-root", str(mock_artifacts["binary_root"]),
                "--threat", str(mock_artifacts["threat"]),
                "--output", str(mock_artifacts["output"]),
            ])
            mock_launch.assert_called_once()
            assert mock_launch.call_args.kwargs["model"] is None

    def test_resume_passed_to_launch(self, mock_artifacts):
        with patch("vuln_verify.cli.run", return_value=MagicMock()), \
             patch("vuln_verify.cli.assemble"), \
             patch("vuln_verify.cli.launch") as mock_launch:
            main([
                "--reports", str(mock_artifacts["reports"]),
                "--source-root", str(mock_artifacts["source_root"]),
                "--binary-root", str(mock_artifacts["binary_root"]),
                "--threat", str(mock_artifacts["threat"]),
                "--output", str(mock_artifacts["output"]),
                "--resume",
            ])
            mock_launch.assert_called_once()
            assert mock_launch.call_args.kwargs["resume"] is True

    def test_session_dir_passed_to_launch(self, mock_artifacts):
        session_dir = mock_artifacts["output"] / "custom-run"
        with patch("vuln_verify.cli.run", return_value=MagicMock()), \
             patch("vuln_verify.cli.assemble"), \
             patch("vuln_verify.cli.launch") as mock_launch:
            main([
                "--reports", str(mock_artifacts["reports"]),
                "--source-root", str(mock_artifacts["source_root"]),
                "--binary-root", str(mock_artifacts["binary_root"]),
                "--threat", str(mock_artifacts["threat"]),
                "--output", str(mock_artifacts["output"]),
                "--session-dir", str(session_dir),
            ])
            mock_launch.assert_called_once()
            assert mock_launch.call_args.kwargs["session_dir"] == session_dir.resolve()
            assert session_dir.is_dir()

    def test_session_dir_defaults_to_task_run(self, mock_artifacts):
        with patch("vuln_verify.cli.run", return_value=MagicMock()), \
             patch("vuln_verify.cli.assemble"), \
             patch("vuln_verify.cli.launch") as mock_launch:
            main([
                "--reports", str(mock_artifacts["reports"]),
                "--source-root", str(mock_artifacts["source_root"]),
                "--binary-root", str(mock_artifacts["binary_root"]),
                "--threat", str(mock_artifacts["threat"]),
                "--output", str(mock_artifacts["output"]),
            ])
            expected = mock_artifacts["output"].resolve().parent / "run"
            mock_launch.assert_called_once()
            assert mock_launch.call_args.kwargs["session_dir"] == expected
            assert expected.is_dir()

    def test_logfile_defaults_to_output_dir(self, mock_artifacts):
        with patch("vuln_verify.cli.run", return_value=MagicMock()), \
             patch("vuln_verify.cli.assemble") as mock_assemble, \
             patch("vuln_verify.cli.launch"):
            main([
                "--reports", str(mock_artifacts["reports"]),
                "--source-root", str(mock_artifacts["source_root"]),
                "--binary-root", str(mock_artifacts["binary_root"]),
                "--threat", str(mock_artifacts["threat"]),
                "--output", str(mock_artifacts["output"]),
            ])
            expected = mock_artifacts["output"].resolve() / "verify.log"
            assert mock_assemble.call_args.kwargs["logfile"] == expected


# ── exception handling ──────────────────────────────────────


class TestExceptionHandling:
    def test_run_exception_returns_one(self, mock_artifacts):
        with patch("vuln_verify.cli.run", side_effect=RuntimeError("boom")), \
             patch("vuln_verify.cli.assemble"), \
             patch("vuln_verify.cli.launch"):
            code = main([
                "--reports", str(mock_artifacts["reports"]),
                "--source-root", str(mock_artifacts["source_root"]),
                "--binary-root", str(mock_artifacts["binary_root"]),
                "--threat", str(mock_artifacts["threat"]),
                "--output", str(mock_artifacts["output"]),
            ])
            assert code == 1

    def test_run_exception_re_raised_with_vv(self, mock_artifacts):
        with patch("vuln_verify.cli.run", side_effect=RuntimeError("boom")):
            with pytest.raises(RuntimeError, match="boom"):
                main([
                    "--reports", str(mock_artifacts["reports"]),
                    "--source-root", str(mock_artifacts["source_root"]),
                    "--binary-root", str(mock_artifacts["binary_root"]),
                    "--threat", str(mock_artifacts["threat"]),
                    "--output", str(mock_artifacts["output"]),
                    "-vv",
                ])
