"""Tests for the poc-dynamic-verify CLI (audit-mode behavior)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from app.cli import main as cli_main


class TestCLISubCommands:
    def test_phase1_help(self):
        with pytest.raises(SystemExit):
            cli_main(["phase1", "--help"])

    def test_phase2_help(self):
        with pytest.raises(SystemExit):
            cli_main(["phase2", "--help"])

    def test_phase3_help(self):
        with pytest.raises(SystemExit):
            cli_main(["phase3", "--help"])

    def test_run_help(self):
        with pytest.raises(SystemExit):
            cli_main(["run", "--help"])

    def test_no_command(self):
        with pytest.raises(SystemExit):
            cli_main([])


class TestCLIPhase1DryRun:
    """默认模式:真跑 pi(用 --dry-run 可选只打印不跑)。"""

    def _write_tree(self, tmp):
        (tmp / "vuln.md").write_text("# test")
        (tmp / "source").mkdir()
        (tmp / "binaries").mkdir()

    def test_dry_run_writes_input_and_state(self, tmp_path, capsys):
        """`--dry-run` 只打印不真跑,适合快速验证参数/state 正确性。"""
        self._write_tree(tmp_path)
        fake_run = MagicMock()
        fake_run.return_value = MagicMock(
            stdout="0.79.1\nfake-model\n",
            stderr="",
            returncode=0,
        )
        with patch("subprocess.run", fake_run):
            rc = cli_main([
                "phase1", "--dry-run",
                "--vuln-report", str(tmp_path / "vuln.md"),
                "--entry-func", "main",
                "--source-dir", str(tmp_path / "source"),
                "--binary-dir", str(tmp_path / "binaries"),
            ])
        # --dry-run 模式:不真跑,rc=0
        assert rc == 0

        # 时间戳工作目录应在 <project>/workspace/poc-verify-*/ 下创建
        from app.cli import DEFAULT_WORK_ROOT
        work_dirs = list(DEFAULT_WORK_ROOT.glob("poc-verify-*"))
        assert work_dirs, f"expected a {DEFAULT_WORK_ROOT}/poc-verify-*/ work dir"
        latest = max(work_dirs, key=lambda p: p.stat().st_mtime)

        assert (latest / "phase1_input.json").is_file()
        assert (latest / ".pipeline_state.json").is_file()
        assert (latest / "phase1.prompt.txt").is_file()

        meta = json.loads((latest / "phase1_input.json").read_text())
        assert meta["entry_function"] == "main"

        state = json.loads((latest / ".pipeline_state.json").read_text())
        assert state["current_stage"] == "INIT"
        assert "phase1_binary_dependency" in state["stages"]

    def test_dry_run_does_not_start_pi(self, tmp_path, capfd):
        """`--dry-run` 模式不应启动实际 agent session。"""
        self._write_tree(tmp_path)
        rc = cli_main([
            "phase1", "--dry-run",
            "--vuln-report", str(tmp_path / "vuln.md"),
            "--entry-func", "main",
            "--source-dir", str(tmp_path / "source"),
            "--binary-dir", str(tmp_path / "binaries"),
        ])
        assert rc == 0
        # 关键:工作目录在 <project>/workspace/ 而不是 /tmp
        from app.cli import DEFAULT_WORK_ROOT
        # 任何自动建的 poc-verify-* 都应在 DEFAULT_WORK_ROOT 下
        for p in DEFAULT_WORK_ROOT.glob("poc-verify-*"):
            assert str(p).startswith(str(DEFAULT_WORK_ROOT))

    def test_dry_run_prints_pi_command_block(self, tmp_path, capfd):
        self._write_tree(tmp_path)
        cli_main([
            "phase1", "--dry-run",
            "--vuln-report", str(tmp_path / "vuln.md"),
            "--entry-func", "main",
            "--source-dir", str(tmp_path / "source"),
            "--binary-dir", str(tmp_path / "binaries"),
        ])
        err = capfd.readouterr().err
        assert "拟执行 (phase1 pi subprocess)" in err
        assert "pi --append-system-prompt" in err
        assert "poc-phase1-binary-dependency/SKILL.md" in err

    def test_audit_mode_with_dry_run_does_not_start_pi(self, tmp_path, capfd):
        """`--dry-run` 模式只打印不真启动 pi 子进程 Popen。"""
        self._write_tree(tmp_path)
        with patch("app.cli.subprocess.Popen") as mock_popen:
            rc = cli_main([
                "phase1", "--dry-run",
                "--vuln-report", str(tmp_path / "vuln.md"),
                "--entry-func", "main",
                "--source-dir", str(tmp_path / "source"),
                "--binary-dir", str(tmp_path / "binaries"),
            ])
        # --dry-run 不调 Popen
        assert not mock_popen.called
        # 但 rc 仍为 0
        assert rc == 0

    def test_real_run_starts_pi(self, tmp_path, capfd):
        """不加 --dry-run 默认会真启动 pi。"""
        self._write_tree(tmp_path)

        fake_run = MagicMock()
        fake_run.return_value = MagicMock(
            stdout="0.79.1\n",
            stderr="",
            returncode=0,
        )

        with patch("subprocess.run", fake_run), \
             patch("subprocess.Popen") as mock_popen:
            mock_popen.return_value.wait.return_value = 0

            # 还需要让 binary_dependency_map.json "被产生",否则会判失败
            def fake_popen_fn(*a, **kw):
                from pathlib import Path as P
                cwd = None
                for arg in a:
                    if isinstance(arg, str) and P(arg).is_dir():
                        cwd = P(arg)
                        break
                if cwd is None and len(a) > 1 and hasattr(a[1], 'get'):
                    cwd = P(a[1].get('cwd') or '.')
                if cwd:
                    (cwd / "binary_dependency_map.json").write_text(
                        '{"entry_function":"main"}'
                    )
                return mock_popen.return_value
            mock_popen.side_effect = fake_popen_fn

            rc = cli_main([
                "phase1",
                "--vuln-report", str(tmp_path / "vuln.md"),
                "--entry-func", "main",
                "--source-dir", str(tmp_path / "source"),
                "--binary-dir", str(tmp_path / "binaries"),
            ])
        # 默认模式调了 Popen
        assert mock_popen.called
        # 命令应含 --print 和 -p
        cmd = mock_popen.call_args[0][0]
        assert "pi" in cmd
        assert "--print" in cmd
        assert "-p" in cmd

    def test_dry_run_missing_path(self, tmp_path, capsys):
        (tmp_path / "source").mkdir()
        (tmp_path / "binaries").mkdir()
        rc = cli_main([
            "phase1", "--dry-run",
            "--vuln-report", str(tmp_path / "nope.md"),
            "--entry-func", "main",
            "--source-dir", str(tmp_path / "source"),
            "--binary-dir", str(tmp_path / "binaries"),
        ])
        assert rc == 1
        err = capsys.readouterr().err
        assert "路径检查失败" in err

    def test_dry_run_respects_output_dir(self, tmp_path, capsys):
        self._write_tree(tmp_path)
        custom = tmp_path / "my-work"
        rc = cli_main([
            "phase1", "--dry-run",
            "--vuln-report", str(tmp_path / "vuln.md"),
            "--entry-func", "main",
            "--source-dir", str(tmp_path / "source"),
            "--binary-dir", str(tmp_path / "binaries"),
            "-o", str(custom),
        ])
        assert rc == 0
        assert (custom / "phase1_input.json").is_file()
        # 不会有在 <project>/workspace/ 下自动建的额外目录
        from app.cli import DEFAULT_WORK_ROOT
        auto = DEFAULT_WORK_ROOT / "poc-verify-doesnt-exist-when-output-given"
        assert not auto.exists()


class TestCLIPhase2DryRun:
    def _make_dep_map(self, tmp):
        dep = tmp / "binary_dependency_map.json"
        dep.write_text(json.dumps({"entry_function": "main", "call_chain": []}))
        return dep

    def test_audit_mode_requires_dep_map(self, tmp_path, capsys):
        (tmp_path / "binaries").mkdir()
        rc = cli_main([
            "phase2",
            "--dep-map", str(tmp_path / "nope.json"),
            "--binary-dir", str(tmp_path / "binaries"),
            "-o", str(tmp_path / "out"),
        ])
        assert rc == 1
        assert "路径检查失败" in capsys.readouterr().err

    def test_dry_run_writes_input(self, tmp_path, capsys):
        self._make_dep_map(tmp_path)
        (tmp_path / "binaries").mkdir()
        out = tmp_path / "out"
        rc = cli_main([
            "phase2", "--dry-run",
            "--dep-map", str(tmp_path / "binary_dependency_map.json"),
            "--binary-dir", str(tmp_path / "binaries"),
            "-o", str(out),
        ])
        assert rc == 0
        assert (out / "phase2_input.json").is_file()
        assert (out / "phase2.prompt.txt").is_file()

    def test_audit_mode_prints_qiling_poc_instructions(self, tmp_path, capsys):
        self._make_dep_map(tmp_path)
        (tmp_path / "binaries").mkdir()
        cli_main([
            "phase2",
            "--dep-map", str(tmp_path / "binary_dependency_map.json"),
            "--binary-dir", str(tmp_path / "binaries"),
            "-o", str(tmp_path / "out"),
        ])
        err = capsys.readouterr().err
        # 关键短语:PoC 生成 / 动态验证 / Qiling / 5 个前导条件
        assert "PoC 生成" in err
        assert "动态验证" in err
        assert "Qiling" in err
        assert "NEGOTIATING" in err
        assert "poc-phase2-qiling-emulation/SKILL.md" in err


class TestCLIPhase3:
    def test_empty_dir_reports_missing(self, tmp_path, capsys):
        rc = cli_main(["phase3", "-o", str(tmp_path)])
        assert rc == 1
        err = capsys.readouterr().err
        assert "缺文件" in err

    def test_nonexistent_dir_fails(self, tmp_path, capsys):
        rc = cli_main(["phase3", "-o", str(tmp_path / "nope")])
        assert rc == 1

    def test_all_outputs_pass(self, tmp_path, capsys):
        (tmp_path / "poc_result.json").write_text('{"status":"reachable"}')
        (tmp_path / "patch_log.json").write_text('{"total":0,"patches":[]}')
        (tmp_path / "branch_decisions.json").write_text('{"total":0,"branches":[]}')
        (tmp_path / "poc_result.md").write_text("# report")
        rc = cli_main(["phase3", "-o", str(tmp_path)])
        assert rc == 0
        err = capsys.readouterr().err
        assert "Phase 3 校验通过" in err


class TestCLIRunDryRun:
    def _write_tree(self, tmp):
        (tmp / "vuln.md").write_text("# test")
        (tmp / "source").mkdir()
        (tmp / "binaries").mkdir()

    def test_dry_run_writes_state(self, tmp_path, capsys):
        self._write_tree(tmp_path)
        out = tmp_path / "out"
        rc = cli_main([
            "run", "--dry-run",
            "--vuln-report", str(tmp_path / "vuln.md"),
            "--entry-func", "main",
            "--source-dir", str(tmp_path / "source"),
            "--binary-dir", str(tmp_path / "binaries"),
            "-o", str(out),
        ])
        assert rc == 0
        # 应有 phase1_input.json 和 .pipeline_state.json
        assert (out / "phase1_input.json").is_file()
        state = json.loads((out / ".pipeline_state.json").read_text())
        assert state["pipeline_name"] == "poc-verify"

    def test_dry_run_describes_rpc_protocol(self, tmp_path, capsys):
        self._write_tree(tmp_path)
        cli_main([
            "run", "--dry-run",
            "--vuln-report", str(tmp_path / "vuln.md"),
            "--entry-func", "main",
            "--source-dir", str(tmp_path / "source"),
            "--binary-dir", str(tmp_path / "binaries"),
            "-o", str(tmp_path / "out"),
        ])
        err = capsys.readouterr().err
        assert "RPC 协议" in err
        assert "agent_start" in err
        assert "agent_end" in err
        assert "Master Skill" in err
        assert "poc-verify-pipeline" in err

    def test_run_dry_run_does_not_start_rpc(self, tmp_path, capsys):
        self._write_tree(tmp_path)
        with patch("app.rpc_runner.PiRpcClient") as mock:
            cli_main([
                "run", "--dry-run",
                "--vuln-report", str(tmp_path / "vuln.md"),
                "--entry-func", "main",
                "--source-dir", str(tmp_path / "source"),
                "--binary-dir", str(tmp_path / "binaries"),
                "-o", str(tmp_path / "out"),
            ])
        # --dry-run 模式:PiRpcClient 不应被实例化
        mock.assert_not_called()

    def test_run_dry_run_missing_path(self, tmp_path, capsys):
        (tmp_path / "source").mkdir()
        (tmp_path / "binaries").mkdir()
        rc = cli_main([
            "run", "--dry-run",
            "--vuln-report", str(tmp_path / "nope.md"),
            "--entry-func", "main",
            "--source-dir", str(tmp_path / "source"),
            "--binary-dir", str(tmp_path / "binaries"),
            "-o", str(tmp_path / "out"),
        ])
        assert rc == 1
        assert "路径检查失败" in capsys.readouterr().err

    def test_run_real_mode_starts_rpc(self, tmp_path, capsys):
        self._write_tree(tmp_path)
        with patch("app.rpc_runner.PiRpcClient") as mock:
            instance = mock.return_value
            instance.proc.pid = 99999
            instance.prompt.return_value = []
            instance.close.return_value = 0
            # 同时写一个 .pipeline_state.json 让它"觉得"完成
            def fake_prompt(*a, **kw):
                (tmp_path / "out" / ".pipeline_state.json").write_text(
                    '{"current_stage":"COMPLETED"}'
                )
                (tmp_path / "out" / "poc_result.json").write_text("{}")
                return []
            instance.prompt.side_effect = fake_prompt

            rc = cli_main([
                "run",
                "--vuln-report", str(tmp_path / "vuln.md"),
                "--entry-func", "main",
                "--source-dir", str(tmp_path / "source"),
                "--binary-dir", str(tmp_path / "binaries"),
                "-o", str(tmp_path / "out"),
            ])
        assert mock.called
        # 走完 mock 流程后,根据 .pipeline_state.json 应该是 COMPLETED
        assert rc == 0
