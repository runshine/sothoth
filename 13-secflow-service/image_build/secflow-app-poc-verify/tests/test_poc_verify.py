"""Tests for shared state-file & meta-data structures."""

import json
import os
from pathlib import Path


class TestPhase1InputMeta:
    def test_meta_structure(self, tmp_path):
        meta = {
            "vuln_report": "/tmp/vuln.md",
            "entry_function": "main",
            "source_dir": "/tmp/source",
            "binary_dir": "/tmp/binaries",
            "output_dir": "/tmp/output",
        }
        p = tmp_path / "phase1_input.json"
        p.write_text(json.dumps(meta, indent=2))
        loaded = json.loads(p.read_text())
        assert loaded["entry_function"] == "main"
        assert "source_dir" in loaded
        # no dataflow_report
        assert "dataflow_report" not in loaded


class TestPipelineStateFile:
    def test_state_structure(self, tmp_path):
        state = {
            "pipeline_name": "poc-verify",
            "current_stage": "INIT",
            "stages": ["phase1_binary_dependency", "phase2_qiling_emulation", "phase3_verify_report"],
            "vuln_report": "/tmp/v.md",
            "entry_function": "main",
            "source_dir": "/tmp/s",
            "binary_dir": "/tmp/b",
            "output_dir": str(tmp_path),
            "rootfs": "/tmp/r",
            "model": None,
            "thinking": None,
        }
        p = tmp_path / ".pipeline_state.json"
        p.write_text(json.dumps(state, indent=2, ensure_ascii=False))
        loaded = json.loads(p.read_text())
        assert loaded["current_stage"] == "INIT"
        assert len(loaded["stages"]) == 3
        assert "phase1_binary_dependency" in loaded["stages"]
        assert "phase2_qiling_emulation" in loaded["stages"]
        assert "phase3_verify_report" in loaded["stages"]

    def test_state_stages_in_order(self, tmp_path):
        from app.cli import _write_state_file
        out = _write_state_file(
            tmp_path,
            vuln="/v", entry_func="main", src="/s", bindir="/b", rootfs="/r",
            model=None, thinking=None,
        )
        s = json.loads(out.read_text())
        assert s["stages"][0] == "phase1_binary_dependency"
        assert s["stages"][1] == "phase2_qiling_emulation"
        assert s["stages"][2] == "phase3_verify_report"
