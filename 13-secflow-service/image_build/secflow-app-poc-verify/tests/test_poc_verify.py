"""Tests for shared models and utilities."""

import json
from pathlib import Path

from app.cli import _check_paths


class TestCheckPaths:
    def test_all_exist(self, tmp_path):
        f = tmp_path / "a.md"
        f.write_text("")
        d = tmp_path / "dir"
        d.mkdir()
        assert _check_paths(file=str(f), folder=str(d)) == 0

    def test_missing_file(self, tmp_path):
        assert _check_paths(missing=str(tmp_path / "nope.md")) == 1

    def test_missing_dir(self, tmp_path):
        assert _check_paths(missing_dir=str(tmp_path / "nodir")) == 1


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
        assert "dataflow_report" not in loaded
