import os
from pathlib import Path

from app.services.decompiler_adapter import DecompilerAdapter


def test_decompile_success(tmp_path: Path):
    elf = tmp_path / "ok.elf"
    elf.write_bytes(b"ELF")
    out_dir = tmp_path / "out"

    result = DecompilerAdapter().decompile_elf(str(elf), str(out_dir))

    assert result.status == "success"
    assert result.generated_files


def test_decompile_failed(tmp_path: Path):
    out_dir = tmp_path / "out"
    result = DecompilerAdapter().decompile_elf(str(tmp_path / "missing.elf"), str(out_dir))

    assert result.status == "failed"
