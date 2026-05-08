import tempfile
from pathlib import Path

from app.preprocess import run_preprocess


def test_preprocess_extracts_embedded_elf_with_prefix():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        firmware = root / "server"
        output = root / "output"
        firmware.write_bytes(b"\x00" * 1024 + b"\x7fELF" + b"\x02\x01\x01\x00payload")

        result = run_preprocess(str(firmware), str(output))

        assert result == {"success": True, "method": "embedded ELF extraction"}
        assert (output / "server_elf").read_bytes().startswith(b"\x7fELF")
        assert (output / "header.bin").stat().st_size == 1024
        summary = (output / "summary.txt").read_text(encoding="utf-8")
        assert "ELF offset: 1024" in summary
        assert "Skill Reuse Notes" in summary
