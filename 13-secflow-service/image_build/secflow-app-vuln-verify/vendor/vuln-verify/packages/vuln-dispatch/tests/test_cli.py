from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from vuln_dispatch.cli import main


def make_valid_argv(base: Path) -> list[str]:
    reports = base / "reports"
    source_root = base / "src"
    binary_root = base / "bin"
    threat = base / "threat.md"
    output = base / "out"
    logfile = base / "routing_log.json"

    reports.mkdir()
    source_root.mkdir()
    binary_root.mkdir()
    threat.write_text("threat model", encoding="utf-8")

    return [
        "--reports",
        str(reports),
        "--source-root",
        str(source_root),
        "--binary-root",
        str(binary_root),
        "--threat",
        str(threat),
        "--output",
        str(output),
        "--logfile",
        str(logfile),
    ]


def without_option(argv: list[str], option: str) -> list[str]:
    index = argv.index(option)
    return argv[:index] + argv[index + 2 :]


def test_valid_invocation():
    with TemporaryDirectory() as tmp:
        argv = make_valid_argv(Path(tmp))

        assert main(argv) == 0


def test_missing_reports():
    with TemporaryDirectory() as tmp:
        argv = without_option(make_valid_argv(Path(tmp)), "--reports")

        assert main(argv) == 1


def test_missing_source_root():
    with TemporaryDirectory() as tmp:
        argv = without_option(make_valid_argv(Path(tmp)), "--source-root")

        assert main(argv) == 1


def test_missing_binary_root():
    with TemporaryDirectory() as tmp:
        argv = without_option(make_valid_argv(Path(tmp)), "--binary-root")

        assert main(argv) == 1


def test_missing_threat():
    with TemporaryDirectory() as tmp:
        argv = without_option(make_valid_argv(Path(tmp)), "--threat")

        assert main(argv) == 1


def test_nonexistent_reports_dir():
    with TemporaryDirectory() as tmp:
        base = Path(tmp)
        argv = make_valid_argv(base)
        argv[argv.index("--reports") + 1] = str(base / "missing-reports")

        assert main(argv) == 1


def test_nonexistent_threat_file():
    with TemporaryDirectory() as tmp:
        base = Path(tmp)
        argv = make_valid_argv(base)
        argv[argv.index("--threat") + 1] = str(base / "missing-threat.md")

        assert main(argv) == 1


def test_verbose_flag():
    with TemporaryDirectory() as tmp:
        argv = make_valid_argv(Path(tmp)) + ["-v"]

        assert main(argv) == 0
