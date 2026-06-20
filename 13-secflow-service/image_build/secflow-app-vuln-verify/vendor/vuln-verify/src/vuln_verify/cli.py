from __future__ import annotations

import argparse
import logging
from pathlib import Path
import sys

from vuln_dispatch.assembler import assemble
from vuln_dispatch.log import setup as setup_logging
from vuln_dispatch.pipeline import run
from vuln_verify.launcher import launch


def _validate_args(args: argparse.Namespace) -> list[str]:
    errors: list[str] = []
    reports = Path(args.reports).expanduser()
    source_root = Path(args.source_root).expanduser()

    if not reports.is_dir():
        errors.append(f"--reports must be an existing directory: {reports}")
    if not source_root.is_dir():
        errors.append(f"--source-root must be an existing directory: {source_root}")
    if args.binary_root:
        binary_root = Path(args.binary_root).expanduser()
        if not binary_root.is_dir():
            errors.append(f"--binary-root must be an existing directory: {binary_root}")
    if args.threat:
        threat = Path(args.threat).expanduser()
        if not threat.is_file():
            errors.append(f"--threat must be an existing file: {threat}")
    if args.concurrency < 1:
        errors.append(f"--concurrency must be >= 1, got {args.concurrency}")

    return errors


def _log_level(verbose: int) -> int:
    if verbose >= 2:
        return logging.DEBUG
    if verbose >= 1:
        return logging.INFO
    return logging.WARNING


def _run_pipeline(args: argparse.Namespace, output_dir: Path, logfile: Path) -> int:
    """Router → assemble → Verifier."""
    threat_path = Path(args.threat).expanduser() if args.threat else None
    binary_root = Path(args.binary_root).expanduser() if args.binary_root else None
    source_root = Path(args.source_root).expanduser()
    output_data = run(
        reports_dir=Path(args.reports).expanduser(),
        threat_model_path=threat_path,
        source_root=source_root,
        binary_root=binary_root,
    )
    assemble(
        output_data=output_data,
        output_dir=output_dir,
        logfile=logfile,
        threat_model_path=threat_path,
        source_root=source_root,
        binary_root=binary_root,
    )
    session_dir = Path(args.session_dir).expanduser().resolve() if args.session_dir else output_dir.parent / "run"
    session_dir.mkdir(parents=True, exist_ok=True)
    launch(
        output_dir,
        str(threat_path) if threat_path else None,
        model=args.model,
        concurrency=args.concurrency,
        resume=args.resume,
        session_dir=session_dir,
        source_root=source_root,
        binary_root=binary_root,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="vuln-verify: automated security assessment pipeline"
    )
    parser.add_argument("--reports", required=True, help="directory containing scan findings (Markdown)")
    parser.add_argument("--source-root", required=True, help="root directory of source files")
    parser.add_argument("--binary-root", help="root directory of binary artifacts (optional)")
    parser.add_argument("--threat", help="threat model file (optional)")
    parser.add_argument("--output", required=True, help="output directory")
    parser.add_argument("--logfile", help="routing summary path; defaults to {output}/verify.log")
    parser.add_argument("--model", help="LLM model for assessment engine. Uses pi default if omitted.")
    parser.add_argument("--session-dir", help="pi session directory. Defaults to {output}/../run.")
    parser.add_argument("-j", "--concurrency", type=int, default=4,
                        help="最大并发验证数 (默认 4)")
    parser.add_argument("--resume", action="store_true",
                        help="跳过已完成的分组")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="-v for INFO, -vv for DEBUG")

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code == 0 else 1

    errors = _validate_args(args)
    if errors:
        for error in errors:
            print(f"vuln-verify: error: {error}", file=sys.stderr)
        return 1

    output_dir = Path(args.output).expanduser().resolve()
    logfile = Path(args.logfile).expanduser().resolve() if args.logfile else output_dir / "verify.log"
    try:
        setup_logging(
            _log_level(args.verbose),
            loggers=["vuln_dispatch", "vuln_verify"],
        )
        return _run_pipeline(args, output_dir, logfile)
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        if args.verbose >= 2:
            raise
        print(f"vuln-verify: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
