from __future__ import annotations

import argparse
import logging
from pathlib import Path
import sys

from vuln_dispatch.assembler import assemble
from vuln_dispatch.log import setup as setup_logging
from vuln_dispatch.pipeline import run


def _validate_args(args: argparse.Namespace) -> list[str]:
    errors: list[str] = []
    reports = Path(args.reports)
    source_root = Path(args.source_root)
    binary_root = Path(args.binary_root)
    threat = Path(args.threat)

    if not reports.is_dir():
        errors.append(f"--reports must be an existing directory: {reports}")
    if not source_root.is_dir():
        errors.append(f"--source-root must be an existing directory: {source_root}")
    if not binary_root.is_dir():
        errors.append(f"--binary-root must be an existing directory: {binary_root}")
    if not threat.is_file():
        errors.append(f"--threat must be an existing file: {threat}")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="vuln-dispatch: vulnerability report grouping tool")
    parser.add_argument("--reports", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--binary-root", required=True)
    parser.add_argument("--threat", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--logfile", required=True, help="path for routing_log.json")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="-v for INFO, -vv for DEBUG")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code == 0 else 1

    if args.verbose >= 2:
        level = logging.DEBUG
    elif args.verbose >= 1:
        level = logging.INFO
    else:
        level = logging.WARNING
    setup_logging(level)

    errors = _validate_args(args)
    if errors:
        for error in errors:
            print(f"vuln-dispatch: error: {error}", file=sys.stderr)
        return 1

    try:
        output_data = run(
            reports_dir=args.reports,
            threat_model_path=args.threat,
            source_root=args.source_root,
            binary_root=args.binary_root,
        )
        assemble(
            output_data=output_data,
            output_dir=args.output,
            logfile=args.logfile,
            threat_model_path=args.threat,
            source_root=args.source_root,
            binary_root=args.binary_root,
        )

        return 0
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        if args.verbose >= 2:
            raise
        print(f"vuln-dispatch: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
