from __future__ import annotations

import json
from pathlib import Path
import re

from vuln_dispatch.log import logged
from vuln_dispatch.models import ParsedReport, UnrouteableError
import logging


RE_REPORT_ID = re.compile(r'\*\*report_id\*\*:\s*(.*)', re.IGNORECASE)


def _none_if_empty(value: str) -> str | None:
    return value or None


def _read_text(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise UnrouteableError(str(path), str(exc)) from exc

    if len(data) == 0:
        raise UnrouteableError(str(path), "empty file")

    for encoding in ("utf-8", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue

    raise UnrouteableError(str(path), "unable to decode file")


@logged(level=logging.DEBUG)
def parse_json_report(file_path: str | Path) -> ParsedReport:
    """Parse a secflow vuln platform JSON report without file/function routing."""
    path = Path(file_path)

    try:
        data = path.read_bytes()
    except OSError as exc:
        raise UnrouteableError(str(path), str(exc)) from exc

    if len(data) == 0:
        raise UnrouteableError(str(path), "empty file")

    try:
        case = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise UnrouteableError(str(path), f"invalid JSON: {exc}") from exc

    report_id = case.get("finding_id") or case.get("report_id") or path.stem

    return ParsedReport(
        report_id=str(report_id),
        fingerprint=None,
        file=None,
        function=None,
        source_path=str(path.resolve()),
    )


@logged(level=logging.DEBUG)
def parse_report(file_path: str | Path) -> ParsedReport:
    path = Path(file_path)
    text = _read_text(path)

    report_id: str | None = None
    for line in text.splitlines():
        match = RE_REPORT_ID.search(line)
        if match:
            report_id = _none_if_empty(match.group(1).strip())
            break

    if report_id is None:
        report_id = path.stem

    return ParsedReport(
        report_id=report_id,
        fingerprint=None,
        file=None,
        function=None,
        source_path=str(path.resolve()),
    )
