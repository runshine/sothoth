from __future__ import annotations

import json
from pathlib import Path
import re

from vuln_dispatch.log import logged
from vuln_dispatch.models import ParsedReport, UnrouteableError
import logging


RE_FINGERPRINT = re.compile(r'\*\*fingerprint\*\*:\s*(.*)', re.IGNORECASE)
RE_FUNCTION = re.compile(r'\*\*subject\.name\*\*:\s*(.*)', re.IGNORECASE)
RE_FILE = re.compile(r'\*\*subject\.locator\*\*:\s*([^:]+):', re.IGNORECASE)
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


def _extract_file_from_locator(locator: str) -> str | None:
    """Extract source file path from locator string.

    Handles formats:
        src/file.c:123
        src/file.c:func_name:L123
        libipsec.c:IPSEC_SADB_Func:L123-L456
    """
    if not locator:
        return None
    # Split on first colon — anything before it is the file path
    return _none_if_empty(locator.split(':')[0].strip())


def _extract_function_from_json(case: dict) -> str | None:
    """Extract function name from secflow vuln JSON.

    Priority:
        1. metadata.source.function_name (DVS v2+, most reliable)
        2. dvs-finding.json artifact's function_name
        3. subject.name (report title, not ideal but better than nothing)
    """
    # 1. Structured function_name in source metadata (new in DVS v2)
    src = (case.get('metadata') or {}).get('source') or {}
    func = src.get('function_name')
    if func:
        return func.strip()

    # 2. Check dvs-finding artifact
    for art in (case.get('artifacts') or []):
        if art.get('name') == 'dvs-finding.json':
            content = art.get('content', '')
            if isinstance(content, str):
                try:
                    finding = json.loads(content)
                except json.JSONDecodeError:
                    continue
            else:
                finding = content
            func = finding.get('function_name')
            if func:
                return func.strip()

    # 3. Fall back to subject.name (title)
    subject = case.get('subject') or {}
    return _none_if_empty(subject.get('name', ''))


@logged(level=logging.DEBUG)
def parse_json_report(file_path: str | Path) -> ParsedReport:
    """Parse a secflow vuln platform JSON report."""
    path = Path(file_path)

    try:
        data = path.read_bytes()
    except OSError as exc:
        raise UnrouteableError(str(path), str(exc)) from exc

    if len(data) == 0:
        raise UnrouteableError(str(path), "empty file")

    try:
        case = json.loads(data.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise UnrouteableError(str(path), f"invalid JSON: {exc}") from exc

    report_id = case.get('finding_id') or case.get('report_id') or path.stem
    fingerprint = _none_if_empty((case.get('fingerprint') or '').strip())
    locator = (case.get('subject') or {}).get('locator', '')
    file = _extract_file_from_locator(locator)
    function = _extract_function_from_json(case)

    return ParsedReport(
        report_id=report_id,
        fingerprint=fingerprint,
        file=file,
        function=function,
        source_path=str(path.resolve()),
    )


@logged(level=logging.DEBUG)
def parse_report(file_path: str | Path) -> ParsedReport:
    path = Path(file_path)
    text = _read_text(path)

    fingerprint: str | None = None
    file: str | None = None
    function: str | None = None
    report_id: str | None = None

    for line in text.splitlines():
        if fingerprint is None:
            match = RE_FINGERPRINT.search(line)
            if match:
                fingerprint = _none_if_empty(match.group(1).strip())
                continue
        if file is None:
            match = RE_FILE.search(line)
            if match:
                file = _none_if_empty(match.group(1).strip())
                continue
        if function is None:
            match = RE_FUNCTION.search(line)
            if match:
                function = _none_if_empty(match.group(1).strip())
                continue
        if report_id is None:
            match = RE_REPORT_ID.search(line)
            if match:
                report_id = _none_if_empty(match.group(1).strip())
                continue

    if report_id is None:
        report_id = path.stem

    return ParsedReport(
        report_id=report_id,
        fingerprint=fingerprint,
        file=file,
        function=function,
        source_path=str(path.resolve()),
    )
