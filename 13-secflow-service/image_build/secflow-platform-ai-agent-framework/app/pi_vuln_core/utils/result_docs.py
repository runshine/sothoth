from __future__ import annotations

import re
from pathlib import Path

_RESULT_REPORT_RE = re.compile(r"^result_(\d+)\.md$")


def extract_result_number(name: str) -> int | None:
    match = _RESULT_REPORT_RE.match(name)
    if not match:
        return None
    return int(match.group(1))


def is_result_report_filename(name: str) -> bool:
    return extract_result_number(name) is not None


def list_result_report_files(dir_path: str | Path) -> list[str]:
    path = Path(dir_path)
    if not path.is_dir():
        return []
    return sorted(
        item.name
        for item in path.iterdir()
        if item.is_file() and is_result_report_filename(item.name)
    )


def list_supporting_markdown_files(dir_path: str | Path) -> list[str]:
    path = Path(dir_path)
    if not path.is_dir():
        return []
    return sorted(
        item.name
        for item in path.iterdir()
        if item.is_file()
        and item.suffix == ".md"
        and item.name != "summary.md"
        and not is_result_report_filename(item.name)
    )


def split_markdown_outputs(dir_path: str | Path) -> tuple[list[str], list[str]]:
    return list_result_report_files(dir_path), list_supporting_markdown_files(dir_path)
