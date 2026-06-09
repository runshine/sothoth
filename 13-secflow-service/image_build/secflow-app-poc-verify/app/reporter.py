"""Reporter: validates and summarizes Phase 2 outputs for human consumption."""

from __future__ import annotations

import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)


def validate_phase2_outputs(output_dir: Path) -> dict[str, bool]:
    """Check that all expected Phase 2 output files exist and are valid JSON."""
    checks = {}
    for name in ["poc_result.json", "patch_log.json", "branch_decisions.json"]:
        fp = output_dir / name
        if not fp.exists():
            log.warning("Missing: %s", fp)
            checks[name] = False
            continue
        try:
            json.loads(fp.read_text())
            checks[name] = True
        except json.JSONDecodeError:
            log.warning("Invalid JSON: %s", fp)
            checks[name] = False

    md = output_dir / "poc_result.md"
    checks["poc_result.md"] = md.exists()

    return checks


def summarize_result(output_dir: Path) -> str:
    """Print a brief summary of the verification result."""
    result_file = output_dir / "poc_result.json"
    if not result_file.exists():
        return f"No result found in {output_dir}"

    try:
        data = json.loads(result_file.read_text())
    except json.JSONDecodeError:
        return f"Invalid JSON in {result_file}"

    status = data.get("status", "unknown")
    reachable = data.get("reach_vuln_point", False)
    patches = data.get("total_patches", 0)
    branches = data.get("total_branches", 0)
    vuln = data.get("vuln_function", "?")
    entry = data.get("entry_function", "?")

    return (
        f"  vuln={vuln}  entry={entry}  status={status}"
        f"  reachable={'YES' if reachable else 'NO'}"
        f"  patches={patches}  branches={branches}"
    )
