"""PoC result verification: deterministic structural checks on poc CLI output.

After the poc CLI finishes, verify the reported path (A/B) against deterministic
artifacts on disk:
  V1 poc_report_exists   output/poc_report.md exists (Stage2 ran)
  V2 gdb_trigger_exists   output/gdb_trigger.log exists (trigger attempt recorded)
  V3 poc_input_exists     output/poc_input.bin exists (PoC input generated)
  V4 stage0_exists        output/stage0_report.md exists (Stage0 ran)
  V5 path_marker_match    poc_report.md contains the canonical 漏洞结论 line
  V6 artifacts_nonempty   output/ has at least some files

Checks are fail-safe: missing artifact → check=False but doesn't override the
LLM's conclusion. The verification result is stored alongside poc_path for
transparency.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List

from app.service.task_service import _PATH_A_RE, _PATH_B_RE

logger = logging.getLogger("poc.poc_verifier")


def verify_poc_result(output_dir: str, returncode: int | None, poc_path: str | None) -> Dict[str, Any]:
    """Run deterministic checks on the poc CLI output directory.

    Returns: {verified, poc_path, checks: [...], summary}.
    """
    checks: List[Dict[str, Any]] = []
    out = Path(output_dir) / "output" if output_dir else Path("")
    if out:
        out.mkdir(parents=True, exist_ok=True)

    def _check(name: str, condition: bool, detail: str = "") -> None:
        checks.append({"name": name, "pass": condition, "detail": detail})

    # V1: poc_report.md exists
    poc_report = out / "poc_report.md" if out else Path("")
    _check("poc_report_exists", poc_report.is_file(), str(poc_report))

    # V2: gdb_trigger.log exists (trigger attempt recorded)
    gdb_trigger = out / "gdb_trigger.log" if out else Path("")
    _check("gdb_trigger_exists", gdb_trigger.is_file(), str(gdb_trigger))

    # V3: poc_input.bin exists (malicious PoC input generated)
    poc_input = out / "poc_input.bin" if out else Path("")
    _check("poc_input_exists", poc_input.is_file(), str(poc_input))

    # V4: stage0_report.md exists (Stage0 ran)
    stage0 = out / "stage0_report.md" if out else Path("")
    _check("stage0_exists", stage0.is_file(), str(stage0))

    # V5: path marker match — poc_report.md contains canonical 漏洞结论 line
    path_match = False
    path_detail = "no poc_report.md"
    if poc_report.is_file():
        try:
            txt = poc_report.read_text(encoding="utf-8", errors="replace")[:3000]
            if _PATH_A_RE.search(txt):
                path_match = True
                path_detail = "matched 路径A（确认触发）"
            elif _PATH_B_RE.search(txt):
                path_match = True
                path_detail = "matched 路径B（证伪/不可达）"
            else:
                path_detail = "no canonical 漏洞结论 line found"
        except Exception as exc:
            path_detail = f"read error: {exc}"
    _check("path_marker_match", path_match, path_detail)

    # V6: artifacts nonempty
    artifact_count = 0
    if out.is_dir():
        artifact_count = sum(1 for _ in out.iterdir())
    _check("artifacts_nonempty", artifact_count > 0, f"{artifact_count} files in output/")

    # Summary
    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)
    verified = path_match and (returncode == 0)

    summary_parts = []
    for c in checks:
        status = "✅" if c["pass"] else "❌"
        summary_parts.append(f"{c['name']}={status}")
    summary = f"Verification: {passed}/{total} checks passed. poc_path={poc_path}. " + ", ".join(summary_parts)

    return {
        "verified": verified,
        "poc_path": poc_path,
        "checks": checks,
        "summary": summary,
    }
