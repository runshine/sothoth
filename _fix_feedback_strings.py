#!/usr/bin/env python3
"""Fix broken multi-line string literals in stage files."""
import sys

BASE = "D:/workspace/pi/sothoth/13-secflow-service/image_build/secflow-app-system-analyse/app/pipeline/"


def fix_file(path, replacements):
    """replacements: list of (start_0idx, end_0idx_exclusive, new_lines)"""
    lines = open(path, encoding="utf-8").readlines()
    for start, end, new_lines in sorted(replacements, reverse=True):
        lines[start:end] = new_lines
    open(path, "w", encoding="utf-8").writelines(lines)
    print(f"Fixed {path.split('/')[-1]}")


# ── s1_security_filter.py ─────────────────────────────────────────────────
# Lines 357-363 (1-indexed) = 0-indexed 356-362
# Replace broken f-string with single-line version
fix_file(
    BASE + "s1_security_filter.py",
    [
        (
            356, 363,
            [
                "                    corrections_parts.append(\n",
                "                        f\"### Judge-{i}\\uff08\\u5206\\u6570 {rec['score']}\\uff09\\u4fee\\u6b63\\u5217\\u8868\\n\\n{raw}\"\n",
                "                    )\n",
            ],
        )
    ],
)

# ── s2_refine.py ──────────────────────────────────────────────────────────
# Lines 543-551 (1-indexed) = 0-indexed 542-550
fix_file(
    BASE + "s2_refine.py",
    [
        (
            542, 551,
            [
                "                feedback = (\n",
                "                    \"\\u8bf7\\u5148\\u9605\\u8bfb judge \\u5b8c\\u6574\\u610f\\u89c1\\uff1a\\n\"\n",
                "                    f\"```\\nread {fail_fb}\\n```\\n\"\n",
                "                    + guidance\n",
                "                )\n",
            ],
        )
    ],
)

# ── s3_analyse.py ─────────────────────────────────────────────────────────
# Lines 457-465 (1-indexed) = 0-indexed 456-464
fix_file(
    BASE + "s3_analyse.py",
    [
        (
            456, 465,
            [
                "                feedback = (\n",
                "                    \"\\u8bc4\\u5ba1\\u610f\\u89c1\\uff08\\u672a\\u901a\\u8fc7\\uff09\\u5df2\\u5199\\u5165\\uff1a\\n\"\n",
                "                    f\"```\\nread {fb_rel}\\n```\\n\"\n",
                "                    f\"\\u8bf7\\u9605\\u8bfb\\u540e\\u4fee\\u6b63 modules/{mod_name}/module_report.md\\u3002\"\n",
                "                )\n",
            ],
        )
    ],
)

# ── s4_report.py ──────────────────────────────────────────────────────────
# Lines 240-246 (1-indexed) = 0-indexed 239-245  (redo block)
fix_file(
    BASE + "s4_report.py",
    [
        (
            239, 246,
            [
                "                    feedback = (\n",
                "                        \"\\u8bc4\\u5ba1\\u610f\\u89c1\\uff08\\u672a\\u901a\\u8fc7\\uff09\\u5df2\\u5199\\u5165\\uff1a\\n\"\n",
                "                        f\"```\\nread {fb_rel}\\n```\"\n",
                "                    )\n",
            ],
        )
    ],
)

print("All files patched.")
