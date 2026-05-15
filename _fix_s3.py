#!/usr/bin/env python3
"""
Minimal safe patch: only single-line string replacements, no newline escapes.
"""
BASE = "D:/workspace/pi/sothoth/13-secflow-service/image_build/secflow-app-system-analyse/app/pipeline/"


def patch(path, old, new):
    content = open(path, encoding="utf-8").read()
    assert old in content, f"Not found in {path.split('/')[-1]}: {repr(old[:80])}"
    content = content.replace(old, new, 1)
    open(path, "w", encoding="utf-8").write(content)
    print(f"OK  {path.split('/')[-1]}")


# ── s3_analyse.py ─────────────────────────────────────────────────────────────

# 1. Import
patch(
    BASE + "s3_analyse.py",
    "    archive_file, max_iter,\n    module_has_nonempty_files,",
    "    archive_file, max_iter, write_judge_feedback,\n    module_has_nonempty_files,"
)

# 2. cwd fix
patch(
    BASE + "s3_analyse.py",
    "                    cwd=str(mod_dir) if mod_dir.exists() else str(workspace),",
    "                    cwd=str(workspace),  # workspace根, 避免双重modules/路径"
)

# 3. reflect jfb: remove [:500]
patch(
    BASE + "s3_analyse.py",
    "                    jfb = \"\\n\".join(\n"
    "                        f\"judge-{i}: {r['feedback'][:500]}\"\n"
    "                        for i, r in enumerate(judge_results))\n"
    "                    feedback += \"\\n\\n## Judge 上轮意见\\n\\n\" + jfb\n",
    "                    jfb = \"\\n\".join(\n"
    "                        f\"judge-{i}: {r['feedback']}\"\n"
    "                        for i, r in enumerate(judge_results))\n"
    "                    feedback += \"\\n\\n## Judge 上轮意见\\n\\n\" + jfb\n"
)

# 4. fail_fb block: replace with file-based approach (single-line feedback)
patch(
    BASE + "s3_analyse.py",
    "            else:\n"
    "                fail_fb = \"\\n\".join(\n"
    "                    f\"judge-{i}: {r['feedback'][:500]}\"\n"
    "                    for i, r in enumerate(judge_results) if not r[\"pass\"])\n"
    "                feedback = \"# 评审意见（未通过）\\n\\n\" + fail_fb + \"\\n\\n请根据意见修正分析。\"\n",
    "            else:\n"
    "                fb_rel = write_judge_feedback(\n"
    "                    workspace, \"s3_analyse\", mod_name, attempt + 1, judge_results)\n"
    "                ctx.emit_event(\"log\", level=\"info\",\n"
    "                               msg=f\"[S3] judge意见已写入 {fb_rel}\")\n"
    "                feedback = f\"评审未通过，完整意见请 read {fb_rel} ，阅后修正 modules/{mod_name}/module_report.md\"\n"
    "                if report_path.exists():\n"
    "                    try:\n"
    "                        report_path.unlink()\n"
    "                    except OSError:\n"
    "                        pass\n"
)

# 5. redo reflect jfb: remove [:500]
patch(
    BASE + "s3_analyse.py",
    "                    jfb = \"\\n\".join(\n"
    "                        f\"judge-{i}: {r['feedback'][:500]}\"\n"
    "                        for i, r in enumerate(judge_results))\n"
    "                    feedback += \"\\n\\n## Judge 上轮意见\\n\\n\" + jfb\n",
    "                    jfb = \"\\n\".join(\n"
    "                        f\"judge-{i}: {r['feedback']}\"\n"
    "                        for i, r in enumerate(judge_results))\n"
    "                    feedback += \"\\n\\n## Judge 上轮意见\\n\\n\" + jfb\n"
)

# 6. redo fail_fb: fix both [:500] occurrences and feedback assignment
patch(
    BASE + "s3_analyse.py",
    "                    fail_fb = \"\\n\".join(\n"
    "                        f\"judge-{i}: {r['feedback'][:500]}\"\n"
    "                        for i, r in enumerate(judge_results))\n"
    "                    feedback = f\"# 评审意见\\n\\n{fail_fb}\"\n",
    "                    _fb_redo = write_judge_feedback(\n"
    "                        workspace, \"s2_refine\", mod_name, attempt + 1, judge_results)\n"
    "                    feedback = f\"评审未通过，完整意见请 read {_fb_redo}\"\n"
)

patch(
    BASE + "s3_analyse.py",
    "                        f\"judge-{i}: {r['feedback'][:500]}\"\n"
    "                        for i, r in enumerate(judge_results) if not r[\"pass\"])\n"
    "                    feedback = f\"# 评审意见\\n\\n{fail_fb}\"\n",
    "                        f\"judge-{i}: {r['feedback']}\"\n"
    "                        for i, r in enumerate(judge_results) if not r[\"pass\"])\n"
    "                    _fb_redo2 = write_judge_feedback(\n"
    "                        workspace, \"s3_analyse\", mod_name, attempt + 1, judge_results)\n"
    "                    feedback = f\"评审未通过，完整意见请 read {_fb_redo2}\"\n"
)

print("\nDone.")
