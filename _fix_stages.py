#!/usr/bin/env python3
"""
Safe patch: write_judge_feedback integration into stage files.
Uses simple string operations to avoid multi-line f-string issues.
"""
import sys

BASE = "D:/workspace/pi/sothoth/13-secflow-service/image_build/secflow-app-system-analyse/app/pipeline/"


def patch(path, old, new):
    content = open(path, encoding="utf-8").read()
    assert old in content, f"Pattern not found in {path}:\n{repr(old[:100])}"
    content = content.replace(old, new, 1)
    open(path, "w", encoding="utf-8").write(content)
    print(f"Patched {path.split('/')[-1]}")


# ─────────────────────────────────────────────────────────────────────────────
# s1_classify.py  — add import + feedback file
# ─────────────────────────────────────────────────────────────────────────────
patch(
    BASE + "s1_classify.py",
    """from .helpers import (
    run_agent_with_stage_guard, parse_eval_md, check_voting,
    discover_modules, get_modules_root, load_prompt, StageError,
    max_rounds_exceeded_treated_as_passed,
)""",
    """from .helpers import (
    run_agent_with_stage_guard, parse_eval_md, check_voting,
    discover_modules, get_modules_root, load_prompt, StageError,
    max_rounds_exceeded_treated_as_passed, write_judge_feedback,
    max_iter,
)"""
)

patch(
    BASE + "s1_classify.py",
    '''            else:
                # judge 失败
                fail_fb = "\\n".join(
                    f"judge-{i}: {r['feedback'][:500]}"
                    for i, r in enumerate(judge_results)
                )''',
    '''            else:
                # judge 失败 — 写完整意见到 judge_output/s1_classify/
                fb_rel = write_judge_feedback(
                    workspace, "s1_classify", None, attempt + 1, judge_results)
                ctx.emit_event("log", level="info",
                               msg=f"[S1] judge 意见已写入 {fb_rel}")
                fail_fb = str(fb_rel)'''
)

patch(
    BASE + "s1_classify.py",
    '''                feedback = (
                    f"# 上轮评审不通过（第 {attempt+1} 轮）\\n\\n"
                    f"## Judge 上轮意见\\n\\n{fail_fb}\\n\\n"
                    + incremental_guidance
                    + reflect_prompt
                )''',
    '''                feedback = (
                    f"# 上轮评审不通过（第 {attempt + 1} 轮）\\n\\n"
                    "Judge 完整意见已写入文件，请先阅读：\\n"
                    f"```\\nread {fail_fb}\\n```\\n\\n"
                    + incremental_guidance
                    + reflect_prompt
                )'''
)

# ─────────────────────────────────────────────────────────────────────────────
# s1_security_filter.py — add import + feedback file
# ─────────────────────────────────────────────────────────────────────────────
patch(
    BASE + "s1_security_filter.py",
    """from .helpers import (
    run_agent_checked, parse_eval_md, check_voting,
    discover_modules, get_modules_root, load_prompt, StageError,
)""",
    """from .helpers import (
    run_agent_checked, parse_eval_md, check_voting,
    discover_modules, get_modules_root, load_prompt, StageError,
    write_judge_feedback,
)"""
)

patch(
    BASE + "s1_security_filter.py",
    '''            # ── 未通过：从 Judge 输出中提取结构化修正列表注入下轮 ────────────
            if not max_reached:
                corrections_parts: list[str] = []
                for i, rec in enumerate(judge_records):
                    raw = rec.get("raw_output", "")
                    corrections_parts.append(
                        f"### Judge-{i}（分数 {rec['score']}）修正列表\\n\\n{raw}"
                    )
                judge_corrections = "\\n\\n".join(corrections_parts)''',
    '''            # ── 未通过：写完整 judge 意见到文件 + 提取结构化修正列表 ────────────
            if not max_reached:
                fb_rel = write_judge_feedback(
                    workspace, "s1_security", None, attempt + 1, judge_results)
                ctx.emit_event("log", level="info",
                               msg=f"[S1.5] judge 意见已写入 {fb_rel}")
                corrections_parts: list[str] = []
                for i, rec in enumerate(judge_records):
                    raw = rec.get("raw_output", "")
                    corrections_parts.append(
                        f"### Judge-{i}（分数 {rec['score']}）修正列表\\n\\n{raw}"
                    )
                judge_corrections = (
                    f"请先阅读 judge 完整意见：\\n"
                    f"```\\nread {fb_rel}\\n```\\n\\n"
                    + "\\n\\n".join(corrections_parts)
                )'''
)

# ─────────────────────────────────────────────────────────────────────────────
# s2_refine.py — add import + feedback file
# ─────────────────────────────────────────────────────────────────────────────
patch(
    BASE + "s2_refine.py",
    """from .helpers import (
    run_agent_with_stage_guard, parse_eval_md, check_voting,
    discover_modules, get_modules_root, load_prompt, build_granularity_hint,
    archive_file, max_iter,""",
    """from .helpers import (
    run_agent_with_stage_guard, parse_eval_md, check_voting,
    discover_modules, get_modules_root, load_prompt, build_granularity_hint,
    archive_file, max_iter, write_judge_feedback,"""
)

# Fix [:500] in reflect jfb
patch(
    BASE + "s2_refine.py",
    "                    jfb = \"\\n\".join(\n"
    "                        f\"judge-{i}: {r['feedback'][:500]}\"\n"
    "                        for i, r in enumerate(judge_results))\n"
    "                    feedback += \"\\n\\n## Judge 上轮意见\\n\\n\" + jfb\n",
    "                    jfb = \"\\n\".join(\n"
    "                        f\"judge-{i}: {r['feedback']}\"\n"
    "                        for i, r in enumerate(judge_results))\n"
    "                    feedback += \"\\n\\n## Judge 上轮意见\\n\\n\" + jfb\n"
)

# Fix fail_fb block
patch(
    BASE + "s2_refine.py",
    "                fail_fb = \"\\n\".join(\n"
    "                    f\"judge-{i}: {r['feedback'][:500]}\"\n"
    "                    for i, r in enumerate(judge_results) if not r[\"pass\"])\n"
    "                if \"missing\" in fail_fb.lower()",
    "                fb_rel = write_judge_feedback(\n"
    "                    workspace, \"s2_refine\", mod_name, attempt + 1, judge_results)\n"
    "                ctx.emit_event(\"log\", level=\"info\",\n"
    "                               msg=f\"[S2] judge 意见已写入 {fb_rel}\")\n"
    "                fail_fb = str(fb_rel)\n"
    "                if \"missing\" in fail_fb.lower()"
)

# Fix feedback assignment to use file reference
patch(
    BASE + "s2_refine.py",
    '                feedback = "# 评审意见（未通过）\\n\\n" + fail_fb + guidance\n',
    '                feedback = (\n'
    '                    "请先阅读 judge 完整意见：\\n"\n'
    '                    + f"```\\nread {fail_fb}\\n```\\n"\n'
    '                    + guidance\n'
    '                )\n'
)

# ─────────────────────────────────────────────────────────────────────────────
# s3_analyse.py — add import + feedback file + cwd fix
# ─────────────────────────────────────────────────────────────────────────────
patch(
    BASE + "s3_analyse.py",
    """from .helpers import (
    run_agent_with_stage_guard, parse_eval_md, check_voting,
    discover_modules, get_modules_root, load_prompt, build_granularity_hint,
    archive_file, max_iter,""",
    """from .helpers import (
    run_agent_with_stage_guard, parse_eval_md, check_voting,
    discover_modules, get_modules_root, load_prompt, build_granularity_hint,
    archive_file, max_iter, write_judge_feedback,"""
)

# Fix cwd
patch(
    BASE + "s3_analyse.py",
    "                    cwd=str(mod_dir) if mod_dir.exists() else str(workspace),",
    "                    cwd=str(workspace),  # workspace根目录，避免双重modules/路径错误"
)

# Fix reflect [:500]
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

# Fix fail_fb block in s3
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
    "                               msg=f\"[S3] judge 意见已写入 {fb_rel}\")\n"
    "                feedback = (\n"
    "                    \"评审意见（未通过）已写入：\\n\"\n"
    "                    + f\"```\\nread {fb_rel}\\n```\\n\"\n"
    "                    + f\"请阅读后修正 modules/{mod_name}/module_report.md。\"\n"
    "                )\n"
    "                # 清除本轮未完成产物，避免半成品干扰下轮\n"
    "                if report_path.exists():\n"
    "                    try:\n"
    "                        report_path.unlink()\n"
    "                    except OSError:\n"
    "                        pass\n"
)

# Fix redo [:500] blocks
patch(
    BASE + "s3_analyse.py",
    "                        f\"judge-{i}: {r['feedback'][:500]}\"\n"
    "                        for i, r in enumerate(judge_results))\n"
    "                    feedback = f\"# 评审意见\\n\\n{fail_fb}\"\n",
    "                        f\"judge-{i}: {r['feedback']}\"\n"
    "                        for i, r in enumerate(judge_results))\n"
    "                    fb_rel2 = write_judge_feedback(\n"
    "                        workspace, \"s2_refine\", mod_name, attempt + 1, judge_results)\n"
    "                    feedback = (\n"
    "                        \"评审意见已写入：\\n\"\n"
    "                        + f\"```\\nread {fb_rel2}\\n```\"\n"
    "                    )\n"
)

patch(
    BASE + "s3_analyse.py",
    "                        f\"judge-{i}: {r['feedback'][:500]}\"\n"
    "                        for i, r in enumerate(judge_results) if not r[\"pass\"])\n"
    "                    feedback = f\"# 评审意见\\n\\n{fail_fb}\"\n",
    "                        f\"judge-{i}: {r['feedback']}\"\n"
    "                        for i, r in enumerate(judge_results) if not r[\"pass\"])\n"
    "                    fb_rel3 = write_judge_feedback(\n"
    "                        workspace, \"s3_analyse\", mod_name, attempt + 1, judge_results)\n"
    "                    feedback = (\n"
    "                        \"评审意见已写入：\\n\"\n"
    "                        + f\"```\\nread {fb_rel3}\\n```\"\n"
    "                    )\n"
)

# ─────────────────────────────────────────────────────────────────────────────
# s4_report.py — add import + feedback file + cwd fix + parallel judge
# ─────────────────────────────────────────────────────────────────────────────
patch(
    BASE + "s4_report.py",
    """from .helpers import (
    run_agent_with_stage_guard, parse_eval_md, check_voting,
    discover_modules, get_modules_root, load_prompt,
    archive_file, max_iter, pre_read_module, pre_read_module_with_details,
    generate_modules_list, strip_target_prefix,
    StageError, PiFatalError, max_rounds_exceeded_treated_as_passed,
    enforce_filter_constraint,
)""",
    """from .helpers import (
    run_agent_with_stage_guard, parse_eval_md, check_voting,
    discover_modules, get_modules_root, load_prompt,
    archive_file, max_iter, pre_read_module, pre_read_module_with_details,
    generate_modules_list, strip_target_prefix, write_judge_feedback,
    StageError, PiFatalError, max_rounds_exceeded_treated_as_passed,
    enforce_filter_constraint,
)"""
)

# Fix cwd for s4 redo judge
patch(
    BASE + "s4_report.py",
    "                            cwd=str(mod_dir) if mod_dir.exists() else str(workspace),",
    "                            cwd=str(workspace),  # workspace根目录，避免双重modules/路径"
)

# Fix redo feedback
patch(
    BASE + "s4_report.py",
    "                    fail_fb = \"\\n\".join(\n"
    "                        f\"judge-{i}: {r['feedback'][:500]}\"\n"
    "                        for i, r in enumerate(judge_results) if not r[\"pass\"])\n"
    "                    feedback = f\"# 评审意见\\n\\n{fail_fb}\"\n",
    "                    fb_rel = write_judge_feedback(\n"
    "                        workspace, \"s3_analyse\", mod_name, attempt + 1, judge_results)\n"
    "                    feedback = (\n"
    "                        \"评审意见（未通过）已写入：\\n\"\n"
    "                        + f\"```\\nread {fb_rel}\\n```\"\n"
    "                    )\n"
)

# Fix final_report feedback
patch(
    BASE + "s4_report.py",
    "                fail_fb = \"\\n\".join(\n"
    "                    f\"judge-{i}: {r['feedback'][:500]}\"\n"
    "                    for i, r in enumerate(judge_results) if not r[\"pass\"])\n"
    "                feedback = (f\"# 评审意见（未通过）\\n\\n{fail_fb}\"\n"
    "                            \"\\n\\n请根据意见修正 final_report.md。\")\n",
    "                fb_rel4 = write_judge_feedback(\n"
    "                    workspace, \"s4_report\", None, attempt + 1, judge_results)\n"
    "                ctx.emit_event(\"log\", level=\"info\",\n"
    "                               msg=f\"[S4b] judge 意见已写入 {fb_rel4}\")\n"
    "                feedback = (\n"
    "                    \"评审意见（未通过）已写入：\\n\"\n"
    "                    + f\"```\\nread {fb_rel4}\\n```\\n\"\n"
    "                    + \"请阅读后修正 final_report.md。\"\n"
    "                )\n"
)

# ── s4_report.py: insert parallel per-module judge after stage_result event ──
patch(
    BASE + "s4_report.py",
    "            has_report = (workspace / \"final_report.md\").exists()\n"
    "            ctx.emit_event(\"stage_result\", stage=\"4b\", has_report=has_report)\n"
    "\n"
    "            judge_results = []\n"
    "            judge_records = []\n"
    "            for j_idx, j_item in enumerate(ctx.j_cfgs):\n"
    "                j_model = ctx.jm(\"report\", j_item)\n",
    "            has_report = (workspace / \"final_report.md\").exists()\n"
    "            ctx.emit_event(\"stage_result\", stage=\"4b\", has_report=has_report)\n"
    "\n"
    "            # ── 并行 per-module 验收 judge ──────────────────────────────────────\n"
    "            if has_report and ctx.j_cfgs:\n"
    "                _final_mods = discover_modules(str(workspace))\n"
    "                _j_sys_analyse = load_prompt(cfg, \"step3_check_analyse\", \"judges\")\n"
    "                _sem_pm = asyncio.Semaphore(cfg.parallel_modules)\n"
    "                _pm_failed: list[str] = []\n"
    "                _pm_lock = asyncio.Lock()\n"
    "\n"
    "                async def _check_one_module_pm(mod_name_pm: str) -> None:\n"
    "                    async with _sem_pm:\n"
    "                        jpm_sess = ctx.session_path(\n"
    "                            \"judges\", \"final_check\", mod_name_pm,\n"
    "                            f\"final-check-a{attempt + 1}-j0.jsonl\",\n"
    "                        )\n"
    "                        try:\n"
    "                            jpm_ar = await run_agent_with_stage_guard(\n"
    "                                ctx=ctx, stage=\"4b-check\",\n"
    "                                context=f\"s4b-check-{mod_name_pm}\",\n"
    "                                heartbeat_payload_factory=lambda beat, m=mod_name_pm: {\n"
    "                                    \"module\": m, \"heartbeat\": beat},\n"
    "                                prompt=f\"最终验收：评审模块 `{mod_name_pm}` 的分析报告完整性。\",\n"
    "                                model=ctx.jm(\"analyse\", ctx.j_cfgs[0]),\n"
    "                                system_prompt=_j_sys_analyse,\n"
    "                                tools=cfg.judges.default_tools,\n"
    "                                cwd=str(workspace),\n"
    "                                session_file=jpm_sess,\n"
    "                                cancel_event=ctx.cancel_event,\n"
    "                                max_retries=cfg.agent_max_retries,\n"
    "                                retry_delay=cfg.agent_retry_delay,\n"
    "                                pi_max_retries=cfg.pi_max_retries,\n"
    "                                pi_retry_delay=cfg.pi_retry_delay,\n"
    "                            )\n"
    "                            ctx.tokens += jpm_ar.token_usage\n"
    "                            _parsed_pm = parse_eval_md(jpm_ar.output or \"\")\n"
    "                            if not _parsed_pm[\"pass\"]:\n"
    "                                async with _pm_lock:\n"
    "                                    _pm_failed.append(mod_name_pm)\n"
    "                                write_judge_feedback(\n"
    "                                    workspace, \"s4_completeness\", mod_name_pm,\n"
    "                                    attempt + 1, [_parsed_pm])\n"
    "                        except Exception as _exc_pm:\n"
    "                            ctx.emit_event(\"log\", level=\"warn\",\n"
    "                                           msg=f\"[S4b-check] {mod_name_pm} 评审异常: {_exc_pm}\")\n"
    "\n"
    "                await asyncio.gather(*[_check_one_module_pm(m) for m in _final_mods])\n"
    "\n"
    "                if _pm_failed:\n"
    "                    _summary = workspace / \"judge_output\" / \"s4_completeness\" / \"module_check_summary.md\"\n"
    "                    _summary.parent.mkdir(parents=True, exist_ok=True)\n"
    "                    _summary.write_text(\n"
    "                        f\"# 最终验收失败模块（第 {attempt + 1} 轮）\\n\\n\"\n"
    "                        + \"\\n\".join(f\"- {m}\" for m in _pm_failed),\n"
    "                        encoding=\"utf-8\",\n"
    "                    )\n"
    "                    ctx.emit_event(\"log\", level=\"warn\",\n"
    "                                   msg=f\"[S4b-check] {len(_pm_failed)} 个模块未通过验收，详见 judge_output/s4_completeness/\")\n"
    "\n"
    "            # ── 全局 Judge ──────────────────────────────────────────────────────\n"
    "            judge_results = []\n"
    "            judge_records = []\n"
    "            for j_idx, j_item in enumerate(ctx.j_cfgs):\n"
    "                j_model = ctx.jm(\"report\", j_item)\n"
)

print("\nAll patches applied.")
