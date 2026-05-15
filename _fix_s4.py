#!/usr/bin/env python3
"""Apply all s4_report.py patches safely."""

BASE = "D:/workspace/pi/sothoth/13-secflow-service/image_build/secflow-app-system-analyse/app/pipeline/"


def patch(path, old, new, label=""):
    content = open(path, encoding="utf-8").read()
    assert old in content, f"NOT FOUND [{label}]: {repr(old[:80])}"
    content = content.replace(old, new, 1)
    open(path, "w", encoding="utf-8").write(content)
    print(f"OK  {label or path.split('/')[-1]}")


f = BASE + "s4_report.py"

# 1. Add write_judge_feedback to import
patch(f,
    "    generate_modules_list, strip_target_prefix,\n"
    "    StageError, PiFatalError, max_rounds_exceeded_treated_as_passed,\n"
    "    enforce_filter_constraint,\n"
    ")",
    "    generate_modules_list, strip_target_prefix, write_judge_feedback,\n"
    "    StageError, PiFatalError, max_rounds_exceeded_treated_as_passed,\n"
    "    enforce_filter_constraint,\n"
    ")",
    "s4 import write_judge_feedback")

# 2. Fix cwd in s4 redo judge
patch(f,
    "                            cwd=str(mod_dir) if mod_dir.exists() else str(workspace),",
    "                            cwd=str(workspace),  # workspace根, 避免双重modules/路径",
    "s4 redo judge cwd fix")

# 3. Fix redo feedback (lines ~238-241)
patch(f,
    "                    fail_fb = \"\\n\".join(\n"
    "                        f\"judge-{i}: {r['feedback'][:500]}\"\n"
    "                        for i, r in enumerate(judge_results) if not r[\"pass\"])\n"
    "                    feedback = f\"# 评审意见\\n\\n{fail_fb}\"\n",
    "                    fb_redo = write_judge_feedback(\n"
    "                        workspace, \"s3_analyse\", mod_name, attempt + 1, judge_results)\n"
    "                    feedback = f\"评审未通过，完整意见请 read {fb_redo}\"\n",
    "s4 redo feedback file")

# 4. Fix final_report feedback (lines ~416-420)
patch(f,
    "                fail_fb = \"\\n\".join(\n"
    "                    f\"judge-{i}: {r['feedback'][:500]}\"\n"
    "                    for i, r in enumerate(judge_results) if not r[\"pass\"])\n"
    "                feedback = (f\"# 评审意见（未通过）\\n\\n{fail_fb}\"\n"
    "                            \"\\n\\n请根据意见修正 final_report.md。\")\n",
    "                fb4 = write_judge_feedback(\n"
    "                    workspace, \"s4_report\", None, attempt + 1, judge_results)\n"
    "                ctx.emit_event(\"log\", level=\"info\",\n"
    "                               msg=f\"[S4b] judge意见已写入 {fb4}\")\n"
    "                feedback = f\"评审未通过，完整意见请 read {fb4} ，阅后修正 final_report.md\"\n",
    "s4 final feedback file")

# 5. Insert parallel per-module judge after stage_result event
patch(f,
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
    "            # ── 并行 per-module 验收 judge ─────────────────────────────────────\n"
    "            if has_report and ctx.j_cfgs:\n"
    "                _final_mods = discover_modules(str(workspace))\n"
    "                _j_sys = load_prompt(cfg, \"step3_check_analyse\", \"judges\")\n"
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
    "                                system_prompt=_j_sys,\n"
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
    "                            _pm_parsed = parse_eval_md(jpm_ar.output or \"\")\n"
    "                            if not _pm_parsed[\"pass\"]:\n"
    "                                async with _pm_lock:\n"
    "                                    _pm_failed.append(mod_name_pm)\n"
    "                                write_judge_feedback(\n"
    "                                    workspace, \"s4_completeness\", mod_name_pm,\n"
    "                                    attempt + 1, [_pm_parsed])\n"
    "                        except Exception as _exc_pm:\n"
    "                            ctx.emit_event(\"log\", level=\"warn\",\n"
    "                                           msg=f\"[S4b-check] {mod_name_pm} 异常: {_exc_pm}\")\n"
    "\n"
    "                await asyncio.gather(*[_check_one_module_pm(m) for m in _final_mods])\n"
    "\n"
    "                if _pm_failed:\n"
    "                    _sum = workspace / \"judge_output\" / \"s4_completeness\" / \"module_check_summary.md\"\n"
    "                    _sum.parent.mkdir(parents=True, exist_ok=True)\n"
    "                    _sum.write_text(\n"
    "                        f\"# 最终验收失败模块（第 {attempt + 1} 轮）\\n\\n\"\n"
    "                        + \"\\n\".join(f\"- {m}\" for m in _pm_failed),\n"
    "                        encoding=\"utf-8\",\n"
    "                    )\n"
    "                    ctx.emit_event(\"log\", level=\"warn\",\n"
    "                                   msg=f\"[S4b-check] {len(_pm_failed)} 个模块未通过，详见 judge_output/s4_completeness/\")\n"
    "\n"
    "            # ── 全局 Judge ───────────────────────────────────────────────────────\n"
    "            judge_results = []\n"
    "            judge_records = []\n"
    "            for j_idx, j_item in enumerate(ctx.j_cfgs):\n"
    "                j_model = ctx.jm(\"report\", j_item)\n",
    "s4 parallel per-module judge")

import py_compile, re
try:
    py_compile.compile(f, doraise=True)
    print("Syntax OK: s4_report.py")
except py_compile.PyCompileError as e:
    print(f"SYNTAX ERR: {e}")
    m = re.search(r"line (\d+)", str(e))
    if m:
        ln = int(m.group(1))
        ls = open(f, encoding="utf-8").readlines()
        for i in range(max(0, ln-3), min(ln+4, len(ls))):
            print(f"  {i+1}: {repr(ls[i])}")
