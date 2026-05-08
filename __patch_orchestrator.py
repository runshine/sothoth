"""Patch _orchestrator_legacy.py to use {task_id}/run/ and {task_id}/output/ layout."""
import sys

PATH = "/home/icsl/sa_build/app_src/app/_orchestrator_legacy.py"

with open(PATH, encoding="utf-8") as f:
    src = f.read()

# ── Change 1: Directory setup in execute() ──────────────────────────────────
OLD1 = """\
        # ── resume_workspace: 直接使用已有 workspace（跳过 Stage 1/2）──
        if cfg.resume_workspace and cfg.start_stage > 1:
            workspace = Path(os.path.abspath(cfg.resume_workspace))
            out_dir = workspace.parent
            task_id = out_dir.name  # 继承原 task_id
            sess_dir = out_dir / "sessions"
            sess_dir.mkdir(exist_ok=True)
            task_tmp = workspace / "tmp"
            task_tmp.mkdir(exist_ok=True)
        else:
            out_dir = Path(os.path.abspath(cfg.output_dir)) / task_id
            out_dir.mkdir(parents=True, exist_ok=True)
            sess_dir = out_dir / "sessions"
            sess_dir.mkdir(exist_ok=True)
            workspace = out_dir / "workspace"
            workspace.mkdir(exist_ok=True)
            # Per-task workspace isolation: private tmp dir + read-only target symlink
            task_tmp = workspace / "tmp"
            task_tmp.mkdir(exist_ok=True)
            target_link = workspace / "target"
            if not target_link.exists():
                try:
                    target_link.symlink_to(os.path.abspath(cfg.target_dir))
                except OSError:
                    pass"""

NEW1 = """\
        # ── resume_workspace: 直接使用已有 workspace（跳过 Stage 1/2）──
        # 输出目录结构: {output_dir}/{task_id}/run/ (中间过程) + {output_dir}/{task_id}/output/ (最终结果)
        if cfg.resume_workspace and cfg.start_stage > 1:
            workspace = Path(os.path.abspath(cfg.resume_workspace))
            run_dir = workspace.parent
            base_dir = run_dir.parent
            task_id = base_dir.name  # 继承原 task_id
            final_dir = base_dir / "output"
            final_dir.mkdir(parents=True, exist_ok=True)
            sess_dir = run_dir / "sessions"
            sess_dir.mkdir(exist_ok=True)
            task_tmp = workspace / "tmp"
            task_tmp.mkdir(exist_ok=True)
            out_dir = run_dir
        else:
            base_dir = Path(os.path.abspath(cfg.output_dir)) / task_id
            run_dir = base_dir / "run"
            final_dir = base_dir / "output"
            run_dir.mkdir(parents=True, exist_ok=True)
            final_dir.mkdir(parents=True, exist_ok=True)
            sess_dir = run_dir / "sessions"
            sess_dir.mkdir(exist_ok=True)
            workspace = run_dir / "workspace"
            workspace.mkdir(exist_ok=True)
            # Per-task workspace isolation: private tmp dir + read-only target symlink
            task_tmp = workspace / "tmp"
            task_tmp.mkdir(exist_ok=True)
            target_link = workspace / "target"
            if not target_link.exists():
                try:
                    target_link.symlink_to(os.path.abspath(cfg.target_dir))
                except OSError:
                    pass
            out_dir = run_dir"""

# ── Change 2: result_dir initialization ────────────────────────────────────
OLD2 = """\
        result_dir = Path(os.path.abspath(cfg.result_dir))
        result_dir.mkdir(parents=True, exist_ok=True)
        flag_path = result_dir / "flag"\
"""

NEW2 = """\
        result_dir = final_dir  # 最终结果固定写入 {task_id}/output/
        result_dir.mkdir(parents=True, exist_ok=True)
        flag_path = result_dir / "flag"\
"""

# ── Change 3: Finalization — remove zip archive and out_dir cleanup ─────────
OLD3 = """\
        # 6) archive.zip — 所有中间件 (judge评审、session、原始workspace)
        (out_dir / "result.json").write_text(
            result.model_dump_json(indent=2), encoding="utf-8")
        archive_path = str(result_dir / "archive")
        shutil.make_archive(archive_path, "zip", str(out_dir.parent), out_dir.name)

        # 写最终 flag: 成功=1, 失败/错误=0
        try:
            flag_path.write_text(
                "1" if result.status == TaskStatus.PASSED else "0",
                encoding="utf-8")
        except OSError:
            pass

        self._emit("task_end", task_id, status=result.status.value,
                    report=str(report_dst),
                    modules=str(modules_out),
                    archive=f"{archive_path}.zip")

        try:
            shutil.rmtree(str(out_dir))
        except OSError:
            pass"""

NEW3 = """\
        # 6) result.json — 保存运行摘要到 run/ 目录
        (run_dir / "result.json").write_text(
            result.model_dump_json(indent=2), encoding="utf-8")

        # 写最终 flag: 成功=1, 失败/错误=0
        try:
            flag_path.write_text(
                "1" if result.status == TaskStatus.PASSED else "0",
                encoding="utf-8")
        except OSError:
            pass

        self._emit("task_end", task_id, status=result.status.value,
                    report=str(report_dst),
                    modules=str(modules_out))"""

changes = [(OLD1, NEW1, "directory setup"), (OLD2, NEW2, "result_dir"), (OLD3, NEW3, "finalization")]
for old, new, label in changes:
    if old not in src:
        print(f"ERROR: '{label}' not found in source", file=sys.stderr)
        sys.exit(1)
    src = src.replace(old, new, 1)
    print(f"OK: patched '{label}'")

with open(PATH, "w", encoding="utf-8") as f:
    f.write(src)
print("Done.")
