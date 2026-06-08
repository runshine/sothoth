from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import subprocess
import tempfile

from vuln_dispatch.log import get_logger
from vuln_verify.prompt import load_prompt


def _verify_one(
    group_dir: Path,
    out_dir: Path,
    base_prompt: str,
    prompt_msg: str,
    model: str | None,
    tmp_files: list[Path],
) -> tuple[str, int]:
    """对一个分组执行 pi 验证，返回 (group_id, exit_code)。"""
    log = get_logger("vuln_verify.launcher")

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=f"_{group_dir.name}_verifier_prompt.md",
        delete=False,
    ) as handle:
        handle.write(base_prompt)
        tmp_prompt = Path(handle.name)
    tmp_files.append(tmp_prompt)

    log.info("verifier_start", group_id=group_dir.name)

    stdout_file = out_dir / f"{group_dir.name}.stdout"
    stderr_file = out_dir / f"{group_dir.name}.stderr"

    pi_cmd = ["pi", "--append-system-prompt", str(tmp_prompt), "-p", prompt_msg]
    if model:
        pi_cmd.extend(["--model", model])

    with open(stdout_file, "w") as f_out, open(stderr_file, "w") as f_err:
        process = subprocess.Popen(
            pi_cmd,
            cwd=str(group_dir),
            stdout=f_out,
            stderr=f_err,
        )
        returncode = process.wait()

    if returncode == 0:
        log.info("verifier_ok", group_id=group_dir.name)
    else:
        log.warning("verifier_fail", group_id=group_dir.name, exit_code=returncode)

    return (group_dir.name, returncode)


def launch(assembled_dir: Path, threat_path: str, model: str | None = None,
           concurrency: int = 4, resume: bool = False) -> None:
    log = get_logger("vuln_verify.launcher")
    """
    遍历 {assembled_dir}/groups/group_*/ 目录。
    每个分组启动一个 pi 进程，最多 concurrency 个并发。
    将 verifier 输出写入 {assembled_dir}/verifier_output/，并记录里程碑结构化日志。
    当 resume=True 时，跳过已存在 verifier_output/group_XXX.done 标记的分组。
    """
    assembled_path = Path(assembled_dir)
    groups_dir = assembled_path / "groups"
    out_dir = (assembled_path / "verifier_output").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not groups_dir.is_dir():
        raise FileNotFoundError(f"groups directory not found: {groups_dir}")

    group_dirs = sorted(
        path for path in groups_dir.iterdir()
        if path.is_dir() and path.name.startswith("group_")
    )

    if resume:
        skipped = 0
        pending: list[Path] = []
        for g in group_dirs:
            if (out_dir / f"{g.name}.done").exists():
                log.info("verifier_skip", group_id=g.name, reason="already completed")
                skipped += 1
            else:
                pending.append(g)
        if skipped:
            log.info("verifier_resume", skipped_count=skipped, pending_count=len(pending))
        group_dirs = pending

    base_prompt = load_prompt(threat_path)
    tmp_files: list[Path] = []

    prompt_msg = (
        "分析 reports/ 下的漏洞报告。manifest.json 中有 file_path 和 binary_root 路径。"
        f"将 result_*.json 输出到 {out_dir}。"
        "不需要生成任何 .md 文件，仅输出 JSON 格式的验证结果。"
    )

    try:
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {
                executor.submit(
                    _verify_one, g, out_dir, base_prompt, prompt_msg, model, tmp_files
                ): g
                for g in group_dirs
            }

            ok_count = 0
            error_count = 0
            for future in as_completed(futures):
                group_id, returncode = future.result()
                if returncode == 0:
                    ok_count += 1
                    (out_dir / f"{group_id}.done").touch()
                else:
                    error_count += 1

        log.info("verifier_summary",
                 total_group_count=len(group_dirs),
                 ok_count=ok_count,
                 error_count=error_count)

        if error_count:
            raise RuntimeError(f"verifier failed: {error_count}/{len(group_dirs)} groups exited with error")
    finally:
        for tmp_file in tmp_files:
            try:
                tmp_file.unlink()
            except FileNotFoundError:
                pass
