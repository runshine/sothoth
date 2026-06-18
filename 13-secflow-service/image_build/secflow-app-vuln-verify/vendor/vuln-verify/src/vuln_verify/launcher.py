from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import os
import subprocess
import tempfile
import time

from vuln_dispatch.log import get_logger
from vuln_verify.prompt import load_prompt

RATE_LIMIT_RETRY_DELAY_SECONDS = 30
TERMINAL_SKILLS_CANARY_VALUES = {"1", "true", "yes", "readonly", "read-only", "full"}
TERMINAL_SKILLS_ALL = [
    "wiki-mount",
    "skill-recall-pull",
    "post-task-reflect",
    "distill-experience",
    "task-score",
    "task-trace",
    "vuln-report",
    "skill-recall-onboard",
    "sec-skill-local-evolve",
    "skill-recall-propose",
    "task-collect",
]


def _terminal_skills_canary_mode() -> str:
    return os.getenv("SECOCTO_TERMINAL_SKILLS_CANARY", "").strip().lower()


def _terminal_skills_canary_enabled() -> bool:
    return _terminal_skills_canary_mode() in TERMINAL_SKILLS_CANARY_VALUES


def _terminal_skills_canary_prompt() -> str:
    mode = _terminal_skills_canary_mode()
    if mode not in TERMINAL_SKILLS_CANARY_VALUES:
        return ""

    if mode == "full":
        return (
            "在执行任务前你先把~/.config/secocto/.env 这里面的环境变量加到全局环境变量里面，"
            "自动尽最大可能获取当前的session_id, 如果无法行获取请自行创建，"
            "后续skill里面的session_id统一使用这个session_id，"
            "然后依次加载wiki-mount和skill-recall-pull这两个skill，"
            "后续任务必须从这两个skill加载的wiiki和远程skill中去搜索"
            "（skill-recall-pull里面包含相关的调用方法）需要使用的经验和skill，"
            "在任务执行之后，依次执行post-task-reflect、distill-experience、task-score、"
            "task-trace、vuln-report、skill-recall-onboard、sec-skill-local-evolve"
            "(除非skill完全符合要求，否则找到最需要进化的1-2个skill触发进化)、"
            "skill-recall-propose，最后执行task-collect\n"
        )

    return (
        "【Terminal Skills Canary - Readonly Mode】\n"
        "本次任务用于测试 terminal-skills 的只读集成效果。"
        "在执行漏洞验证前，先检查 /root/.config/secocto/.env 是否存在；如存在，读取其中环境变量。"
        "优先加载并使用 wiki-mount 和 skill-recall-pull，查找项目 Wiki、历史经验和可复用 Skill。"
        "除非用户明确要求，禁止执行会写入远端系统或修改本地 Skill 的操作，"
        "包括 skill-recall-onboard、sec-skill-local-evolve、skill-recall-propose、"
        "task-collect、vuln-report、distill-experience。"
        "如果外部服务不可达，记录原因并继续完成漏洞验证。"
        "最终仍必须将 result_*.json 输出到指定 verifier_output 目录。\n"
    )


def _is_rate_limited_output(text: str) -> bool:
    lowered = str(text or "").lower()
    return "429" in lowered or "rate limit" in lowered or "too many requests" in lowered


def _verify_one(
    group_dir: Path,
    out_dir: Path,
    base_prompt: str,
    prompt_msg: str,
    model: str | None,
    tmp_files: list[Path],
    session_dir: Path,
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

    pi_cmd = ["pi", "--session-dir", str(session_dir)]
    if _terminal_skills_canary_enabled():
        for skill_name in TERMINAL_SKILLS_ALL:
            pi_cmd.extend(["--skill", f"/root/.pi/agent/skills/{skill_name}"])
    pi_cmd.extend(["--append-system-prompt", str(tmp_prompt), "-p", prompt_msg])
    if model:
        pi_cmd.extend(["--model", model])

    consecutive_rate_limit_count = 0
    while True:
        with open(stdout_file, "w") as f_out, open(stderr_file, "w") as f_err:
            process = subprocess.Popen(
                pi_cmd,
                cwd=str(group_dir),
                stdout=f_out,
                stderr=f_err,
            )
            returncode = process.wait()
        if returncode == 0:
            break
        stderr_text = stderr_file.read_text(encoding="utf-8", errors="ignore") if stderr_file.exists() else ""
        stdout_text = stdout_file.read_text(encoding="utf-8", errors="ignore") if stdout_file.exists() else ""
        combined = f"{stderr_text}\n{stdout_text}"
        if not _is_rate_limited_output(combined):
            break
        consecutive_rate_limit_count += 1
        log.warning(
            "verifier_rate_limited",
            group_id=group_dir.name,
            consecutive_rate_limit_count=consecutive_rate_limit_count,
            retry_delay_seconds=RATE_LIMIT_RETRY_DELAY_SECONDS,
        )
        time.sleep(RATE_LIMIT_RETRY_DELAY_SECONDS)

    if returncode == 0:
        log.info("verifier_ok", group_id=group_dir.name)
    else:
        log.warning("verifier_fail", group_id=group_dir.name, exit_code=returncode)

    return (group_dir.name, returncode)


def launch(assembled_dir: Path, threat_path: str | None = None, model: str | None = None,
           concurrency: int = 4, resume: bool = False, session_dir: Path | None = None) -> None:
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
    session_path = (session_dir or assembled_path.parent / "run").resolve()
    session_path.mkdir(parents=True, exist_ok=True)

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
        _terminal_skills_canary_prompt()
        + "分析 reports/ 下的漏洞报告。manifest.json 中有 file_path 和 binary_root 路径。"
        f"将 result_*.json 输出到 {out_dir}。"
        "不需要生成任何 .md 文件，仅输出 JSON 格式的验证结果。"
    )

    try:
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {
                executor.submit(
                    _verify_one, g, out_dir, base_prompt, prompt_msg, model, tmp_files, session_path
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
