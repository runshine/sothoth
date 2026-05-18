#!/usr/bin/env python3
import argparse
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

MARK_DONE = "[DONE]"
MARK_FAILED = "[FAILED]"

file_lock = threading.Lock()


def run_claude(prompt: str, model: str) -> tuple[str, bool]:
    proc = subprocess.run(
        ["claude", "--dangerously-skip-permissions", "--model", model, "-p", prompt],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        print(f"  claude failed: {proc.stderr.strip()}")
        return proc.stdout, False
    return proc.stdout, True


def strip_mark(line: str) -> tuple[str, str]:
    s = line.rstrip()
    for m in (MARK_DONE, MARK_FAILED):
        if s.endswith(m):
            return s[: -len(m)].rstrip(), m
    return s, ""


def save_devlist(path: Path, lines: list[str]):
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def process_task(
    idx: int,
    line: str,
    lines: list[str],
    devlist_path: Path,
    kernel_dir: str,
    report_dir: str,
    model: str,
) -> tuple[int, str, bool]:
    base, _ = strip_mark(line)
    func_name = base.split()[0]

    print(f"processing {func_name}", flush=True)
    prompt = (
        '加载kernel-security-audit，从攻击入口%s开始分析，找出所有内核漏洞,源码目录在："%s"，'
        '报告保存在：%s'
        % (func_name, kernel_dir, report_dir)
    )
    _, success = run_claude(prompt, model)

    with file_lock:
        lines[idx] = f"{base} {MARK_DONE if success else MARK_FAILED}"
        save_devlist(devlist_path, lines)

    print(f"done: {func_name}", flush=True)
    return idx, func_name, success


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--devlist", required=True, help="入口列表文件，每行 'func ... method'")
    parser.add_argument("--threads", type=int, default=4, help="Number of worker threads")
    parser.add_argument("--kernel-dir", required=True, help="内核源码目录")
    parser.add_argument("--report-dir", required=True, help="漏洞报告输出目录")
    parser.add_argument("--model", default="zai-org/GLM-5")
    parser.add_argument("--method-filter", default="ioctl",
                        help="仅处理 method 字段包含该子串的条目，传空串则处理全部")
    args = parser.parse_args()

    devlist_path = Path(args.devlist)
    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    lines = devlist_path.read_text(encoding="utf-8", errors="replace").splitlines()

    tasks = []
    skip_count = 0
    for idx, line in enumerate(lines):
        if not line.strip():
            continue
        base, mark = strip_mark(line)
        parts = base.split()
        if not parts:
            continue
        type_ = parts[-1]

        if args.method_filter and args.method_filter not in type_:
            continue
        if mark == MARK_DONE:
            skip_count += 1
            continue

        tasks.append((idx, line))

    if skip_count:
        print(f"Skipped {skip_count} done entries")

    if not tasks:
        print("No tasks to process")
        return 0

    print(f"Processing {len(tasks)} tasks with {args.threads} threads "
          f"| kernel={args.kernel_dir} | reports={report_dir} | model={args.model}",
          flush=True)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(
                process_task, idx, line, lines, devlist_path,
                args.kernel_dir, str(report_dir), args.model,
            ): (idx, line)
            for idx, line in tasks
        }
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                _, line = futures[future]
                base, _ = strip_mark(line)
                print(f"error processing {base.split()[0]}: {e}")

    print(f"All {len(tasks)} tasks completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
