#!/usr/bin/env python3
import argparse
import json
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

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


def load_progress(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {"done": [], "failed": []}


def save_progress(path: Path, progress: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(progress, ensure_ascii=False, indent=2), encoding="utf-8")


def process_task(
    func_name: str,
    progress: dict,
    progress_path: Path,
    kernel_dir: str,
    report_dir: str,
    model: str,
) -> tuple[str, bool]:
    print(f"processing {func_name}", flush=True)
    prompt = (
        '加载kernel-security-audit，从攻击入口%s开始分析，找出所有内核漏洞,源码目录在："%s"，'
        '报告保存在：%s'
        % (func_name, kernel_dir, report_dir)
    )
    _, success = run_claude(prompt, model)

    with file_lock:
        if success:
            progress["done"].append(func_name)
        else:
            progress["failed"].append(func_name)
        save_progress(progress_path, progress)

    print(f"done: {func_name} ({'ok' if success else 'FAILED'})", flush=True)
    return func_name, success


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

    progress_path = report_dir / "audit_progress.json"
    progress = load_progress(progress_path)
    done_set = set(progress["done"])
    failed_set = set(progress["failed"])

    lines = devlist_path.read_text(encoding="utf-8", errors="replace").splitlines()

    tasks = []
    skip_count = 0
    for line in lines:
        if not line.strip():
            continue
        parts = line.strip().split()
        if not parts:
            continue
        func_name = parts[0]
        type_ = parts[-1]

        if args.method_filter and args.method_filter not in type_:
            continue
        if func_name in done_set:
            skip_count += 1
            continue
        if func_name in failed_set:
            skip_count += 1
            continue

        tasks.append(func_name)

    if skip_count:
        print(f"Skipped {skip_count} done/failed entries")

    if not tasks:
        print("No tasks to process")
        return 0

    print(f"Processing {len(tasks)} tasks with {args.threads} threads "
          f"| kernel={args.kernel_dir} | reports={report_dir} | model={args.model}",
          flush=True)

    completed = 0
    failed = 0
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(
                process_task, func_name, progress, progress_path,
                args.kernel_dir, str(report_dir), args.model,
            ): func_name
            for func_name in tasks
        }
        for future in as_completed(futures):
            func_name = futures[future]
            try:
                _, success = future.result()
                if success:
                    completed += 1
                else:
                    failed += 1
            except Exception as e:
                failed += 1
                print(f"error processing {func_name}: {e}")

    print(f"All done: {completed} succeeded, {failed} failed, {skip_count} skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
