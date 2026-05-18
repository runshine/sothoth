#!/usr/bin/env python3
"""
遍历内核源码所有 .c 文件，调用 Claude 判断是否有用户态可达的攻击入口。
支持并行处理、可中断重来。
"""
import argparse
import json
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

file_lock = threading.Lock()


def run_claude(prompt: str, model: str) -> tuple[str, bool]:
    proc = subprocess.run(
        ["claude", "--dangerously-skip-permissions", "--model", model, "-p", prompt],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )
    if proc.returncode != 0:
        return proc.stdout, False
    return proc.stdout, True


def build_prompt(file_path: str) -> str:
    return (
        f"读取{file_path}，找出该文件内*所有*的用户态可达的攻击入口。"
        "用户态可达是指：通过ioctl、syscall、read/write、procfs/sysfs/debugfs、netlink、socket等方式，"
        "用户态进程可以触发执行的内核函数。"
        "严格按照如下JSON格式返回结果，不要输出任何其他内容：\n"
        '{"entries": [{"func": "函数名", "method": "ioctl/syscall/read/write/procfs/sysfs/netlink/socket"}]}\n'
        "如果该文件没有用户态可达的攻击入口，返回：\n"
        '{"entries": []}\n'
        "只返回JSON，不要有任何解释文字。"
    )


def parse_response(response: str) -> list[dict]:
    response = response.strip()
    start = response.find("{")
    end = response.rfind("}") + 1
    if start == -1 or end == 0:
        return []
    try:
        data = json.loads(response[start:end])
        return data.get("entries", [])
    except json.JSONDecodeError:
        return []


def load_progress(path: Path) -> dict:
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {"done": [], "failed": [], "entries": []}
        data.setdefault("done", [])
        data.setdefault("failed", [])
        data.setdefault("entries", [])
        return data
    return {"done": [], "failed": [], "entries": []}


def save_progress(path: Path, progress: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(progress, ensure_ascii=False, indent=2), encoding="utf-8")


def save_results_text(path: Path, entries: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    seen = set()
    lines: list[str] = []
    for e in entries:
        key = (e.get("func", ""), e.get("method", ""))
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"{key[0]} [{key[1]}]")
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def save_results_json(path: Path, entries: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    seen: set[tuple[str, str]] = set()
    deduped: list[dict] = []
    for e in entries:
        key = (e.get("func", ""), e.get("method", ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append({
            "func": key[0],
            "method": key[1],
            "file": e.get("file", ""),
        })
    path.write_text(json.dumps({"entries": deduped}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def collect_files(kernel_dir: Path) -> list[str]:
    return [str(f) for f in sorted(kernel_dir.rglob("*.c"))]


def process_file(
    file_path: str,
    progress: dict,
    progress_path: Path,
    results_json_path: Path,
    results_text_path: Path,
    model: str,
) -> tuple[str, bool]:
    prompt = build_prompt(file_path)
    response, success = run_claude(prompt, model)

    if not success:
        with file_lock:
            progress["failed"].append(file_path)
            save_progress(progress_path, progress)
        return file_path, False

    entries = parse_response(response)

    with file_lock:
        progress["done"].append(file_path)
        for e in entries:
            progress["entries"].append({
                "func": e.get("func", ""),
                "method": e.get("method", ""),
                "file": file_path,
            })
        save_progress(progress_path, progress)
        save_results_json(results_json_path, progress["entries"])
        save_results_text(results_text_path, progress["entries"])

    return file_path, True


def main() -> int:
    parser = argparse.ArgumentParser(description="扫描内核源码攻击入口")
    parser.add_argument("--threads", type=int, default=4, help="并行线程数")
    parser.add_argument("--retry-failed", action="store_true", help="重试之前失败的文件")
    parser.add_argument("--kernel-dir", required=True, help="内核源码目录")
    parser.add_argument("--output-dir", required=True, help="进度/结果输出目录")
    parser.add_argument("--model", default="zai-org/GLM-5", help="Claude 模型名")
    args = parser.parse_args()

    kernel_dir = Path(args.kernel_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    progress_path = output_dir / "entry_scan_progress.json"
    results_json_path = output_dir / "entry_scan_results.json"
    results_text_path = output_dir / "entry_scan_results.txt"

    all_files = collect_files(kernel_dir)
    progress = load_progress(progress_path)

    done_set = set(progress["done"])
    failed_set = set(progress["failed"])

    if args.retry_failed:
        progress["failed"] = []
        failed_set = set()
        save_progress(progress_path, progress)

    pending = [f for f in all_files if f not in done_set and f not in failed_set]

    print(f"总文件数: {len(all_files)}")
    print(f"已完成: {len(done_set)}")
    print(f"已失败: {len(failed_set)}")
    print(f"待处理: {len(pending)}")
    print(f"已发现入口数: {len(progress['entries'])}")
    print(f"输出目录: {output_dir}")
    print(f"模型: {args.model}", flush=True)

    if not pending:
        print("没有待处理的文件")
        save_results_json(results_json_path, progress["entries"])
        save_results_text(results_text_path, progress["entries"])
        return 0

    print(f"\n开始处理，线程数: {args.threads}", flush=True)
    start_time = time.time()
    completed = 0
    failed = 0

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(
                process_file, f, progress, progress_path,
                results_json_path, results_text_path, args.model,
            ): f
            for f in pending
        }
        for future in as_completed(futures):
            file_path = futures[future]
            try:
                _, success = future.result()
                if success:
                    completed += 1
                else:
                    failed += 1
            except Exception as e:
                failed += 1
                print(f"  异常: {Path(file_path).name}: {e}")
                with file_lock:
                    progress["failed"].append(file_path)
                    save_progress(progress_path, progress)

            total_done = completed + failed
            if total_done % 10 == 0:
                elapsed = time.time() - start_time
                rate = total_done / elapsed if elapsed > 0 else 0
                eta = (len(pending) - total_done) / rate if rate > 0 else 0
                print(f"  进度: {total_done}/{len(pending)} | 成功:{completed} 失败:{failed} | "
                      f"速率:{rate:.1f}/s | ETA:{eta/60:.0f}min", flush=True)

    save_results_json(results_json_path, progress["entries"])
    save_results_text(results_text_path, progress["entries"])
    elapsed = time.time() - start_time
    print(f"\n完成! 耗时:{elapsed/60:.1f}min | 成功:{completed} 失败:{failed}")
    print(f"JSON 结果: {results_json_path}")
    print(f"文本结果: {results_text_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
