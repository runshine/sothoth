#!/usr/bin/env python3

from __future__ import annotations

import argparse
import shlex
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from selection import SelectionOption, resolve_named_targets
from workspace import discover_batch_repos, resolve_batch_group_keys

FAILURE_TAIL_LINES = 8
SUMMARY_BAR_WIDTH = 32


@dataclass
class TaskState:
    repo: str
    path: Path
    status: str = "pending"
    self_healed: bool = False
    returncode: int | None = None
    heal_returncode: int | None = None
    started_at: float | None = None
    finished_at: float | None = None
    last_line: str = ""
    output_tail: deque[str] = field(
        default_factory=lambda: deque(maxlen=FAILURE_TAIL_LINES)
    )
    heal_output_tail: deque[str] = field(
        default_factory=lambda: deque(maxlen=FAILURE_TAIL_LINES)
    )
    process: subprocess.Popen[str] | None = field(default=None, repr=False)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def elapsed(self, now: float | None = None) -> float:
        if self.started_at is None:
            return 0.0
        end = self.finished_at if self.finished_at is not None else (now or time.time())
        return max(0.0, end - self.started_at)


class ProgressTracker:
    SPINNER_FRAMES = "|/-\\"
    STATUS_LABELS = {
        "pending": "QUEUED",
        "running": "RUN",
        "healing": "HEAL",
        "verify": "VERIFY",
        "success": "OK",
        "failed": "FAIL",
    }

    def __init__(self, tasks: list[TaskState], make_args: list[str]) -> None:
        self._tasks = tasks
        self._make_args = make_args
        self._interactive = sys.stdout.isatty()
        self._cursor_hidden = False
        self._last_rendered_lines = 0
        self._tick = 0

    def render(self) -> None:
        self._tick += 1
        lines = build_dashboard_lines(self._tasks, self._make_args, self._tick)
        if self._interactive:
            self._render_interactive(lines)
            return
        sys.stdout.write("\n".join(lines) + "\n")
        sys.stdout.flush()

    def finish_render(self) -> None:
        if not self._interactive:
            return
        if self._cursor_hidden:
            sys.stdout.write("\x1b[?25h")
            sys.stdout.flush()
            self._cursor_hidden = False

    def _render_interactive(self, lines: list[str]) -> None:
        cursor_up = ""
        if self._last_rendered_lines > 1:
            cursor_up = f"\x1b[{self._last_rendered_lines - 1}F"
        output = "\x1b[?25l" + cursor_up + "\x1b[2J" + "\n".join(lines)
        sys.stdout.write(output)
        sys.stdout.flush()
        self._cursor_hidden = True
        self._last_rendered_lines = len(lines)

    def indicator(self, task: TaskState) -> str:
        if task.status == "success":
            return self._color("OK", "32")
        if task.status == "failed":
            return self._color("!!", "31")
        if task.status == "pending":
            return self._color("..", "90")
        spinner = self.SPINNER_FRAMES[self._tick % len(self.SPINNER_FRAMES)]
        return self._color(spinner, "36")

    def _color(self, text: str, code: str) -> str:
        if not self._interactive:
            return text
        return f"\x1b[{code}m{text}\x1b[0m"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a make target across selected managed image build directories."
    )
    parser.add_argument(
        "--group",
        action="append",
        default=[],
        help="only include repositories from this managed group; repeatable",
    )
    parser.add_argument(
        "--repo",
        action="append",
        default=[],
        help="only include repositories with this name or alias; repeatable",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=0,
        help="maximum concurrent repositories; default is all repositories",
    )
    parser.add_argument(
        "--match",
        action="append",
        default=[],
        help="only include repositories whose name contains this substring; repeatable",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show which repositories would run without executing make",
    )
    parser.add_argument(
        "--plain",
        action="store_true",
        help="disable ANSI dashboard output and print plain status lines",
    )
    parser.add_argument(
        "make_args",
        nargs=argparse.REMAINDER,
        help="arguments passed through to make, for example: build or pull IMAGE_TAG=v1",
    )
    args = parser.parse_args()
    if args.make_args and args.make_args[0] == "--":
        args.make_args = args.make_args[1:]
    if not args.make_args:
        parser.error("missing make target or arguments")
    if args.jobs < 0:
        parser.error("--jobs must be >= 0")
    return args


def discover_repos(group_keys: list[str], matches: Iterable[str], repo_names: Iterable[str]) -> list[Path]:
    repos = discover_batch_repos(group_keys)
    selected_names = [name for name in repo_names if name]
    if selected_names:
        options = [
            SelectionOption(
                value=repo.name,
                display_name=repo.display_name,
                description=f"{repo.group.display_name}/{repo.name}",
                aliases=repo.aliases,
            )
            for repo in repos
        ]
        resolved_names = resolve_named_targets(
            selected_names,
            options=options,
            item_label="repositories",
            example="0 or 1,4 or platform-auth,agent-helper",
            unknown_label="repository",
            no_selection_message="No repositories selected",
        )
        allowed = set(resolved_names)
        repos = [repo for repo in repos if repo.name in allowed]
    match_terms = [term for term in matches if term]
    if match_terms:
        repos = [
            repo
            for repo in repos
            if any(term in repo.name or term in repo.display_name for term in match_terms)
        ]
    return [repo.path for repo in repos]


def format_seconds(seconds: float) -> str:
    total = int(seconds)
    minutes, secs = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def truncate(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 3:
        return "." * width
    return text[: width - 3] + "..."


def render_summary_bar(completed: int, total: int) -> str:
    if total <= 0:
        return "." * SUMMARY_BAR_WIDTH
    filled = int(SUMMARY_BAR_WIDTH * completed / total)
    return "#" * filled + "." * (SUMMARY_BAR_WIDTH - filled)


def fit_line(text: str, width: int) -> str:
    if width <= 0:
        return ""
    return truncate(text, width)


def collect_failure_tail(task: TaskState) -> list[str]:
    tail = list(task.output_tail)
    if tail:
        return tail
    if task.last_line:
        return [task.last_line]
    return []


def format_phase_elapsed(task: TaskState, now: float) -> str:
    if task.started_at is None:
        return "--"
    return f"{task.elapsed(now):.1f}s"


def format_overview_line(
    completed: int,
    total: int,
    success: int,
    healed: int,
    failed: int,
    running_now: int,
    elapsed_seconds: float,
) -> str:
    bar = render_summary_bar(completed, total)
    return (
        f"[{bar}] {completed}/{total} done "
        f"| ok={success} healed={healed} failed={failed} running={running_now} "
        f"| elapsed={elapsed_seconds:.1f}s"
    )


def indicator_for_task(task: TaskState, tick: int, interactive: bool) -> str:
    if task.status == "success":
        return colorize("OK", "32", interactive)
    if task.status == "failed":
        return colorize("!!", "31", interactive)
    if task.status == "pending":
        return colorize("..", "90", interactive)
    spinner = ProgressTracker.SPINNER_FRAMES[tick % len(ProgressTracker.SPINNER_FRAMES)]
    return colorize(spinner, "36", interactive)


def colorize(text: str, code: str, interactive: bool) -> str:
    if not interactive:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def status_label_for_task(task: TaskState) -> str:
    if task.self_healed and task.status == "success":
        return "HEALED"
    if task.status == "failed" and task.heal_returncode is not None:
        return "FAIL*"
    return ProgressTracker.STATUS_LABELS.get(task.status, task.status.upper())


def plain_print(message: str) -> None:
    print(message, flush=True)


def execute_command(
    task: TaskState,
    argv: list[str],
    status: str,
    tail: deque[str],
    plain_mode: bool,
    plain_label: str,
) -> tuple[int | None, str | None]:
    command_text = shlex.join(argv)
    with task.lock:
        task.status = status
        task.last_line = command_text

    if plain_mode:
        plain_print(f"[{plain_label}] {task.repo}: {command_text}")

    try:
        process = subprocess.Popen(
            argv,
            cwd=task.path,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except Exception as exc:
        message = str(exc)
        with task.lock:
            task.last_line = message
            tail.append(message)
            task.process = None
        return None, message

    with task.lock:
        task.process = process

    assert process.stdout is not None
    for raw_line in process.stdout:
        line = raw_line.rstrip()
        if not line:
            continue
        with task.lock:
            task.last_line = line
            tail.append(line)

    returncode = process.wait()
    with task.lock:
        task.process = None
    return returncode, None


def build_self_heal_prompt(task: TaskState, make_args: list[str]) -> str:
    command_text = shlex.join(["make", *make_args])
    failure_lines = list(task.output_tail)
    if not failure_lines:
        failure_lines = [task.last_line or f"command exited with {task.returncode}"]

    return "\n".join(
        [
            f"项目: {task.repo}",
            f"工作目录: {task.path}",
            f"命令: {command_text}",
            "错误信息:",
            *failure_lines,
            "请修复上述问题，并在修复后重新运行该命令验证通过。",
        ]
    )


def run_task(
    task: TaskState,
    make_args: list[str],
    semaphore: threading.Semaphore,
    plain_mode: bool,
) -> None:
    with semaphore:
        start = time.time()
        with task.lock:
            task.started_at = start
            task.last_line = shlex.join(["make", *make_args])
            task.output_tail.clear()
            task.heal_output_tail.clear()

        returncode, launch_error = execute_command(
            task=task,
            argv=["make", *make_args],
            status="running",
            tail=task.output_tail,
            plain_mode=plain_mode,
            plain_label="RUN ",
        )

        if launch_error is None and returncode == 0:
            finish = time.time()
            with task.lock:
                task.returncode = 0
                task.finished_at = finish
                task.status = "success"
            if plain_mode:
                plain_print(
                    f"[DONE] {task.repo}: {format_seconds(finish - start)}"
                )
            return

        with task.lock:
            task.returncode = 127 if launch_error is not None else returncode
            if launch_error is not None:
                task.last_line = launch_error

        prompt = build_self_heal_prompt(task, make_args)
        heal_returncode, heal_error = execute_command(
            task=task,
            argv=["opencode", "run", prompt],
            status="healing",
            tail=task.heal_output_tail,
            plain_mode=plain_mode,
            plain_label="HEAL",
        )

        if heal_error is not None or heal_returncode != 0:
            finish = time.time()
            with task.lock:
                task.heal_returncode = 127 if heal_error is not None else heal_returncode
                task.finished_at = finish
                task.status = "failed"
                if heal_error is not None:
                    task.last_line = heal_error
            if plain_mode:
                plain_print(
                    f"[FAIL] {task.repo}: self-heal failed after {format_seconds(finish - start)}"
                )
            return

        verify_returncode, verify_error = execute_command(
            task=task,
            argv=["make", *make_args],
            status="verify",
            tail=task.output_tail,
            plain_mode=plain_mode,
            plain_label="RETRY",
        )

        finish = time.time()
        with task.lock:
            task.heal_returncode = heal_returncode
            task.finished_at = finish
            task.returncode = 127 if verify_error is not None else verify_returncode
            task.self_healed = verify_error is None and verify_returncode == 0
            task.status = "success" if task.self_healed else "failed"
            if verify_error is not None:
                task.last_line = verify_error

        if plain_mode:
            state = "DONE" if task.self_healed else "FAIL"
            plain_print(
                f"[{state}] {task.repo}: {format_seconds(finish - start)}"
            )


def terminate_running(tasks: list[TaskState]) -> None:
    for task in tasks:
        with task.lock:
            process = task.process
        if process is None or process.poll() is not None:
            continue
        try:
            process.terminate()
        except ProcessLookupError:
            continue


def build_dashboard_lines(
    tasks: list[TaskState], make_args: list[str], tick: int
) -> list[str]:
    now = time.time()
    total = len(tasks)
    completed = sum(task.status in {"success", "failed"} for task in tasks)
    running = sum(task.status == "running" for task in tasks)
    healing = sum(task.status == "healing" for task in tasks)
    verifying = sum(task.status == "verify" for task in tasks)
    success = sum(task.status == "success" for task in tasks)
    healed = sum(task.self_healed for task in tasks)
    failed = sum(task.status == "failed" for task in tasks)
    pending = total - completed - running - healing - verifying

    columns = shutil.get_terminal_size(fallback=(120, 40)).columns
    interactive = sys.stdout.isatty()

    lines = [
        fit_line(f"Target: make {' '.join(make_args)}", columns),
        fit_line(
            format_overview_line(
                completed=completed,
                total=total,
                success=success,
                healed=healed,
                failed=failed,
                running_now=running + healing + verifying,
                elapsed_seconds=max((task.elapsed(now) for task in tasks), default=0.0),
            ),
            columns,
        ),
        fit_line(
            (
                f"Phase counts: queued={pending} run={running} "
                f"heal={healing} verify={verifying}"
            ),
            columns,
        ),
        "",
    ]

    name_width = max((len(task.repo) for task in tasks), default=10)
    status_width = 6
    elapsed_width = 7
    prefix_width = 2 + name_width + 2 + status_width + 2 + elapsed_width + 2
    message_width = max(20, columns - prefix_width)

    for task in tasks:
        message = truncate(task.last_line or task.status, message_width)
        lines.append(
            fit_line(
                (
                    f"{indicator_for_task(task, tick, interactive)} {task.repo:<{name_width}}  "
                    f"{status_label_for_task(task):<{status_width}}  {format_phase_elapsed(task, now):>{elapsed_width}}  "
                    f"{message}"
                ),
                columns,
            )
        )

    return lines


def print_failure_summary(tasks: list[TaskState]) -> None:
    failed_tasks = [task for task in tasks if task.status == "failed"]
    if not failed_tasks:
        return

    print("\nFailures:", flush=True)
    for task in failed_tasks:
        print(f"- {task.repo} (exit {task.returncode})", flush=True)
        tail = collect_failure_tail(task)
        for line in tail:
            print(f"    {line}", flush=True)
        if task.heal_returncode is not None:
            print(f"    self-heal exit {task.heal_returncode}", flush=True)
        heal_tail = list(task.heal_output_tail)
        for line in heal_tail:
            print(f"    [heal] {line}", flush=True)


def print_auto_heal_summary(tasks: list[TaskState]) -> None:
    healed_tasks = [task for task in tasks if task.self_healed]
    if not healed_tasks:
        return

    print("\nAuto-healed:", flush=True)
    for task in healed_tasks:
        print(f"- {task.repo}", flush=True)


def main() -> int:
    args = parse_args()
    group_keys = resolve_batch_group_keys(args.group)
    repos = discover_repos(group_keys, args.match, args.repo)
    if not repos:
        print(
            f"No matching image build directories found in groups: {', '.join(group_keys)}.",
            file=sys.stderr,
        )
        return 1

    if args.dry_run:
        print(f"Target: make {' '.join(args.make_args)}")
        print(f"Repositories: {len(repos)}")
        for repo in repos:
            print(f"- {repo.name}")
        return 0

    tasks = [TaskState(repo=repo.name, path=repo) for repo in repos]
    max_workers = args.jobs or len(tasks)
    semaphore = threading.Semaphore(max_workers)
    plain_mode = args.plain or not sys.stdout.isatty()
    tracker = ProgressTracker(tasks, args.make_args)

    threads = [
        threading.Thread(
            target=run_task,
            args=(task, args.make_args, semaphore, plain_mode),
            daemon=True,
        )
        for task in tasks
    ]

    for thread in threads:
        thread.start()

    try:
        if not plain_mode:
            while any(thread.is_alive() for thread in threads):
                tracker.render()
                time.sleep(0.1)
            tracker.render()
            print_failure_summary(tasks)
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        terminate_running(tasks)
        for thread in threads:
            thread.join(timeout=1)
        print("\nInterrupted.", file=sys.stderr)
        return 130
    finally:
        with suppress(Exception):
            tracker.finish_render()

    failed = [task for task in tasks if task.status == "failed"]
    if plain_mode:
        completed = sum(task.status in {"success", "failed"} for task in tasks)
        success = sum(task.status == "success" for task in tasks)
        healed = sum(task.self_healed for task in tasks)
        print(
            (
                f"Summary: {completed}/{len(tasks)} done, "
                f"{success} succeeded, {healed} auto-healed, {len(failed)} failed."
            ),
            flush=True,
        )
        print_auto_heal_summary(tasks)
        print_failure_summary(tasks)
    else:
        print_auto_heal_summary(tasks)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
