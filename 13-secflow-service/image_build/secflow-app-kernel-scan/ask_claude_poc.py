#!/usr/bin/env python3
"""
遍历 ./AI4Vul 下所有报告，提取每份报告里的 VUL 问题单，
对每个问题单调用 claude CLI 处理一次。已处理项写入
vullist 文件，下次运行时自动跳过，可断点续跑。
客户端运行：ssh -N -R 15037:127.0.0.1:5037 icsl@172.31.30.81
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path
import re

REPORT_DIR = Path("AI4Vul")
VULLIST = Path("vullist")

FIELDS = [
    ("类型", ["类型"]),
    ("严重程度", ["严重程度"]),
    ("位置", ["位置"]),
    ("描述", ["描述"]),
    ("利用场景", ["利用场景"]),
    ("攻击路径", ["攻击路径", "攻击路径分析"]),
    ("参考", ["参考"]),
]



def clean(text: str) -> str:
    text = text.strip()
    text = re.sub(r"\r\n?", "\n", text)
    return text


def extract_sections(content: str):
    pattern = re.compile(r"^###\s+\[(VUL-\d+)\]\s+(.+)$", re.MULTILINE)
    matches = list(pattern.finditer(content))
    sections = []
    for idx, match in enumerate(matches):
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(content)
        sections.append(
            {
                "id": match.group(1).strip(),
                "title": match.group(2).strip(),
                "body": content[start:end].strip(),
            }
        )
    return sections


def extract_field(body: str, aliases):
    for alias in aliases:
        pattern = re.compile(
            rf"^\s*-\s*\*\*{re.escape(alias)}\*\*:\s*(.*?)(?=^\s*-\s*\*\*|\Z)",
            re.MULTILINE | re.DOTALL,
        )
        match = pattern.search(body)
        if match:
            return clean(match.group(1))
    return ""


def make_key(report: Path, vul_id: str) -> str:
    return f"{report.name}::{vul_id}"


def safe_path_component(value: str) -> str:
    cleaned = re.sub(r"[^\w.-]+", "_", value.strip(), flags=re.UNICODE).strip("._")
    return cleaned[:120] or "item"


def vulnerability_output_dir(output_root: Path, report: Path, vul_id: str) -> Path:
    return output_root / safe_path_component(report.stem) / safe_path_component(vul_id)


def write_vulnerability_context(vul_dir: Path, key: str, title: str, body: str) -> None:
    vul_dir.mkdir(parents=True, exist_ok=True)
    (vul_dir / "vulnerability.md").write_text(
        f"# {key}\n\n## 标题\n{title}\n\n## 原始漏洞内容\n{body}\n",
        encoding="utf-8",
    )


def load_vullist(path: Path) -> dict[str, tuple[str, str, str]]:
    """Return {key: (result, is_panic, reason)}."""
    state: dict[str, tuple[str, str, str]] = {}
    if not path.exists():
        return state
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        reason = ""
        quote_start = line.find("'")
        if quote_start >= 0:
            quote_end = line.rfind("'")
            if quote_end > quote_start:
                reason = line[quote_start + 1:quote_end]
            line = line[:quote_start].rstrip()
        parts = line.rsplit(None, 2)
        if len(parts) == 3:
            state[parts[0]] = (parts[1], parts[2], reason)
        elif len(parts) == 2:
            state[parts[0]] = (parts[1], "", reason)
        else:
            state[line] = ("", "", reason)
    return state


def save_vullist(path: Path, state: dict[str, tuple[str, str, str]]) -> None:
    lines = []
    for key in sorted(state):
        result, is_panic, reason = state[key]
        entry = f"{key} {result}"
        if is_panic:
            entry += f" {is_panic}"
        if reason:
            entry += f" '{reason}'"
        lines.append(entry.rstrip())
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_prompt(
    report: Path,
    vul_id: str,
    title: str,
    body: str,
    kernel_dir: str | None = None,
    device_ip: str | None = None,
    vul_dir: Path | None = None,
) -> str:
    fields_text = []
    for name, aliases in FIELDS:
        value = extract_field(body, aliases)
        if value:
            fields_text.append(f"- {name}: {value}")
    kernel_line = f"## 内核源码目录：\n{kernel_dir}\n\n" if kernel_dir else ""
    device_line = ""
    if device_ip:
        device_line = (
            "## 目标设备：\n"
            f"ADB serial: {device_ip}\n"
            "stage_poc 已在任务开始前设置 ADB_SERVER_SOCKET 和 ANDROID_SERIAL，请使用该已连接设备进行验证。\n\n"
        )
    output_line = ""
    if vul_dir:
        output_line = (
            "把本漏洞的所有 PoC 、最终验证报告都保存到{vul_dir}目录下；"
            "不要写入其它漏洞目录。建议最终验证报告命名为 verification_report.md，PoC 源码或脚本放在 poc/ 子目录或该目录内。\n\n"
        )

    return (
        f"加载poc-verification，在安卓手机上调试，验证漏洞是否真实存在。\n"
        f"{kernel_line}"
        f"{device_line}"
        f"{output_line}"
        f"## 漏洞内容：\n{body}\n\n"
        f"请严格以 JSON 格式返回结果，不要输出任何其他内容。JSON 格式如下:\n"
        f'{{"isvul": "yes或no或nofeature", "is_panic": "panic或no_panic", "reason": "简要理由(一句话)"}}\n\n'
        f"判断标准: 1) 漏洞是否真实存在; 2) 触达条件是否成立; \n"
        f"如果漏洞真实存在且可触达，isvul 为 yes，poc验证证明不存在则为 no。如果特性在手机上没开无法证明，则为nofeature。\n"
        f"is_panic: 如果验证过程中设备发生了 kernel panic / oops / crash，填 panic；否则填 no_panic。\n"
    )


def parse_isvul(output: str) -> tuple[str, str, str]:
    """从 claude 返回中提取 isvul、is_panic 和 reason。"""
    text = output.strip()
    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        try:
            data = json.loads(text[start:end])
            val = data.get("isvul", "").strip().lower()
            is_panic = data.get("is_panic", "no_panic").strip().lower()
            reason = data.get("reason", "").strip()
            if is_panic not in ("panic", "no_panic"):
                is_panic = "no_panic"
            if val in ("yes", "no", "nofeature"):
                return val, is_panic, reason
        except (json.JSONDecodeError, AttributeError):
            pass
    if "yes" in text.lower()[:50]:
        return "yes", "no_panic", ""
    if "nofeature" in text.lower()[:80]:
        return "nofeature", "no_panic", ""
    if "no" in text.lower()[:50]:
        return "no", "no_panic", ""
    return "unknown", "no_panic", ""


def run_claude(prompt: str, timeout: int, model: str) -> tuple[str, bool]:
    last_output = ""
    for attempt in range(1, 3):
        try:
            proc = subprocess.run(
                ["claude", "--dangerously-skip-permissions", "--model", model, "-p", prompt],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            last_output = exc.stdout or ""
            if isinstance(last_output, bytes):
                last_output = last_output.decode("utf-8", errors="replace")
            print(f"  claude 超时: attempt {attempt}/2")
            if attempt == 2:
                return last_output, False
            continue
        except FileNotFoundError:
            print("未找到 claude CLI，请确认已安装并加入 PATH。", file=sys.stderr)
            sys.exit(2)

        last_output = proc.stdout or ""
        if proc.returncode == 0:
            return last_output, True

        print(f"  claude 失败: attempt {attempt}/2: {proc.stderr.strip()[:300]}")
        if attempt == 2:
            return last_output, False

    return last_output, False


def iter_reports(report_dir: Path):
    for path in sorted(report_dir.glob("*.md")):
        if path.name.startswith("."):
            continue
        if path.suffix.lower() != ".md":
            continue
        if not path.is_file():
            continue
        yield path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path, default=REPORT_DIR)
    parser.add_argument("--vullist", type=Path, default=VULLIST)

    parser.add_argument("--dry-run", action="store_true",
                        help="只打印将要处理的条目，不调用 claude")
    parser.add_argument("--timeout", type=int, default=600,
                        help="单次 claude 调用超时秒数")
    parser.add_argument("--output-dir", type=Path, default=Path("AI4Vul/vul_results"),
                        help="每个漏洞独立输出目录的根目录")
    parser.add_argument("--model", default="zai-org/GLM-5")
    parser.add_argument("--kernel-dir", default=None, help="内核源码目录，用于 PoC 验证提示")
    parser.add_argument("--device-ip", default=None, help="已连接的 adb 目标设备 serial，例如 emulator-5554")
    parser.add_argument("--results-json", type=Path, default=None,
                        help="可选：结构化 poc 结果 JSON 输出路径")
    args = parser.parse_args()

    if not args.report_dir.is_dir():
        print(f"目录不存在: {args.report_dir}", file=sys.stderr)
        return 1

    state = load_vullist(args.vullist)
    if not args.dry_run:
        args.output_dir.mkdir(parents=True, exist_ok=True)

    total = done = failed = skipped = 0

    for report in iter_reports(args.report_dir):
        try:
            content = report.read_text(encoding="utf-8")
        except OSError as e:
            print(f"读取失败 {report}: {e}")
            continue
        sections = extract_sections(content)
        if not sections:
            key = make_key(report, "NO_VUL")
            if key not in state:
                state[key] = ("failed", "", "no VUL sections found")
                save_vullist(args.vullist, state)
                print(f"  {report.name}: 未提取到 VUL 条目，标记 failed")
            continue

        for sec in sections:
            total += 1
            key = make_key(report, sec["id"])
            result, _, _ = state.get(key, ("", "", ""))
            vul_dir = vulnerability_output_dir(args.output_dir, report, sec["id"])

            print(f"[{total}] {key}  {sec['title'][:60]}")
            if args.dry_run:
                print(f"  output dir: {vul_dir}")
                continue
            try:
                write_vulnerability_context(vul_dir, key, sec["title"], sec["body"])
            except OSError as e:
                print(f"  准备漏洞目录失败: {e}")
                state[key] = ("failed", "", "failed to prepare vulnerability output dir")
                failed += 1
                save_vullist(args.vullist, state)
                continue

            if result == "no":
                skipped += 1
                continue
            if result == "nofeature":
                skipped += 1
                continue

            print("skipped " + str(skipped) + ", done " + str(done) + ", failed " + str(failed))
            prompt = build_prompt(
                report,
                sec["id"],
                sec["title"],
                sec["body"],
                args.kernel_dir,
                args.device_ip,
                vul_dir,
            )
            output, ok = run_claude(prompt, args.timeout, args.model)

            if ok:
                isvul, is_panic, reason = parse_isvul(output)
                state[key] = (isvul, is_panic, reason)
                print(f"  -> {sec['id']} {isvul} {is_panic} '{reason}'")
                done += 1
            else:
                state[key] = ("failed", "", "claude call failed")
                failed += 1

            out_file = vul_dir / "claude_response.md"
            try:
                out_file.write_text(
                    f"# {key}\n\n## 标题\n{sec['title']}\n\n## Claude 回复\n{output}\n",
                    encoding="utf-8",
                )
            except OSError as e:
                print(f"  保存输出失败: {e}")

            save_vullist(args.vullist, state)

    print(f"\n汇总: 共 {total} 条, 本轮完成 {done}, 失败 {failed}, 跳过 {skipped}")

    if args.results_json is not None:
        try:
            args.results_json.parent.mkdir(parents=True, exist_ok=True)
            results_payload = []
            for key, (result, is_panic, reason) in state.items():
                report_name, _, vul_id = key.partition("::")
                report_stem = Path(report_name).stem if report_name else ""
                output_dir = ""
                if report_stem and vul_id and vul_id != "NO_VUL":
                    output_dir = str(args.output_dir / safe_path_component(report_stem) / safe_path_component(vul_id))
                results_payload.append({
                    "report": report_name,
                    "vul_id": vul_id,
                    "isvul": result,
                    "is_panic": is_panic,
                    "reason": reason,
                    "output_dir": output_dir,
                })
            args.results_json.write_text(
                json.dumps({"results": results_payload}, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        except OSError as e:
            print(f"写入 results-json 失败: {e}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
