#!/usr/bin/env python3
import re
import sys
from pathlib import Path


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


def main():
    if len(sys.argv) != 2:
        print("用法: python3 extract_report_info.py <report.md>", file=sys.stderr)
        return 1

    report = Path(sys.argv[1])
    if not report.is_file():
        print(f"文件不存在: {report}", file=sys.stderr)
        return 1

    content = report.read_text(encoding="utf-8")
    sections = extract_sections(content)
    if not sections:
        print("未找到漏洞条目，预期标题格式为: ### [VUL-001] 标题", file=sys.stderr)
        return 2

    for item in sections:
        print(f"{item['id']}: {item['title']}")
        for field_name, aliases in FIELDS:
            value = extract_field(item["body"], aliases)
            if value:
                one_line = value.replace("\n", " ").strip()
                print(f"  {field_name}: {one_line}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
