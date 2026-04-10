"""文件操作工具"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def read_file(path: str | Path) -> str:
    """读取文本文件，不存在则抛出 FileNotFoundError"""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"文件不存在: {p}")
    return p.read_text(encoding="utf-8")


def write_file(path: str | Path, content: str) -> Path:
    """写入文本文件，自动创建父目录"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def read_json(path: str | Path) -> Any:
    """读取 JSON 文件"""
    return json.loads(read_file(path))


def write_json(path: str | Path, data: Any, indent: int = 2) -> Path:
    """写入 JSON 文件"""
    return write_file(path, json.dumps(data, ensure_ascii=False, indent=indent))


def list_dir_files(dir_path: str | Path, suffix: str = ".md") -> list[str]:
    """
    列出目录下指定后缀的文件名列表（不含路径，按名排序）
    """
    p = Path(dir_path)
    if not p.is_dir():
        return []
    return sorted(f.name for f in p.iterdir() if f.is_file() and f.suffix == suffix)


def ensure_dirs(*dirs: str | Path) -> None:
    """确保多个目录存在"""
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)


def copy_file(src: str | Path, dst: str | Path) -> Path:
    """复制文件"""
    import shutil
    dst_path = Path(dst)
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(src), str(dst))
    return dst_path
