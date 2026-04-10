"""Prompt 模板渲染工具"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from jinja2 import Environment, BaseLoader, StrictUndefined

from app.pi_vuln_core.utils.file_ops import read_file

# Jinja2 环境，使用严格模式（未定义变量报错）
_jinja_env = Environment(loader=BaseLoader(), undefined=StrictUndefined)


def render_template(template_path: str | Path, **kwargs: Any) -> str:
    """
    读取模板文件并渲染变量

    支持两种变量风格：
    - Jinja2: {{ variable }}
    - 简单替换: {variable}（兼容 JSON 配置中的模板）
    """
    raw = read_file(template_path)
    return render_string(raw, **kwargs)


def render_string(template_str: str, **kwargs: Any) -> str:
    """渲染模板字符串"""
    # 先尝试 Jinja2 风格
    if "{{" in template_str or "{%" in template_str:
        tmpl = _jinja_env.from_string(template_str)
        return tmpl.render(**kwargs)

    # 退回到 str.format 风格（只替换存在的 key）
    result = template_str
    for key, value in kwargs.items():
        result = result.replace(f"{{{key}}}", str(value))
    return result


def resolve_env_vars(text: str) -> str:
    """
    解析环境变量引用: ${VAR_NAME} → os.environ['VAR_NAME']
    不存在的环境变量保留原样
    """
    import os

    def _replace(match: re.Match) -> str:
        var_name = match.group(1)
        return os.environ.get(var_name, match.group(0))

    return re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', _replace, text)
