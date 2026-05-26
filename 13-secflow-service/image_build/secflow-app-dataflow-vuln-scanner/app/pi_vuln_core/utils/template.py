"""Prompt 模板渲染工具"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable, Mapping

from jinja2 import Environment, BaseLoader, StrictUndefined, TemplateError

from app.pi_vuln_core.utils.file_ops import read_file

# Jinja2 环境，使用严格模式（未定义变量报错）
_jinja_env = Environment(loader=BaseLoader(), undefined=StrictUndefined)
_SIMPLE_PLACEHOLDER_RE = re.compile(r"(?<!{){([A-Za-z_][A-Za-z0-9_]*)}(?!})")


class TemplateRenderError(ValueError):
    """Raised when a prompt template cannot be rendered safely."""
    pass


def render_template(
    template_path: str | Path,
    *,
    strict: bool = False,
    **kwargs: Any,
) -> str:
    """
    读取模板文件并渲染变量

    支持两种变量风格：
    - Jinja2: {{ variable }}
    - 简单替换: {variable}（兼容 JSON 配置中的模板）
    """
    raw = read_file(template_path)
    return render_string(raw, strict=strict, **kwargs)


def render_string(
    template_str: str,
    *,
    strict: bool = False,
    **kwargs: Any,
) -> str:
    """渲染模板字符串"""
    # 先尝试 Jinja2 风格
    if "{{" in template_str or "{%" in template_str:
        try:
            tmpl = _jinja_env.from_string(template_str)
            return tmpl.render(**kwargs)
        except TemplateError as exc:
            raise TemplateRenderError(f"Jinja template render failed: {exc}") from exc

    # 退回到 str.format 风格（只替换存在的 key）
    if strict:
        _raise_if_missing_template_vars(template_str, kwargs)
    result = template_str
    for key, value in kwargs.items():
        result = result.replace(f"{{{key}}}", str(value))
    return result


def unresolved_placeholders(rendered_text: str) -> list[str]:
    """Return unresolved simple ``{name}`` placeholders left in rendered text."""
    found = []
    for match in _SIMPLE_PLACEHOLDER_RE.finditer(rendered_text or ""):
        name = match.group(1)
        if name not in found:
            found.append(name)
    return found


def referenced_placeholders(template_str: str) -> list[str]:
    """Return simple ``{name}`` placeholders referenced by a template string."""
    if "{{" in (template_str or "") or "{%" in (template_str or ""):
        return []
    return unresolved_placeholders(template_str)


def collect_template_kwargs(
    template_str: str,
    *,
    values: Mapping[str, Any] | None = None,
    value_factories: Mapping[str, Callable[[], Any]] | None = None,
) -> dict[str, Any]:
    """Collect only the kwargs actually referenced by the template.

    For simple ``{name}`` templates, unused kwargs are dropped and lazy factories are
    only evaluated when the placeholder is present. For Jinja templates we conservatively
    materialize every provided value/factory because placeholder introspection would be
    incomplete.
    """
    if "{{" in (template_str or "") or "{%" in (template_str or ""):
        collected = dict(values or {})
        for key, factory in (value_factories or {}).items():
            collected[key] = factory()
        return collected

    required = set(referenced_placeholders(template_str))
    collected: dict[str, Any] = {}
    for key, value in (values or {}).items():
        if key in required:
            collected[key] = value
    for key, factory in (value_factories or {}).items():
        if key in required:
            collected[key] = factory()
    return collected


def _raise_if_unresolved(rendered_text: str) -> None:
    unresolved = unresolved_placeholders(rendered_text)
    if unresolved:
        raise TemplateRenderError(
            "Prompt template contains unresolved placeholders: "
            + ", ".join(f"{{{name}}}" for name in unresolved)
        )


def _raise_if_missing_template_vars(
    template_str: str,
    kwargs: dict[str, Any],
) -> None:
    placeholders = unresolved_placeholders(template_str)
    missing = [name for name in placeholders if name not in kwargs]
    if missing:
        raise TemplateRenderError(
            "Prompt template references variables that were not provided: "
            + ", ".join(f"{{{name}}}" for name in missing)
        )


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
