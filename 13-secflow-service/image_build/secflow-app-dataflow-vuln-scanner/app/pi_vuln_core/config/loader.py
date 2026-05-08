"""
配置加载器 + 校验器

职责：
1. 加载 JSON 文件
2. 解析环境变量引用 (${VAR})
3. 通过 Pydantic 模型校验
4. 校验引用完整性（agent_id, plugin_id, workflow_ref 是否存在）
5. 校验无循环引用
"""

from __future__ import annotations

import json
import re
import os
from pathlib import Path
from typing import Any

from app.pi_vuln_core.config.models import (
    FrameworkConfig, AtomicWorkflowDef, CompositeWorkflowDef,
)
from app.pi_vuln_core.utils.logger import get_logger
from app.pi_vuln_core.utils.win_compat import from_msys_path

PROJECT_ROOT = Path(__file__).resolve().parents[3]

logger = get_logger("config")

GLOBAL_REVIEW_SCORE_KEYS = {
    "input_coverage",
    "export_followthrough",
    "used_coverage",
    "vuln_pattern_breadth",
    "code_evidence_depth",
    "limitations_honesty",
    "report_completeness",
}


class ConfigValidationError(Exception):
    """配置校验错误"""
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(f"配置校验失败 ({len(errors)} 个错误):\n" +
                         "\n".join(f"  - {e}" for e in errors))


class ConfigLoader:
    """配置加载器"""

    @staticmethod
    def load(config_path: str | Path) -> FrameworkConfig:
        """
        加载并校验 JSON 配置文件

        流程: 读取 → 环境变量替换 → Pydantic 解析 → 引用完整性校验
        """
        path = Path(from_msys_path(config_path) or config_path)
        if not path.exists():
            raise FileNotFoundError(f"配置文件不存在: {path}")

        logger.info("loading_config", path=str(path))

        # 1. 读取 JSON
        raw_text = path.read_text(encoding="utf-8")

        # 2. 替换环境变量引用
        resolved_text = ConfigLoader._resolve_env_vars(raw_text)

        # 3. 解析 JSON
        try:
            raw_data = json.loads(resolved_text)
        except json.JSONDecodeError as e:
            raise ConfigValidationError([f"JSON 解析失败: {e}"])

        # 3.1 解析相对 prompt 路径（相对于配置文件目录）
        ConfigLoader._resolve_prompt_paths(raw_data, base_dir=path.parent)
        # 3.2 Windows/Git Bash: 兜底转换 JSON 中的 /c/... 路径
        ConfigLoader._normalize_windows_paths(raw_data)

        # 4. Pydantic 模型校验
        try:
            config = FrameworkConfig.model_validate(raw_data)
        except Exception as e:
            raise ConfigValidationError([f"配置模型校验失败: {e}"])

        # 5. 引用完整性校验
        ConfigLoader._validate_references(config)

        logger.info("config_loaded",
                     agents=len(config.agents),
                     plugins=len(config.plugins),
                     atomic_workflows=len(config.workflows.atomic),
                     composite_workflows=len(config.workflows.composite))

        return config

    @staticmethod
    def _resolve_env_vars(text: str) -> str:
        """替换 ${VAR_NAME} 为环境变量值"""
        def _replace(match: re.Match) -> str:
            var_name = match.group(1)
            value = os.environ.get(var_name)
            if value is None:
                logger.warning("env_var_not_found", var=var_name)
                return match.group(0)  # 保留原样
            return value
        return re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', _replace, text)

    @staticmethod
    def _resolve_prompt_paths(obj: Any, *, base_dir: Path) -> None:
        prompt_keys = {
            "system_prompt_file", "user_prompt_file",
            "rework_prompt_file", "user_prompt_template", "prompt_file",
        }
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in prompt_keys and isinstance(value, str) and not os.path.isabs(value):
                    config_relative = (base_dir / value).resolve()
                    project_relative = (PROJECT_ROOT / value).resolve()
                    if config_relative.exists() or not project_relative.exists():
                        obj[key] = str(config_relative)
                    else:
                        obj[key] = str(project_relative)
                else:
                    ConfigLoader._resolve_prompt_paths(value, base_dir=base_dir)
        elif isinstance(obj, list):
            for item in obj:
                ConfigLoader._resolve_prompt_paths(item, base_dir=base_dir)

    @staticmethod
    def _normalize_windows_paths(obj: Any) -> None:
        """转换 JSON 配置中的 Git Bash/MSYS 路径。

        Git Bash 只会自动转换命令行参数，不会转换配置文件内容；
        Windows 下把 `/c/Users/...` 这类路径转换成 `C:/Users/...`。
        """
        path_keys = {
            "workspace_root",
            "task_file",
            "output_dir",
            "summary_file",
            "system_prompt_file",
            "user_prompt_file",
            "rework_prompt_file",
            "user_prompt_template",
            "prompt_file",
            "env_file",
        }
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in path_keys and isinstance(value, str):
                    obj[key] = from_msys_path(value) or value
                else:
                    ConfigLoader._normalize_windows_paths(value)
        elif isinstance(obj, list):
            for item in obj:
                ConfigLoader._normalize_windows_paths(item)

    @staticmethod
    def _validate_references(config: FrameworkConfig) -> None:
        """
        校验所有引用的完整性

        - agent_id 必须存在
        - plugin_id 必须存在
        - workflow_ref 必须存在
        - 无循环引用
        - 入口工作流必须存在
        """
        errors: list[str] = []

        # 构建 ID 集合
        agent_ids = {a.id for a in config.agents}
        plugin_ids = {p.id for p in config.plugins}
        atomic_ids = {w.id for w in config.workflows.atomic}
        composite_ids = {w.id for w in config.workflows.composite}
        all_workflow_ids = atomic_ids | composite_ids

        # 校验原子工作流引用
        for wf in config.workflows.atomic:
            # Worker agent_id
            if wf.roles.worker.agent_id not in agent_ids:
                errors.append(
                    f"原子工作流 '{wf.id}' 的 worker.agent_id "
                    f"'{wf.roles.worker.agent_id}' 不存在于 agents 定义中")

            # Advisor agent_id
            for advisor in (wf.roles.advisors.global_review +
                            wf.roles.advisors.result_review):
                if advisor.agent_id not in agent_ids:
                    errors.append(
                        f"原子工作流 '{wf.id}' 的 advisor "
                        f"'{advisor.instance_id}' 引用的 agent_id "
                        f"'{advisor.agent_id}' 不存在于 agents 定义中")

            for advisor in wf.roles.advisors.global_review:
                errors.extend(ConfigLoader._validate_global_review_score_contract(wf.id, advisor))

            # Plugin IDs
            for pid in wf.start_plugins + wf.end_plugins:
                if pid not in plugin_ids:
                    errors.append(
                        f"原子工作流 '{wf.id}' 引用的 plugin '{pid}' "
                        f"不存在于 plugins 定义中")

        # 校验组合工作流引用
        for cwf in config.workflows.composite:
            for stage in cwf.stages:
                if stage.workflow_ref not in all_workflow_ids:
                    errors.append(
                        f"组合工作流 '{cwf.id}' 的 stage "
                        f"'{stage.stage_id}' 引用的 workflow_ref "
                        f"'{stage.workflow_ref}' 不存在")
                # 类型匹配检查
                if stage.workflow_type == "atomic" and stage.workflow_ref not in atomic_ids:
                    if stage.workflow_ref in composite_ids:
                        errors.append(
                            f"stage '{stage.stage_id}' 声明 workflow_type='atomic',"
                            f" 但 '{stage.workflow_ref}' 是 composite 工作流")
                elif stage.workflow_type == "composite" and stage.workflow_ref not in composite_ids:
                    if stage.workflow_ref in atomic_ids:
                        errors.append(
                            f"stage '{stage.stage_id}' 声明 workflow_type='composite',"
                            f" 但 '{stage.workflow_ref}' 是 atomic 工作流")

        # 校验入口工作流
        entry = config.execution.entry_workflow
        if entry not in composite_ids:
            errors.append(
                f"执行入口 '{entry}' 不存在于 composite 工作流中 (R11)")

        # 校验循环引用
        cycle_errors = ConfigLoader._check_circular_refs(config)
        errors.extend(cycle_errors)

        if errors:
            raise ConfigValidationError(errors)

    @staticmethod
    def _validate_global_review_score_contract(wf_id: str, advisor) -> list[str]:
        errors: list[str] = []
        prefix = f"原子工作流 '{wf_id}' 的 global_review advisor '{advisor.instance_id}'"
        score_fields = [str(item).strip() for item in advisor.score_fields if str(item).strip()]
        if not score_fields:
            return [f"{prefix} 必须显式配置 score_fields"]

        duplicated = sorted({item for item in score_fields if score_fields.count(item) > 1})
        if duplicated:
            errors.append(f"{prefix} 的 score_fields 存在重复字段: {', '.join(duplicated)}")

        unknown = sorted(set(score_fields) - GLOBAL_REVIEW_SCORE_KEYS)
        if unknown:
            errors.append(f"{prefix} 的 score_fields 包含未知字段: {', '.join(unknown)}")

        final_thresholds = advisor.score_thresholds or {}
        start_thresholds = advisor.score_thresholds_start or final_thresholds
        missing_final = [key for key in score_fields if key not in final_thresholds]
        if missing_final:
            errors.append(f"{prefix} 的 score_thresholds 缺少字段: {', '.join(missing_final)}")
        extra_final = sorted(set(final_thresholds) - set(score_fields))
        if extra_final:
            errors.append(f"{prefix} 的 score_thresholds 包含非本角色字段: {', '.join(extra_final)}")
        extra_start = sorted(set(start_thresholds) - set(score_fields))
        if extra_start:
            errors.append(f"{prefix} 的 score_thresholds_start 包含非本角色字段: {', '.join(extra_start)}")

        for label, thresholds in (
            ("score_thresholds", final_thresholds),
            ("score_thresholds_start", start_thresholds),
        ):
            for key, value in thresholds.items():
                try:
                    numeric = float(value)
                except (TypeError, ValueError):
                    errors.append(f"{prefix} 的 {label}.{key} 必须是 0.0-1.0 数值")
                    continue
                if numeric < 0.0 or numeric > 1.0:
                    errors.append(f"{prefix} 的 {label}.{key} 超出 0.0-1.0 范围")

        for key in score_fields:
            if key not in final_thresholds or key not in start_thresholds:
                continue
            try:
                start_value = float(start_thresholds[key])
                final_value = float(final_thresholds[key])
            except (TypeError, ValueError):
                continue
            if start_value > final_value:
                errors.append(
                    f"{prefix} 的 score_thresholds_start.{key} 不能高于最终阈值 {final_value:.2f}"
                )

        return errors

    @staticmethod
    def _check_circular_refs(config: FrameworkConfig) -> list[str]:
        """检测组合工作流之间的循环引用"""
        errors = []
        # 构建引用图: composite_id → set of referenced composite_ids
        graph: dict[str, set[str]] = {}
        composite_ids = {w.id for w in config.workflows.composite}

        for cwf in config.workflows.composite:
            refs = set()
            for stage in cwf.stages:
                if stage.workflow_type == "composite":
                    refs.add(stage.workflow_ref)
            graph[cwf.id] = refs

        # DFS 检测环
        visited: set[str] = set()
        in_stack: set[str] = set()

        def _dfs(node: str, path: list[str]) -> None:
            if node in in_stack:
                cycle = " → ".join(path[path.index(node):] + [node])
                errors.append(f"检测到循环引用: {cycle}")
                return
            if node in visited:
                return
            visited.add(node)
            in_stack.add(node)
            path.append(node)
            for neighbor in graph.get(node, set()):
                _dfs(neighbor, path)
            path.pop()
            in_stack.discard(node)

        for cid in composite_ids:
            if cid not in visited:
                _dfs(cid, [])

        return errors
