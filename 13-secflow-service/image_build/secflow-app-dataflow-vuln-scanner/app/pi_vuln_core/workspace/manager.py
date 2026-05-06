"""
工作目录管理器

职责：
- 创建组合工作流/阶段/原子工作流的目录结构
- 按组合关系形成嵌套 (R6j)
- 创建标准子目录 (input/working/results/reviews/plugins/output)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("workspace")

# 原子工作流标准子目录
ATOMIC_SUBDIRS = [
    "_meta",
    "input",
    "working",
    "results",
    "reviews/global",
    "reviews/results",
    "plugins/start",
    "plugins/end",
    "output",
]


class WorkspaceManager:
    """
    工作目录管理器 (R6j)

    目录层级：
    {root}/{composite_dir}/{stage_id}/{task_dir}/
        ├── _meta/
        ├── input/
        ├── working/
        ├── results/
        ├── reviews/{global,results}/
        ├── plugins/{start,end}/
        └── output/
    """

    def __init__(self, root: str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        logger.info("workspace_initialized", root=str(self.root))

    def create_composite_dir(
        self,
        template: str,
        parent_dir: Optional[str | Path] = None,
        **kwargs,
    ) -> str:
        """创建组合工作流目录"""
        dir_name = template.format(**kwargs)
        base = Path(parent_dir) if parent_dir else self.root
        path = base / dir_name
        path.mkdir(parents=True, exist_ok=True)
        (path / "_meta").mkdir(exist_ok=True)
        logger.debug("composite_dir_created", path=str(path))
        return str(path)

    def create_stage_dir(self, composite_dir: str, stage_id: str) -> str:
        """创建阶段目录"""
        path = Path(composite_dir) / stage_id
        path.mkdir(parents=True, exist_ok=True)
        (path / "_meta").mkdir(exist_ok=True)
        logger.debug("stage_dir_created", path=str(path))
        return str(path)

    def create_atomic_dir(
        self,
        template: str,
        task_id: str,
        parent_dir: Optional[str] = None,
    ) -> str:
        """
        创建原子工作流工作目录 + 标准子目录

        Args:
            template:    目录名模板，支持 {task_id}
            task_id:     任务ID
            parent_dir:  父目录（阶段目录），None则在root下创建

        Returns:
            工作目录绝对路径
        """
        dir_name = template.format(task_id=task_id)
        base = Path(parent_dir) if parent_dir else self.root
        path = base / dir_name

        for subdir in ATOMIC_SUBDIRS:
            (path / subdir).mkdir(parents=True, exist_ok=True)

        logger.debug("atomic_dir_created", path=str(path), task_id=task_id)
        return str(path)

    def get_review_dir(self, work_dir: str, review_type: str,
                        cycle: int, target: str = "") -> str:
        """
        获取评审记录目录

        Args:
            work_dir:    原子工作流工作目录
            review_type: "global" | "results"
            cycle:       循环轮次
            target:      结果评审时的目标文件名（如 "result_001"）
        """
        if review_type == "global":
            path = Path(work_dir) / "reviews" / "global" / f"cycle_{cycle:03d}"
        else:
            path = Path(work_dir) / "reviews" / "results" / target / f"cycle_{cycle:03d}"
        path.mkdir(parents=True, exist_ok=True)
        return str(path)

    def get_plugin_record_dir(self, work_dir: str, phase: str) -> str:
        """获取插件记录目录"""
        path = Path(work_dir) / "plugins" / phase
        path.mkdir(parents=True, exist_ok=True)
        return str(path)
