"""
Workspace 管理模块

职责:
  - 创建 evolution session 目录结构
  - 管理 agent 目录（skills/ + memory/）
  - 保存/加载会话状态
  - 轮次目录管理
"""

from __future__ import annotations

import json
import shutil
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from core.preprocess import SourceTask

TZ_SHANGHAI = timezone(timedelta(hours=8))


def _now() -> str:
    return datetime.now(TZ_SHANGHAI).isoformat(timespec="seconds")


class Workspace:
    """
    管理一个 evolution session 的文件系统布局。

    布局:
      {base}/agent-state/evolution/{session_id}/
      ├── session.json
      ├── source_tasks.json
      ├── agents/{agent_id}/skills/
      ├── agents/{agent_id}/memory/
      └── rounds/round_{N}/
    """

    def __init__(
        self,
        config: dict[str, Any],
        project_id: str,
        source_tasks: list[SourceTask],
        session_id: str | None = None,
    ) -> None:
        self.project_id = project_id
        self.source_tasks = source_tasks
        self.session_id = session_id or f"evol-{uuid.uuid4().hex[:12]}"

        data_mount = config["workspace"]["data_mount_path"]
        files_dir = config["workspace"]["project_files_dirname"]
        subproject = config["workspace"]["dataflow_subproject_name"]

        self.root = (
            Path(data_mount)
            / files_dir
            / project_id
            / subproject
            / "agent-state"
            / "evolution"
            / self.session_id
        )
        self._current_round = 0

    @property
    def current_round(self) -> int:
        return self._current_round

    @property
    def agents_dir(self) -> Path:
        return self.root / "agents"

    def create(self, evolution_goal: str) -> None:
        """创建 workspace 目录结构并写入初始状态。"""
        self.root.mkdir(parents=True, exist_ok=True)
        self.agents_dir.mkdir(parents=True, exist_ok=True)
        (self.root / "rounds").mkdir(parents=True, exist_ok=True)

        # 初始化每个 agent 的 evolution 目录
        for source_task in self.source_tasks:
            for agent_id, dirs in source_task.agent_state_dirs.items():
                agent_dir = self.agents_dir / agent_id
                skills_dir = agent_dir / "skills"
                memory_dir = agent_dir / "memory"
                skills_dir.mkdir(parents=True, exist_ok=True)
                memory_dir.mkdir(parents=True, exist_ok=True)

                # 从原始 agent 目录复制已有内容
                source_root = dirs.get("root_dir", "")
                if source_root and Path(source_root).is_dir():
                    src_skills = Path(source_root) / "skills"
                    src_memory = Path(source_root) / "memory"
                    if src_skills.is_dir():
                        shutil.copytree(src_skills, skills_dir, dirs_exist_ok=True)
                    if src_memory.is_dir():
                        shutil.copytree(src_memory, memory_dir, dirs_exist_ok=True)

        # 写入会话元数据
        session_meta = {
            "session_id": self.session_id,
            "project_id": self.project_id,
            "evolution_goal": evolution_goal,
            "current_round": 0,
            "status": "active",
            "created_at": _now(),
            "source_task_ids": [t.task_id for t in self.source_tasks],
        }
        self._write_json(self.root / "session.json", session_meta)

        # 写入原始任务快照
        tasks_snapshot = [
            {
                "task_id": t.task_id,
                "execution_id": t.execution_id,
                "title": t.title,
                "case_ids": t.case_ids,
                "agent_state_dirs": t.agent_state_dirs,
                "task_detail": t.task_detail,
                "case_details": t.case_details,
            }
            for t in self.source_tasks
        ]
        self._write_json(self.root / "source_tasks.json", tasks_snapshot)

    def get_agent_roots(self) -> dict[str, str]:
        """
        返回 {agent_id: evolution_root_dir} 映射。
        用于传给 create-evolution API 的 agent_state_roots。
        """
        roots: dict[str, str] = {}
        if not self.agents_dir.is_dir():
            return roots
        for agent_dir in self.agents_dir.iterdir():
            if agent_dir.is_dir():
                roots[agent_dir.name] = str(agent_dir)
        return roots

    def get_agent_skills_dir(self, agent_id: str) -> Path:
        return self.agents_dir / agent_id / "skills"

    def get_agent_memory_dir(self, agent_id: str) -> Path:
        return self.agents_dir / agent_id / "memory"

    def start_round(self) -> int:
        """开始新一轮，返回轮次号。"""
        self._current_round += 1
        round_dir = self.root / "rounds" / f"round_{self._current_round}"
        round_dir.mkdir(parents=True, exist_ok=True)
        (round_dir / "docs_snapshot").mkdir(exist_ok=True)

        # 快照当前 agent docs
        for agent_dir in self.agents_dir.iterdir():
            if not agent_dir.is_dir():
                continue
            snapshot_dir = round_dir / "docs_snapshot" / agent_dir.name
            snapshot_dir.mkdir(parents=True, exist_ok=True)
            skills_dir = agent_dir / "skills"
            memory_dir = agent_dir / "memory"
            if skills_dir.is_dir():
                shutil.copytree(skills_dir, snapshot_dir / "skills", dirs_exist_ok=True)
            if memory_dir.is_dir():
                shutil.copytree(memory_dir, snapshot_dir / "memory", dirs_exist_ok=True)

        # 更新 session.json
        self._update_session({"current_round": self._current_round})
        return self._current_round

    def save_round_results(self, round_no: int, results: list[dict[str, Any]]) -> None:
        """保存某轮的 replay 结果。"""
        round_dir = self.root / "rounds" / f"round_{round_no}"
        round_dir.mkdir(parents=True, exist_ok=True)
        self._write_json(round_dir / "results.json", results)

    def write_round_memory(self, round_no: int, summary: str) -> None:
        """将本轮结果摘要写入所有 agent 的 memory/ 目录。"""
        for agent_dir in self.agents_dir.iterdir():
            if not agent_dir.is_dir():
                continue
            memory_dir = agent_dir / "memory"
            memory_dir.mkdir(parents=True, exist_ok=True)
            (memory_dir / f"evolution-round-{round_no}.md").write_text(
                summary, encoding="utf-8"
            )

    def finish(self) -> None:
        """标记会话完成。"""
        self._update_session({"status": "completed", "finished_at": _now()})

    def load_session(self) -> dict[str, Any]:
        """加载已有会话状态。"""
        session_path = self.root / "session.json"
        if not session_path.exists():
            return {}
        return json.loads(session_path.read_text(encoding="utf-8"))

    def _update_session(self, updates: dict[str, Any]) -> None:
        session_path = self.root / "session.json"
        data = {}
        if session_path.exists():
            data = json.loads(session_path.read_text(encoding="utf-8"))
        data.update(updates)
        data["updated_at"] = _now()
        self._write_json(session_path, data)

    @staticmethod
    def _write_json(path: Path, data: Any) -> None:
        path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
