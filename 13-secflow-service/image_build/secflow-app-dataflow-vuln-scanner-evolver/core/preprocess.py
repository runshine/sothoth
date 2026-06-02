"""
预处理模块 — Step 0

职责:
  0.1 根据 case_ids 从 vuln_service 反查原始任务
  0.2 从 dataflow-vuln-scanner 获取 agent 目录布局
  0.3 校验 replay 可行性
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class SourceTask:
    """一个可 replay 的原始任务。"""

    task_id: str
    execution_id: str
    title: str
    case_ids: list[str] = field(default_factory=list)
    agent_state_dirs: dict[str, dict[str, str]] = field(default_factory=dict)
    task_detail: dict[str, Any] = field(default_factory=dict)
    case_details: list[dict[str, Any]] = field(default_factory=list)
    # agent_state_dirs 结构: {agent_id: {"root_dir": ..., "skills_dir": ..., "memory_dir": ...}}


class PreprocessError(Exception):
    """预处理阶段的错误。"""


class Preprocessor:
    """
    从 case_ids 反向提取所有可 replay 的原始任务。

    流程:
      1. 对每个 case_id 调 vuln_service GET /cases/{case_id}
         → 拿到 source_task (task_id, execution_id, service_name)
      2. 校验 source_service == "secflow-app-dataflow-vuln-scanner"
      3. 去重: 同一个 source_task_id 只取一次
      4. 对每个唯一的 source_task_id:
         → 调 dfvs GET /tasks/{task_id} 获取 agent_state_dirs
         → 调 dfvs GET /tasks/{task_id}/replay-ready 校验可 replay
      5. 返回 SourceTask 列表
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._vuln_base = (
            config["vuln_service"]["base_url"].rstrip("/")
            + config["vuln_service"]["api_prefix"]
        )
        self._dfvs_base = (
            config["dataflow_vuln_scanner"]["base_url"].rstrip("/")
            + config["dataflow_vuln_scanner"]["api_prefix"]
        )
        self._timeout = config["dataflow_vuln_scanner"].get("timeout", 60)
        self._token = config["auth"]["machine_token"]
        self._host_header = (
            config["dataflow_vuln_scanner"].get("host_header")
            or config["vuln_service"].get("host_header")
            or ""
        )

    @property
    def _headers(self) -> dict[str, str]:
        token = self._token
        if not token.lower().startswith("bearer "):
            token = f"Bearer {token}"
        headers = {"Authorization": token}
        if self._host_header:
            headers["Host"] = self._host_header
        return headers

    async def extract_source_tasks(
        self, project_id: str, case_ids: list[str]
    ) -> list[SourceTask]:
        """从 case_ids 提取所有可 replay 的原始任务。"""
        if not case_ids:
            raise PreprocessError("case_ids 不能为空")

        # Step 1-3: 从 case 反查 source_task_id，去重
        task_case_map: dict[str, dict[str, Any]] = {}
        # {source_task_id: {"case_ids": [...], "case_details": [...], "execution_id": ..., "title": ...}}

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            for case_id in case_ids:
                case = await self._get_case(client, case_id)
                source_task = case.get("source_task") or {}
                source_service = (
                    source_task.get("service_name")
                    or source_task.get("service_id")
                    or ""
                ).strip()

                if source_service != "secflow-app-dataflow-vuln-scanner":
                    logger.warning(
                        "跳过案例 %s: 来源服务为 %s，非 dataflow-vuln-scanner",
                        case_id,
                        source_service,
                    )
                    continue

                source_task_id = (source_task.get("task_id") or "").strip()
                if not source_task_id:
                    logger.warning("跳过案例 %s: 缺少 source_task_id", case_id)
                    continue

                if source_task_id not in task_case_map:
                    task_case_map[source_task_id] = {
                        "case_ids": [],
                        "case_details": [],
                        "execution_id": source_task.get("execution_id") or "",
                        "title": source_task.get("run_name") or source_task_id,
                    }
                task_case_map[source_task_id]["case_ids"].append(case_id)
                task_case_map[source_task_id]["case_details"].append(case)

        if not task_case_map:
            raise PreprocessError(
                "没有找到任何来自 dataflow-vuln-scanner 的原始任务"
            )

        # Step 4: 获取每个 source_task 的详情和 replay 状态
        source_tasks: list[SourceTask] = []
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            for task_id, info in task_case_map.items():
                # 获取任务详情
                task_detail = await self._get_dfvs_task(client, task_id)
                task_purpose = (
                    task_detail.get("task_purpose") or "normal"
                ).strip().lower()
                if task_purpose != "normal":
                    logger.warning(
                        "跳过任务 %s: task_purpose=%s (需要 normal)",
                        task_id,
                        task_purpose,
                    )
                    continue

                # 校验 replay-ready
                replay_info = await self._get_replay_ready(client, task_id)
                if not replay_info.get("replay_ready"):
                    reason = replay_info.get("reason") or "未知原因"
                    logger.warning(
                        "跳过任务 %s: 不可 replay (%s)", task_id, reason
                    )
                    continue

                # 提取 agent_state_dirs
                agent_state_dirs = task_detail.get("agent_state_dirs") or {}
                if not agent_state_dirs:
                    # 尝试从 effective config 获取默认布局
                    effective_config = await self._get_effective_config(client)
                    agent_state_dirs = self._extract_agent_dirs_from_config(
                        project_id, effective_config
                    )

                source_tasks.append(
                    SourceTask(
                        task_id=task_id,
                        execution_id=info["execution_id"],
                        title=info["title"],
                        case_ids=info["case_ids"],
                        agent_state_dirs=agent_state_dirs,
                        task_detail=task_detail,
                        case_details=info["case_details"],
                    )
                )

        if not source_tasks:
            raise PreprocessError("所有原始任务均不可 replay")

        return source_tasks

    async def _get_case(self, client: httpx.AsyncClient, case_id: str) -> dict:
        """从 vuln_service 获取案例详情。"""
        resp = await client.get(
            f"{self._vuln_base}/cases/{case_id}",
            headers=self._headers,
        )
        resp.raise_for_status()
        return resp.json()

    async def _get_dfvs_task(
        self, client: httpx.AsyncClient, task_id: str
    ) -> dict:
        """从 dataflow-vuln-scanner 获取任务详情。"""
        resp = await client.get(
            f"{self._dfvs_base}/tasks/{task_id}",
            headers=self._headers,
        )
        resp.raise_for_status()
        return resp.json()

    async def _get_replay_ready(
        self, client: httpx.AsyncClient, task_id: str
    ) -> dict:
        """检查任务是否可以 replay。"""
        resp = await client.get(
            f"{self._dfvs_base}/tasks/{task_id}/replay-ready",
            headers=self._headers,
        )
        resp.raise_for_status()
        return resp.json()

    async def _get_effective_config(self, client: httpx.AsyncClient) -> dict:
        """获取 dataflow-vuln-scanner 的 effective config。"""
        resp = await client.get(
            f"{self._dfvs_base}/service/config/effective",
            headers=self._headers,
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _extract_agent_dirs_from_config(
        project_id: str, config_payload: dict[str, Any]
    ) -> dict[str, dict[str, str]]:
        """从 effective config 中提取 agent 目录布局。"""
        result: dict[str, dict[str, str]] = {}
        agent_storage = config_payload.get("agent_storage") or {}
        agents = agent_storage.get("agents") or []
        for item in agents:
            if not isinstance(item, dict):
                continue
            agent_id = (item.get("agent_id") or "").strip()
            if not agent_id:
                continue
            result[agent_id] = {
                "root_dir": (item.get("root_dir_template") or "")
                .replace("{project_id}", project_id)
                .replace("<project_id>", project_id),
                "skills_dir": (item.get("skills_dir_template") or "")
                .replace("{project_id}", project_id)
                .replace("<project_id>", project_id),
                "memory_dir": (item.get("memory_dir_template") or "")
                .replace("{project_id}", project_id)
                .replace("<project_id>", project_id),
            }
        return result
