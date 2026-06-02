"""
Replay 模块

职责:
  - 调用 dataflow-vuln-scanner 的 create-evolution API 创建派生任务
  - 并发轮询任务状态直到终态
  - 收集 replay 结果
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from core.preprocess import SourceTask

logger = logging.getLogger(__name__)

TERMINAL_STATUSES = frozenset(
    {"completed", "succeeded", "failed", "cancelled", "interrupted", "error"}
)


@dataclass
class ReplayResult:
    """单个原始任务的 replay 结果。"""

    source_task_id: str
    derived_task_id: str
    status: str
    run_id: str | None = None
    duration_seconds: float = 0.0
    results_summary: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class ReplayManager:
    """
    触发并监控 dataflow-vuln-scanner 的 replay。

    对每个 source_task:
      1. POST /tasks/{task_id}/create-evolution 创建派生任务
      2. 轮询 GET /tasks/{derived_task_id} 直到终态
      3. 收集结果
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._dfvs_base = (
            config["dataflow_vuln_scanner"]["base_url"].rstrip("/")
            + config["dataflow_vuln_scanner"]["api_prefix"]
        )
        self._timeout = config["dataflow_vuln_scanner"].get("timeout", 60)
        self._token = config["auth"]["machine_token"]
        self._host_header = config["dataflow_vuln_scanner"].get("host_header", "")
        self._max_concurrency = config["replay"].get("max_concurrency", 4)
        self._poll_interval = config["replay"].get("poll_interval_seconds", 5)
        self._task_timeout = config["replay"].get("task_timeout_seconds", 7200)
        self._model = str(config["replay"].get("model") or "").strip()
        self._provider = str(config["replay"].get("provider") or "").strip()

    @property
    def _headers(self) -> dict[str, str]:
        token = self._token
        if not token.lower().startswith("bearer "):
            token = f"Bearer {token}"
        headers = {"Authorization": token}
        if self._host_header:
            headers["Host"] = self._host_header
        return headers

    async def replay_all(
        self,
        source_tasks: list[SourceTask],
        agent_roots: dict[str, str],
        project_id: str,
        *,
        evolution_session_id: str = "",
        round_no: int = 1,
        on_progress: Any = None,
    ) -> list[ReplayResult]:
        """
        并发 replay 所有原始任务。

        Args:
            source_tasks: 要 replay 的原始任务列表
            agent_roots: {agent_id: evolution_root_dir} 映射
            project_id: 项目 ID
            evolution_session_id: 进化会话 ID
            round_no: 当前轮次
            on_progress: 可选的进度回调 (task_id, status, message)
        """
        semaphore = asyncio.Semaphore(self._max_concurrency)
        results: list[ReplayResult] = []

        async def _run_one(source_task: SourceTask) -> ReplayResult:
            async with semaphore:
                return await self._replay_single(
                    source_task=source_task,
                    agent_roots=agent_roots,
                    project_id=project_id,
                    evolution_session_id=evolution_session_id,
                    round_no=round_no,
                    on_progress=on_progress,
                )

        tasks = [asyncio.create_task(_run_one(st)) for st in source_tasks]
        for completed in asyncio.as_completed(tasks):
            result = await completed
            results.append(result)

        return results

    async def _replay_single(
        self,
        *,
        source_task: SourceTask,
        agent_roots: dict[str, str],
        project_id: str,
        evolution_session_id: str,
        round_no: int,
        on_progress: Any,
    ) -> ReplayResult:
        """Replay 单个原始任务。"""
        started = time.monotonic()

        try:
            # Step 1: 创建派生任务
            derived = await self._create_evolution_task(
                source_task=source_task,
                agent_roots=agent_roots,
                project_id=project_id,
                evolution_session_id=evolution_session_id,
                round_no=round_no,
            )
            derived_task_id = (derived.get("task_id") or "").strip()
            if not derived_task_id:
                return ReplayResult(
                    source_task_id=source_task.task_id,
                    derived_task_id="",
                    status="failed",
                    error="create-evolution 未返回 task_id",
                )

            if on_progress:
                on_progress(
                    source_task.task_id, "started", f"派生任务: {derived_task_id}"
                )

            # Step 2: 轮询直到终态
            final_status = await self._poll_until_done(
                derived_task_id, on_progress, source_task.task_id
            )

            # Step 3: 收集结果
            duration = time.monotonic() - started
            results_summary = await self._collect_task_results(derived_task_id)

            return ReplayResult(
                source_task_id=source_task.task_id,
                derived_task_id=derived_task_id,
                status=final_status.get("status", "unknown"),
                run_id=final_status.get("latest_run_id"),
                duration_seconds=duration,
                results_summary=results_summary,
            )

        except Exception as exc:
            duration = time.monotonic() - started
            logger.exception("replay failed for task %s", source_task.task_id)
            return ReplayResult(
                source_task_id=source_task.task_id,
                derived_task_id="",
                status="error",
                duration_seconds=duration,
                error=str(exc),
            )

    async def _create_evolution_task(
        self,
        *,
        source_task: SourceTask,
        agent_roots: dict[str, str],
        project_id: str,
        evolution_session_id: str,
        round_no: int,
    ) -> dict[str, Any]:
        """调用 create-evolution API。"""
        # 构建 agent_state_roots payload
        # 将本地绝对路径转为 project_filesystem 相对路径
        agent_state_roots_payload: dict[str, Any] = {}
        for agent_id, root_dir in agent_roots.items():
            # 计算相对于 project 根目录的路径
            visible_path = self._to_project_visible_path(root_dir, project_id)
            agent_state_roots_payload[agent_id] = {
                "root_dir": {
                    "source": "project_filesystem",
                    "path": visible_path,
                }
            }

        payload: dict[str, Any] = {
            "title": f"Evolution round {round_no} / {source_task.task_id}",
            "agent_state_roots": agent_state_roots_payload,
            "evolution_task_id": evolution_session_id,
            "evolution_round": round_no,
            "evolution_source_task_id": source_task.task_id,
            "evolution_source_execution_id": source_task.execution_id,
            "auto_report_vulnerabilities": True,
        }
        if self._model:
            payload["model"] = self._model
        if self._provider:
            payload["provider"] = self._provider
        # 去掉空值
        payload = {k: v for k, v in payload.items() if v not in (None, "", {}, [])}

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._dfvs_base}/tasks/{source_task.task_id}/create-evolution",
                json=payload,
                headers=self._headers,
            )
            resp.raise_for_status()
            return resp.json()

    async def _poll_until_done(
        self,
        task_id: str,
        on_progress: Any,
        source_task_id: str,
    ) -> dict[str, Any]:
        """轮询任务状态直到终态或超时。"""
        deadline = time.monotonic() + self._task_timeout

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            while True:
                if time.monotonic() > deadline:
                    return {"status": "timeout", "latest_run_id": None}

                await asyncio.sleep(self._poll_interval)

                resp = await client.get(
                    f"{self._dfvs_base}/tasks/{task_id}",
                    headers=self._headers,
                )
                resp.raise_for_status()
                detail = resp.json()

                status = (detail.get("status") or "").strip().lower()
                if on_progress:
                    on_progress(source_task_id, status, f"{task_id}: {status}")

                if status in TERMINAL_STATUSES:
                    return {
                        "status": status,
                        "latest_run_id": detail.get("latest_run_id")
                        or detail.get("latest_execution_id"),
                    }

    async def _collect_task_results(self, task_id: str) -> dict[str, Any]:
        """收集任务的结果摘要。"""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.get(
                f"{self._dfvs_base}/tasks/{task_id}",
                headers=self._headers,
            )
            resp.raise_for_status()
            detail = resp.json()

            # 提取关键结果信息
            return {
                "task_id": task_id,
                "status": detail.get("status"),
                "title": detail.get("title"),
                "latest_execution_id": detail.get("latest_execution_id"),
                "latest_run_id": detail.get("latest_run_id"),
                "result_count": detail.get("result_count", 0),
                "vuln_report_status": detail.get("vuln_report_status"),
            }

    @staticmethod
    def _to_project_visible_path(absolute_path: str, project_id: str) -> str:
        """
        将绝对路径转为 project_filesystem 可见路径。
        例: /data/files/proj123/app/... → /app/...
        """
        # 找到 project_id 后面的部分
        marker = f"/{project_id}/"
        idx = absolute_path.find(marker)
        if idx >= 0:
            relative = absolute_path[idx + len(marker) - 1:]  # 保留前导 /
            return relative
        # fallback: 返回原路径
        return absolute_path
