"""漏洞判定引擎心跳循环（契约接口3，Contract v2.3 §5.1）。

引擎 POD（API 角色）启动后立即发起首次心跳（不等周期），之后每 30s 一次。
仅刷新活性，不携带 / 不修改 endpoint / version / bind_tools（配置由管理员维护）。

实现遵循项目规则：**线程 + time.sleep()**（不在 FastAPI 路由 / uvicorn 之外使用 asyncio）。
错误处理（§5.1.3）：
- 网络 / 5xx / 4xx → 记录日志并继续重试，不中断循环
- engine.heartbeat_url / engine.name 均有非空默认值；只有显式置空才跳过心跳任务
"""
from __future__ import annotations

import logging
import threading

import httpx

from app.config import get_engine_config

logger = logging.getLogger("poc.engine_heartbeat")


class EngineHeartbeat:
    """后台心跳线程：周期性 POST {engine_name} 到平台心跳接口。"""

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        cfg = get_engine_config()
        if not cfg.heartbeat_url or not cfg.name:
            logger.info(
                "engine heartbeat skipped (heartbeat_url or engine.name explicitly empty)"
            )
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="poc_engine_heartbeat", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        cfg = get_engine_config()
        url = cfg.heartbeat_url
        name = cfg.name
        interval = max(1, cfg.heartbeat_interval_seconds)
        timeout = max(0.1, cfg.heartbeat_request_timeout_seconds)
        logger.info("engine heartbeat loop starting: engine_name=%s interval=%ss url=%s", name, interval, url)

        # 启动后立即首次心跳（契约 §5.1.4）
        self._beat_once(url, name, timeout)
        while not self._stop.wait(interval):
            self._beat_once(url, name, timeout)
        logger.info("engine heartbeat loop stopped: engine_name=%s", name)

    def _beat_once(self, url: str, engine_name: str, timeout: float) -> None:
        try:
            resp = httpx.post(url, json={"engine_name": engine_name}, timeout=timeout)
        except (httpx.HTTPError, OSError) as exc:
            logger.warning("engine heartbeat network error: %s", exc)
            return
        if resp.status_code == 200:
            return
        if resp.status_code == 404:
            logger.error(
                "engine heartbeat engine_not_registered (404); engine_name=%s body=%s",
                engine_name, resp.text[:200],
            )
            return
        if resp.status_code == 400:
            logger.error(
                "engine heartbeat bad request (400); engine_name=%s body=%s",
                engine_name, resp.text[:200],
            )
            return
        logger.warning(
            "engine heartbeat unexpected status %s: %s", resp.status_code, resp.text[:200]
        )


_engine_heartbeat: EngineHeartbeat | None = None


def get_engine_heartbeat() -> EngineHeartbeat:
    global _engine_heartbeat
    if _engine_heartbeat is None:
        _engine_heartbeat = EngineHeartbeat()
    return _engine_heartbeat
