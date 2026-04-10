"""
智能体运行时数据模型
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class AgentMessage:
    """智能体消息"""
    role: str                    # "system" | "user" | "assistant"
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResponse:
    """智能体响应"""
    content: str                 # 主要文本输出
    tool_outputs: list[dict] = field(default_factory=list)
    files_created: list[str] = field(default_factory=list)
    files_modified: list[str] = field(default_factory=list)
    conversation_id: Optional[str] = None
    turn_count: int = 0
    finished: bool = False       # 任务是否完成
    token_usage: dict[str, int] = field(default_factory=dict)
    raw_response: Any = None
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None
