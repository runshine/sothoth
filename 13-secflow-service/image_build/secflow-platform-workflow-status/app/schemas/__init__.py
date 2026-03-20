"""
Pydantic模式模块
"""

from app.schemas.schemas import (
    # 通用模式
    ErrorResponse,
    SuccessResponse,
    # 节点状态
    NodeStatusInfo,
    NodeStatusResponse,
    NodeListResponse,
    # 工作流状态
    WorkflowStatusInfo,
    WorkflowStatusResponse,
    WorkflowStatusListResponse,
    # 状态历史
    NodeHistoryEntry,
    NodeHistoryResponse,
    WorkflowHistoryResponse,
    # 请求响应
    NodeSyncRequest,
    NodeSyncResponse,
    NodeInfo,
    BatchSyncRequest,
    BatchSyncResponse,
    NodeInitialRequest,
    NodeInitialResponse,
    NodeUpdateRequest,
    NodeUpdateResponse,
    NodeLogResponse,
    # 统计
    StatusStatistics,
    StatisticsResponse,
    # 工作流生命周期
    WorkflowNodeConfig,
    WorkflowInitializeRequest,
    WorkflowNodeResult,
    WorkflowLifecycleResponse,
    WorkflowDeinitializeRequest,
    WorkflowStopRequest,
    NodeStartRequest,
    NodeStartResponse,
)

__all__ = [
    "ErrorResponse",
    "SuccessResponse",
    "NodeStatusInfo",
    "NodeStatusResponse",
    "NodeListResponse",
    "WorkflowStatusInfo",
    "WorkflowStatusResponse",
    "WorkflowStatusListResponse",
    "NodeHistoryEntry",
    "NodeHistoryResponse",
    "WorkflowHistoryResponse",
    "NodeSyncRequest",
    "NodeSyncResponse",
    "NodeInfo",
    "BatchSyncRequest",
    "BatchSyncResponse",
    "NodeInitialRequest",
    "NodeInitialResponse",
    "NodeUpdateRequest",
    "NodeUpdateResponse",
    "NodeLogResponse",
    "StatusStatistics",
    "StatisticsResponse",
    # 工作流生命周期
    "WorkflowNodeConfig",
    "WorkflowInitializeRequest",
    "WorkflowNodeResult",
    "WorkflowLifecycleResponse",
    "WorkflowDeinitializeRequest",
    "WorkflowStopRequest",
]
