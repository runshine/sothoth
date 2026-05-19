from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from app.services.adb_service import run_adb_devices

router = APIRouter()

DEFAULT_ADB_SERVER_IP = "172.31.30.81"


class AdbConnectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AdbDevicesResponse(BaseModel):
    command: list[str] = Field(..., description="执行的 adb devices 命令")
    return_code: int | None = Field(None, description="进程退出码；为 null 表示命令未启动或超时")
    output: str = Field("", description="adb devices 的 stdout/stderr 合并输出")


@router.post(
    "/devices/adb/connect",
    response_model=AdbDevicesResponse,
    summary="连接远程 ADB 设备",
    description=(
        "接口不再接收 IP 参数；后端固定连接 `172.31.30.81:15037`，并在容器服务进程内设置 "
        "`ADB_SERVER_SOCKET=tcp:172.31.30.81:15037`，后续 adb/PoC 子进程会继承该值。"
        "仅当 `adb devices` 中存在 `device` 状态设备且 `adb shell true` 成功时，才写入 `~/.bashrc`。"
        "接口只执行并返回 `adb devices` 命令结果。"
    ),
)
def connect_adb(req: AdbConnectRequest | None = None):
    result = run_adb_devices(DEFAULT_ADB_SERVER_IP)
    response = AdbDevicesResponse(
        command=result.command,
        return_code=result.return_code,
        output=result.output,
    )
    return response
