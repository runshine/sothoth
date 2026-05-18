from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.adb_service import run_adb_devices

router = APIRouter()


class AdbConnectRequest(BaseModel):
    ip: str = Field(
        ...,
        description="远端 ADB server IP 或 `ip:port`。不带端口时默认使用 5037。",
        examples=["192.168.1.10"],
    )


class AdbDevicesResponse(BaseModel):
    command: list[str] = Field(..., description="执行的 adb devices 命令")
    return_code: int | None = Field(None, description="进程退出码；为 null 表示命令未启动或超时")
    output: str = Field("", description="adb devices 的 stdout/stderr 合并输出")


@router.post(
    "/devices/adb/connect",
    response_model=AdbDevicesResponse,
    summary="连接远程 ADB 设备",
    description=(
        "前端提供远端 ADB server IP 或 `ip:port`，后端在容器服务进程内设置 "
        "`ADB_SERVER_SOCKET=tcp:<ip>:<port>`（默认 5037），后续 adb/PoC 子进程会继承该值。"
        "仅当 `adb devices` 中存在 `device` 状态设备且 `adb shell true` 成功时，才写入 `~/.bashrc`。"
        "接口只执行并返回 `adb devices` 命令结果。"
    ),
)
def connect_adb(req: AdbConnectRequest):
    ip = req.ip.strip()
    if not ip:
        raise HTTPException(422, "ip is required")

    result = run_adb_devices(ip)
    response = AdbDevicesResponse(
        command=result.command,
        return_code=result.return_code,
        output=result.output,
    )
    return response
