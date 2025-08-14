import asyncio
from fastapi import FastAPI, HTTPException
import paramiko
from contextlib import asynccontextmanager
import os
import logging
from fastapi.responses import Response

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 全局配置
PRIVATE_KEY_PATH = "/data/id_rsa"
SSH_TIMEOUT = 120  # 2分钟超时

app = FastAPI()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 验证私钥文件是否存在
    if not os.path.exists(PRIVATE_KEY_PATH):
        logger.error(f"SSH私钥文件不存在: {PRIVATE_KEY_PATH}")
        raise RuntimeError(f"SSH私钥文件未找到: {PRIVATE_KEY_PATH}")
    yield

app = FastAPI(lifespan=lifespan)


def create_ssh_client(ip: str, username: str) -> paramiko.SSHClient:
    """创建并配置SSH客户端"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # 加载私钥
        private_key = paramiko.RSAKey.from_private_key_file(PRIVATE_KEY_PATH)
        client.connect(
            hostname=ip,
            username=username,
            pkey=private_key,
            timeout=10,  # 连接超时
            banner_timeout=10
        )
        return client
    except paramiko.AuthenticationException:
        logger.error(f"认证失败: {username}@{ip}")
        raise HTTPException(status_code=401, detail="SSH认证失败")
    except Exception as e:
        logger.error(f"连接错误: {str(e)}")
        raise HTTPException(status_code=500, detail=f"SSH连接错误: {str(e)}")


async def execute_remote_command(ip: str, username: str, command: str) -> str:
    """在远程主机执行命令（带超时）"""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_execute_command, ip, username, command),
            timeout=SSH_TIMEOUT
        )
    except asyncio.TimeoutError:
        logger.warning(f"命令执行超时: {command} @ {ip}")
        raise HTTPException(status_code=408, detail="命令执行超时")


def _execute_command(ip: str, username: str, command: str) -> str:
    """同步执行命令的实现"""
    client = None
    try:
        client = create_ssh_client(ip, username)
        # 设置命令执行超时
        _, stdout, stderr = client.exec_command(command, timeout=SSH_TIMEOUT)
        output = stdout.read().decode() + stderr.read().decode()
        return output.strip()
    finally:
        if client:
            client.close()


async def fetch_remote_file(ip: str, username: str, file_path: str) -> Response:
    """从远程主机获取文件（带超时）"""
    try:
        content = await asyncio.wait_for(
            asyncio.to_thread(_fetch_file, ip, username, file_path),
            timeout=SSH_TIMEOUT
        )
        return Response(content, media_type="application/octet-stream",
                        headers={"Content-Disposition": f"attachment; filename={os.path.basename(file_path)}"})
    except asyncio.TimeoutError:
        logger.warning(f"文件传输超时: {file_path} @ {ip}")
        raise HTTPException(status_code=408, detail="文件传输超时")
    except FileNotFoundError:
        logger.error(f"文件不存在: {file_path} @ {ip}")
        raise HTTPException(status_code=404, detail="远程文件不存在")
    except Exception as e:
        logger.error(f"文件传输错误: {str(e)}")
        raise HTTPException(status_code=500, detail=f"文件传输错误: {str(e)}")


def _fetch_file(ip: str, username: str, file_path: str) -> bytes:
    """同步获取文件的实现"""
    client = None
    try:
        client = create_ssh_client(ip, username)
        sftp = client.open_sftp()
        # 设置SFTP操作超时
        sftp.get_channel().settimeout(SSH_TIMEOUT)
        with sftp.open(file_path, "rb") as remote_file:
            return remote_file.read()
    except IOError as e:
        if "No such file" in str(e):
            raise FileNotFoundError(f"文件不存在: {file_path}")
        raise
    finally:
        if client:
            client.close()


@app.post("/execute-command/")
async def execute_command(ip: str, username: str, command: str):
    """远程执行命令端点"""
    logger.info(f"执行命令: {command} @ {username}@{ip}")
    result = await execute_remote_command(ip, username, command)
    return {"result": result}


@app.get("/fetch-file/")
async def fetch_file(ip: str, username: str, file_path: str):
    """远程获取文件端点"""
    logger.info(f"获取文件: {file_path} @ {username}@{ip}")
    return await fetch_remote_file(ip, username, file_path)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10002)