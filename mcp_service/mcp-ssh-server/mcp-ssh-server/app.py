import logging
import re

import requests
import asyncio
import asyncssh
from fastmcp import FastMCP

app = FastMCP("mcp-ssh-server")
ssh_port = 11192
private_key = "/data/id_rsa"
#private_key = "/root/CLionProjects/sothoth/openvpn_service/data/conf/openssh/id_rsa"
timeout_command = 120  # 2分钟
timeout_file = 1200    # 20分钟


async def connect_ssh(ip, username):
    """建立SSH连接"""
    return await asyncssh.connect(
        host=ip,
        username=username,
        client_keys=[private_key],
        port=ssh_port,
        known_hosts=None,  # 跳过主机密钥验证
        connect_timeout=30
    )


@app.tool(name="list_all_node",title="列出当前所有可连接的节点",description="列出当前所有可连接的节点,，返回IP列表")
def list_all_node() -> list:
    try:
        # logging.info("list_all_node call")
        service_lists = []
        node_list = []
        current_page = 1
        page_size = 1000
        while True:
            tmp_service = requests.get(f"http://200.64.0.2:8848/nacos/v1/ns/service/list?pageNo={current_page}&pageSize={page_size}").json()
            if tmp_service["count"] != page_size:
                service_lists = service_lists + tmp_service["doms"]
                break
            else:
                service_lists = service_lists + tmp_service["doms"]
                current_page = current_page + 1
        for service in service_lists:
            # logging.info(f"process: {service}")
            node_ip = re.findall(r".*-(\d+.\d+.\d+.\d+)$",service)
            if len(node_ip) == 1:
                node_list.append(node_ip[0])
                # logging.info(f"add ip {node_ip[0]} to list")
        return node_list
    except Exception as e:
        logging.error(f"error happened: {e}")
        return []


@app.tool(name="execute_command",title="在远程服务器上执行命令并获取结果",description="在远程服务器上执行命令并获取结果，输入远程IP、用户名和要执行的命令")
async def execute_command(ip: str,username: str,command: str) -> str:
    """功能一：远程执行命令"""
    if ip is None or len(ip) == 0:
        return "请输入IP地址"
    if username is None or len(username) == 0:
        return "请输入执行的用户名"
    if command is None or len(command) == 0:
        return "请输入执行的命令"
    try:
        conn = await asyncio.wait_for(connect_ssh(ip.strip(), username.strip()), timeout=timeout_command)
        try:
            result = await asyncio.wait_for(conn.run(command.strip()), timeout=timeout_command)
            res = result.stdout + result.stderr
        finally:
            conn.close()
    except Exception as e:
        res = str(e)
    return res


@app.tool(name="get_remote_file_content",title="在远程服务器上打开文件并返回文件内容",description="在远程服务器上打开文件并返回文件内容，输入远程IP和要打开的文件名")
async def get_remote_file_content(ip: str,remote_path: str) -> bytes:
    """功能二：远程获取文件"""
    if ip is None or len(ip) == 0:
        return "请输入IP地址"
    if remote_path is None or len(remote_path) == 0:
        return "请输入要获取的文件名"
    content = b""
    try:
        conn = await asyncio.wait_for(connect_ssh(ip.strip(), "root"), timeout=timeout_file)
        async with conn.start_sftp_client() as sftp:
            file_stat = await asyncio.wait_for(sftp.stat(remote_path.strip()), timeout=timeout_file)
            chunks = []
            async with sftp.open(remote_path.strip(), "rb") as file:
                while True:
                    chunk = await asyncio.wait_for(file.read(4096), timeout=timeout_file)
                    if not chunk:
                        break
                    chunks.append(chunk)
            content = b"".join(chunks)
    finally:
        conn.close()
    return content


if __name__ == "__main__":
    #logging.basicConfig(format="%(asctime)s-%(name)s-%(levelname)s-%(message)s",level=logging.INFO)
    app.run(transport="sse",host="0.0.0.0",port=10002)