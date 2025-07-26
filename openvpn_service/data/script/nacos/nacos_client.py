import os
import re
import signal
import sys
import socket
import struct
import fcntl
from logging.handlers import RotatingFileHandler

import requests
import time
import logging
import threading


NACOS_SERVER=""
NACOS_PORT="11193"
server_should_stop = False


#nacos服务注册
def service_register(service_name,service_ip,service_port):
    global logger
    url = f"http://{NACOS_SERVER}:{NACOS_PORT}/nacos/v1/ns/instance?serviceName={service_name}&ip={service_ip}&port={service_port}&weight=1.0&enabled=true&healthy=true&ephemeral=true&metadata={{'hostname':'{socket.gethostname()}'}}"
    res = requests.post(url)
    logger.info(f"向nacos注册中心，发起服务注册请求，注册响应状态： {res.status_code}, {service_name}-->{service_ip}:{service_port}")


#服务检测（每5秒心跳一次）
def service_beat(service_name,service_ip,service_port):
    global logger
    url = f"http://{NACOS_SERVER}:{NACOS_PORT}/nacos/v1/ns/instance/beat?serviceName={service_name}&ip={service_ip}&port={service_port}"
    res = requests.put(url)
    logger.info(f"已注册服务，执行心跳服务，续期服务响应状态： {res.status_code}, {service_name}-->{service_ip}:{service_port}")
    time.sleep(5)


def get_ip(ifname):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', bytes(ifname[:15],'utf-8')))[20:24])
    except Exception as e:
        return ""


def is_valid_ipv4(ip):
    if len(ip.strip()) == 0:
        return False
    pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    regex = re.compile(pattern)
    if regex.match(ip):
        return True
    else:
        return False


def start_common_service(service_name,port):
    global logger
    global server_should_stop
    ip_address = get_ip("tap-sothoth")
    while not is_valid_ipv4(ip_address):
        logger.warning("wait tap-sothoth avaiable")
        time.sleep(5)
        ip_address = get_ip("tap-sothoth")
    service_register(service_name,ip_address,port)
    while not server_should_stop:
        time.sleep(5)
        ip_address = get_ip("tap-sothoth")
        service_beat(service_name,ip_address,port)


def start_ttyd_service():
    start_common_service("ttyd","11198")


def graceful_exit():
    global server_should_stop
    server_should_stop = True


def prevent_multiple_running(lock_file_path):
    lock_file = open(lock_file_path, 'w')
    try:
        # 尝试获取独占锁（非阻塞模式）
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, IOError):
        print("Another instance is already running. Exiting.")
        sys.exit(1)
    return lock_file


def setup_logger(NACOS_ROOT_DIR):
    # 创建日志记录器
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)  # 设置默认日志级别为INFO

    # 创建文件处理器 - 限制单个文件最大5MB，保留3个备份
    log_file = os.path.join(NACOS_ROOT_DIR,"log/nacos_client.log")
    file_handler = RotatingFileHandler(
        filename=log_file,
        maxBytes=5*1024*1024,  # 5MB
        backupCount=3,          # 保留3个备份文件
        encoding='utf-8'
    )

    # 创建控制台处理器（可选）
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # 创建日志格式
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # 应用格式到处理器
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # 添加处理器到记录器
    logger.addHandler(file_handler)
    # logger.addHandler(console_handler)  # 可选：同时在控制台输出

    return logger


if __name__ == "__main__":
    signal.signal(signal.SIGINT, graceful_exit)  # Ctrl+C
    signal.signal(signal.SIGTERM, graceful_exit)  # kill 命令
    logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)
    NACOS_ROOT_DIR=os.getenv("NACOS_ROOT_DIR")
    UPSTREAM_SERVER=os.getenv("UPSTREAM_SERVER")
    if NACOS_ROOT_DIR is None or not os.path.exists(NACOS_ROOT_DIR):
        print(f"NACOS_ROOT_DIR env check failed: {NACOS_ROOT_DIR}")
        exit(-1)
    if UPSTREAM_SERVER is None or len(UPSTREAM_SERVER) == 0:
        print(f"UPSTREAM_SERVER env check failed: {UPSTREAM_SERVER}")
        exit(-1)
    NACOS_SERVER = UPSTREAM_SERVER
    logger = setup_logger(NACOS_ROOT_DIR)
    lock_file = prevent_multiple_running(os.path.join(NACOS_ROOT_DIR,"run/nacos_client.lock"))
    try:
        ttyd_thread = threading.Thread(target=start_ttyd_service)
        ttyd_thread.start()
        ttyd_thread.join()
    finally:
        lock_file.close()

