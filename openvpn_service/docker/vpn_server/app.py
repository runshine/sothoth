import asyncio
import logging
import signal
import time
import socket,struct,fcntl

from nacos import NacosClient

logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)
import re
import os
import threading
from flask import Flask, jsonify, request, send_file, abort, redirect

app = Flask(__name__)
nginx_config_template=""
server_ip_address = ""
server_should_stop=False

nacos_naming_client = None


def register_instance(client, servic_name,service_ip,service_port):
    retry = 10
    while not server_should_stop and retry != 0:
        try:
            client.add_naming_instance(
                service_name=servic_name,
                ip=service_ip,
                port=service_port,
                ephemeral=True,  # 确保是临时实例（需要心跳）
                metadata={"hostname":socket.gethostname()},
                healthy=True,
                heartbeat_interval=5
            )
            logging.info(f"✅ 实例注册成功:{servic_name} --> {service_ip}:{service_port}")
            break
        except Exception as e:
            logging.info("register_instance error, waiting, retry: {}, {}".format(retry,str(e)))
            retry = retry -1
            time.sleep(5)
    

# 3. 注销实例（退出时调用）
def deregister_instance(client, servic_name,service_ip,service_port):
    retry = 10
    while not server_should_stop and retry != 0:
        try:
            client.remove_naming_instance(
                service_name=servic_name,
                ip=service_ip,
                port=service_port
            )
            logging.info(f"⛔ 实例注销成功: {servic_name} --> {service_ip}:{service_port}")
            break
        except Exception as e:
            logging.info("deregister_instance error, waiting 5 seconds, retry: {}, {}".format(retry,str(e)))
            retry = retry -1
            time.sleep(5)


@app.route('/utils/<name>/<release>/<arch>', methods=['GET'])
def download_utils(name,release,arch):
    if os.path.exists("/data/utils/{}-{}-{}".format(name,release,arch)):
        return redirect("/download/utils/{}-{}-{}".format(name,release,arch))
    return abort(404)


@app.route('/package/<name>/<release>/<arch>', methods=['GET'])
def download_package(name,release,arch):
    suffix_list = ["tar.gz","tar.zst","tar","zip"]
    for suffix in suffix_list:
        if os.path.exists("/data/package/{}-{}-{}.{}".format(name,release,arch,suffix)):
            return redirect("/download/package/{}-{}-{}.{}".format(name,release,arch,suffix))
    return abort(404)


@app.route('/docker/<name>/<release>/<arch>', methods=['GET'])
def download_docker_package(name,release,arch):
    suffix_list = ["tar.gz","tar.zst","tar","zip"]
    for suffix in suffix_list:
        if os.path.exists("/data/package/docker/{}-{}-{}.{}".format(name,release,arch,suffix)):
            return redirect("/download/package/docker/{}-{}-{}.{}".format(name,release,arch,suffix))
    return abort(404)


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


def nacos_thread():
    global nacos_naming_client
    nacos_naming_client = NacosClient("localhost:8848")
    register_instance(nacos_naming_client,"sothoth-file-server",server_ip_address,"8080")
    logging.info("nacos_worker end")


def graceful_exit():
    global server_should_stop,nacos_naming_client
    server_should_stop = True
    deregister_instance(nacos_naming_client,"sothoth-file-server",server_ip_address,"8080")


if __name__ == '__main__':
    signal.signal(signal.SIGINT, graceful_exit)  # Ctrl+C
    signal.signal(signal.SIGTERM, graceful_exit)  # kill 命令
    server_ip_address = get_ip("br-openvpn")
    while not is_valid_ipv4(server_ip_address):
        logging.info("trying get server address, old is failed: {}".format(server_ip_address))
        server_ip_address = get_ip("br-openvpn")
        time.sleep(1)
    logging.info("server address: {}".format(server_ip_address))
    threading.Thread(target=nacos_thread).start()
    app.run(host="0.0.0.0",port="8081",debug=False,threaded=True)