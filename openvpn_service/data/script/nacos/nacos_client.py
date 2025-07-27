import threading
from common_utils import *
server_should_stop = False


def start_ttyd_service():
    start_nacos_service(service_name="ttyd",port="11198",metadata=translate_ipv4_list_to_map(get_ipv4_addresses()))


def start_openssh_service():
    start_nacos_service(service_name="sshd",port="11192")


def graceful_exit():
    global server_should_stop
    server_should_stop = True


if __name__ == "__main__":
    setup_grace_exit(graceful_exit)
    NACOS_ROOT_DIR=os.getenv("NACOS_ROOT_DIR")
    UPSTREAM_SERVER=os.getenv("UPSTREAM_SERVER")
    if NACOS_ROOT_DIR is None or not os.path.exists(NACOS_ROOT_DIR):
        print(f"NACOS_ROOT_DIR env check failed: {NACOS_ROOT_DIR}")
        exit(-1)
    if UPSTREAM_SERVER is None or len(UPSTREAM_SERVER) == 0:
        print(f"UPSTREAM_SERVER env check failed: {UPSTREAM_SERVER}")
        exit(-1)
    NACOS_SERVER = UPSTREAM_SERVER
    setup_logger(os.path.join(NACOS_ROOT_DIR,"log/nacos_client.log"))
    setup_singal_runner(os.path.join(NACOS_ROOT_DIR,"run/nacos_client.lock"))
    setup_nacos_server()
    ttyd_thread = threading.Thread(target=start_ttyd_service)
    ttyd_thread.start()
    sshd_thread = threading.Thread(target=start_openssh_service)
    sshd_thread.start()

    ttyd_thread.join()
    sshd_thread.join()


