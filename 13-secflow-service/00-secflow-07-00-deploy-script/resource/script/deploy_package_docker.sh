#!/bin/sh

set -e

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
cd "$(cd "$(dirname $0)";pwd)"
. "${ROOT_DIR}/script/common.sh"

download_script_file "script/start_dockerd.sh"             "$ROOT_DIR/script/start_dockerd.sh"                && chmod +x "$ROOT_DIR/script/start_dockerd.sh"
download_script_file "script/stop_dockerd.sh"              "$ROOT_DIR/script/stop_dockerd.sh"                 && chmod +x "$ROOT_DIR/script/stop_dockerd.sh"
download_script_file "script/docker_env.sh"                "$ROOT_DIR/script/docker_env.sh"                   && chmod +x "$ROOT_DIR/script/docker_env.sh"
deploy_package.sh docker


cat  <<EOF > ${ROOT_DIR}/usr/conf/config.toml
disabled_plugins = ["cri"]
root = "${ROOT_DIR}/var/lib/containerd"
state = "${ROOT_DIR}/var/run/containerd"
#subreaper = true
#oom_score = 0
[grpc]
address = "${ROOT_DIR}/var/run/containerd.sock"
uid = 0
gid = 0
#[debug]
#  address = "${ROOT_DIR}/var/run/debug.sock"
#  uid = 0
#  gid = 0
#  level = "info"
EOF

cat  <<EOF > ${ROOT_DIR}/usr/conf/daemon.json
{
  "allow-direct-routing": false,
  "authorization-plugins": [],
  "bip": "",
  "bip6": "",
  "bridge": "br-sothoth",
  "builder": {
    "gc": {
      "enabled": true,
      "defaultKeepStorage": "10GB",
      "policy": [
        { "keepStorage": "10GB", "filter": ["unused-for=2200h"] },
        { "keepStorage": "50GB", "filter": ["unused-for=3300h"] },
        { "keepStorage": "100GB", "all": true }
      ]
    }
  },
  "cgroup-parent": "",
  "containerd": "${ROOT_DIR}/var/run/containerd.sock",
  "containerd-namespace": "docker-sothoth",
  "containerd-plugins-namespace": "docker-plugins-sothoth",
  "data-root": "${ROOT_DIR}/var/lib/data-root",
  "debug": false,
  "default-address-pools": [
    {
      "base": "200.65.0.0/16",
      "size": 24
    },
    {
      "base": "200.65.1.0/16",
      "size": 24
    }
  ],
  "default-cgroupns-mode": "private",
  "default-gateway": "",
  "default-gateway-v6": "",
  "default-network-opts": {},
  "default-runtime": "runc",
  "default-shm-size": "64M",
  "default-ulimits": {
    "nofile": {
      "Hard": 64000,
      "Name": "nofile",
      "Soft": 64000
    }
  },
  "dns": [],
  "dns-opts": [],
  "dns-search": [],
  "exec-opts": [],
  "exec-root": "${ROOT_DIR}/var/run",
  "experimental": false,
  "features": {
    "cdi": false,
    "containerd-snapshotter": false
  },
  "fixed-cidr": "",
  "fixed-cidr-v6": "",
  "group": "",
  "host-gateway-ip": "",
  "hosts": ["unix://${ROOT_DIR}/var/run/docker.sock","tcp://0.0.0.0:11191"],
  "proxies": {
  },
  "icc": true,
  "init": true,
  "init-path": "${ROOT_DIR}/usr/bin/docker-init",
  "insecure-registries": ["200.64.0.4"],
  "ip-forward": true,
  "ip-masq": true,
  "iptables": true,
  "ip6tables": false,
  "ipv6": false,
  "labels": [],
  "live-restore": false,
  "log-driver": "json-file",
  "log-format": "text",
  "log-level": "",
  "log-opts": {
    "cache-disabled": "false",
    "cache-max-file": "5",
    "cache-max-size": "20m",
    "cache-compress": "true",
    "env": "os,customer",
    "labels": "somelabel",
    "max-file": "5",
    "max-size": "10m"
  },
  "max-concurrent-downloads": 3,
  "max-concurrent-uploads": 5,
  "max-download-attempts": 5,
  "mtu": 0,
  "no-new-privileges": false,
  "node-generic-resources": [
  ],
  "pidfile": "${ROOT_DIR}/var/run/dockerd.pid",
  "raw-logs": false,
  "registry-mirrors": [],
  "runtimes": {
    "custom": {
      "path": "${ROOT_DIR}/usr/bin/runc",
      "runtimeArgs": [
        "--debug"
      ]
    }
  },
  "seccomp-profile": "",
  "selinux-enabled": false,
  "shutdown-timeout": 15,
  "storage-driver": "",
  "storage-opts": [],
  "swarm-default-advertise-addr": "",
  "userland-proxy": false,
  "userland-proxy-path": "${ROOT_DIR}/usr/bin/docker-proxy",
  "userns-remap": ""
}
EOF

cat  <<EOF > ${ROOT_DIR}/usr/conf/docker-swarm.conf
DOCKER_SWARM_TOKEN=
DOCKER_SWARM_SERVER=
EOF

cat  <<EOF > ${ROOT_DIR}/service_config/05_dockerd_service.json
{
  "name": "dockerd",
  "description": "dockerd service",
  "start_cmd": "${ROOT_DIR}/script/start_dockerd.sh",
  "stop_cmd": "${ROOT_DIR}/script/stop_dockerd.sh",
  "pid_file": "${ROOT_DIR}/var/run/dockerd.pid",
  "stdout_log": "${ROOT_DIR}/var/log/dockerd_stdout.log",
  "stderr_log": "${ROOT_DIR}/var/log/dockerd_stderr.log",
  "work_dir": "${ROOT_DIR}",
  "monitor_mode": "self",
  "check_interval": 30,
  "max_failures": 2,
  "depends_on": []
}
EOF

