#!/bin/sh

set -e

ARCH="$(uname -m)"
OS="linux"
WORKSPACE=""
UPSTREAM=""
TARGET_DIR=""
FORCE_DOWNLOAD=""

unset http_proxy
unset https_proxy
unset HTTP_PROXY
unset HTTPS_PROXY

ulimit -n 65535

# 参数解析函数
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -w|--workspace)
                WORKSPACE="$2"
                shift 2
                ;;
            -u|--upstream)
                UPSTREAM="$2"
                shift 2
                ;;
            -t|--target-dir)
                TARGET_DIR="$2"
                shift 2
                ;;
            -f|--force)
                FORCE_DOWNLOAD="true"
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo "$(date): 未知参数: $1" >&2
                echo "使用 -h 或 --help 查看帮助信息" >&2
                exit 1
                ;;
        esac
    done
}

# 显示帮助信息
show_help() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -w, --workspace <工作空间>    设置工作空间ID"
    echo "  -u, --upstream <上游地址>      设置上游服务器地址 (格式: host:port)"
    echo "  -t, --target-dir <目标目录>    设置目标安装目录"
    echo "  -f, --force                    强制重新下载文件"
    echo "  -h, --help                    显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 -w my-workspace -u server.example.com:8080 -t /opt/sothoth"
    echo "  $0 --workspace my-workspace --upstream server.example.com:8080 --target-dir /opt/sothoth"
}

# 解析命令行参数
parse_args "$@"

if [ "$ARCH" = "armv7l" ] || [ "$ARCH" = "armv7" ] || [ "$ARCH" = "armv8l" ];then
  if [ "x$(cat /proc/self/maps | grep ld-linux-armhf)" != "x" ];then
    echo "$(date): set current ARCH=armhf"
    ARCH="armhf"
  elif [ "x$(cat /proc/self/maps | grep ld-linux.so)" != "x" ];then
    echo "$(date): set current ARCH=armel"
    ARCH="armel"
  else
    echo "$(date): unable current ARCH, use origin: $ARCH"
  fi
else
  echo "$(date): set current ARCH=$ARCH"
fi

download() {
    local url="$1"
    local output_file="$2"

    # 检查URL是否为空
    if [ -z "$url" ]; then
        echo "$(date):错误：URL参数为空" >&2
        return 1
    fi

    # 检查输出路径是否为空
    if [ -z "$output_file" ]; then
        echo "$(date):错误：输出文件路径为空" >&2
        return 1
    fi

    if [ -f "$output_file" ] && [ "x${FORCE_DOWNLOAD}" = "x" ];then
      return 0
    fi

    #ignore bash even in force download
    if [ -f "$output_file" ] && [ "x$(basename $output_file)" = "xbash" ];then
      return 0;
    fi

    # 创建输出目录（如果不存在）
    local output_dir=$(dirname "$output_file")
    if [ ! -d "$output_dir" ]; then
        mkdir -p "$output_dir" || {
            echo "$(date):错误：无法创建目录 '$output_dir'" >&2
            exit 255
        }
    fi
    if [ "x${CURL}" != "x" ];then
      if ! "${CURL}" -fL -s -o "$output_file" "$url"; then
            echo "$(date):错误：${CURL}下载失败: $url" >&2
            rm -f "$output_file"  # 删除可能的部分下载文件
            exit 255
      else
        echo "$(date):下载成功: $url --> $output_file"
      fi
    elif [ "x${WGET}" != "x" ]; then
      if ! "${WGET}" -q -O "$output_file" "$url"; then
        echo "$(date):错误：${WGET}下载失败: $url" >&2
        rm -f "$output_file"  # 删除可能的部分下载文件
        exit 255
      else
        echo "$(date):下载成功: $url --> $output_file"
      fi
    else
      # 检查下载工具
      if [ "x$(command -v curl)" != "x" ]; then
          if ! curl -fL -s -o "$output_file" "$url"; then
              echo "$(date):错误：curl下载失败: $url" >&2
              rm -f "$output_file"  # 删除可能的部分下载文件
              exit 255
          else
            echo "$(date):下载成功: $url --> $output_file"
          fi
      elif [ "x$(command -v wget)" != "x" ]; then
          if ! wget -q -O "$output_file" "$url"; then
              echo "$(date):错误：wget下载失败: $url" >&2
              rm -f "$output_file"  # 删除可能的部分下载文件
              exit 255
          else
            echo "$(date):下载成功: $url --> $output_file"
          fi
      else
          echo "$(date):错误：未找到curl或wget，请安装任一工具" >&2
          exit 255
      fi
    fi
    return 0
}

download_package_file(){
  filename=$1
  target=$2
  download "${UPSTREAM}/api/packages/files/download/by-conditions/redirect?system=${OS}&architecture=${ARCH}&filename=${filename}" "${target}"
}

download_script_file(){
  filename=$1
  target=$2
  download "${UPSTREAM}/script/${filename}" "${target}"
  if [ -f "${target}" ];then
    chmod +x "${target}"
    if [ -f "${ROOT_DIR}/bin/bash" ];then
      sed -i "1s:.*:#!${ROOT_DIR}/bin/bash:g" "${target}"
    elif [ -f '/bin/bash' ];then
      sed -i "1s/.*/#!\/bin\/bash/" "$2"
    fi
  fi
}

# 参数检查
if [ "x${WORKSPACE}" = "x" ] || [ "x${UPSTREAM}" = "x" ] || [ "x${TARGET_DIR}" = "x" ];then
  echo "$(date): 参数检查失败" >&2
  echo "$(date): WORKSPACE=${WORKSPACE}" >&2
  echo "$(date): UPSTREAM=${UPSTREAM}" >&2
  echo "$(date): TARGET_DIR=${TARGET_DIR}" >&2
  echo "" >&2
  show_help
  exit 255
fi

ROOT_DIR="${TARGET_DIR}"
echo "$(date): we are working at ${ROOT_DIR}"

[ -d "${ROOT_DIR}" ] || mkdir -p "${ROOT_DIR}"
cd "${ROOT_DIR}"

pre_build_dirs="$ROOT_DIR/bin $ROOT_DIR/script $ROOT_DIR/config  $ROOT_DIR/service_config $ROOT_DIR/log/sothothv2_agent  $ROOT_DIR/var/run $ROOT_DIR/var/log"
for dir in ${pre_build_dirs};
do
  if [ ! -d "${dir}" ];then
    echo "$(date): start create dir: ${dir}"
    mkdir -p "$dir"
  fi
done
export DNS_SERVER="10.96.0.10"
UPSTREAM_SERVER="$(echo $UPSTREAM | awk -F':' '{print $1}')"
UPSTREAM_PORT="$(echo $UPSTREAM | awk -F':' '{print $2}')"
UUID="$(cat /dev/urandom | od -x | head -1 | awk '{print $2$3$4$5}')"
export PATH="${ROOT_DIR}/bin:${ROOT_DIR}/script:${PATH}"

cat << EOF > "$ROOT_DIR/config/sothothv2_agent.ini"
workspace=${ROOT_DIR}
project_id=${WORKSPACE}
server_addr=${UPSTREAM_SERVER}
server_port=${UPSTREAM_PORT}
uuid=${UUID}
log_level=info
log_path=${ROOT_DIR}/log/sothothv2_agent
foreground=false
EOF

export WORKSPACE=${WORKSPACE}

download_package_file "sothothv2_agent"                   "$ROOT_DIR/bin/sothothv2_agent"                  && chmod +x "$ROOT_DIR/bin/sothothv2_agent"
download_package_file "bash"                              "$ROOT_DIR/bin/bash"                             && chmod +x "$ROOT_DIR/bin/bash"
download_script_file  "script/common.sh"                  "$ROOT_DIR/script/common.sh"                     && chmod +x "$ROOT_DIR/script/common.sh"
download_script_file  "script/deploy_package.sh"          "$ROOT_DIR/script/deploy_package.sh"             && chmod +x "$ROOT_DIR/script/deploy_package.sh"

package_list="base_file sothothv2_agent nginx openvpn ttyd openssh rpcapd docker frida_server nacos_client sothoth_agent"
for package in ${package_list};
do
  if [ "$ARCH" = "armel" ] && [ "${package}" = "frida_server" ];then
    continue
  fi
  download_script_file "script/deploy_package_${package}.sh" "${ROOT_DIR}/script/deploy_package_${package}.sh"
  "${ROOT_DIR}/script/deploy_package_${package}.sh"
done

if [ -d "/usr/lib/systemd/system" ];then
  echo "$(date): find systemd, enable it for autoboot"

  cat << EOF > /usr/lib/systemd/system/sothothv2.service
[Unit]
Description=SothothV2 Service
After=network.target
Documentation=https://example.com/sothothv2-docs

[Service]
Type=simple
User=root
WorkingDirectory=$ROOT_DIR
ExecStart="$ROOT_DIR/bin/sothothv2_agent" -config "$ROOT_DIR/config/sothothv2_agent.ini" -foreground
PIDFile=$ROOT_DIR/var/run/sothothv2_agent.pid
Restart=yes
KillMode=mixed
TimeoutSec=300

# 安全相关设置
#NoNewPrivileges=yes
#ProtectSystem=strict
#ProtectHome=read-only
#PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sothothv2
    systemctl start sothothv2
else
  echo "$(date): not find systemd, unable enable autoboot, start it maunal: $ROOT_DIR/bin/sothothv2_agent -config $ROOT_DIR/config/sothothv2_agent.ini"
  "$ROOT_DIR/bin/sothothv2_agent" -config "$ROOT_DIR/config/sothothv2_agent.ini"
fi

exit 0

#kill -SIGTERM `pidof sothothv2_agent`
