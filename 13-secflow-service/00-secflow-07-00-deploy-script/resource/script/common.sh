#!/bin/sh

#if [ ! -z "${NODE_ID}" ];then

download() {
    local url="$1"
    local output_file="$2"

    # 检查URL是否为空
    if [ -z "$url" ]; then
        logger "错误：URL参数为空" >&2
        return 1
    fi

    # 检查输出路径是否为空
    if [ -z "$output_file" ]; then
        logger "错误：输出文件路径为空" >&2
        return 1
    fi


    if [ -f "$output_file" ] && [ "x${FORCE_DOWNLOAD}" = "x" ];then
      return 0
    fi

    # 创建输出目录（如果不存在）
    local output_dir=$(dirname "$output_file")
    if [ ! -d "$output_dir" ]; then
        mkdir -p "$output_dir" || {
            logger "错误：无法创建目录 '$output_dir'" >&2
            return 1
        }
    fi
    if [ "x${CURL}" != "x" ];then
      if ! "${CURL}" -fL -s -o "$output_file" "$url"; then
            echo "$(date):错误：${CURL}下载失败: $url" >&2
            rm -f "$output_file"  # 删除可能的部分下载文件
            return 1
      else
        echo "$(date):下载成功: $url --> $output_file"
      fi
    elif [ "x${WGET}" != "x" ]; then
      if ! "${WGET}" -q -O "$output_file" "$url"; then
        echo "$(date):错误：${WGET}下载失败: $url" >&2
        rm -f "$output_file"  # 删除可能的部分下载文件
        return 1
      else
        echo "$(date):下载成功: $url --> $output_file"
      fi
    else
      # 检查下载工具
      if [ "x$(command -v curl)" != "x" ]; then
          if ! curl -fL -s -o "$output_file" "$url"; then
              logger "错误：curl下载失败: $url" >&2
              rm -f "$output_file"  # 删除可能的部分下载文件
              return 1
          else
            logger "下载成功: $url --> $output_file"
          fi
      elif [ "x$(command -v wget)" != "x" ]; then
          if ! wget -q -O "$output_file" "$url"; then
              logger "错误：wget下载失败: $url" >&2
              rm -f "$output_file"  # 删除可能的部分下载文件
              return 1
          else
            logger "下载成功: $url --> $output_file"
          fi
      else
          logger "错误：未找到curl或wget，请安装任一工具" >&2
          return 1
      fi
    fi
    return 0
}


download_package(){
  package=$1
  target=$2
  download "${UPSTREAM}/api/packages/download/latest?system=${OS}&architecture=${ARCH}&name=${package}" "${target}"
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

logger(){
  echo "$(date): $1"
}

pid_exists_and_name_contains() {
  # 检查参数数量
  if [ $# -ne 2 ]; then
      echo "用法: pid_exists_and_name_contains <PID> <进程名关键字>" >&2
      return 1
  fi

  local pid="$1"
  local name_pattern="$2"

  # 检查PID是否为数字
  if ! [[ "$pid" =~ ^[0-9]+$ ]]; then
      echo "错误: PID 必须是数字" >&2
      return 1
  fi

  # 检查进程是否存在
  if ! kill -0 "$pid" >/dev/null 2>&1; then
      # echo "PID $pid 不存在" >&2
      return 2
  fi

  # 获取进程名并检查是否包含指定字符串
  local process_name
  # 尝试从/proc获取进程名（Linux系统）
  if [ -f "/proc/$pid/comm" ]; then
      process_name=$(cat "/proc/$pid/comm")
  else
      # 如果/proc不可用，使用ps命令（兼容其他Unix系统）
      process_name=$(ps -p "$pid" -o comm= 2>/dev/null)
  fi

  # 检查进程名是否包含指定模式
  if [[ "$process_name" == *"$name_pattern"* ]]; then
      # echo "PID $pid 存在且进程名($process_name)包含 '$name_pattern'"
      return 0
  else
      # echo "PID $pid 存在但进程名($process_name)不包含 '$name_pattern'" >&2
      return 3
  fi
}

is_pid_running(){
  pid="$1"
  helper="$2"
  # 使用kill -0检查PID是否存在
  if kill -0 "$pid" >/dev/null 2>&1; then
    if [ "x$helper" == "x" ];then
      return 0
    else
      pid_exists_and_name_contains "$pid" "$helper"
      return $?
    fi
  else
    return 255
  fi
}

is_pid_file_running(){
  pid_file="$1"
  if [ -f "$pid_file" ];then
    pid="$(cat $pid_file)"
    is_pid_running "$pid"
    return $?
  fi
  return 1
}

kill_pid_file(){
  pid_file="$1"
  if [ -f "$pid_file" ];then
    pid="$(cat $pid_file)"
    is_pid_running "$pid"
    if [ "$?" = "0" ];then
      children=$(ps -o pid --ppid "$pid" --no-headers 2>/dev/null | awk '{print $1}')
      logger "kill process: $pid"
      kill -9 "$pid"
      for child in $children; do
        logger "kill child process: $pid"
        kill -9 "$child"
      done
    fi
  else
    logger "pid_file not exist: ${pid_file}"
  fi
}

prepare_dir(){
  dirs="$1"
  for dir in ${dirs};
  do
    if [ ! -d "${dir}" ];then
      logger "start create dir: ${dir}"
      mkdir -p "$dir"
    fi
  done
}

clean_proxy(){
  unset http_proxy
  unset https_proxy
  unset HTTP_PROXY
  unset HTTPS_PROXY
}

create_bridge() {
    local bridge_name="$1"
    # 检查网桥是否存在
    if ! ip link show type bridge | grep -q "$bridge_name"; then
        #logger "网桥 $bridge_name 不存在，正在创建..."
        ip link add name "$bridge_name" type bridge
        if [ ! $? -eq 0 ];then
          logger "网桥 $bridge_name 创建失败..."
        else
          ip link set dev "$bridge_name" up
          logger "已成功创建网桥 $bridge_name"
        fi
    else
        logger "网桥 $bridge_name 已存在，无需创建"
    fi
}

remove_bridge_if_exists() {
    local bridge_name="$1"
    # 检查网桥是否存在
    if ip link show type bridge | grep -q "$bridge_name"; then
        #logger "网桥 $bridge_name 存在，正在删除..."
        ip link set dev "$bridge_name" down
        ip link delete "$bridge_name" type bridge
        logger "已成功删除网桥 $bridge_name"
    else
        logger "网桥 $bridge_name 不存在，无需操作"
    fi
}

is_valid_ip_port() {
    local input="$1"

    # 检查是否只包含一个冒号
    if [[ $(echo "$input" |grep -o ':' | wc -l) -ne 1 ]]; then
        return 1
    fi

    # 分割IP和端口
    local ip="${input%%:*}"
    local port="${input##*:}"

    # 验证IP部分（IPv4格式）
    if [[ ! $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 1
    fi
    local IFS='.'
    echo "$ip" | read -ra ip_parts
    if [[ ${#ip_parts[@]} -ne 4 ]]; then
        return 1
    fi
    for part in "${ip_parts[@]}"; do
        if [[ $part -lt 0 || $part -gt 255 ]]; then
            return 1
        fi
    done
    # 验证端口部分（0-65535）
    if [[ ! $port =~ ^[0-9]+$ ]]; then
        return 1
    fi
    if [[ $port -lt 0 || $port -gt 65535 ]]; then
        return 1
    fi
    return 0
}

if [ -f "${ROOT_DIR}/bin/curl" ];then
  export CURL="${ROOT_DIR}/bin/curl"
fi


#we are in local run mode
chmod +x "${ROOT_DIR}/config/sothothv2_agent.ini"
.  "${ROOT_DIR}/config/sothothv2_agent.ini"


PROJECT_ID="${project_id}"
NODE_ID="${uuid}"
UPSTREAM_SERVER="${server_addr}"
UPSTREAM_PORT="${server_port}"
UPSTREAM="http://${server_addr}:${server_port}"
ARCH="$(uname -m)"
OS="linux"


if [ "$ARCH" = "armv7l" ] || [ "$ARCH" = "armv7" ] || [ "$ARCH" = "armv8l" ];then
  if [ "x$(cat /proc/self/maps | grep ld-linux-armhf)" != "x" ];then
    ARCH="armhf"
  elif [ "x$(cat /proc/self/maps | grep ld-linux.so)" != "x" ];then
    ARCH="armel"
  else
    logger" unable current ARCH, use origin: $ARCH"
  fi
fi

if [[ ":$PATH:" != *":$ROOT_DIR:"* ]] && [[ ":$PATH:" != *":$ROOT_DIR"* ]] && [[ ":$PATH:" != *"$ROOT_DIR:"* ]]; then
    export PATH="$ROOT_DIR/bin:$ROOT_DIR/script:$ROOT_DIR/usr/bin:$PATH"
fi

#fi