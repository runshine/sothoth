#!/bin/sh

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
    return 0
}

download_if_none_exist() {
  if [ ! -f "$2" ];then
    download "$1" "$2"
  fi
}

download_script() {
  download "$1" "$2"
  if [ -f "$2" ];then
    chmod +x "$2"
  fi
}

download_utils(){
  download_script "$1" "$2"
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