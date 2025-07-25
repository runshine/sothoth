#!/bin/bash
echo "$(date): Running nginx new entrypoint"
bridge_name="br-openvpn"

if [ ! -d "/etc/nginx/stream.d/" ];then
  mkdir -p /etc/nginx/stream.d
fi
IFS=' '
read -ra MAP_LIST_ARRAY <<<"$MAP_LIST"
for MAP_ITEM in "${MAP_LIST_ARRAY[@]}"
do
  source_port="$(echo ${MAP_ITEM} | awk -F':' '{print $1}')"
  dest_port="$(echo ${MAP_ITEM} | awk -F':' '{print $2}')"
  if [ "x${source_port}" == "x" ] || [ "x${dest_port}" == "x" ];then
    echo "map item is error: ${MAP_ITEM}"
    continue
  fi
  echo "start process: ${source_port} --> ${dest_port}"
cat << EOF > /etc/nginx/stream.d/${source_port}_${dest_port}.conf
    server {
        listen ${source_port} udp reuseport;  # 监听UDP端口1194
        proxy_pass 127.0.0.1:${dest_port};    # 目标服务器地址
        proxy_timeout 60s;                   # 超时时间（按需调整）
        #proxy_responses 0;                    # 适用于单方向UDP流（如VPN）
    }
EOF
done


echo "$(date): Running old entrypoint: /docker-entrypoint.sh nginx -g 'daemon off;'"
exec /docker-entrypoint.sh nginx -g "daemon off;"