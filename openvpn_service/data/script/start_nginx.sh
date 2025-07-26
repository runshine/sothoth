#!/bin/sh

NGINX_ROOT_DIR="$(cd "$(dirname $0)";pwd)/../nginx"
ARCH="$(uname -m)"
OS="linux"
WORKSPACE="$1"
UPSTREAM="$2"
UPSTREAM_SERVER="$(echo $2 | awk -F':' '{print $1}')"
UPSTREAM_PORT="$(echo $2 | awk -F':' '{print $2}')"
cd "$(cd "$(dirname $0)";pwd)"
. common.sh

pre_build_dirs="$NGINX_ROOT_DIR/conf $NGINX_ROOT_DIR/log $NGINX_ROOT_DIR/run $NGINX_ROOT_DIR/conf/conf.d $NGINX_ROOT_DIR/conf/stream.d"
prepare_dir "$pre_build_dirs"

download_replace(){
  download "$1" "$2"
  sed -i "s#/var/log/nginx#${NGINX_ROOT_DIR}#g" "$2"
}

download_replace "$UPSTREAM/download/conf/nginx/nginx.conf" "${NGINX_ROOT_DIR}/conf/nginx.conf"
download_replace "$UPSTREAM/download/conf/nginx/mime.types" "${NGINX_ROOT_DIR}/conf/mime.types"

cat << EOF > ${NGINX_ROOT_DIR}/conf/stream.d/${UPSTREAM_SERVER}.conf
    server {
        listen 11194 udp reuseport;
        proxy_pass ${UPSTREAM_SERVER}:11194;    # 目标服务器地址
        proxy_timeout 60s;                   # 超时时间（按需调整）
    }
    server {
        listen 11195 udp reuseport;
        proxy_pass ${UPSTREAM_SERVER}:11195;    # 目标服务器地址
        proxy_timeout 60s;                   # 超时时间（按需调整）
    }
    server {
        listen 11196 udp reuseport;
        proxy_pass ${UPSTREAM_SERVER}:11196;    # 目标服务器地址
        proxy_timeout 60s;                   # 超时时间（按需调整）
    }
    server {
        listen 11197 udp reuseport;
        proxy_pass ${UPSTREAM_SERVER}:11197;    # 目标服务器地址
        proxy_timeout 60s;                   # 超时时间（按需调整）
    }
EOF

cat << EOF > ${NGINX_ROOT_DIR}/conf/conf.d/${UPSTREAM_SERVER}.conf
server {
        listen 11199;                  # 监听 HTTP 8080 端口
        server_name _;                # 匹配所有域名

        # 处理所有其他请求
        location / {
            proxy_pass http://${UPSTREAM_SERVER}:${UPSTREAM_PORT};  # 重定向到后端服务器
            proxy_set_header Host \$host;       # 传递原始主机头
            proxy_set_header X-Real-IP \$remote_addr;  # 传递客户端真实IP
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;

            # 可选：增加超时设置（根据后端需求调整）
            proxy_connect_timeout 60s;
            proxy_read_timeout 120s;
        }
        # 错误页面配置（可选）
        error_page 404 /404.html;
        location = /404.html {
            internal;
        }
    }

EOF

if ! is_pid_file_running "${NGINX_ROOT_DIR}/run/nginx.pid";then
  logger "start nginx daemon: ${NGINX_ROOT_DIR}/../utils/nginx -p \"${NGINX_ROOT_DIR}\" -c \"${NGINX_ROOT_DIR}/conf/nginx.conf\" -g \"daemon on;\""
  chmod +x "${NGINX_ROOT_DIR}/../utils/nginx"
  "${NGINX_ROOT_DIR}/../utils/nginx" -p "${NGINX_ROOT_DIR}" -c "${NGINX_ROOT_DIR}/conf/nginx.conf" -g "daemon on;"
else
  logger "nginx already run, ignore re-run, pid: $(cat ${NGINX_ROOT_DIR}/run/nginx.pid)"
fi


