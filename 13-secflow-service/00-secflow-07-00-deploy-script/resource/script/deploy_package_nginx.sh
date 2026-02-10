#!/bin/sh

set -e

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
cd "$(cd "$(dirname $0)";pwd)"
. "${ROOT_DIR}/script/common.sh"

deploy_package.sh nginx

[ -d "${ROOT_DIR}/usr/etc/nginx" ] || mkdir -p "${ROOT_DIR}/usr/etc/nginx"
[ -d "${ROOT_DIR}/usr/etc/nginx/conf.d" ] || mkdir -p "${ROOT_DIR}/usr/etc/nginx/conf.d"
[ -d "${ROOT_DIR}/usr/etc/nginx/stream.d" ] || mkdir -p "${ROOT_DIR}/usr/etc/nginx/stream.d"


cat << EOF > ${ROOT_DIR}/usr/etc/nginx/stream.d/${UPSTREAM_SERVER}.conf
    server {
        listen 11194 udp reuseport;
        proxy_pass ${UPSTREAM_SERVER}:11194;    # 目标服务器地址
        proxy_timeout 60s;                   # 超时时间（按需调整）
    }
EOF

cat << EOF > ${ROOT_DIR}/usr/etc/nginx/conf.d/${UPSTREAM_SERVER}.conf
server {
        listen 11199;                  # 监听 HTTP 11199 端口
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

cat << EOF > ${ROOT_DIR}/usr/etc/nginx/nginx.conf
user  root;
worker_processes  auto;

error_log  ${ROOT_DIR}/var/log/nginx_error.log notice;
pid        ${ROOT_DIR}/var/run/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include      ${ROOT_DIR}/usr/etc/nginx/mime.types;
    default_type  application/octet-stream;
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';
    access_log ${ROOT_DIR}/var/log/nginx_http_access.log  main;
    sendfile        on;
    #tcp_nopush     on;
    keepalive_timeout  65;
    #gzip  on;
    include ${ROOT_DIR}/usr/etc/nginx/conf.d/*.conf;
}
stream {
    log_format proxy '\$remote_addr [\$time_local] '
                 '\$protocol \$status \$bytes_sent \$bytes_received '
                 '\$session_time "\$upstream_addr" '
                 '"\$upstream_bytes_sent" "\$upstream_bytes_received" "\$upstream_connect_time"';

    access_log ${ROOT_DIR}/var/log/nginx_stream_access.log proxy;
    open_log_file_cache off;
    include  ${ROOT_DIR}/usr/etc/nginx/stream.d/*.conf;
}
EOF

cat << EOF > ${ROOT_DIR}/usr/etc/nginx/mime.types

types {
    text/html                             html htm shtml;
    text/css                              css;
    text/xml                              xml;
    image/gif                             gif;
    image/jpeg                            jpeg jpg;
    application/javascript                js;
    application/atom+xml                  atom;
    application/rss+xml                   rss;

    text/mathml                           mml;
    text/plain                            txt;
    text/vnd.sun.j2me.app-descriptor      jad;
    text/vnd.wap.wml                      wml;
    text/x-component                      htc;

    image/png                             png;
    image/tiff                            tif tiff;
    image/vnd.wap.wbmp                    wbmp;
    image/x-icon                          ico;
    image/x-jng                           jng;
    image/x-ms-bmp                        bmp;
    image/svg+xml                         svg svgz;
    image/webp                            webp;

    application/font-woff                 woff;
    application/java-archive              jar war ear;
    application/json                      json;
    application/mac-binhex40              hqx;
    application/msword                    doc;
    application/pdf                       pdf;
    application/postscript                ps eps ai;
    application/rtf                       rtf;
    application/vnd.apple.mpegurl         m3u8;
    application/vnd.ms-excel              xls;
    application/vnd.ms-fontobject         eot;
    application/vnd.ms-powerpoint         ppt;
    application/vnd.wap.wmlc              wmlc;
    application/vnd.google-earth.kml+xml  kml;
    application/vnd.google-earth.kmz      kmz;
    application/x-7z-compressed           7z;
    application/x-cocoa                   cco;
    application/x-java-archive-diff       jardiff;
    application/x-java-jnlp-file          jnlp;
    application/x-makeself                run;
    application/x-perl                    pl pm;
    application/x-pilot                   prc pdb;
    application/x-rar-compressed          rar;
    application/x-redhat-package-manager  rpm;
    application/x-sea                     sea;
    application/x-shockwave-flash         swf;
    application/x-stuffit                 sit;
    application/x-tcl                     tcl tk;
    application/x-x509-ca-cert            der pem crt;
    application/x-xpinstall               xpi;
    application/xhtml+xml                 xhtml;
    application/xspf+xml                  xspf;
    application/zip                       zip;

    application/octet-stream              bin exe dll;
    application/octet-stream              deb;
    application/octet-stream              dmg;
    application/octet-stream              iso img;
    application/octet-stream              msi msp msm;

    application/vnd.openxmlformats-officedocument.wordprocessingml.document    docx;
    application/vnd.openxmlformats-officedocument.spreadsheetml.sheet          xlsx;
    application/vnd.openxmlformats-officedocument.presentationml.presentation  pptx;

    audio/midi                            mid midi kar;
    audio/mpeg                            mp3;
    audio/ogg                             ogg;
    audio/x-m4a                           m4a;
    audio/x-realaudio                     ra;

    video/3gpp                            3gpp 3gp;
    video/mp2t                            ts;
    video/mp4                             mp4;
    video/mpeg                            mpeg mpg;
    video/quicktime                       mov;
    video/webm                            webm;
    video/x-flv                           flv;
    video/x-m4v                           m4v;
    video/x-mng                           mng;
    video/x-ms-asf                        asx asf;
    video/x-ms-wmv                        wmv;
    video/x-msvideo                       avi;
}
EOF

cat  <<EOF > ${ROOT_DIR}/service_config/00_nginx_service.json
{
  "name": "nginx",
  "description": "nginx service",
  "start_cmd": "${ROOT_DIR}/bin/bash -c \"exec -a ng_web ${ROOT_DIR}/usr/bin/nginx -p ${ROOT_DIR}/usr/etc/nginx -c ${ROOT_DIR}/usr/etc/nginx/nginx.conf\"",
  "stop_cmd": "${ROOT_DIR}/usr/bin/nginx -p ${ROOT_DIR}/usr/etc/nginx -c  ${ROOT_DIR}/usr/etc/nginx/nginx.conf -s quit",
  "restart_cmd": "${ROOT_DIR}/usr/bin/nginx -p ${ROOT_DIR}/usr/etc/nginx -c  ${ROOT_DIR}/usr/etc/nginx/nginx.conf -s reopen",
  "pid_file": "${ROOT_DIR}/var/run/nginx.pid",
  "stdout_log": "${ROOT_DIR}/var/log/monitor_nginx_stdout.log",
  "stderr_log": "${ROOT_DIR}/var/log/monitor_nginx_stderr.log",
  "work_dir": "${ROOT_DIR}",
  "monitor_mode": "self",
  "check_interval": 30,
  "max_failures": 2,
  "depends_on": []
}
EOF

#if ! is_pid_file_running "${NGINX_ROOT_DIR}/run/nginx.pid";then
#  logger "start nginx daemon: ${NGINX_ROOT_DIR}/../utils/nginx -p \"${NGINX_ROOT_DIR}\" -c \"${NGINX_ROOT_DIR}/conf/nginx.conf\" -g \"daemon on;\""
#  chmod +x "${NGINX_ROOT_DIR}/../utils/nginx"
#  exec -a "ng_web" "${NGINX_ROOT_DIR}/../utils/nginx" -p "${NGINX_ROOT_DIR}" -c "${NGINX_ROOT_DIR}/conf/nginx.conf" -g "daemon on;"
#else
#  logger "nginx already run, ignore re-run, pid: $(cat ${NGINX_ROOT_DIR}/run/nginx.pid)"
#fi


