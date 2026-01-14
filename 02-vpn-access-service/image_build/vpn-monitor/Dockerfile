FROM alpine/kubectl:latest

WORKDIR /

#sudo apt install default-libmysqlclient-dev
# 安装编译依赖
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories \
RUN apk add --no-cache jq iproute2 net-tools vim curl bash grep ipcalc

CMD [ "sh"]