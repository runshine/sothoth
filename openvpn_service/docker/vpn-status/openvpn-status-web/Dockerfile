FROM alpine:3.22

EXPOSE 8080

ENV VERSION=3.4.0

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories

RUN apk --no-cache add openssl ca-certificates && \
    apk --no-cache add ruby ruby-webrick && \
    apk --no-cache add --virtual .build-deps ruby-dev build-base tzdata && \
    gem install --no-document openvpn-status-web -v ${VERSION} && \
    # set timezone to Berlin
    cp /usr/share/zoneinfo/Europe/Berlin /etc/localtime && \
    apk del .build-deps

ENTRYPOINT ["openvpn-status-web", "/etc/openvpn-status-web/config.yml"]
