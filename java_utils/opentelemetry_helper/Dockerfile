FROM ubuntu:latest as nodevpn-builder
LABEL previous-stage=nodevpn-builder

# prepare builder
RUN apt update && apt install -y make gcc g++ liblzo2-dev cmake openjdk-8-jdk
# do make
RUN mkdir -p /build/

COPY . /build/

RUN cd /build/source && cmake -DCMAKE_BUILD_TYPE=Release . && make && make install

FROM busybox:latest
COPY --from=nodevpn-builder /build/source/dist/lib/libjava_helper.so /libjava_helper.so
CMD ["/bin/sh"]