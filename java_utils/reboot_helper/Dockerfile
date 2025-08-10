FROM ubuntu:latest as reboot_helper_builder

# prepare builder
RUN apt update && apt install -y make gcc g++ liblzo2-dev cmake openjdk-8-jdk
# do make
RUN mkdir -p /build/

COPY . /build/

RUN cd /build/source && cmake -DCMAKE_BUILD_TYPE=Release . && make && make install

FROM busybox:latest
COPY --from=reboot_helper_builder /build/source/dist/lib/libreboot_helper.so /libreboot_helper.so
CMD ["/bin/sh"]