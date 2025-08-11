FROM runshine0819/reboot_helper:latest AS reboot_helper
FROM runshine0819/attach_helper:latest AS attach_helper
FROM ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-java:2.18.1 AS autoinstrumentation-java
FROM openjdk:8-jdk
COPY --from=reboot_helper            /libreboot_helper.so /libreboot_helper.so
COPY --from=attach_helper            /attach_helper.jar   /attach_helper.jar
COPY --from=autoinstrumentation-java /javaagent.jar       /opentelemetry-javaagent.jar
COPY . /opt/
CMD ["/bin/sh"]