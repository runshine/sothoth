FROM runshine0819/java_helper:latest AS java_helper

FROM ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-java:2.18.1 as autoinstrumentation-java

FROM openjdk:8-jdk

COPY --from=java_helper /libjava_helper.so /libjava_helper.so
COPY --from=autoinstrumentation-java /javaagent.jar /opentelemetry-javaagent.jar
CMD ["/bin/sh"]