FROM ubuntu:latest AS attach_helper_builder

# prepare builder
RUN apt update && apt install -y openjdk-8-jdk maven
# do make
RUN mkdir -p /build/

COPY . /build/

RUN cd /build/agent-attach-java && mvn -B package --file pom.xml

FROM openjdk:17-jdk-alpine
COPY --from=attach_helper_builder /build/agent-attach-java/target/agent-attach-java-jar-with-dependencies.jar /attach_helper.jar
CMD ["/bin/sh"]


#https://github.com/GuanceCloud/agent-attach-java.git